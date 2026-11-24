import json
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import AwareDatetime, Field, model_validator

from app.provenance.local import REPO, OperationError, digest, run_tool, tool_path, validate_json
from app.provenance.models import Digest, Provenance, Reference, ScanId, StrictModel
from app.schemas.findings import FindingsDocument

POLICY = REPO / "policies" / "kestral" / "security.rego"
Decision = Literal["ALLOW", "REVIEW", "BLOCK"]


class Violation(StrictModel):
    policy_id: Literal["POL-001", "POL-002", "POL-003", "POL-004", "POL-005", "POL-006"]
    severity: Literal["REVIEW", "BLOCK"]
    message: Reference
    evidence_refs: list[Reference] = Field(min_length=1, max_length=12)


class DecisionResult(StrictModel):
    decision: Decision
    violations: list[Violation] = Field(max_length=4096)

    @model_validator(mode="after")
    def check_precedence(self):
        severities = {violation.severity for violation in self.violations}
        expected = "BLOCK" if "BLOCK" in severities else "REVIEW" if severities else "ALLOW"
        if self.decision != expected:
            raise ValueError("OPA decision disagrees with its violations")
        return self


class PolicyResult(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_id: ScanId
    timestamp: AwareDatetime
    decision: Decision | None
    evaluation_status: Literal["evaluated", "error"]
    violations: list[Violation]
    policy_version: Literal["1.0"] = "1.0"
    policy_hash: Digest | None
    tool_version: str | None
    warnings: list[Reference]


def build_input(
    scan_id: str, findings_json: bytes, provenance_json: bytes, strict: bool,
) -> dict:
    raw = json.loads(validate_json(findings_json))
    required = {"schema_version", "scan_id", "findings", "sources", "stats", "partial", "warnings"}
    if type(raw) is not dict or not required <= raw.keys():
        raise OperationError("Findings document is missing required fields")
    if type(raw["findings"]) is not list or len(raw["findings"]) > 2048:
        raise OperationError("Invalid findings list or count")
    findings = FindingsDocument.model_validate(raw, strict=True)
    provenance = Provenance.model_validate_json(validate_json(provenance_json))
    if findings.scan_id != scan_id or provenance.scan_id != scan_id:
        raise OperationError("Evidence scan ID does not match the requested scan ID")
    items = []
    for finding in findings.findings:
        if not 0 < len(finding.finding_id) <= 512:
            raise OperationError("Invalid finding ID")
        items.append({
            "id": finding.finding_id, "kind": finding.kind, "scope": finding.scope,
            "score": finding.cvss.base_score if finding.cvss else None,
        })
    runs = {source.name: source.status for source in findings.sources}
    vulnerabilities = sum(item["kind"] == "vulnerability" for item in items)
    if (
        len({item["id"] for item in items}) != len(items)
        or len(runs) != len(findings.sources)
        or findings.stats.vulnerabilities != vulnerabilities
        or findings.stats.workflow_pins != len(items) - vulnerabilities
        or findings.stats.components_total
        != findings.stats.components_assessed + findings.stats.components_not_assessed
    ):
        raise OperationError("Findings counts or identities are inconsistent")
    unavailable = (
        runs.get("workflow-scan") != "ok"
        or "failed" in runs.values()
        or findings.stats.components_not_assessed > 0
        or (
            findings.stats.components_total > 0
            and not any(runs.get(name) == "ok" for name in ("OSV", "Grype"))
        )
    )
    return {
        "schema_version": "1.0", "strict": strict,
        "findings_partial": findings.partial or unavailable, "findings": items,
        "assessment": provenance.assessment_status,
        "artifacts": [artifact.model_dump() for artifact in provenance.artifacts],
    }


def parse_result(output: bytes) -> DecisionResult:
    try:
        body = json.loads(validate_json(output))
        [result] = body["result"]
        [expression] = result["expressions"]
        return DecisionResult.model_validate(expression["value"])
    except (KeyError, TypeError, ValueError, RecursionError):
        raise OperationError("OPA returned an undefined or invalid decision") from None


def evaluate(scan_id: str, root: Path, policy_input: dict) -> PolicyResult:
    policy_hash = None
    version = None
    result = None
    warnings = []
    try:
        if POLICY.resolve() != POLICY or POLICY.is_relative_to(root):
            raise OperationError("Implementation policy must be outside the evidence directory")
        with POLICY.open("rb") as source:
            policy = source.read(65537)
        if len(policy) > 65536:
            raise OperationError("Implementation policy exceeds size limit")
        policy_hash = digest(policy)
        opa = tool_path("opa", root)
        with tempfile.TemporaryDirectory(prefix="kestral-opa-") as directory:
            stage = Path(directory)
            (stage / "security.rego").write_bytes(policy)
            (stage / "input.json").write_text(json.dumps(policy_input), encoding="utf-8")
            code, output = run_tool(opa, ["version"], stage)
            match = re.search(rb"(?m)^Version:\s+([0-9][a-zA-Z0-9.+-]{0,63})\s*$", output)
            if code or not match:
                raise OperationError("Could not identify OPA version")
            version = match[1].decode("ascii")
            code, output = run_tool(
                opa, ["eval", "--fail", "--data", "security.rego", "--input", "input.json",
                      "--format", "json", "data.kestral.security.result"], stage,
            )
            if code:
                raise OperationError("OPA evaluation failed or was undefined")
            result = parse_result(output)
    except OperationError as error:
        warnings.append(str(error))
    except OSError:
        warnings.append("OPA or implementation policy could not be accessed locally")
    return PolicyResult(
        scan_id=scan_id, timestamp=datetime.now(UTC),
        decision=result.decision if result else None,
        evaluation_status="evaluated" if result else "error",
        violations=result.violations if result else [], warnings=warnings,
        policy_hash=policy_hash, tool_version=version,
    )
