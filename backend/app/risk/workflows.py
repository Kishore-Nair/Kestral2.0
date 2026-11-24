"""Detect GitHub Actions steps that use a mutable reference instead of a commit SHA.

``uses: owner/action@v4`` or ``@main`` can be moved to different code by whoever
controls that tag or branch. Only a full 40-character commit SHA (or a Docker
image digest) is immutable. Files are read as text; nothing is executed.
"""

import re
from pathlib import Path

from app.graph.serialization import stable_id
from app.schemas.findings import Finding, FindingSource
from app.schemas.inventory import Evidence

MAX_WORKFLOW_BYTES = 1024 * 1024
_USES = re.compile(r"""^\s*(?:-\s*)?uses\s*:\s*(["']?)([^"'\s#]+)\1""")
_SHA = re.compile(r"^[0-9a-f]{40}$")
MUTABLE_NOTE = "A tag or branch can be moved to different code; only a full commit SHA is immutable"


def _is_workflow(path: str) -> bool:
    return path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))


def _read_text(repo_dir: Path, relative: str, max_bytes: int = MAX_WORKFLOW_BYTES) -> str | None:
    candidate = repo_dir / relative
    try:
        resolved = candidate.resolve()
        resolved.relative_to(repo_dir.resolve())
    except (OSError, ValueError):
        return None
    if candidate.is_symlink() or not resolved.is_file():
        return None
    if resolved.stat().st_size > max_bytes:
        return None
    try:
        return resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _problem(value: str) -> tuple[str, str] | None:
    """(action, reason) when the reference is mutable, else None."""
    if value.startswith("./"):
        return None  # local action, versioned with this repository
    if value.startswith("docker://"):
        return None if "@sha256:" in value else (value, "Docker image referenced without a digest")
    action, _, ref = value.partition("@")
    if not ref:
        return action, "No version reference: uses the action's default branch"
    if _SHA.match(ref):
        return None
    return action, f"Pinned to mutable ref '{ref}'"


def workflow_findings(repo_dir: Path, ci_files: list[str]) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    warnings: list[str] = []
    for path in sorted(p for p in ci_files if _is_workflow(p)):
        text = _read_text(repo_dir, path)
        if text is None:
            warnings.append(f"Workflow {path} could not be read safely and was skipped")
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            matched = _USES.match(line)
            if not matched:
                continue
            value = matched.group(2)
            problem = _problem(value)
            if problem is None:
                continue
            action, reason = problem
            uncertainty = [MUTABLE_NOTE]
            if action.split("/", 1)[0] in {"actions", "github"}:
                uncertainty.append("First-party GitHub action: lower risk, but still mutable")
            locator = f"line {number}: uses: {value}"
            findings.append(
                Finding(
                    finding_id=stable_id("finding", "workflow_pin", path, number, value),
                    kind="workflow_pin",
                    title=f"{action}: {reason}",
                    subject_id=None,
                    subject_label=action,
                    advisory_ids=[],
                    sources=[FindingSource(name="workflow-scan", record_id=f"{path}:{number}")],
                    fixed_versions=[],
                    evidence=[Evidence(path=path, kind="ci-workflow", locator=locator)],
                    uncertainty=uncertainty,
                )
            )
    return findings, warnings
