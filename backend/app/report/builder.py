"""Assemble the Guardian report from a scan's saved artifacts and recorded decisions.

The report only restates what Kestral recorded: scan artifacts, scanner findings, human
decisions, AI proposals (labelled as such) and sandbox validations. Nothing is inferred.
"""

import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.database.models import AiAnalysisRow, RemediationProposalRow, Scan, ValidationRunRow
from app.privacy.service import assess as assess_privacy
from app.remediation.service import to_proposal
from app.schemas.dependency import DependencyDocument
from app.schemas.findings import FindingsDocument
from app.validation.service import to_api as validation_to_api

REPORT_SCHEMA = "kestral-guardian-report/1.0"

RESPONSIBLE_AI = [
    "AI is optional and used only when a reviewer asks for an analysis of one finding. "
    "Scanning, SBOM generation, dependency graphs, vulnerability matching, CVSS scoring and "
    "priority are deterministic and never come from a model.",
    "The model can only call registered read-only tools (at most 5 per finding, 2 of them "
    "network lookups to OSV or the npm/PyPI registry). It cannot run commands, write files, "
    "change findings or apply changes.",
    "Every AI claim must cite evidence IDs from the scan; Kestral rejects unknown IDs, marks "
    "unsupported facts as unverified, and checks proposed fixed versions against OSV affected "
    "ranges, manifest ranges and the dependency graph before showing them.",
    "Repository and advisory text is passed to the model as quoted untrusted data; instructions "
    "inside it are ignored. Secret-looking values are redacted; source code, .env files and "
    "credentials are never sent to the AI provider.",
    "Every change needs explicit human approval. Approval records a decision only; sandbox "
    "validation runs in an isolated copy and nothing is merged, pushed or deployed by Kestral.",
    "The scanned project's own code (installs, tests) runs only inside a locked-down container; "
    "without a container runtime, tests are reported as not run.",
]

LIMITATIONS = [
    "Findings are not reachability-checked: a vulnerable package may never be called.",
    "A skipped or failed scanner is not a zero-finding result; see the source status table.",
    "Suspicious-change checks are heuristics and indicators, not proof of malicious intent.",
    "Sandbox validation proves the dependency change and rescan; it is not a full release test.",
]


def _load(path: Path, model):
    return model.model_validate_json(path.read_bytes())


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def privacy_view(findings: FindingsDocument, settings: Settings) -> dict:
    """ENISA privacy impact under the configured data processing context (top 25 scored)."""
    assessment = assess_privacy(findings, settings.privacy_data_context)
    scored = [i for i in assessment.impacts if i.score is not None]
    return {
        "data_context": assessment.data_context,
        "dpc": assessment.dpc,
        "method": assessment.method,
        "dataset": assessment.dataset.model_dump(mode="json"),
        "summary": assessment.summary.model_dump(mode="json"),
        "top": [
            {
                "package": i.subject_label,
                "title": i.title,
                "score": i.score,
                "band": i.band,
                "linddun": i.linddun,
                "ei": i.ei,
                "cb": i.cb,
                "cwes": [m.cwe_id for m in i.mappings if m.status == "mapped"],
            }
            for i in scored[:25]
        ],
        "caveats": assessment.caveats,
    }


def build_report(db: Session, settings: Settings, scan: Scan) -> dict:
    scan_dir = settings.scan_output_root / scan.scan_id
    findings: FindingsDocument = _load(scan_dir / "findings.json", FindingsDocument)
    document: DependencyDocument = _load(scan_dir / "normalized.json", DependencyDocument)
    graph = _json(scan_dir / "graph.json")
    labels = {
        n["data"]["id"]: n["data"].get("label", n["data"]["id"]) for n in graph.get("nodes", [])
    }
    directness = {n["data"]["id"]: n["data"].get("directness") for n in graph.get("nodes", [])}

    def path_labels(paths: list[list[str]]) -> list[str]:
        return [" → ".join(labels.get(node, node) for node in path) for path in paths[:3]]

    # Inventory ---------------------------------------------------------------
    ecosystems: dict[str, int] = {}
    for component in document.components:
        ecosystems[component.ecosystem] = ecosystems.get(component.ecosystem, 0) + 1
    components = [
        {
            "name": c.name,
            "version": c.version,
            "ecosystem": c.ecosystem,
            "purl": c.purl,
            "scope": c.scope,
            "project": c.project_path or ".",
            "directness": directness.get(c.component_id),
        }
        for c in sorted(document.components, key=lambda c: (c.ecosystem, c.name, c.version or ""))
    ]

    # Findings ----------------------------------------------------------------
    def finding_view(f) -> dict:
        return {
            "finding_id": f.finding_id,
            "kind": f.kind,
            "category": f.category,
            "title": f.title,
            "package": f.subject_label,
            "advisories": f.advisory_ids,
            "cves": [c.id for c in f.cves],
            "cwes": [c.id for c in f.cwes],
            "cvss": f.cvss.base_score if f.cvss else None,
            "cvss_severity": f.cvss.severity if f.cvss else None,
            "epss_percentile": f.epss.percentile if f.epss else None,
            "priority": f.priority.score if f.priority else None,
            "band": f.priority.band if f.priority else f.risk_level,
            "risk_reason": f.risk_reason,
            "directness": f.directness,
            "scope": f.scope,
            "fixed_versions": f.fixed_versions,
            "dependency_paths": path_labels(f.dependency_paths),
            "sources": sorted({s.name for s in f.sources}),
            "evidence": [f"{e.path} · {e.locator}" for e in f.evidence[:6]],
            "uncertainty": f.uncertainty,
        }

    vulns = sorted(
        (f for f in findings.findings if f.kind == "vulnerability"),
        key=lambda f: (
            -(f.priority.score if f.priority else -1),
            -(f.cvss.base_score or 0) if f.cvss else 0,
        ),
    )
    suspicious = [f for f in findings.findings if f.kind == "suspicious"]
    level = {"high": 0, "medium": 1, "low": 2}
    suspicious.sort(key=lambda f: (level.get(f.risk_level or "low", 3), f.title))
    pins = [f for f in findings.findings if f.kind == "workflow_pin"]

    bands = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in vulns:
        if f.priority:
            bands[f.priority.band] += 1

    # Actions and decisions ---------------------------------------------------
    proposal_rows = db.scalars(
        select(RemediationProposalRow).where(RemediationProposalRow.scan_id == scan.scan_id)
    ).all()
    proposals = [to_proposal(db, row).model_dump(mode="json") for row in proposal_rows]
    analyses_rows = db.scalars(
        select(AiAnalysisRow)
        .where(AiAnalysisRow.scan_id == scan.scan_id, AiAnalysisRow.result_json.is_not(None))
        .order_by(AiAnalysisRow.created_at)
    ).all()
    latest: dict[str, AiAnalysisRow] = {}
    for row in analyses_rows:
        latest[row.finding_id] = row
    ai = []
    for row in latest.values():
        rec = row.result_json or {}
        rem = rec.get("recommended_remediation") or {}
        meta = rec.get("model_metadata") or {}
        ai.append(
            {
                "analysis_id": row.analysis_id,
                "finding_id": row.finding_id,
                "revision": row.revision,
                "status": row.status,
                "title": rec.get("title"),
                "summary": rec.get("summary"),
                "strategy": rem.get("type"),
                "target_version": rem.get("target_version"),
                "fixed_version_verified": rem.get("fixed_version_verified"),
                "validation": (rec.get("validation") or {}).get("status"),
                "decision": row.decision,
                "decision_note": row.decision_note,
                "decided_at": _iso(row.decided_at),
                "model": f"{meta.get('provider')} · {meta.get('model')}",
                "tool_calls": len(rec.get("tool_trace") or []),
            }
        )
    validations = [
        validation_to_api(row).model_dump(mode="json")
        for row in db.scalars(
            select(ValidationRunRow)
            .where(ValidationRunRow.scan_id == scan.scan_id)
            .order_by(ValidationRunRow.created_at)
        ).all()
    ]

    # Remaining / accepted risk ------------------------------------------------
    verified = {
        v["change"]["finding_id"]
        for v in validations
        if v.get("result") and v["result"]["verdict"] in ("FIXED", "FIXED_WITH_NEW_RISK")
    }
    decided = {p["finding_id"]: p for p in proposals if p.get("decision")}
    remaining = []
    for f in vulns:
        proposal = decided.get(f.finding_id)
        if f.finding_id in verified:
            state = "Fix verified in sandbox; not yet applied to the repository"
        elif proposal and proposal["status"] == "REJECTED":
            state = "Accepted / deferred by reviewer (proposal rejected)"
        elif proposal and proposal["status"] == "APPROVED":
            state = "Fix approved; not yet validated"
        else:
            state = "Open"
        remaining.append(
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "package": f.subject_label,
                "band": f.priority.band if f.priority else None,
                "state": state,
                "reviewer": (proposal or {}).get("decision", {}).get("decided_by")
                if proposal
                else None,
            }
        )

    # Audit trail -------------------------------------------------------------
    events = [
        {"at": _iso(scan.created_at), "event": "Scan requested", "detail": scan.repository_url},
        {
            "at": _iso(scan.finished_at),
            "event": f"Scan {scan.status.lower()}",
            "detail": f"commit {scan.commit_sha}",
        },
    ]
    for p in proposals:
        d = p.get("decision")
        if d:
            events.append(
                {
                    "at": d["decided_at"],
                    "event": f"Remediation proposal {d['decision'].lower()}",
                    "detail": f"{p['subject_label']}: {p['recommendation']} — by {d['decided_by']}",
                }
            )
    for row in analyses_rows:
        events.append(
            {
                "at": _iso(row.finished_at or row.created_at),
                "event": f"AI analysis (revision {row.revision}) {row.status}",
                "detail": f"{row.finding_id} · {row.provider} {row.model}",
            }
        )
        if row.decision:
            events.append(
                {
                    "at": _iso(row.decided_at),
                    "event": f"AI proposal {row.decision.replace('_', ' ')}",
                    "detail": row.finding_id
                    + (f" — {row.decision_note}" if row.decision_note else ""),
                }
            )
    for v in validations:
        verdict = (v.get("result") or {}).get("verdict") or v["status"]
        events.append(
            {
                "at": v["finished_at"] or v["created_at"],
                "event": f"Sandbox validation {verdict}",
                "detail": f"{v['change']['package']} {v['change']['from_version']} → "
                f"{v['change']['to_version']}",
            }
        )
    events = [e for e in events if e["at"]]
    events.sort(key=lambda e: e["at"])

    verdicts: dict[str, int] = {}
    for v in validations:
        key = (v.get("result") or {}).get("verdict") or v["status"].upper()
        verdicts[key] = verdicts.get(key, 0) + 1

    return {
        "schema": REPORT_SCHEMA,
        "generated_at": datetime.now(UTC).isoformat(),
        "scan": {
            "scan_id": scan.scan_id,
            "repository": scan.repository_url,
            "requested_ref": scan.requested_ref,
            "resolved_ref": scan.resolved_ref,
            "commit": scan.commit_sha,
            "status": scan.status,
            "started_at": _iso(scan.started_at),
            "finished_at": _iso(scan.finished_at),
        },
        "summary": {
            "packages": len(document.components),
            "projects": len(document.roots),
            "ecosystems": ecosystems,
            "dependency_edges": (graph.get("meta") or {}).get("stats", {}).get("depends_on_edges"),
            "vulnerabilities": len(vulns),
            "vulnerability_bands": bands,
            "cves_linked": findings.stats.cves_linked,
            "suspicious_changes": len(suspicious),
            "workflow_pins": len(pins),
            "proposals": {
                status: sum(1 for p in proposals if p["status"] == status)
                for status in ("PENDING", "APPROVED", "REJECTED", "SUPERSEDED")
            },
            "ai_analyses": len(ai),
            "validations": verdicts,
            "open_risks": sum(1 for r in remaining if r["state"] == "Open"),
            "partial": findings.partial,
        },
        "sources": [s.model_dump(mode="json") for s in findings.sources],
        "warnings": findings.warnings,
        "inventory": {"ecosystems": ecosystems, "components": components},
        "findings": {
            "vulnerabilities": [finding_view(f) for f in vulns],
            "suspicious": [finding_view(f) for f in suspicious],
            "workflow_pins": [finding_view(f) for f in pins],
        },
        "changes_since_previous_scan": findings.changes.model_dump(mode="json")
        if findings.changes
        else None,
        "privacy": privacy_view(findings, settings),
        "actions": {"remediation_proposals": proposals, "ai_recommendations": ai},
        "validations": validations,
        "remaining_risks": remaining,
        "audit_trail": events,
        "responsible_ai": RESPONSIBLE_AI,
        "limitations": LIMITATIONS,
    }
