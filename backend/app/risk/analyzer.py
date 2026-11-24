"""Risk analysis stage: vulnerabilities (OSV + Grype, NVD/CVSS), workflow pins,
suspicious supply-chain changes and the diff against the previous scan.

A failing source never fails the scan: it is recorded as failed, the document is
marked partial, and the other source's findings are still reported. Raw source
output is saved next to findings.json so each finding can be traced.
"""

import json
import os
import uuid
from pathlib import Path

from app.graph.builder import make_networkx_graph
from app.risk.changes import (
    CHANGES_FILE,
    SNAPSHOT_FILE,
    Baseline,
    change_findings,
    compare,
    file_snapshot,
    load_baseline,
)
from app.risk.declarations import manifest_declarations
from app.risk.grype import GrypeError, GrypeResult, run_grype
from app.risk.merge import GRYPE_FILE, OSV_FILE, vulnerability_findings
from app.risk.nvd import NvdClient, NvdLookup
from app.risk.osv import OsvError, OsvResult, query_osv
from app.risk.scoring import NVD_FILE, cve_ids, enrich_findings
from app.risk.suspicious import escalate, suspicious_findings
from app.risk.targets import select_targets
from app.risk.workflows import workflow_findings
from app.schemas.dependency import DependencyDocument
from app.schemas.findings import FindingsDocument, FindingStats, SourceRun
from app.schemas.inventory import Inventory


def _write_json(path: Path, value: dict) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(
            json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8"
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def analyze_risk(
    repo_dir: Path,
    inventory: Inventory,
    document: DependencyDocument,
    scan_id: str,
    scan_dir: Path,
    app_name: str,
    *,
    osv_enabled: bool = True,
    grype_enabled: bool = True,
    osv_timeout: int = 20,
    grype_timeout: int = 180,
    osv_query=query_osv,
    grype_run=run_grype,
    nvd_client: NvdClient | None = None,
    nvd_budget: float = 1200,
    baseline: Baseline | None = None,
    current_commit: str | None = None,
) -> FindingsDocument:
    targets = select_targets(document.components)
    graph = make_networkx_graph(document, app_name)
    warnings: list[str] = []
    runs: list[SourceRun] = []
    purls = targets.purls

    osv: OsvResult | None = None
    if not osv_enabled:
        runs.append(SourceRun(name="OSV", status="skipped", message="Disabled in configuration"))
    elif not purls:
        runs.append(SourceRun(name="OSV", status="skipped", message="No assessable packages"))
    else:
        try:
            osv = osv_query(purls, timeout=osv_timeout)
            _write_json(scan_dir / OSV_FILE, osv.raw())
            warnings.extend(osv.warnings)
            runs.append(
                SourceRun(
                    name="OSV",
                    status="ok",
                    retrieved_at=osv.retrieved_at,
                    queried=len(purls),
                    raw_output=OSV_FILE,
                )
            )
        except OsvError as exc:
            warnings.append(f"OSV unavailable: {exc}")
            runs.append(
                SourceRun(name="OSV", status="failed", queried=len(purls), message=str(exc))
            )

    grype: GrypeResult | None = None
    if not grype_enabled:
        runs.append(SourceRun(name="Grype", status="skipped", message="Disabled in configuration"))
    elif not purls:
        runs.append(SourceRun(name="Grype", status="skipped", message="No assessable packages"))
    else:
        try:
            grype = grype_run(purls, scan_dir, timeout=grype_timeout)
            _write_json(scan_dir / GRYPE_FILE, grype.raw)
            runs.append(
                SourceRun(
                    name="Grype",
                    status="ok",
                    tool_version=grype.tool_version,
                    database_built=grype.database_built,
                    queried=len(purls),
                    raw_output=GRYPE_FILE,
                )
            )
        except GrypeError as exc:
            warnings.append(f"Grype unavailable: {exc}")
            runs.append(
                SourceRun(name="Grype", status="failed", queried=len(purls), message=str(exc))
            )

    vulnerabilities = vulnerability_findings(targets, graph, osv, grype)
    all_cves = sorted({c for f in vulnerabilities for c in cve_ids(f)})
    nvd: NvdLookup | None = None
    if nvd_client is None:
        runs.append(SourceRun(name="NVD", status="skipped", message="Disabled in configuration"))
    elif not all_cves:
        runs.append(SourceRun(name="NVD", status="skipped", message="No CVEs to look up"))
    else:
        nvd = nvd_client.lookup(all_cves, budget_seconds=nvd_budget)
        warnings.extend(nvd.warnings)
        _write_json(
            scan_dir / NVD_FILE,
            {
                "source": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "records": {
                    cve: {"fetched_at": nvd.fetched_at[cve], "cve": record}
                    for cve, record in nvd.records.items()
                },
                "not_looked_up": nvd.not_looked_up,
            },
        )
        reached = nvd.fetched + nvd.from_cache
        runs.append(
            SourceRun(
                name="NVD",
                status="failed" if reached == 0 else "ok",
                retrieved_at=max(nvd.fetched_at.values(), default=None),
                queried=len(all_cves),
                raw_output=NVD_FILE,
                message=f"{nvd.fetched} fetched, {nvd.from_cache} from cache, "
                f"{len(nvd.not_looked_up)} not looked up",
            )
        )
    vulnerabilities = enrich_findings(vulnerabilities, nvd, osv, grype)
    pins, pin_warnings = workflow_findings(repo_dir, inventory.ci_files)
    warnings.extend(pin_warnings)
    runs.append(SourceRun(name="workflow-scan", status="ok", queried=len(inventory.ci_files)))

    suspicious, suspicious_warnings, files_checked = suspicious_findings(
        repo_dir, inventory, document, graph
    )
    warnings.extend(suspicious_warnings)
    runs.append(
        SourceRun(
            name="supply-chain-scan",
            status="ok",
            queried=files_checked,
            message=f"{files_checked} lockfile/manifest/container file(s) and "
            f"{len(document.components)} package names checked",
        )
    )
    snapshot = file_snapshot(repo_dir, inventory)
    _write_json(
        scan_dir / SNAPSHOT_FILE,
        {
            "scan_id": scan_id,
            "files": snapshot,
            "declarations": manifest_declarations(repo_dir, inventory),
        },
    )
    changes = None
    if baseline is None:
        runs.append(
            SourceRun(
                name="scan-diff",
                status="skipped",
                message="No previous completed scan of this repository to compare with",
            )
        )
    else:
        loaded = load_baseline(baseline)
        if loaded is None:
            warnings.append(f"Previous scan {baseline.scan_id} could not be read for comparison")
            runs.append(
                SourceRun(
                    name="scan-diff", status="failed", message="Baseline artifacts unreadable"
                )
            )
        else:
            baseline_doc, baseline_files = loaded
            changes = compare(
                document, baseline_doc, baseline, current_commit, snapshot, baseline_files
            )
            _write_json(scan_dir / CHANGES_FILE, changes.model_dump(mode="json"))
            suspicious.extend(change_findings(changes, document, inventory, graph))
            t = changes.totals
            runs.append(
                SourceRun(
                    name="scan-diff",
                    status="ok",
                    queried=len(baseline_doc.components),
                    raw_output=CHANGES_FILE,
                    message=f"Compared with {baseline.scan_id}: {t['added']} added, "
                    f"{t['removed']} removed, {t['upgraded']} upgraded, "
                    f"{t['downgraded']} downgraded",
                )
            )
    suspicious = escalate(suspicious)

    assessed_any = osv is not None or grype is not None
    if purls and not assessed_any:
        warnings.append("Vulnerabilities not assessed: no vulnerability source was available")
    if targets.not_assessed:
        warnings.append(
            f"{targets.not_assessed} package(s) not assessed: "
            "no exact version or unsupported ecosystem"
        )

    assessed = sum(len(c) for c in targets.by_purl.values()) if assessed_any else 0
    stats = FindingStats(
        vulnerabilities=len(vulnerabilities),
        vulnerable_packages=len({f.subject_id for f in vulnerabilities}),
        confirmed_by_both=sum(
            1 for f in vulnerabilities if {s.name for s in f.sources} == {"OSV", "Grype"}
        ),
        workflow_pins=len(pins),
        components_total=len(document.components),
        components_assessed=assessed,
        components_not_assessed=len(document.components) - assessed,
        cves_linked=len(all_cves),
        nvd_scored=sum(1 for f in vulnerabilities if f.cvss and f.cvss.source.startswith("NVD")),
        suspicious=len(suspicious),
    )
    failed = (
        any(run.status == "failed" for run in runs)
        or bool(pin_warnings)
        or bool(suspicious_warnings)
        or bool(nvd and nvd.not_looked_up)
    )
    return FindingsDocument(
        scan_id=scan_id,
        findings=[*vulnerabilities, *pins, *suspicious],
        sources=runs,
        stats=stats,
        partial=failed or targets.not_assessed > 0 or (bool(purls) and not assessed_any),
        warnings=list(dict.fromkeys(warnings)),
        changes=changes,
    )
