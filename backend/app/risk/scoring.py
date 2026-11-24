"""Link findings to CVEs and CWEs, score them with CVSS, and rank them.

* CVEs come from each finding's advisory aliases; NVD supplies status, dates,
  CVSS metrics and CWE weaknesses.
* CVSS base scores are recomputed from the vector (see ``cvss.py``) and shown
  next to the score NVD published; NVD's own Primary metric is preferred.
* If NVD has no CVSS, the GHSA vector reported by OSV/Grype is used and labelled.
* EPSS (exploit probability) comes from FIRST data already inside Grype's database.
* The priority score is a transparent rule: every factor and its points are listed.
"""

import re

from app.risk.cvss import CvssError, score_vector
from app.risk.grype import GrypeResult
from app.risk.nvd import NvdLookup
from app.risk.osv import OsvResult
from app.schemas.findings import (
    CveRef,
    CvssScore,
    CweRef,
    EpssScore,
    Finding,
    Priority,
    PriorityFactor,
)
from app.schemas.inventory import Evidence

NVD_FILE = "nvd.json"
NVD_SOURCE = "nvd@nist.gov"
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CWE = re.compile(r"^CWE-(\d+)$")
_METRIC_ORDER = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")
PRIORITY_METHOD = (
    "Kestral rule-based priority v1: 50% CVSS base score, 20% EPSS percentile, "
    "20% exposure (direct/transitive, runtime/dev), 10% fix available. Not a vendor score."
)
_EXPOSURE = {
    ("direct", "runtime"): (1.0, "direct runtime dependency"),
    ("transitive", "runtime"): (0.7, "transitive runtime dependency"),
    ("unknown", "runtime"): (0.5, "runtime dependency, no proven path"),
    ("direct", "dev"): (0.4, "direct development dependency"),
    ("transitive", "dev"): (0.25, "transitive development dependency"),
    ("unknown", "dev"): (0.25, "development dependency, no proven path"),
}


def cve_ids(finding: Finding) -> list[str]:
    return sorted(i for i in finding.advisory_ids if _CVE.match(i))


def _english(descriptions: list[dict] | None) -> str | None:
    for item in descriptions or []:
        if item.get("lang") == "en" and item.get("value"):
            text = item["value"].strip()
            return text if len(text) <= 400 else text[:397] + "..."
    return None


def _cve_ref(cve_id: str, nvd: NvdLookup | None) -> CveRef:
    looked_up = nvd is not None and cve_id in nvd.records
    record = nvd.records.get(cve_id) if nvd else None
    return CveRef(
        id=cve_id,
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        looked_up=looked_up,
        in_nvd=record is not None,
        nvd_status=(record or {}).get("vulnStatus"),
        published=(record or {}).get("published"),
        last_modified=(record or {}).get("lastModified"),
        description=_english((record or {}).get("descriptions")),
    )


def _pick_metric(metrics: list[dict]) -> dict | None:
    def rank(m: dict) -> tuple[int, int]:
        return (0 if m.get("source") == NVD_SOURCE else 1, 0 if m.get("type") == "Primary" else 1)

    usable = [m for m in metrics if (m.get("cvssData") or {}).get("vectorString")]
    return min(usable, key=rank) if usable else None


def _nvd_cvss(cve_id: str, record: dict) -> CvssScore | None:
    metrics = record.get("metrics") or {}
    for key in _METRIC_ORDER:
        metric = _pick_metric(metrics.get(key) or [])
        if metric is None:
            continue
        data = metric["cvssData"]
        published = data.get("baseScore")
        try:
            result = score_vector(data["vectorString"], published)
        except CvssError:
            continue
        matches = None
        if result.computed and published is not None and result.base_score is not None:
            matches = abs(result.base_score - published) < 0.05
        return CvssScore(
            version=result.version,
            vector=result.vector,
            base_score=result.base_score,
            severity=result.severity,
            source=f"NVD ({metric.get('source', 'unknown')})",
            source_type=metric.get("type"),
            cve_id=cve_id,
            computed=result.computed,
            published_score=published,
            matches_published=matches,
        )
    return None


def grype_published_scores(grype: GrypeResult | None) -> dict[str, float]:
    """Base scores Grype's database publishes per vector (needed for CVSS 4.0)."""
    scores: dict[str, float] = {}
    for match in grype.matches if grype else []:
        vulns = [match.get("vulnerability") or {}, *(match.get("relatedVulnerabilities") or [])]
        for vuln in vulns:
            for item in vuln.get("cvss") or []:
                score = (item.get("metrics") or {}).get("baseScore")
                if item.get("vector") and isinstance(score, int | float):
                    scores.setdefault(item["vector"], float(score))
    return scores


def _fallback_cvss(finding: Finding, published: dict[str, float]) -> CvssScore | None:
    """GHSA vector reported by OSV or Grype when NVD has no score."""
    candidates = []
    for source in sorted(finding.sources, key=lambda s: s.name != "OSV"):
        for vector in source.cvss_vectors:
            order = 0 if vector.startswith("CVSS:3") else 1 if vector.startswith("CVSS:4") else 2
            candidates.append((order, source.name, source.record_id, vector))
    for _, name, record_id, vector in sorted(candidates, key=lambda c: c[0]):
        try:
            result = score_vector(vector, published.get(vector))
        except CvssError:
            continue
        if result.base_score is None:
            continue  # v4 without any published score cannot be scored
        return CvssScore(
            version=result.version,
            vector=result.vector,
            base_score=result.base_score,
            severity=result.severity,
            source=f"{name} ({record_id})"
            if result.computed
            else f"{name} ({record_id}), score from Grype database",
            computed=result.computed,
            published_score=published.get(vector),
            matches_published=(
                abs(result.base_score - published[vector]) < 0.05
                if result.computed and vector in published
                else None
            ),
        )
    return None


def _cwes(
    finding: Finding, nvd: NvdLookup | None, osv: OsvResult | None, grype_cwes: dict[str, set[str]]
) -> list[CweRef]:
    found: dict[str, set[str]] = {}
    for cve_id in cve_ids(finding):
        record = (nvd.records.get(cve_id) if nvd else None) or {}
        for weakness in record.get("weaknesses") or []:
            for item in weakness.get("description") or []:
                found.setdefault(item.get("value", ""), set()).add("NVD")
        for cwe in grype_cwes.get(cve_id, set()):
            found.setdefault(cwe, set()).add("Grype")
    for source in finding.sources:
        if source.name == "OSV" and osv is not None:
            record = osv.records.get(source.record_id) or {}
            for cwe in (record.get("database_specific") or {}).get("cwe_ids") or []:
                found.setdefault(cwe, set()).add("OSV")
        if source.name == "Grype":
            for cwe in grype_cwes.get(source.record_id, set()):
                found.setdefault(cwe, set()).add("Grype")
    refs = []
    for cwe_id, sources in found.items():
        matched = _CWE.match(cwe_id)
        if matched:
            url = f"https://cwe.mitre.org/data/definitions/{matched.group(1)}.html"
        elif cwe_id in ("NVD-CWE-noinfo", "NVD-CWE-Other"):
            url = None  # NVD's own "insufficient information" / "other" markers
        else:
            continue
        refs.append(CweRef(id=cwe_id, url=url, sources=sorted(sources)))
    return sorted(
        refs, key=lambda r: (r.url is None, int(_CWE.match(r.id).group(1)) if r.url else 0)
    )


def grype_side_data(grype: GrypeResult | None) -> tuple[dict[str, EpssScore], dict[str, set[str]]]:
    """EPSS per CVE and CWEs per advisory ID, from Grype's matches."""
    epss: dict[str, EpssScore] = {}
    cwes: dict[str, set[str]] = {}
    for match in grype.matches if grype else []:
        vulns = [match.get("vulnerability") or {}, *(match.get("relatedVulnerabilities") or [])]
        for vuln in vulns:
            for item in vuln.get("epss") or []:
                cve = item.get("cve")
                if not cve or item.get("epss") is None:
                    continue
                score = EpssScore(
                    cve_id=cve,
                    probability=float(item["epss"]),
                    percentile=float(item.get("percentile") or 0),
                    date=item.get("date"),
                    source="FIRST EPSS via Grype database",
                )
                if cve not in epss or score.probability > epss[cve].probability:
                    epss[cve] = score
            for item in vuln.get("cwes") or []:
                if item.get("cwe"):
                    for key in {vuln.get("id"), item.get("cve")} - {None}:
                        cwes.setdefault(key, set()).add(item["cwe"])
    return epss, cwes


def priority_for(finding: Finding, cvss: CvssScore | None, epss: EpssScore | None) -> Priority:
    factors = []
    if cvss and cvss.base_score is not None:
        severity_value, severity_text = (
            cvss.base_score / 10,
            f"CVSS {cvss.base_score} ({cvss.source})",
        )
    else:
        severity_value, severity_text = 0.5, "no CVSS available; assumed 5.0"
    factors.append(
        PriorityFactor(
            name="Severity (CVSS base score)",
            value=severity_text,
            weight=0.5,
            points=round(50 * severity_value, 1),
        )
    )
    if epss:
        factors.append(
            PriorityFactor(
                name="Exploit likelihood (EPSS percentile)",
                value=(
                    f"{epss.probability:.2%} probability, "
                    f"{epss.percentile:.0%} percentile ({epss.cve_id})"
                ),
                weight=0.2,
                points=round(20 * epss.percentile, 1),
            )
        )
    else:
        factors.append(
            PriorityFactor(
                name="Exploit likelihood (EPSS percentile)",
                value="EPSS unavailable",
                weight=0.2,
                points=0,
            )
        )
    scope = "dev" if finding.scope == "dev" else "runtime"
    exposure, exposure_text = _EXPOSURE[(finding.directness or "unknown", scope)]
    if finding.scope == "optional":
        exposure, exposure_text = exposure * 0.8, exposure_text.replace("runtime", "optional")
    factors.append(
        PriorityFactor(
            name="Exposure", value=exposure_text, weight=0.2, points=round(20 * exposure, 1)
        )
    )
    has_fix = bool(finding.fixed_versions)
    factors.append(
        PriorityFactor(
            name="Fix available (actionable now)",
            value=f"fixed in {', '.join(finding.fixed_versions)}"
            if has_fix
            else "no fixed version reported",
            weight=0.1,
            points=10.0 if has_fix else 0.0,
        )
    )
    score = max(0, min(100, round(sum(f.points for f in factors))))
    band = (
        "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 40 else "low"
    )
    return Priority(score=score, band=band, factors=factors, method=PRIORITY_METHOD)


def enrich_findings(
    findings: list[Finding],
    nvd: NvdLookup | None,
    osv: OsvResult | None,
    grype: GrypeResult | None,
) -> list[Finding]:
    epss_by_cve, grype_cwes = grype_side_data(grype)
    published = grype_published_scores(grype)
    enriched = []
    for finding in findings:
        if finding.kind != "vulnerability":
            enriched.append(finding)
            continue
        ids = cve_ids(finding)
        cves = [_cve_ref(c, nvd) for c in ids]
        nvd_scores = [
            s
            for c in ids
            if nvd and nvd.records.get(c) and (s := _nvd_cvss(c, nvd.records[c])) is not None
        ]
        cvss = (
            max(nvd_scores, key=lambda s: s.base_score or 0)
            if nvd_scores
            else _fallback_cvss(finding, published)
        )
        epss_scores = [epss_by_cve[c] for c in ids if c in epss_by_cve]
        epss = max(epss_scores, key=lambda e: e.probability) if epss_scores else None

        uncertainty = list(finding.uncertainty)
        if cvss is None:
            uncertainty.append("No scorable CVSS from NVD, OSV or Grype; priority assumes 5.0")
        elif not ids:
            uncertainty.append("No CVE assigned; scored from the advisory's own CVSS vector")
        elif cvss is not None and not cvss.source.startswith("NVD"):
            uncertainty.append(f"NVD has no CVSS for this CVE; using the vector from {cvss.source}")
        if any(c.nvd_status == "Rejected" for c in cves):
            uncertainty.append("NVD marks a linked CVE as Rejected")
        if any(not c.looked_up for c in cves) and nvd is not None:
            uncertainty.append("Some CVEs were not looked up in NVD during this scan")
        if cvss and cvss.matches_published is False:
            uncertainty.append(
                f"Computed CVSS {cvss.base_score} differs from "
                f"NVD's published {cvss.published_score}"
            )

        evidence = list(finding.evidence)
        evidence += [
            Evidence(path=NVD_FILE, kind="nvd-record", locator=c.id) for c in cves if c.in_nvd
        ]
        enriched.append(
            finding.model_copy(
                update={
                    "cves": cves,
                    "cwes": _cwes(finding, nvd, osv, grype_cwes),
                    "cvss": cvss,
                    "epss": epss,
                    "priority": priority_for(finding, cvss, epss),
                    "uncertainty": uncertainty,
                    "evidence": evidence,
                }
            )
        )
    return enriched
