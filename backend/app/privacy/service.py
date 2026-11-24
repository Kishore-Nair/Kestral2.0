"""Privacy impact assessment for a scan's vulnerability findings."""

from collections import Counter

from app.privacy import enisa, linddun
from app.schemas.findings import Finding, FindingsDocument
from app.schemas.privacy import (
    DataContext,
    EnisaFactor,
    PrivacyAssessment,
    PrivacyImpact,
    PrivacySummary,
)

BANDS = ("very_high", "high", "medium", "low")

CAVEATS = [
    "A vulnerability is scored as a potential personal data breach; the score says how bad a "
    "breach through it would be, not that one happened or that the code path is reachable.",
    "LINDDUN classes come from the CVE-LINDDUN dataset, where they depend on the CWE only. "
    "The mapping has no expert validation yet and 14 CWE-level overrides move about 27% of "
    "its labelled CVEs.",
    "CWEs the dataset leaves unmapped (for example denial of service CWE-400, ReDoS CWE-1333, "
    "prototype pollution CWE-1321) get no privacy class and no score here; they are counted "
    "with their reason, not treated as privacy-safe.",
    "The data processing context (DPC) is chosen by the reviewer; Kestral cannot see what "
    "personal data the application handles.",
    "Suspicious-package and workflow findings are not scored; a malicious package can still "
    "exfiltrate personal data.",
]


def assess_finding(finding: Finding, context: DataContext) -> PrivacyImpact:
    option = enisa.DATA_CONTEXTS[context]
    status, classes, mappings = linddun.classify(finding)
    base = {
        "finding_id": finding.finding_id,
        "title": finding.title,
        "subject_label": finding.subject_label,
        "advisory_ids": finding.advisory_ids,
        "status": status,
        "linddun": classes,
        "mappings": mappings,
        "dpc": option.dpc,
        "security_priority": finding.priority.score if finding.priority else None,
    }
    if status != "mapped":
        return PrivacyImpact(**base)

    ei, ei_basis = enisa.ease_of_identification(classes)
    cb, cb_factors, uncertainty = enisa.circumstances(finding, classes)
    score = round(option.dpc * ei + cb, 2)
    factors = [
        EnisaFactor(name="DPC", value=option.dpc, basis=f"{option.label} ({option.examples})"),
        EnisaFactor(name="EI", value=ei, basis=ei_basis),
        *cb_factors,
    ]
    if any(m.override for m in mappings if m.status == "mapped"):
        uncertainty.append("The LINDDUN class comes from a dataset override with a rationale.")
    return PrivacyImpact(
        **base,
        score=score,
        band=enisa.band_for(score),
        ei=ei,
        cb=cb,
        factors=factors,
        uncertainty=uncertainty,
    )


def assess(document: FindingsDocument, context: DataContext) -> PrivacyAssessment:
    impacts = [assess_finding(f, context) for f in document.findings if f.kind == "vulnerability"]
    impacts.sort(
        key=lambda i: (
            i.score is None,
            -(i.score or 0),
            -(i.security_priority or 0),
            i.finding_id,
        )
    )
    scored = [i for i in impacts if i.score is not None]
    by_band = Counter(i.band for i in scored)
    by_linddun = Counter(c for i in scored for c in i.linddun)
    reasons = Counter(i.status for i in impacts if i.status != "mapped")
    top = scored[0] if scored else None
    summary = PrivacySummary(
        assessed=len(impacts),
        mapped=len(scored),
        unmapped=len(impacts) - len(scored),
        by_band={b: by_band.get(b, 0) for b in BANDS},
        by_linddun={c: by_linddun[c] for c in linddun.LINDDUN_CLASSES if by_linddun.get(c)},
        unmapped_reasons=dict(sorted(reasons.items(), key=lambda kv: -kv[1])),
        max_score=top.score if top else None,
        max_band=top.band if top else None,
    )
    return PrivacyAssessment(
        scan_id=document.scan_id,
        data_context=context,
        dpc=enisa.DATA_CONTEXTS[context].dpc,
        data_contexts=list(enisa.DATA_CONTEXTS.values()),
        method=enisa.METHOD,
        dataset=linddun.dataset_info(),
        summary=summary,
        impacts=impacts,
        caveats=CAVEATS,
    )
