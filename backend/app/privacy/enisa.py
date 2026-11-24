"""ENISA personal-data-breach severity, applied to a vulnerability as a potential breach.

ENISA, "Recommendations for a methodology of the assessment of severity of personal data
breaches" (2013):

    SE = DPC x EI + CB

* DPC, data processing context (1-4): what kind of personal data the application handles.
  A scan cannot see that, so the reviewer chooses it (default from settings).
* EI, ease of identification (0.25-1): how easily people can be identified from the data.
  Kestral derives it from the finding's LINDDUN classes (CVE-LINDDUN dataset).
* CB, circumstances of breach (0-2): loss of confidentiality, integrity and availability
  (each 0 / 0.25 / 0.5) plus malicious intent (0 / 0.5). Kestral derives them from the CVSS
  impact metrics and exploitability signals (attack vector, privileges, EPSS).

Bands: SE < 2 low, 2-3 medium, 3-4 high, >= 4 very high. Every term is returned with the
value used and the reason, so the score can be checked by hand.
"""

from dataclasses import dataclass

from app.schemas.findings import Finding
from app.schemas.privacy import DataContext, DataContextOption, EnisaFactor, PrivacyBand

DATA_CONTEXTS: dict[DataContext, DataContextOption] = {
    "simple": DataContextOption(
        value="simple",
        label="Simple data",
        dpc=1,
        examples="names, contact details, professional or education data",
    ),
    "behavioural": DataContextOption(
        value="behavioural",
        label="Behavioural data",
        dpc=2,
        examples="location, traffic data, habits, preferences",
    ),
    "financial": DataContextOption(
        value="financial",
        label="Financial data",
        dpc=3,
        examples="income, transactions, bank or card data",
    ),
    "sensitive": DataContextOption(
        value="sensitive",
        label="Sensitive data",
        dpc=4,
        examples="health, beliefs, sexual orientation, data on children",
    ),
}

# Ease of identification implied by each LINDDUN class (ENISA EI levels).
EI_BY_LINDDUN: dict[str, tuple[float, str]] = {
    "Identifiability": (1.0, "maximum: the weakness lets an attacker identify individuals"),
    "Linkability": (0.75, "significant: records can be linked to the same person"),
    "Data Disclosure": (0.5, "limited: personal data is exposed, identity needs more work"),
    "Non-repudiation": (0.5, "limited: actions can be attributed to individuals"),
    "Detectability": (0.25, "negligible: reveals that data exists, not whose it is"),
    "Unawareness": (0.25, "negligible: processing the person is not informed about"),
    "Non-compliance": (0.25, "negligible: a policy/consent failure, no direct identification"),
}

_CIA_POINTS = {"H": 0.5, "L": 0.25, "N": 0.0}
EPSS_MALICIOUS_PERCENTILE = 0.90

METHOD = (
    "ENISA personal data breach severity (2013): SE = DPC x EI + CB. DPC is the reviewer's "
    "data processing context; EI comes from the finding's LINDDUN classes (CVE-LINDDUN "
    "dataset); CB comes from CVSS confidentiality/integrity/availability impact plus malicious "
    "intent when exploitation is remote and unauthenticated or EPSS is in the top 10%."
)


@dataclass(frozen=True)
class CvssSignals:
    version: str
    confidentiality: str | None
    integrity: str | None
    availability: str | None
    attack_vector: str | None
    privileges: str | None
    user_interaction: str | None


def parse_vector(vector: str, version: str | None = None) -> CvssSignals | None:
    """Read the impact and exploitability metrics from a CVSS v2, v3.x or v4.0 vector."""
    text = vector.strip().strip("()")
    parts = text.split("/")
    detected = version or ""
    if parts and parts[0].upper().startswith("CVSS:"):
        detected = parts[0].split(":", 1)[1]
        parts = parts[1:]
    metrics: dict[str, str] = {}
    for part in parts:
        key, sep, value = part.partition(":")
        if sep and key and value:
            metrics[key] = value.upper()
    if not metrics:
        return None
    if detected.startswith("4"):

        def worst(a: str, b: str) -> str | None:
            values = [metrics.get(a), metrics.get(b)]
            for level in ("H", "L", "N"):
                if level in values:
                    return level
            return None

        ui = metrics.get("UI")
        return CvssSignals(
            version="4.0",
            confidentiality=worst("VC", "SC"),
            integrity=worst("VI", "SI"),
            availability=worst("VA", "SA"),
            attack_vector=metrics.get("AV"),
            privileges=metrics.get("PR"),
            user_interaction=None if ui is None else ("N" if ui == "N" else "R"),
        )
    if "Au" in metrics or detected.startswith("2"):
        v2 = {"C": "H", "P": "L", "N": "N"}
        auth = {"N": "N", "S": "L", "M": "H"}
        return CvssSignals(
            version="2.0",
            confidentiality=v2.get(metrics.get("C", "")),
            integrity=v2.get(metrics.get("I", "")),
            availability=v2.get(metrics.get("A", "")),
            attack_vector=metrics.get("AV"),
            privileges=auth.get(metrics.get("Au", "")),
            user_interaction=None,
        )
    return CvssSignals(
        version=detected or "3.x",
        confidentiality=metrics.get("C"),
        integrity=metrics.get("I"),
        availability=metrics.get("A"),
        attack_vector=metrics.get("AV"),
        privileges=metrics.get("PR"),
        user_interaction=metrics.get("UI"),
    )


def finding_signals(finding: Finding) -> CvssSignals | None:
    if finding.cvss is not None:
        parsed = parse_vector(finding.cvss.vector, finding.cvss.version)
        if parsed is not None:
            return parsed
    for source in finding.sources:
        for vector in source.cvss_vectors:
            parsed = parse_vector(vector)
            if parsed is not None:
                return parsed
    return None


def band_for(score: float) -> PrivacyBand:
    if score < 2:
        return "low"
    if score < 3:
        return "medium"
    if score < 4:
        return "high"
    return "very_high"


def ease_of_identification(linddun: list[str]) -> tuple[float, str]:
    best = max(linddun, key=lambda c: EI_BY_LINDDUN.get(c, (0.0, ""))[0])
    value, reason = EI_BY_LINDDUN[best]
    return value, f"{best}: {reason}"


def circumstances(
    finding: Finding, linddun: list[str]
) -> tuple[float, list[EnisaFactor], list[str]]:
    signals = finding_signals(finding)
    factors: list[EnisaFactor] = []
    uncertainty: list[str] = []
    if signals is None:
        exposes = any(c in linddun for c in ("Data Disclosure", "Identifiability", "Linkability"))
        conf = 0.25 if exposes else 0.0
        factors.append(
            EnisaFactor(
                name="CB confidentiality",
                value=conf,
                basis="no CVSS vector; assumed limited exposure from the LINDDUN class"
                if exposes
                else "no CVSS vector and no disclosure-type LINDDUN class",
            )
        )
        factors.append(EnisaFactor(name="CB integrity", value=0, basis="no CVSS vector"))
        factors.append(EnisaFactor(name="CB availability", value=0, basis="no CVSS vector"))
        uncertainty.append("No CVSS vector: breach circumstances are estimated, not measured.")
        cb = conf
    else:
        label = f"CVSS {signals.version}"
        conf = _CIA_POINTS.get(signals.confidentiality or "", 0.0)
        integ = _CIA_POINTS.get(signals.integrity or "", 0.0)
        # A vulnerability usually causes temporary unavailability (ENISA +0.25); permanent loss
        # of personal data (+0.5) is not something a CVSS vector states.
        avail = 0.25 if signals.availability == "H" else 0.0
        factors.append(
            EnisaFactor(
                name="CB confidentiality",
                value=conf,
                basis=f"{label} C:{signals.confidentiality or '?'}"
                + (" - data exposed to unknown recipients" if conf == 0.5 else ""),
            )
        )
        factors.append(
            EnisaFactor(
                name="CB integrity",
                value=integ,
                basis=f"{label} I:{signals.integrity or '?'}",
            )
        )
        factors.append(
            EnisaFactor(
                name="CB availability",
                value=avail,
                basis=f"{label} A:{signals.availability or '?'} (temporary loss at most)",
            )
        )
        cb = conf + integ + avail

    malicious, basis = _malicious_intent(finding, signals)
    factors.append(EnisaFactor(name="CB malicious intent", value=malicious, basis=basis))
    return round(cb + malicious, 2), factors, uncertainty


def _malicious_intent(finding: Finding, signals: CvssSignals | None) -> tuple[float, str]:
    if finding.epss is not None and finding.epss.percentile >= EPSS_MALICIOUS_PERCENTILE:
        return 0.5, (
            f"EPSS {finding.epss.percentile:.0%} percentile ({finding.epss.cve_id}): "
            "exploitation in the wild is likely"
        )
    if (
        signals is not None
        and signals.attack_vector == "N"
        and signals.privileges == "N"
        and signals.user_interaction in ("N", None)
    ):
        return 0.5, "remotely exploitable without privileges or user interaction"
    return 0.0, "no sign of easy or observed exploitation"
