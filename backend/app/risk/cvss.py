"""Compute CVSS base scores from vector strings (FIRST specifications).

v3.1 and v3.0 follow the FIRST CVSS v3.x equations; v2 follows the CVSS v2 guide.
v4.0 scores need FIRST's macro-vector lookup tables, so a v4 vector is parsed and
its published score is used as-is (``computed`` is False).
"""

import math
from dataclasses import dataclass

_V3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_V3_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_V2_WEIGHTS = {
    "AV": {"L": 0.395, "A": 0.646, "N": 1.0},
    "AC": {"H": 0.35, "M": 0.61, "L": 0.71},
    "Au": {"M": 0.45, "S": 0.56, "N": 0.704},
    "C": {"N": 0.0, "P": 0.275, "C": 0.660},
    "I": {"N": 0.0, "P": 0.275, "C": 0.660},
    "A": {"N": 0.0, "P": 0.275, "C": 0.660},
}


class CvssError(ValueError):
    """The vector string is not a valid CVSS base vector."""


@dataclass(frozen=True)
class CvssResult:
    version: str
    vector: str
    base_score: float | None
    severity: str | None
    computed: bool


def _parse(parts: list[str]) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in parts:
        key, sep, value = part.partition(":")
        if not sep or not key or not value or key in metrics:
            raise CvssError(f"Malformed CVSS metric: {part!r}")
        metrics[key] = value
    return metrics


def _roundup_31(value: float) -> float:
    """CVSS v3.1 Roundup: smallest one-decimal number >= value, float-safe."""
    integer = round(value * 100_000)
    if integer % 10_000 == 0:
        return integer / 100_000
    return (math.floor(integer / 10_000) + 1) / 10.0


def _roundup_30(value: float) -> float:
    return math.ceil(value * 10) / 10


def severity_v3(score: float) -> str:
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def severity_v2(score: float) -> str:
    if score < 4.0:
        return "LOW"
    return "MEDIUM" if score < 7.0 else "HIGH"


def _score_v3(version: str, metrics: dict[str, str]) -> float:
    try:
        scope = metrics["S"]
        if scope not in ("U", "C"):
            raise KeyError("S")
        av = _V3_WEIGHTS["AV"][metrics["AV"]]
        ac = _V3_WEIGHTS["AC"][metrics["AC"]]
        pr = _V3_PR[scope][metrics["PR"]]
        ui = _V3_WEIGHTS["UI"][metrics["UI"]]
        c, i, a = (_V3_WEIGHTS[k][metrics[k]] for k in ("C", "I", "A"))
    except KeyError as exc:
        raise CvssError(f"Missing or invalid CVSS v{version} base metric {exc}") from exc
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    changed_impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    impact = 6.42 * iss if scope == "U" else changed_impact
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    roundup = _roundup_31 if version == "3.1" else _roundup_30
    if scope == "U":
        return roundup(min(impact + exploitability, 10))
    return roundup(min(1.08 * (impact + exploitability), 10))


def _score_v2(metrics: dict[str, str]) -> float:
    try:
        av, ac, au = (_V2_WEIGHTS[k][metrics[k]] for k in ("AV", "AC", "Au"))
        c, i, a = (_V2_WEIGHTS[k][metrics[k]] for k in ("C", "I", "A"))
    except KeyError as exc:
        raise CvssError(f"Missing or invalid CVSS v2 base metric {exc}") from exc
    impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
    exploitability = 20 * av * ac * au
    f_impact = 0 if impact == 0 else 1.176
    raw = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact
    return float(f"{round(raw + 1e-9, 1):.1f}")


def score_vector(vector: str, published_score: float | None = None) -> CvssResult:
    """Base score for a CVSS vector; v4 falls back to the published score."""
    vector = vector.strip()
    if vector.startswith("CVSS:3.1/") or vector.startswith("CVSS:3.0/"):
        version = vector[5:8]
        score = _score_v3(version, _parse(vector.split("/")[1:]))
        return CvssResult(version, vector, score, severity_v3(score), True)
    if vector.startswith("CVSS:4.0/"):
        _parse(vector.split("/")[1:])
        severity = severity_v3(published_score) if published_score is not None else None
        return CvssResult("4.0", vector, published_score, severity, False)
    if vector.startswith("CVSS:"):
        raise CvssError(f"Unsupported CVSS version in {vector!r}")
    score = _score_v2(_parse(vector.removeprefix("(").removesuffix(")").split("/")))
    return CvssResult("2.0", vector, score, severity_v2(score), True)
