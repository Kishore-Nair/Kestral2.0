"""Look up LINDDUN privacy threat classes for a finding's CWEs.

The table in ``data/cwe_linddun.json`` is built by ``scripts/build_privacy_table.py`` from the
CVE-LINDDUN dataset. In that dataset the label is a pure function of the CWE, so one row per
CWE carries everything. A CWE the dataset leaves unmapped stays unmapped here: Kestral reports
the reason and never fills the gap with a guess.
"""

import json
from functools import lru_cache
from pathlib import Path

from app.schemas.findings import Finding
from app.schemas.privacy import LinddunMapping, MappingStatus, PrivacyDataset

TABLE_PATH = Path(__file__).parent / "data" / "cwe_linddun.json"

LINDDUN_CLASSES = (
    "Linkability",
    "Identifiability",
    "Non-repudiation",
    "Detectability",
    "Data Disclosure",
    "Unawareness",
    "Non-compliance",
)

# NVD placeholders mean "classified, but not to a listed weakness"; the dataset treats them
# as having no CWE.
NVD_PLACEHOLDERS = frozenset({"NVD-CWE-OTHER", "NVD-CWE-NOINFO"})

# Most specific reason first, when no CWE of a finding is mapped.
_REASON_ORDER: tuple[MappingStatus, ...] = (
    "category_has_no_linddun",
    "cwe_has_no_category",
    "cwe_excluded",
    "cwe_not_in_dataset",
    "no_cwe",
)


@lru_cache(maxsize=1)
def _table() -> dict:
    return json.loads(TABLE_PATH.read_text(encoding="utf-8"))


def dataset_info() -> PrivacyDataset:
    return PrivacyDataset.model_validate(_table()["meta"])


def lookup(cwe_id: str) -> LinddunMapping:
    key = cwe_id.strip().upper()
    if key in NVD_PLACEHOLDERS:
        return LinddunMapping(cwe_id=cwe_id, status="no_cwe", linddun=[])
    row = _table()["cwes"].get(key)
    if row is None:
        return LinddunMapping(cwe_id=key, status="cwe_not_in_dataset", linddun=[])
    return LinddunMapping(cwe_id=key, **row)


def classify(finding: Finding) -> tuple[MappingStatus, list[str], list[LinddunMapping]]:
    """Union of LINDDUN classes over the finding's CWEs, plus each CWE's mapping."""
    mappings = [lookup(ref.id) for ref in finding.cwes]
    classes = {c for m in mappings if m.status == "mapped" for c in m.linddun}
    if classes:
        ordered = [c for c in LINDDUN_CLASSES if c in classes]
        return "mapped", ordered, mappings
    if not mappings:
        return "no_cwe", [], mappings
    statuses = {m.status for m in mappings}
    reason = next((s for s in _REASON_ORDER if s in statuses), "category_has_no_linddun")
    return reason, [], mappings
