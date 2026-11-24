"""Build Kestral's CWE -> LINDDUN privacy table from the CVE-LINDDUN dataset.

The CVE-LINDDUN dataset (280,694 NVD CVEs labelled with LINDDUN privacy threat
classes) derives every label from the CVE's CWE alone, so the reusable asset is
one row per CWE. This script collapses the dataset to that table and, when the
C3-VULMAP chain tables are given, adds CWEs the chain labels that never appear
in an NVD CVE. Output is a small JSON file shipped with the backend, so Kestral
never needs the 36 MB dataset at runtime.

Run with any Python that has pandas + pyarrow (the backend does not need them):

    python3 scripts/build_privacy_table.py \
        --dataset "/path/to/cve_linddun/cve_linddun.parquet" \
        --chain "/path/to/c3_vulmap_v2" \
        --out app/privacy/data/cwe_linddun.json
"""

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

COLUMNS = [
    "cve_id",
    "cwe_id",
    "linddun_status",
    "linddun_categories",
    "linddun_categories_base",
    "linddun_override_applied",
    "linddun_override_rationale",
    "cwe_categories",
]


def _split(value) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return []
    return sorted({part.strip() for part in value.split(";") if part.strip()})


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def from_dataset(dataset: Path) -> tuple[dict[str, dict], dict]:
    import pandas as pd

    frame = pd.read_parquet(dataset, columns=COLUMNS)
    with_cwe = frame[frame["cwe_id"].notna()]
    entries: dict[str, dict] = {}
    for cwe_id, group in with_cwe.groupby("cwe_id"):
        first = group.iloc[0]
        statuses = group["linddun_status"].dropna().unique().tolist()
        label_sets = group["linddun_categories"].fillna("").unique().tolist()
        if len(statuses) != 1 or len(label_sets) != 1:
            raise SystemExit(f"{cwe_id}: dataset gives more than one label; refusing to guess")
        rationale = first["linddun_override_rationale"]
        entries[str(cwe_id).upper()] = {
            "status": statuses[0],
            "linddun": _split(first["linddun_categories"]),
            "inherited": _split(first["linddun_categories_base"]),
            "override": bool(first["linddun_override_applied"]),
            "rationale": rationale if isinstance(rationale, str) and rationale else None,
            "mitre_categories": _split(first["cwe_categories"]),
            "nvd_cves": int(len(group)),
            "source": "cve-linddun-dataset",
        }
    meta = {
        "dataset_file": dataset.name,
        "dataset_sha256": _sha256(dataset),
        "dataset_rows": int(len(frame)),
        "dataset_labelled_rows": int((frame["linddun_status"] == "mapped").sum()),
    }
    return entries, meta


def from_chain(chain_dir: Path, known: set[str]) -> dict[str, dict]:
    """CWEs the C3-VULMAP chain labels that no NVD CVE in the dataset carries."""
    sys.path.insert(0, str(chain_dir))
    from xai import Explainer  # type: ignore[import-not-found]
    from xai.chains import ChainIndex  # type: ignore[import-not-found]

    explainer = Explainer()
    added: dict[str, dict] = {}
    for cwe_id in ChainIndex().all_labelled_cwes():
        if cwe_id in known:
            continue
        explanation = explainer.explain(cwe_id)
        steps = explanation.chain.categories if explanation.chain else []
        override = explanation.override
        added[cwe_id] = {
            "status": explanation.status,
            "linddun": sorted(explanation.final),
            "inherited": sorted(explanation.inherited),
            "override": bool(override and override.changes_label),
            "rationale": override.rationale if override else None,
            "mitre_categories": sorted({s.category_name for s in steps}),
            "nvd_cves": 0,
            "source": "c3-vulmap-chain",
        }
    return added


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--chain", type=Path, help="c3_vulmap_v2 folder (optional)")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    entries, meta = from_dataset(args.dataset)
    chain_added = from_chain(args.chain, set(entries)) if args.chain else {}
    entries.update(chain_added)
    meta.update(
        {
            "built_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
            "cwes": len(entries),
            "cwes_mapped": sum(1 for e in entries.values() if e["status"] == "mapped"),
            "cwes_from_chain": len(chain_added),
            "label_rule": "LINDDUN classes are a pure function of the CWE (CWE -> MITRE "
            "category -> LINDDUN, then CWE-level overrides).",
        }
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    document = {"meta": meta, "cwes": dict(sorted(entries.items()))}
    args.out.write_text(json.dumps(document, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {args.out}: {meta['cwes']} CWEs ({meta['cwes_mapped']} mapped)")


if __name__ == "__main__":
    main()
