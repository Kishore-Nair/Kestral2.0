"""Query the OSV.dev API for known vulnerabilities by exact PURL.

The raw responses are kept (``osv.json``) so every finding can be traced back to
the record OSV returned. Network calls go through injectable functions, so tests
never touch the network.
"""

import json
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime

OSV_API = "https://api.osv.dev/v1"
BATCH_SIZE = 500  # OSV accepts up to 1000 queries per batch
MAX_DETAIL_LOOKUPS = 1000
USER_AGENT = "kestral-scanner"

PostJson = Callable[[str, dict, int], dict]
GetJson = Callable[[str, int], dict]


class OsvError(RuntimeError):
    """OSV could not be queried; message is safe to show users."""


def _post_json(url: str, payload: dict, timeout: int) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (fixed https URL)
        return json.load(response)


def _get_json(url: str, timeout: int) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return json.load(response)


@dataclass
class OsvResult:
    retrieved_at: str
    matches: dict[str, list[str]]  # canonical PURL -> OSV ids
    records: dict[str, dict]  # OSV id -> full record
    warnings: list[str] = field(default_factory=list)

    def raw(self) -> dict:
        return {
            "source": OSV_API,
            "retrieved_at": self.retrieved_at,
            "matches": self.matches,
            "records": self.records,
        }


def query_osv(
    purls: list[str],
    *,
    timeout: int = 20,
    post_json: PostJson = _post_json,
    get_json: GetJson = _get_json,
    workers: int = 8,
) -> OsvResult:
    """Batch-query exact PURLs, then fetch each matched record once."""
    retrieved_at = datetime.now(UTC).isoformat(timespec="seconds")
    matches: dict[str, list[str]] = {}
    warnings: list[str] = []
    try:
        for start in range(0, len(purls), BATCH_SIZE):
            chunk = purls[start : start + BATCH_SIZE]
            body = post_json(
                f"{OSV_API}/querybatch",
                {"queries": [{"package": {"purl": purl}} for purl in chunk]},
                timeout,
            )
            results = body.get("results")
            if not isinstance(results, list) or len(results) != len(chunk):
                raise OsvError("OSV returned an unexpected batch response")
            for purl, result in zip(chunk, results, strict=True):
                ids = sorted({v["id"] for v in (result or {}).get("vulns", []) if "id" in v})
                if ids:
                    matches[purl] = ids
                if (result or {}).get("next_page_token"):
                    warnings.append(f"OSV results for {purl} were truncated")
    except OsvError:
        raise
    except Exception as exc:
        raise OsvError(f"OSV query failed: {type(exc).__name__}") from exc

    ids = sorted({i for found in matches.values() for i in found})
    if len(ids) > MAX_DETAIL_LOOKUPS:
        warnings.append(
            f"OSV matched {len(ids)} advisories; details fetched for the first {MAX_DETAIL_LOOKUPS}"
        )
        ids = ids[:MAX_DETAIL_LOOKUPS]

    def fetch(vuln_id: str) -> tuple[str, dict | None]:
        try:
            return vuln_id, get_json(f"{OSV_API}/vulns/{vuln_id}", timeout)
        except Exception:
            return vuln_id, None

    records: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for vuln_id, record in pool.map(fetch, ids):
            if record is None:
                warnings.append(f"OSV record {vuln_id} could not be fetched")
            else:
                records[vuln_id] = record
    return OsvResult(retrieved_at=retrieved_at, matches=matches, records=records, warnings=warnings)
