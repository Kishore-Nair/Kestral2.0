"""Look up CVEs in the NVD CVE API 2.0, with a local cache and NVD's rate limits.

Without an API key NVD allows 5 requests per rolling 30 seconds (it recommends a
6-second pause); with a key, 50. Each CVE record is cached under the project's
data folder, so repeated scans are fast. A time budget keeps one scan from waiting
forever: CVEs not reached are reported as not looked up, never as "no data".
The API key is only sent in the request header; it is never logged or cached.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "kestral-scanner"
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")

# fetch(url, headers, timeout) -> (status, parsed JSON or None)
Fetch = Callable[[str, dict[str, str], int], tuple[int, dict | None]]


def _fetch(url: str, headers: dict[str, str], timeout: int) -> tuple[int, dict | None]:
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (fixed https)
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, None


@dataclass
class NvdLookup:
    records: dict[str, dict | None]  # CVE -> NVD "cve" object, None if NVD has no record
    fetched_at: dict[str, str]
    from_cache: int = 0
    fetched: int = 0
    not_looked_up: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class NvdClient:
    def __init__(
        self,
        cache_dir: Path,
        *,
        api_key: str | None = None,
        timeout: int = 20,
        cache_days: int = 7,
        fetch: Fetch = _fetch,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.cache_dir = cache_dir
        self.api_key = api_key or None
        self.timeout = timeout
        self.cache_age = timedelta(days=cache_days)
        self.fetch = fetch
        self.sleep = sleep
        self.clock = clock
        self.now = now
        # NVD guidance: ~6 s between requests without a key, ~0.6 s with one.
        self.interval = 0.6 if self.api_key else 6.0
        self._last_request: float | None = None

    def _cache_path(self, cve_id: str) -> Path:
        return self.cache_dir / f"{cve_id}.json"

    def _read_cache(self, cve_id: str) -> tuple[dict | None, str] | None:
        path = self._cache_path(cve_id)
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
            fetched_at = datetime.fromisoformat(entry["fetched_at"])
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if self.now() - fetched_at > self.cache_age:
            return None
        return entry.get("cve"), entry["fetched_at"]

    def _write_cache(self, cve_id: str, record: dict | None, fetched_at: str) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        path = self._cache_path(cve_id)
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            temporary.write_text(
                json.dumps({"fetched_at": fetched_at, "cve": record}, separators=(",", ":")),
                encoding="utf-8",
            )
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def _wait_turn(self) -> None:
        if self._last_request is not None:
            remaining = self.interval - (self.clock() - self._last_request)
            if remaining > 0:
                self.sleep(remaining)
        self._last_request = self.clock()

    def _request(self, cve_id: str) -> tuple[int, dict | None]:
        headers = {"User-Agent": USER_AGENT}
        if self.api_key:
            headers["apiKey"] = self.api_key
        url = f"{NVD_API}?cveId={cve_id}"
        for attempt in range(2):
            self._wait_turn()
            try:
                status, body = self.fetch(url, headers, self.timeout)
            except Exception:
                status, body = 0, None
            if status in (403, 429, 503) and attempt == 0:
                self.sleep(30)  # rolling window exceeded or NVD busy: wait one window
                continue
            return status, body
        return status, body

    def lookup(self, cve_ids: list[str], *, budget_seconds: float = 1200) -> NvdLookup:
        ids = sorted({c for c in cve_ids if _CVE_ID.match(c)})
        result = NvdLookup(records={}, fetched_at={})
        started = self.clock()
        failures = 0
        nvd_down = False
        for cve_id in ids:
            cached = self._read_cache(cve_id)
            if cached is not None:
                result.records[cve_id], result.fetched_at[cve_id] = cached
                result.from_cache += 1
                continue
            out_of_time = self.clock() - started + self.interval > budget_seconds
            if nvd_down or out_of_time:
                result.not_looked_up.append(cve_id)
                continue
            status, body = self._request(cve_id)
            if status == 200 and isinstance(body, dict):
                vulns = body.get("vulnerabilities") or []
                record = vulns[0].get("cve") if vulns else None
                fetched_at = self.now().isoformat(timespec="seconds")
                self._write_cache(cve_id, record, fetched_at)
                result.records[cve_id] = record
                result.fetched_at[cve_id] = fetched_at
                result.fetched += 1
                continue
            failures += 1
            result.not_looked_up.append(cve_id)
            if failures >= 5 and result.fetched == 0:
                nvd_down = True
                result.warnings.append("NVD is not responding; remaining CVEs were skipped")
        if result.not_looked_up:
            result.warnings.append(
                f"{len(result.not_looked_up)} CVE(s) not looked up in NVD "
                "(rate-limit time budget or NVD errors); a rescan will continue from the cache"
            )
        return result
