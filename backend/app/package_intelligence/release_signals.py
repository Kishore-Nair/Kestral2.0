from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .registry import canonical_name, exact_version, stable_identity

MAX_RELEASES = 4096
MAX_FILES = 256
HOOKS = ("preinstall", "install", "postinstall")


def timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.astimezone(UTC) if parsed.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


@dataclass(frozen=True)
class Release:
    exact: dict | list
    history: dict[str, datetime]
    complete_history: bool
    created: datetime | None
    published: datetime | None
    earliest: datetime | None


def file_time(files: object) -> datetime | None:
    if not isinstance(files, list) or not 0 < len(files) <= MAX_FILES:
        return None
    times = [
        timestamp(item.get("upload_time_iso_8601")) if isinstance(item, dict) else None
        for item in files
    ]
    return min(item for item in times if item is not None) if all(times) else None


def release_for(data: dict, ecosystem: str, name: str, version: str, now: datetime) -> Release:
    if ecosystem == "npm":
        project, records, dates = data.get("name"), data.get("versions"), data.get("time")
    else:
        info = data.get("info")
        project = info.get("name") if isinstance(info, dict) else None
        records, dates = data.get("releases"), None
    if (
        not isinstance(project, str) or canonical_name(ecosystem, project) != name
        or not isinstance(records, dict) or len(records) > MAX_RELEASES
    ):
        raise ValueError("malformed_metadata")
    if ecosystem == "pypi":
        matches = [
            value for value in records
            if exact_version(ecosystem, value) and _equivalent(value, version)
        ]
        if len(matches) > 1:
            raise ValueError("ambiguous_exact_version")
        key = matches[0] if matches else version
    else:
        key = version
    if key not in records:
        raise ValueError("exact_version_missing")

    exact = records[key]
    if ecosystem == "npm":
        if not (
            isinstance(exact, dict) and exact.get("name") == name
            and exact.get("version") == version
        ):
            raise ValueError("malformed_exact_version")
    elif not isinstance(exact, list) or len(exact) > MAX_FILES:
        raise ValueError("malformed_exact_version")

    history = {}
    observed = []
    complete = True
    published = None
    for raw_version, record in records.items():
        normalized = exact_version(ecosystem, raw_version)
        if normalized is None:
            complete = False
            continue
        when = (
            timestamp(dates.get(raw_version)) if isinstance(dates, dict) else None
        ) if ecosystem == "npm" else file_time(record)
        if when is None or when > now:
            complete = False
            continue
        observed.append(when)
        if raw_version == key:
            published = when
        stable = stable_identity(ecosystem, normalized)
        if stable is not None:
            history[stable] = min(when, history.get(stable, when))
    created = timestamp(dates.get("created")) if isinstance(dates, dict) else None
    created = created if created is not None and created <= now else None
    return Release(exact, history, complete, created, published, min(observed, default=None))


def _equivalent(left: str, right: str) -> bool:
    from packaging.version import Version

    return Version(left) == Version(right)


@dataclass(frozen=True)
class Thresholds:
    package_days: int = 30
    release_days: int = 7
    burst_count: int = 5
    burst_days: int = 7
    quiet_days: int = 90

    def __post_init__(self):
        if not 2 <= self.burst_count <= 100 or not all(
            1 <= value <= 3650
            for value in (self.package_days, self.release_days, self.burst_days, self.quiet_days)
        ):
            raise ValueError("Invalid release heuristic thresholds")


def burst(release: Release, now: datetime, thresholds: Thresholds) -> tuple[str, int]:
    dates = sorted(release.history.values())
    if not release.complete_history or not dates:
        return "unassessed", 0
    start = now - timedelta(days=thresholds.burst_days)
    prior = [date for date in dates if date < start]
    recent = [date for date in dates if date >= start]
    if not prior or now - dates[0] < timedelta(days=thresholds.quiet_days):
        return "unassessed", len(recent)
    if (
        len(recent) >= thresholds.burst_count
        and recent[0] - prior[-1] >= timedelta(days=thresholds.quiet_days)
    ):
        return "signal", len(recent)
    return "assessed", len(recent)


def withdrawal(ecosystem: str, exact: dict | list, filename: str | None) -> str:
    if ecosystem == "npm" and isinstance(exact, dict):
        message = exact.get("deprecated", "")
        if not isinstance(message, str):
            return "unassessed"
        return "signal" if message.strip() else "assessed"
    if not isinstance(exact, list):
        return "unassessed"
    candidates = exact if filename is None else [
        item for item in exact if isinstance(item, dict) and item.get("filename") == filename
    ]
    if not candidates or any(
        not isinstance(item, dict) or type(item.get("yanked")) is not bool for item in candidates
    ):
        return "unassessed"
    states = {item["yanked"] for item in candidates}
    return "partial" if len(states) > 1 else "signal" if True in states else "assessed"
