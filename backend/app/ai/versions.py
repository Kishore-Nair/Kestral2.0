"""Deterministic version logic used to check AI recommendations (never the model).

- npm: semver ordering and the common npm range syntax (``^``, ``~``, x-ranges,
  hyphen ranges, comparators, ``||``). Dist-tags, URLs and aliases are not checkable.
- PyPI: PEP 440 via ``packaging``.
- OSV: whether a version falls inside an advisory's affected ranges.

Every function returns ``None`` when it cannot decide, so callers report "not checked"
instead of guessing.
"""

import re
from functools import cmp_to_key

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


# ---------------------------------------------------------------------------
# npm semver
# ---------------------------------------------------------------------------


def parse_semver(value: str) -> tuple[int, int, int, tuple] | None:
    matched = _SEMVER.match(value.strip())
    if not matched:
        return None
    major, minor, patch, pre = matched.groups()
    pre_parts: tuple = ()
    if pre:
        pre_parts = tuple(int(p) if p.isdigit() else p for p in pre.split("."))
    return int(major), int(minor), int(patch), pre_parts


def _cmp_pre(a: tuple, b: tuple) -> int:
    if a == b:
        return 0
    if not a:
        return 1  # release > prerelease
    if not b:
        return -1
    for x, y in zip(a, b, strict=False):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, int):
            return -1
        if isinstance(y, int):
            return 1
        return -1 if x < y else 1
    return -1 if len(a) < len(b) else 1


def compare_semver(a: str, b: str) -> int | None:
    pa, pb = parse_semver(a), parse_semver(b)
    if pa is None or pb is None:
        return None
    if pa[:3] != pb[:3]:
        return -1 if pa[:3] < pb[:3] else 1
    return _cmp_pre(pa[3], pb[3])


def _partial(value: str) -> tuple[list[int | None], tuple] | None:
    """'1', '1.2', '1.x', '1.2.3-beta' -> ([1, 2, None], pre)."""
    value = value.strip().lstrip("v=")
    if not value or value in {"*", "x", "X"}:
        return [None, None, None], ()
    core, _, pre = value.partition("-")
    core = core.split("+", 1)[0]
    parts = core.split(".")
    if len(parts) > 3:
        return None
    nums: list[int | None] = []
    for part in parts:
        if part in {"x", "X", "*"}:
            nums.append(None)
        elif part.isdigit():
            nums.append(int(part))
        else:
            return None
    while len(nums) < 3:
        nums.append(None)
    if any(n is None for n in nums) and pre:
        return None
    pre_parts = tuple(int(p) if p.isdigit() else p for p in pre.split(".")) if pre else ()
    return nums, pre_parts


def _ver(nums: list[int | None], pre: tuple = ()) -> tuple[int, int, int, tuple]:
    return (nums[0] or 0, nums[1] or 0, nums[2] or 0, pre)


def _cmp_tuple(a: tuple, b: tuple) -> int:
    if a[:3] != b[:3]:
        return -1 if a[:3] < b[:3] else 1
    return _cmp_pre(a[3], b[3])


def _comparators(token: str) -> list[tuple[str, tuple]] | None:
    """Expand one npm comparator token into primitive (op, version) pairs."""
    matched = re.match(r"^(\^|~|>=|<=|>|<|=)?\s*(.*)$", token)
    if not matched:
        return None
    op, rest = matched.group(1) or "", matched.group(2)
    partial = _partial(rest)
    if partial is None:
        return None
    nums, pre = partial
    major, minor, patch = nums
    if op in (">", ">=", "<", "<=") and None not in nums:
        return [(op, _ver(nums, pre))]
    if op in (">", ">=", "<", "<="):
        # x-range with an operator: >1.x means >=2.0.0, <=1.x means <2.0.0, etc.
        if major is None:
            return [("<", (0, 0, 0, ()))] if op in (">", "<") else []
        upper = (major + 1, 0, 0, ()) if minor is None else (major, minor + 1, 0, ())
        lower = _ver(nums)
        return {
            ">": [(">=", upper)],
            ">=": [(">=", lower)],
            "<": [("<", lower)],
            "<=": [("<", upper)],
        }[op]
    if op == "^":
        if major is None:
            return []
        lower = _ver(nums, pre)
        if major > 0 or minor is None:
            upper = (major + 1, 0, 0, ())
        elif minor > 0 or patch is None:
            upper = (0, minor + 1, 0, ())
        else:
            upper = (0, 0, patch + 1, ())
        return [(">=", lower), ("<", upper)]
    if op == "~":
        if major is None:
            return []
        lower = _ver(nums, pre)
        upper = (major + 1, 0, 0, ()) if minor is None else (major, minor + 1, 0, ())
        return [(">=", lower), ("<", upper)]
    # exact or x-range
    if major is None:
        return []
    if minor is None:
        return [(">=", (major, 0, 0, ())), ("<", (major + 1, 0, 0, ()))]
    if patch is None:
        return [(">=", (major, minor, 0, ())), ("<", (major, minor + 1, 0, ()))]
    return [("=", _ver(nums, pre))]


def _check(version: tuple, op: str, bound: tuple) -> bool:
    c = _cmp_tuple(version, bound)
    return {"=": c == 0, ">": c > 0, ">=": c >= 0, "<": c < 0, "<=": c <= 0}[op]


def npm_satisfies(range_spec: str, version: str) -> bool | None:
    """Does an npm range accept ``version``? None when the range is not checkable."""
    spec = range_spec.strip()
    parsed = parse_semver(version)
    if parsed is None:
        return None
    if spec in {"", "*", "x", "X"}:
        return not parsed[3]
    if re.match(r"^[a-z][a-z0-9-]*$", spec) or ":" in spec or "/" in spec:
        return None  # dist-tag, URL, git, file: or alias
    for alternative in spec.split("||"):
        alternative = alternative.strip()
        hyphen = re.match(r"^(\S+)\s+-\s+(\S+)$", alternative)
        if hyphen:
            low, high = _partial(hyphen.group(1)), _partial(hyphen.group(2))
            if low is None or high is None:
                return None
            primitives = [(">=", _ver(*low))]
            hn = high[0]
            if hn[0] is None:
                pass
            elif hn[1] is None:
                primitives.append(("<", (hn[0] + 1, 0, 0, ())))
            elif hn[2] is None:
                primitives.append(("<", (hn[0], hn[1] + 1, 0, ())))
            else:
                primitives.append(("<=", _ver(*high)))
        else:
            tokens = re.findall(r"(?:\^|~|>=|<=|>|<|=)?\s*[^\s]+", alternative) or ["*"]
            primitives = []
            for token in tokens:
                expanded = _comparators(token.replace(" ", ""))
                if expanded is None:
                    return None
                primitives.extend(expanded)
        if parsed[3]:
            # npm: a prerelease only matches comparators on the same major.minor.patch
            same = any(b[:3] == parsed[:3] and b[3] for _, b in primitives)
            if not same:
                continue
        if all(_check(parsed, op, bound) for op, bound in primitives):
            return True
    return False


# ---------------------------------------------------------------------------
# PyPI (PEP 440)
# ---------------------------------------------------------------------------


def pypi_satisfies(specifier: str, version: str) -> bool | None:
    try:
        return SpecifierSet(specifier, prereleases=True).contains(Version(version))
    except (InvalidSpecifier, InvalidVersion):
        return None


def compare(ecosystem: str, a: str, b: str) -> int | None:
    if ecosystem == "npm":
        return compare_semver(a, b)
    if ecosystem == "pypi":
        try:
            va, vb = Version(a), Version(b)
        except InvalidVersion:
            return None
        return (va > vb) - (va < vb)
    return None


def valid(ecosystem: str, version: str) -> bool | None:
    if ecosystem == "npm":
        return parse_semver(version) is not None
    if ecosystem == "pypi":
        try:
            Version(version)
            return True
        except InvalidVersion:
            return False
    return None


def satisfies(ecosystem: str, spec: str, version: str) -> bool | None:
    if ecosystem == "npm":
        return npm_satisfies(spec, version)
    if ecosystem == "pypi":
        return pypi_satisfies(spec, version)
    return None


def sort_versions(ecosystem: str, versions: list[str]) -> list[str]:
    usable = [v for v in versions if valid(ecosystem, v)]
    return sorted(usable, key=cmp_to_key(lambda a, b: compare(ecosystem, a, b) or 0))


# ---------------------------------------------------------------------------
# OSV affected ranges
# ---------------------------------------------------------------------------

_OSV_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI"}


def _matches_package(affected: dict, ecosystem: str, name: str) -> bool:
    package = affected.get("package") or {}
    if package.get("ecosystem") != _OSV_ECOSYSTEM.get(ecosystem):
        return False
    wanted = name.lower()
    got = str(package.get("name", "")).lower()
    if ecosystem == "pypi":
        wanted, got = re.sub(r"[-_.]+", "-", wanted), re.sub(r"[-_.]+", "-", got)
    return wanted == got


def osv_affected(record: dict, ecosystem: str, name: str, version: str) -> bool | None:
    """True if ``version`` is inside the advisory's affected ranges; None if undecidable."""
    if valid(ecosystem, version) is not True:
        return None
    entries = [a for a in record.get("affected") or [] if _matches_package(a, ecosystem, name)]
    if not entries:
        return None
    decided = False
    for affected in entries:
        if version in (affected.get("versions") or []):
            return True
        for range_ in affected.get("ranges") or []:
            if range_.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            decided = True
            inside = False
            for event in range_.get("events") or []:
                if "introduced" in event:
                    start = event["introduced"]
                    c = 1 if start == "0" else compare(ecosystem, version, start)
                    if c is None:
                        return None
                    if c >= 0:
                        inside = True
                elif "fixed" in event and inside:
                    c = compare(ecosystem, version, event["fixed"])
                    if c is None:
                        return None
                    if c >= 0:
                        inside = False
                elif "last_affected" in event and inside:
                    c = compare(ecosystem, version, event["last_affected"])
                    if c is None:
                        return None
                    if c > 0:
                        inside = False
            if inside:
                return True
        if affected.get("versions"):
            decided = True
    return False if decided else None


def osv_fixed_versions(record: dict, ecosystem: str, name: str) -> list[str]:
    fixed = {
        event["fixed"]
        for affected in record.get("affected") or []
        if _matches_package(affected, ecosystem, name)
        for range_ in affected.get("ranges") or []
        for event in range_.get("events") or []
        if "fixed" in event
    }
    return sort_versions(ecosystem, list(fixed))
