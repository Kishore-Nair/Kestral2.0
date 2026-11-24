"""Detect non-CVE supply-chain anomalies from repository files (read as text, never executed).

Detectors:
- install_script     npm lockfile entry with ``hasInstallScript`` (code runs on ``npm install``)
- untrusted_source   package fetched from outside its registry (git, tarball URL, plain HTTP,
                     extra package index)
- missing_integrity  npm lockfile entry downloaded without an integrity hash
- loose_version      manifest asks for "latest" / "*" instead of a version range
- unpinned_image     container base or service image without an immutable digest
- typosquat          name one edit away from a popular package that is not itself popular

Each finding carries the file and line/locator it came from, a rule-based initial risk
level with the reason, and what the rule cannot know.
"""

import json
import re
import tomllib
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path, PurePosixPath

import networkx as nx

from app.graph.impact import package_impact
from app.graph.serialization import stable_id
from app.risk.workflows import _read_text
from app.schemas.dependency import DependencyComponent, DependencyDocument
from app.schemas.findings import Finding, FindingSource, RiskLevel
from app.schemas.inventory import Evidence, Inventory

SOURCE = "supply-chain-scan"
MAX_FILE_BYTES = 16 * 1024 * 1024
DATA_DIR = Path(__file__).resolve().parent / "data"
NPM_REGISTRY = "https://registry.npmjs.org/"
PYPI_HOSTS = ("https://pypi.org/simple", "https://files.pythonhosted.org/")
_SHA_REF = re.compile(r"#[0-9a-f]{40}$")
_LOOSE_SPECS = {"latest", "*", "x", "", "next"}


# ---------------------------------------------------------------------------
# Shared plumbing
# ---------------------------------------------------------------------------


@dataclass
class _Index:
    """Find the SBOM component a lockfile entry belongs to."""

    by_locator: dict[tuple[str, str], DependencyComponent] = field(default_factory=dict)
    by_name: dict[tuple[str, str], list[DependencyComponent]] = field(default_factory=dict)

    @classmethod
    def build(cls, document: DependencyDocument) -> "_Index":
        index = cls()
        for component in document.components:
            for evidence in component.evidence:
                index.by_locator.setdefault((evidence.path, evidence.locator), component)
            key = (component.ecosystem, component.name.lower())
            index.by_name.setdefault(key, []).append(component)
        return index

    def lookup(
        self, path: str, locator: str, ecosystem: str, name: str, version: str | None = None
    ) -> DependencyComponent | None:
        found = self.by_locator.get((path, locator))
        if found:
            return found
        candidates = self.by_name.get((ecosystem, name.lower()), [])
        if version is not None:
            candidates = [c for c in candidates if c.version == version]
        return candidates[0] if len(candidates) == 1 else None


def _attach(finding: dict, component: DependencyComponent | None, graph: nx.DiGraph | None) -> dict:
    if component is None:
        return finding
    finding["subject_id"] = component.component_id
    finding["scope"] = component.scope
    if graph is not None and component.component_id in graph:
        impact = package_impact(graph, component.component_id)
        finding.update(
            directness=impact.directness,
            dependency_paths=impact.paths,
            affected_projects=impact.affected_projects,
            dependent_packages=impact.dependent_packages,
        )
    return finding


def _make(
    category: str,
    title: str,
    label: str,
    evidence: list[Evidence],
    level: RiskLevel,
    reason: str,
    uncertainty: list[str],
    component: DependencyComponent | None = None,
    graph: nx.DiGraph | None = None,
    record: str | None = None,
) -> Finding:
    first = evidence[0]
    data = {
        "finding_id": stable_id("finding", "suspicious", category, first.path, first.locator),
        "kind": "suspicious",
        "category": category,
        "title": title,
        "subject_id": None,
        "subject_label": label,
        "advisory_ids": [],
        "sources": [
            FindingSource(name=SOURCE, record_id=record or f"{first.path}:{first.locator}")
        ],
        "fixed_versions": [],
        "evidence": evidence,
        "risk_level": level,
        "risk_reason": reason,
        "uncertainty": uncertainty,
    }
    return Finding(**_attach(data, component, graph))


def _label(name: str, version: str | None) -> str:
    return f"{name}@{version}" if version else name


# ---------------------------------------------------------------------------
# npm lockfile: install scripts, sources, integrity
# ---------------------------------------------------------------------------


def _npm_name(install_path: str) -> str:
    return install_path.rsplit("node_modules/", 1)[-1]


def _classify_resolved(resolved: str, has_integrity: bool) -> tuple[RiskLevel, str] | None:
    """Risk of where a package is downloaded from; None for the public registry."""
    if resolved.startswith(NPM_REGISTRY):
        return None
    if resolved.startswith("http://"):
        if has_integrity:
            return "medium", (
                "Downloaded over plain HTTP; the lockfile's integrity hash should still "
                "catch an altered download"
            )
        return "high", "Downloaded over plain HTTP with no integrity hash: content can be altered"
    if resolved.startswith(("git+", "git:", "github:")) or "github.com" in resolved:
        if _SHA_REF.search(resolved):
            return "medium", "Fetched from a git repository (pinned to a commit), not the registry"
        branch = resolved.rsplit("/", 1)[-1] if "/tarball/" in resolved else None
        detail = f" branch '{branch}'" if branch else " a branch or tag"
        return "high", f"Fetched from a git repository at{detail}: whoever pushes there controls it"
    if resolved.startswith("file:"):
        return "low", "Installed from a local path inside the repository"
    if resolved.startswith("https://"):
        host = resolved.split("/")[2]
        return "medium", f"Downloaded from {host}, not the public npm registry"
    return "medium", f"Unrecognised source '{resolved[:80]}'"


def _npm_entries(lock: dict) -> list[tuple[str, str, dict]]:
    """(install_path, locator, entry) for lockfile v2/v3 ``packages`` or v1 ``dependencies``."""
    packages = lock.get("packages")
    if isinstance(packages, dict):
        return [
            (path, f"packages.{path}", entry)
            for path, entry in packages.items()
            if path and isinstance(entry, dict)
        ]
    entries: list[tuple[str, str, dict]] = []

    def walk(deps: dict, prefix: str, locator: str) -> None:
        for name, entry in sorted(deps.items()):
            if not isinstance(entry, dict):
                continue
            path = f"{prefix}node_modules/{name}"
            here = f"{locator}dependencies.{name}"
            entries.append((path, here, entry))
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                walk(nested, f"{path}/", f"{here}.")

    if isinstance(lock.get("dependencies"), dict):
        walk(lock["dependencies"], "", "")
    return entries


def npm_lockfile_findings(
    path: str, text: str, index: _Index, graph: nx.DiGraph | None
) -> tuple[list[Finding], list[str]]:
    try:
        lock = json.loads(text)
    except json.JSONDecodeError:
        return [], [f"{path} is not valid JSON and was not checked for suspicious entries"]
    findings: list[Finding] = []
    for install_path, locator, entry in _npm_entries(lock):
        if entry.get("link"):
            continue
        name = entry.get("name") or _npm_name(install_path)
        version = entry.get("version")
        component = index.lookup(path, locator, "npm", name, version)
        label = _label(name, version)

        if entry.get("hasInstallScript"):
            dev = bool(entry.get("dev")) or (component is not None and component.scope == "dev")
            findings.append(
                _make(
                    "install_script",
                    f"{label} runs an install script",
                    label,
                    [Evidence(path=path, kind="lockfile", locator=f"{locator} hasInstallScript")],
                    "low" if dev else "medium",
                    "Install scripts run arbitrary code on every `npm install`"
                    + (
                        " (development dependency: runs on developer and CI machines)"
                        if dev
                        else ""
                    ),
                    [
                        "The lockfile only says a script exists; its contents were not inspected",
                        "Many legitimate packages (native builds) use install scripts",
                    ],
                    component,
                    graph,
                )
            )

        resolved = entry.get("resolved")
        if isinstance(resolved, str) and resolved:
            problem = _classify_resolved(resolved, bool(entry.get("integrity")))
            if problem:
                level, reason = problem
                findings.append(
                    _make(
                        "untrusted_source",
                        f"{label} is not installed from the npm registry",
                        label,
                        [
                            Evidence(
                                path=path, kind="lockfile", locator=f"{locator} resolved={resolved}"
                            )
                        ],
                        level,
                        reason,
                        [
                            "Packages outside the registry skip npm's malware scanning and "
                            "advisory matching; the source may still be legitimate"
                        ],
                        component,
                        graph,
                    )
                )
            if not entry.get("integrity") and not entry.get("inBundle"):
                findings.append(
                    _make(
                        "missing_integrity",
                        f"{label} has no integrity hash in the lockfile",
                        label,
                        [Evidence(path=path, kind="lockfile", locator=f"{locator} (no integrity)")],
                        "medium",
                        "Without an integrity hash npm cannot detect a changed download",
                        ["Older npm versions omitted hashes for some sources"],
                        component,
                        graph,
                    )
                )
    return findings, []


# ---------------------------------------------------------------------------
# Python: uv.lock sources, requirements index options and URLs
# ---------------------------------------------------------------------------


def uv_lock_findings(
    path: str, text: str, index: _Index, graph: nx.DiGraph | None
) -> tuple[list[Finding], list[str]]:
    try:
        lock = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return [], [f"{path} is not valid TOML and was not checked for suspicious entries"]
    findings: list[Finding] = []
    for package in lock.get("package") or []:
        source = package.get("source") or {}
        name, version = package.get("name", "?"), package.get("version")
        locator = f"package[{name}=={version}]" if version else f"package[{name}]"
        problem: tuple[RiskLevel, str, str] | None = None
        if "git" in source:
            url = str(source["git"])
            pinned = re.search(r"[#?&]rev=|#[0-9a-f]{40}$", url) or _SHA_REF.search(url)
            problem = (
                ("medium", "Fetched from a git repository (pinned), not PyPI", url)
                if pinned
                else ("high", "Fetched from a git repository branch or tag, not PyPI", url)
            )
        elif "url" in source:
            url = str(source["url"])
            level: RiskLevel = "high" if url.startswith("http://") else "medium"
            problem = (level, f"Downloaded from a direct URL ({url.split('/')[2]})", url)
        elif "registry" in source and not str(source["registry"]).startswith(PYPI_HOSTS):
            url = str(source["registry"])
            problem = ("medium", f"Installed from a non-PyPI index ({url})", url)
        if problem is None:
            continue
        level, reason, url = problem
        component = index.lookup(path, locator, "pypi", name, version)
        label = _label(name, version)
        findings.append(
            _make(
                "untrusted_source",
                f"{label} is not installed from PyPI",
                label,
                [Evidence(path=path, kind="lockfile", locator=f"{locator} source={url}")],
                level,
                reason,
                ["The source may be a legitimate internal or forked package; confirm it"],
                component,
                graph,
            )
        )
    return findings, []


_REQ_INDEX = re.compile(r"^\s*(--extra-index-url|--index-url|-i)[\s=]+(\S+)")
_REQ_URL = re.compile(r"^\s*(?:-e\s+)?(\S*?)(?:\s*@\s*)?((?:git\+|https?://)\S+)")


def requirements_findings(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        evidence = [Evidence(path=path, kind="manifest", locator=f"line {number}: {line[:160]}")]
        index = _REQ_INDEX.match(line)
        if index:
            option, url = index.groups()
            if url.startswith(PYPI_HOSTS):
                continue
            extra = option == "--extra-index-url"
            findings.append(
                _make(
                    "untrusted_source",
                    f"Extra package index {url}" if extra else f"Package index replaced with {url}",
                    url,
                    evidence,
                    "high" if extra else "medium",
                    "pip picks the highest version across all indexes, so a public package "
                    "with an internal name can win (dependency confusion)"
                    if extra
                    else "All packages come from a non-PyPI index",
                    ["Internal indexes are common; risk depends on who controls the index"],
                )
            )
            continue
        url_match = _REQ_URL.match(line)
        if url_match and ("://" in line):
            url = url_match.group(2)
            pinned = bool(re.search(r"@[0-9a-f]{40}", url))
            findings.append(
                _make(
                    "untrusted_source",
                    f"Requirement installed from {url.split('#')[0][:100]}",
                    url_match.group(1) or url,
                    evidence,
                    "high" if url.startswith("http://") or not pinned else "medium",
                    "Installed from a URL instead of PyPI"
                    + ("" if pinned else "; not pinned to a commit, so its content can change"),
                    ["The URL may point to a legitimate fork; confirm it is intended"],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# package.json version specifiers
# ---------------------------------------------------------------------------


def _json_line(text: str, key: str) -> int | None:
    pattern = re.compile(rf'^\s*"{re.escape(key)}"\s*:')
    for number, line in enumerate(text.splitlines(), start=1):
        if pattern.match(line):
            return number
    return None


def package_json_findings(
    path: str, text: str, index: _Index, graph: nx.DiGraph | None
) -> list[Finding]:
    try:
        manifest = json.loads(text)
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = manifest.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in sorted(deps.items()):
            if not isinstance(spec, str) or spec.strip().lower() not in _LOOSE_SPECS:
                continue
            line = _json_line(text, name)
            locator = f"line {line}: " if line else ""
            candidates = index.by_name.get(("npm", name.lower()), [])
            component = candidates[0] if len(candidates) == 1 else None
            findings.append(
                _make(
                    "loose_version",
                    f'{name} accepts any version ("{spec}")',
                    name,
                    [
                        Evidence(
                            path=path,
                            kind="manifest",
                            locator=f'{locator}{section}.{name}: "{spec}"',
                        )
                    ],
                    "medium" if section == "dependencies" else "low",
                    "A new release, including a compromised one, is accepted without review "
                    "whenever the lockfile is regenerated",
                    ["The lockfile still pins the version installed today"],
                    component,
                    graph,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Container images
# ---------------------------------------------------------------------------

_FROM = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", re.IGNORECASE)
_IMAGE = re.compile(r"""^\s*image\s*:\s*["']?([^"'\s#]+)""")


def _image_problem(image: str) -> tuple[RiskLevel, str] | None:
    if "@sha256:" in image:
        return None
    if "$" in image:
        return "low", "Image comes from a build variable; the actual image is not known statically"
    last = image.rsplit("/", 1)[-1]
    tag = last.split(":", 1)[1] if ":" in last else None
    if tag is None:
        return "high", "No tag or digest: implicitly ':latest', which changes on every push"
    if tag == "latest":
        return "high", "':latest' changes on every push to the image repository"
    return "medium", f"Tag '{tag}' has no digest; the image behind a tag can be replaced"


def container_findings(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    stages: set[str] = set()
    is_compose = PurePosixPath(path).name.lower().endswith((".yml", ".yaml"))
    for number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        matched = (_IMAGE if is_compose else _FROM).match(line)
        if not matched:
            continue
        image = matched.group(1)
        if not is_compose:
            if matched.group(2):
                stages.add(matched.group(2).lower())
            if image.lower() == "scratch" or image.lower() in stages:
                continue
        problem = _image_problem(image)
        if problem is None:
            continue
        level, reason = problem
        findings.append(
            _make(
                "unpinned_image",
                f"{image}: {'service' if is_compose else 'base'} image not pinned by digest",
                image,
                [
                    Evidence(
                        path=path, kind="container", locator=f"line {number}: {line.strip()[:160]}"
                    )
                ],
                level,
                reason,
                ["Image contents were not pulled or scanned; only the reference was checked"],
                record=f"{path}:{number}",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Typosquatting
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PopularList:
    source: str
    names: tuple[str, ...]


@cache
def popular(ecosystem: str) -> PopularList:
    path = DATA_DIR / f"popular_{ecosystem}.txt"
    source = ""
    names: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# source:"):
            source = line.split(":", 1)[1].strip()
        elif line and not line.startswith("#"):
            names.append(_normalise(ecosystem, line))
    return PopularList(source, tuple(names))


def _normalise(ecosystem: str, name: str) -> str:
    name = name.lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "pypi" else name


def _deletes(word: str) -> set[str]:
    return {word[:i] + word[i + 1 :] for i in range(len(word))}


TARGET_TOP = 1000  # names worth imitating; every listed name is treated as established


@cache
def _known(ecosystem: str) -> frozenset[str]:
    return frozenset(popular(ecosystem).names)


@cache
def _delete_index(ecosystem: str) -> dict[str, list[int]]:
    index: dict[str, list[int]] = {}
    for rank, name in enumerate(popular(ecosystem).names[:TARGET_TOP]):
        for variant in {name} | _deletes(name):
            index.setdefault(variant, []).append(rank)
    return index


def _one_edit(a: str, b: str) -> bool:
    """True when a and b differ by one insertion, deletion, substitution or adjacent swap."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (
            len(diff) == 2
            and diff[1] == diff[0] + 1
            and a[diff[0]] == b[diff[1]]
            and a[diff[1]] == b[diff[0]]
        )
    short, long_ = sorted((a, b), key=len)
    return any(long_[:i] + long_[i + 1 :] == short for i in range(len(long_)))


def lookalike(ecosystem: str, name: str) -> tuple[str, int] | None:
    """(popular name, rank) that ``name`` imitates, or None."""
    if ecosystem not in ("npm", "pypi"):
        return None
    normal = _normalise(ecosystem, name)
    popular_names = popular(ecosystem).names
    if normal in _known(ecosystem) or len(normal) < 5:
        return None
    bare = normal.split("/", 1)[1] if normal.startswith("@") and "/" in normal else None
    if bare is not None:
        return None  # scoped packages are namespaced by their owner
    index = _delete_index(ecosystem)
    ranks: set[int] = set()
    for variant in {normal} | _deletes(normal):
        ranks.update(index.get(variant, []))
    for rank in sorted(ranks):
        target = popular_names[rank]
        if len(target) >= 5 and _one_edit(normal, target):
            return target, rank
    rank = _stripped_index(ecosystem).get(re.sub(r"[-_.]", "", normal))
    return (popular_names[rank], rank) if rank is not None else None


@cache
def _stripped_index(ecosystem: str) -> dict[str, int]:
    """Separator-free name -> best rank, to catch 'lodash.merge' vs 'lodashmerge' lookalikes."""
    index: dict[str, int] = {}
    for rank, name in enumerate(popular(ecosystem).names[:TARGET_TOP]):
        index.setdefault(re.sub(r"[-_.]", "", name), rank)
    return index


def typosquat_findings(document: DependencyDocument, graph: nx.DiGraph | None) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for component in sorted(
        document.components, key=lambda c: (c.ecosystem, c.name, c.version or "")
    ):
        key = (component.ecosystem, component.name.lower())
        if key in seen:
            continue
        seen.add(key)
        match = lookalike(component.ecosystem, component.name)
        if match is None:
            continue
        target, rank = match
        reference = popular(component.ecosystem)
        label = _label(component.name, component.version)
        findings.append(
            _make(
                "typosquat",
                f"{component.name} looks like the popular package '{target}'",
                label,
                [
                    *component.evidence[:1],
                    Evidence(
                        path=f"popular_{component.ecosystem}.txt",
                        kind="reference-list",
                        locator=f"rank {rank + 1}: {target} ({reference.source})",
                    ),
                ],
                "medium",
                f"One character or separator away from '{target}' (top {rank + 1} "
                f"{component.ecosystem} package) and not among the established packages",
                [
                    "Name similarity is a heuristic: confirm this is the package you intended",
                    f"Compared against the top {TARGET_TOP} {component.ecosystem} names; "
                    f"{len(reference.names)} established names are never flagged",
                ],
                component,
                graph,
                record=f"{component.ecosystem}:{component.name}",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_NPM_LOCKS = {"package-lock.json", "npm-shrinkwrap.json"}


def suspicious_findings(
    repo_dir: Path,
    inventory: Inventory,
    document: DependencyDocument,
    graph: nx.DiGraph | None,
) -> tuple[list[Finding], list[str], int]:
    """(findings, warnings, files_checked). Unreadable files become warnings."""
    index = _Index.build(document)
    findings: list[Finding] = []
    warnings: list[str] = []
    checked = 0

    def read(path: str) -> str | None:
        nonlocal checked
        text = _read_text(repo_dir, path, MAX_FILE_BYTES)
        if text is None:
            warnings.append(f"{path} could not be read safely and was not checked")
        else:
            checked += 1
        return text

    for entry in inventory.lockfiles:
        name = PurePosixPath(entry.path).name.lower()
        if name in _NPM_LOCKS:
            text = read(entry.path)
            if text is not None:
                found, notes = npm_lockfile_findings(entry.path, text, index, graph)
                findings += found
                warnings += notes
        elif name == "uv.lock":
            text = read(entry.path)
            if text is not None:
                found, notes = uv_lock_findings(entry.path, text, index, graph)
                findings += found
                warnings += notes
    for entry in inventory.manifests:
        name = PurePosixPath(entry.path).name.lower()
        if name == "package.json":
            text = read(entry.path)
            if text is not None:
                findings += package_json_findings(entry.path, text, index, graph)
        elif name.startswith("requirements") and name.endswith(".txt"):
            text = read(entry.path)
            if text is not None:
                findings += requirements_findings(entry.path, text)
    for path in inventory.dockerfiles:
        text = read(path)
        if text is not None:
            findings += container_findings(path, text)
    findings += typosquat_findings(document, graph)

    unique = {f.finding_id: f for f in findings}
    return list(unique.values()), warnings, checked


_LEVELS: tuple[RiskLevel, ...] = ("low", "medium", "high")


def escalate(findings: list[Finding], extra: dict[str, set[str]] | None = None) -> list[Finding]:
    """Raise a package's level when independent signals stack (e.g. typosquat + install script)."""
    by_subject: dict[str, set[str]] = {}
    for finding in findings:
        if finding.subject_id and finding.category:
            by_subject.setdefault(finding.subject_id, set()).add(finding.category)
    for subject, categories in (extra or {}).items():
        by_subject.setdefault(subject, set()).update(categories)
    out: list[Finding] = []
    for finding in findings:
        others = by_subject.get(finding.subject_id or "", set()) - {finding.category}
        if others and finding.risk_level and finding.risk_level != "high":
            raised = _LEVELS[_LEVELS.index(finding.risk_level) + 1]
            names = ", ".join(sorted(o.replace("_", " ") for o in others))
            finding = finding.model_copy(
                update={
                    "risk_level": raised,
                    "risk_reason": f"{finding.risk_reason}. Raised to {raised}: same package "
                    f"also flagged for {names}",
                }
            )
        out.append(finding)
    return out
