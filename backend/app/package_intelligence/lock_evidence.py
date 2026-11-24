import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

from app.provenance.local import OperationError, read_local, validate_json

from .integrity import FILENAME


@dataclass(frozen=True)
class LockEvidence:
    path: str
    locator: str
    artifact: str | None
    digest: str | None
    filename: str | None = None
    nonpublic_source: bool = False


def artifact_path(value: object, host: str) -> str | None:
    if not isinstance(value, str) or len(value) > 2048 or not value.isascii():
        return None
    try:
        parsed = urlsplit(value)
        # Keep the URL path as published. Decoding it for equality would collapse
        # distinct URLs, including encoded path separators.
        if (
            value == f"https://{host}{parsed.path}"
            and re.fullmatch(r"/[a-zA-Z0-9@._+/%-]+", parsed.path)
        ):
            for segment in parsed.path[1:].split("/"):
                decoded = unquote(segment)
                if decoded in {".", ".."} or not re.fullmatch(r"[@a-zA-Z0-9._+-]+", decoded):
                    return None
            return parsed.path
    except ValueError:
        pass
    return None


class LockReader:
    def __init__(self, root: Path | None):
        self.root = root
        self.cache: dict[str, dict] = {}

    def _load(self, path: str) -> dict:
        if path not in self.cache and len(self.cache) < 12 and self.root is not None:
            self.cache[path] = {}
            candidate = Path(path)
            if (
                candidate.anchor or "\\" in path or ":" in path or ".." in candidate.parts
                or len(path) > 512 or not path.isprintable()
            ):
                return {}
            try:
                raw = read_local(self.root / candidate, self.root, 2 * 1024 * 1024)
                if candidate.name == "uv.lock":
                    self.cache[path] = tomllib.loads(raw.decode())
                else:
                    parsed = json.loads(validate_json(raw))
                    self.cache[path] = parsed if isinstance(parsed, dict) else {}
            except (OSError, ValueError, OperationError, RecursionError):
                pass
        return self.cache.get(path, {})

    def for_component(self, component) -> LockEvidence | None:
        if self.root is None:
            return None
        for evidence in component.evidence[:16]:
            if evidence.kind != "lockfile" or len(evidence.locator) > 512:
                continue
            filename = Path(evidence.path).name
            if component.ecosystem == "npm" and filename in {
                "package-lock.json", "npm-shrinkwrap.json",
            }:
                bound = self._npm(component, evidence)
            elif component.ecosystem == "pypi" and filename == "uv.lock":
                bound = self._uv(component, evidence)
            else:
                continue
            if bound is not None:
                return bound
        return None

    def _npm(self, component, evidence) -> LockEvidence | None:
        install = component.install_path
        if not install or evidence.locator != f"packages.{install}":
            return None
        lock = self._load(evidence.path)
        packages = lock.get("packages")
        entry = packages.get(install) if isinstance(packages, dict) else None
        if not isinstance(entry, dict) or entry.get("link") or entry.get("inBundle"):
            return None
        inferred_name = install.rsplit("node_modules/", 1)[-1]
        if entry.get("name", inferred_name) != component.name:
            return None
        if entry.get("version") != component.version:
            return None
        resolved = entry.get("resolved")
        artifact = artifact_path(resolved, "registry.npmjs.org")
        integrity = entry.get("integrity")
        return LockEvidence(
            evidence.path, evidence.locator, artifact, integrity,
            nonpublic_source=isinstance(resolved, str) and bool(resolved) and artifact is None,
        )

    def _uv(self, component, evidence) -> LockEvidence | None:
        lock = self._load(evidence.path)
        packages = lock.get("package")
        if lock.get("version") != 1 or not isinstance(packages, list):
            return None
        matches = [
            entry for entry in packages if isinstance(entry, dict)
            and entry.get("version") == component.version and entry.get("name") == component.name
        ]
        if len(matches) != 1 or evidence.locator != (
            f"package[{component.name}=={component.version}]"
        ):
            return None
        entry = matches[0]
        source = entry.get("source")
        if source not in (
            {"registry": "https://pypi.org/simple"}, {"registry": "https://pypi.org/simple/"},
        ):
            return LockEvidence(
                evidence.path, evidence.locator, None, None, nonpublic_source=bool(source),
            )
        artifact = entry.get("sdist")
        if not isinstance(artifact, dict):
            return None
        path = artifact_path(artifact.get("url"), "files.pythonhosted.org")
        filename = unquote(path.rsplit("/", 1)[-1]) if path else None
        value = artifact.get("hash")
        digest = value[7:] if isinstance(value, str) and value.startswith("sha256:") else None
        if filename is None or not FILENAME.fullmatch(filename):
            return None
        return LockEvidence(evidence.path, evidence.locator, path, digest, filename)
