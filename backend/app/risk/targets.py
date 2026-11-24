"""Choose which components can be honestly checked for known vulnerabilities.

Only components with an exact version and a PURL in an ecosystem both OSV and
Grype understand are assessed. Everything else is counted as "not assessed",
never as "no vulnerabilities".
"""

from dataclasses import dataclass

from packageurl import PackageURL

from app.schemas.dependency import DependencyComponent

# PURL types that OSV and Grype both match against language advisory data.
SUPPORTED_PURL_TYPES = frozenset(
    {"npm", "pypi", "maven", "golang", "cargo", "gem", "nuget", "composer", "hex", "pub"}
)


@dataclass(frozen=True)
class Targets:
    by_purl: dict[str, list[DependencyComponent]]  # canonical PURL -> components
    not_assessed: int

    @property
    def purls(self) -> list[str]:
        return sorted(self.by_purl)


def canonical_purl(purl: str | None, *, with_version: bool = True) -> str | None:
    """type/namespace/name(@version), no qualifiers or subpath; None if unparsable."""
    if not purl:
        return None
    try:
        parsed = PackageURL.from_string(purl)
    except ValueError:
        return None
    return PackageURL(
        type=parsed.type,
        namespace=parsed.namespace,
        name=parsed.name,
        version=parsed.version if with_version else None,
    ).to_string()


def select_targets(components: list[DependencyComponent]) -> Targets:
    by_purl: dict[str, list[DependencyComponent]] = {}
    not_assessed = 0
    for component in components:
        key = canonical_purl(component.purl)
        if (
            key is None
            or not component.resolved
            or not component.version
            or key.split(":", 1)[1].split("/", 1)[0] not in SUPPORTED_PURL_TYPES
            or "@" not in key.rsplit("/", 1)[-1]
        ):
            not_assessed += 1
            continue
        by_purl.setdefault(key, []).append(component)
    for items in by_purl.values():
        items.sort(key=lambda c: c.component_id)
    return Targets(by_purl=by_purl, not_assessed=not_assessed)
