"""Builders for risk-analysis tests. Recorded-shape OSV/Grype data, no network."""

from app.schemas.dependency import DependencyDocument

SCAN_ID = "scan_" + "7" * 32


def ev(path: str, kind: str, locator: str) -> dict:
    return {"path": path, "kind": kind, "locator": locator}


def comp(cid: str, name: str, version: str | None, ecosystem: str = "npm", **extra) -> dict:
    purl_type = {"npm": "npm", "pypi": "pypi", "github-actions": "github"}[ecosystem]
    item = {
        "component_id": cid,
        "name": name,
        "version": version,
        "ecosystem": ecosystem,
        "purl": f"pkg:{purl_type}/{name}@{version}" if version else None,
        "install_path": f"node_modules/{name}",
        "project_path": "",
        "scope": "runtime",
        "licenses": [],
        "hashes": [],
        "evidence": [ev("package-lock.json", "lockfile", f"packages.node_modules/{name}")],
        "resolved": version is not None,
    }
    item.update(extra)
    return item


def rel(rid: str, src: str, dst: str) -> dict:
    return {
        "relationship_id": rid,
        "from_id": src,
        "to_id": dst,
        "unresolved_target": None,
        "resolution_status": "resolved",
        "type": "DEPENDS_ON",
        "evidence": [ev("package-lock.json", "lockfile", f"{src}->{dst}")],
    }


def document(components: list[dict], relationships: list[dict]) -> DependencyDocument:
    return DependencyDocument.model_validate(
        {
            "scan_id": SCAN_ID,
            "roots": [
                {
                    "root_id": "root:demo",
                    "name": "demo",
                    "path": "",
                    "manifest_path": "package.json",
                    "ecosystem": "npm",
                }
            ],
            "components": components,
            "relationships": relationships,
            "partial": False,
            "warnings": [],
        }
    )


def demo_document() -> DependencyDocument:
    """root -> express -> lodash (transitive); lodash also installed nested; orphan qs."""
    return document(
        [
            comp("cmp:express", "express", "4.0.0"),
            comp("cmp:lodash", "lodash", "4.17.15"),
            comp(
                "cmp:lodash-nested",
                "lodash",
                "4.17.15",
                install_path="node_modules/x/node_modules/lodash",
            ),
            comp(
                "cmp:qs",
                "qs",
                "6.0.0",
                evidence=[ev("sbom.cdx.json", "syft-sbom", "components[3]")],
            ),
            comp("cmp:ranged", "left-pad", None),
            comp("cmp:checkout", "actions/checkout", "v4", ecosystem="github-actions"),
        ],
        [
            rel("rel:1", "root:demo", "cmp:express"),
            rel("rel:2", "cmp:express", "cmp:lodash"),
            rel("rel:3", "cmp:express", "cmp:lodash-nested"),
        ],
    )


def osv_record(
    vuln_id: str, name: str, aliases: list[str], fixed: str | None = None, **extra
) -> dict:
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    record = {
        "id": vuln_id,
        "summary": f"Issue {vuln_id}",
        "aliases": aliases,
        "database_specific": {"severity": "HIGH"},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
        "affected": [
            {
                "package": {"name": name, "ecosystem": "npm", "purl": f"pkg:npm/{name}"},
                "ranges": [{"type": "SEMVER", "events": events}],
            }
        ],
    }
    record.update(extra)
    return record


def grype_match(
    vuln_id: str,
    purl: str,
    related: list[str],
    fix: list[str] | None = None,
    match_type: str = "exact-direct-match",
) -> dict:
    return {
        "vulnerability": {
            "id": vuln_id,
            "dataSource": f"https://github.com/advisories/{vuln_id}",
            "severity": "High",
            "description": f"Grype says {vuln_id}",
            "cvss": [{"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
            "fix": {"versions": fix or [], "state": "fixed" if fix else "unknown"},
        },
        "relatedVulnerabilities": [{"id": r} for r in related],
        "matchDetails": [{"type": match_type}],
        "artifact": {"name": purl.split("/")[-1].split("@")[0], "purl": purl},
    }
