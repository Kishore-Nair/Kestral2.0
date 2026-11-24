"""Synthetic fixtures. No test contacts any public registry."""

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError

import pytest

from app.package_intelligence.__main__ import main
from app.package_intelligence.engine import assess
from app.package_intelligence.integrity import npm_compare, pypi_compare
from app.package_intelligence.lock_evidence import artifact_path
from app.package_intelligence.registry import (
    Budget,
    NoRedirect,
    Registry,
    RegistryError,
    fetch_metadata,
)
from app.package_intelligence.release_signals import Thresholds, burst, release_for, withdrawal
from app.package_intelligence.script_analysis import inspect_scripts
from app.schemas.dependency import DependencyDocument

NOW = datetime(2026, 1, 1, tzinfo=UTC)
URL = "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"
LOCK = "package-lock.json"


def sri(byte: bytes, algorithm="sha512", length=64) -> str:
    return f"{algorithm}-" + base64.b64encode(byte * length).decode()


def doc(*, ecosystem="npm", name="demo", duplicates=False) -> DependencyDocument:
    components = [
        {
            "component_id": f"cmp:{i}", "name": name, "version": "1.0.0",
            "ecosystem": ecosystem, "purl": None, "scope": "dev",
            "install_path": "node_modules/demo", "project_path": "",
            "licenses": [], "hashes": [], "resolved": True,
            "evidence": [
                {"path": LOCK, "kind": "lockfile", "locator": "packages.node_modules/demo"}
            ],
        }
        for i in range(2 if duplicates else 1)
    ]
    return DependencyDocument(
        scan_id="synthetic", roots=[], components=components, relationships=[],
        partial=False, warnings=[],
    )


def npm_record(**fields):
    return {
        "name": "demo",
        "versions": {"1.0.0": {
            "name": "demo", "version": "1.0.0",
            "dist": {"tarball": URL, "integrity": sri(b"A")},
            **fields,
        }},
        "time": {
            "created": (NOW - timedelta(days=3)).isoformat(),
            "1.0.0": (NOW - timedelta(days=1)).isoformat(),
        },
    }


def fixture_registry(data, **options):
    return Registry(
        {("npm", "demo"), ("pypi", "demo")}, enabled=True, now=lambda: NOW,
        fetch=lambda *_: json.dumps(data).encode(), **options,
    )


@pytest.mark.parametrize("url", [
    "http://registry.npmjs.org/demo",
    "https://registry.npmjs.org@elsewhere.example/demo",
    "https://registry.npmjs.org:443/demo",
    "https://registry.npmjs.org/demo?forward=elsewhere",
    "https://registry.npmjs.org/%2e%2e",
    "https://pypi.org/pypi/demo/../../json",
])
def test_transport_rejects_noncanonical_targets_without_network(url):
    with pytest.raises(RegistryError, match="invalid_registry_url"):
        fetch_metadata(url, 1, 1024)


def test_distribution_identity_preserves_url_path():
    host = "registry.npmjs.org"
    assert artifact_path(f"https://{host}/@scope/demo/-/demo.tgz", host) == (
        "/@scope/demo/-/demo.tgz"
    )
    assert artifact_path(f"https://{host}/@scope%2Fdemo/-/demo.tgz", host) is None
    assert artifact_path(f"https://{host}/demo/%2e%2e/demo.tgz", host) is None
    assert artifact_path(f"https://{host}/demo/-/demo.tgz?", host) is None


def test_sri_alternatives_and_algorithm_precedence():
    weak = sri(b"W", "sha256", 32)
    assert npm_compare(sri(b"X") + " " + sri(b"A"), sri(b"A")) == ("match", "sha512")
    assert npm_compare(sri(b"X") + " " + weak, sri(b"A") + " " + weak) == ("mismatch", "sha512")
    assert npm_compare(weak, sri(b"A")) == ("uncomparable", None)
    assert npm_compare("sha512-!", sri(b"A")) == ("malformed", None)
    assert npm_compare(None, sri(b"A")) == ("missing", None)


@pytest.mark.parametrize("match", [True, False])
def test_binds_npm_distribution_to_lock(tmp_path, match):
    lock = {"packages": {"node_modules/demo": {
        "version": "1.0.0", "resolved": URL, "integrity": sri(b"A" if match else b"Z"),
    }}}
    (tmp_path / LOCK).write_text(json.dumps(lock))
    registry = fixture_registry(npm_record(deprecated="synthetic warning", scripts={"install": ""}))
    report = assess(doc(duplicates=True), registry, lock_root=tmp_path)
    [package] = report["packages"]
    assert registry.requests == 1
    assert len(package["components"]) == 2
    assert package["integrity"][0]["status"] == ("match" if match else "mismatch")
    assert ("registry_integrity_mismatch" in {s["category"] for s in package["signals"]}) != match
    assert {"recent_package", "recent_release", "deprecated_version"} <= {
        s["category"] for s in package["signals"]
    }
    lock["packages"]["node_modules/demo"]["resolved"] = "https://private.example/file.tgz"
    (tmp_path / LOCK).write_text(json.dumps(lock))
    denied_registry = fixture_registry(npm_record())
    denied = assess(doc(), denied_registry, lock_root=tmp_path)
    assert denied["excluded"] == [{"component_id": "cmp:0", "status": "nonpublic_lock_source"}]
    assert denied_registry.requests == 0


def test_pypi_distribution_and_yank():
    file = {
        "filename": "demo-1.0.0.tar.gz", "digests": {"sha256": "a" * 64}, "yanked": True,
        "upload_time_iso_8601": (NOW - timedelta(days=100)).isoformat(),
    }
    other = {**file, "filename": "demo.whl", "yanked": False}
    assert pypi_compare("b" * 64, [file], file["filename"]) == ("mismatch", "sha256")
    assert pypi_compare("b" * 64, [file], None) == ("ambiguous_distribution", "sha256")
    assert pypi_compare("a" * 64, [file], None) == ("membership_match", "sha256")
    assert withdrawal("pypi", [file, other], None) == "partial"
    data = {"info": {"name": "demo"}, "releases": {"1.0": [file]}}
    [package] = assess(doc(ecosystem="pypi"), fixture_registry(data))["packages"]
    assert {s["category"] for s in package["signals"]} == {"yanked_version"}
    assert package["package_age_basis"] == "earliest_observed"


def test_scripts_are_static_and_redacted():
    assert inspect_scripts({}) == ("unassessed", [])
    assert inspect_scripts({"scripts": {}}) == ("assessed", [])
    assert inspect_scripts({"scripts": {"postinstall": "node-gyp rebuild"}})[0] == "assessed"
    inert = "echo 'curl base64 NODE_AUTH_TOKEN child_process'"
    status, [script] = inspect_scripts({"scripts": {"preinstall": inert}})
    assert status == "signal"
    assert len(script["indicators"]) == 4
    assert inert not in str(script)


def test_interpretable_stable_release_burst():
    data = npm_record()
    data["versions"]["0.9.0"] = {}
    data["time"]["0.9.0"] = (NOW - timedelta(days=120)).isoformat()
    for patch in range(1, 5):
        key = f"1.0.{patch}"
        data["versions"][key] = {}
        data["time"][key] = (NOW - timedelta(days=patch)).isoformat()
    release = release_for(data, "npm", "demo", "1.0.0", NOW)
    assert burst(release, NOW, Thresholds()) == ("signal", 5)
    del data["time"]["1.0.4"]
    release = release_for(data, "npm", "demo", "1.0.0", NOW)
    assert burst(release, NOW, Thresholds()) == ("unassessed", 0)


@pytest.mark.parametrize(("fault", "expected"), [
    (404, "not_found"), (429, "rate_limited"), ("timeout", "timeout"),
    ("malformed", "malformed_metadata"), ("redirect", "redirect_rejected"),
    ("oversize", "oversize"),
])
def test_network_faults_are_distinct(fault, expected):
    def fetch(url, _timeout, limit):
        if isinstance(fault, int):
            raise HTTPError(url, fault, "", {}, None)
        if fault == "timeout":
            raise TimeoutError
        if fault == "redirect":
            NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example")
        return b"!" if fault == "malformed" else b" " * (limit + 1)

    registry = Registry({("npm", "demo")}, enabled=True, fetch=fetch)
    assert registry.get("npm", "demo").status == expected


def test_allowlist_offline_and_budget(monkeypatch):
    calls = []

    def fetch(url, *_):
        calls.append(url)
        return b"{}"

    registry = Registry({("npm", "demo")}, fetch=fetch)
    assert registry.get("npm", "demo").status == "network_disabled"
    assert not calls
    registry = Registry(
        {("npm", "@scope/demo"), ("npm", "demo")}, enabled=True, fetch=fetch,
        budget=Budget(requests=1),
    )
    assert registry.get("npm", "internal").status == "not_authorized"
    assert registry.get("npm", "@scope/demo").status == "ok"
    assert registry.get("npm", "demo").status == "budget_skipped"
    assert calls == ["https://registry.npmjs.org/%40scope%2Fdemo"]
    clock = iter((0, 31))
    registry = Registry({("npm", "demo")}, enabled=True, fetch=fetch, clock=lambda: next(clock))
    assert registry.get("npm", "demo").status == "budget_skipped"
    assert assess(doc(ecosystem="other"), registry)["excluded"][0]["status"] == (
        "unsupported_ecosystem"
    )


def test_cli_scan_match_and_output_boundaries(tmp_path, monkeypatch):
    normalized = tmp_path / "normalized.json"
    normalized.write_text(doc().model_dump_json())
    output = tmp_path / "out.json"
    command = [
        "package-intelligence", "--scan-id", "synthetic", "--workspace", str(tmp_path),
        "--normalized", str(normalized), "--output", str(output),
    ]
    monkeypatch.setattr("sys.argv", command)
    assert main() == 0
    assert json.loads(output.read_text())["coverage"]["skipped"] == 1
    command[2] = "other"
    assert main() == 1
    command[2] = "synthetic"
    command[-1] = str(Path(__file__).resolve().parent / "forbidden.json")
    assert main() == 1
    assert not Path(command[-1]).exists()
