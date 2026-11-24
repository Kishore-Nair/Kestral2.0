import json
from pathlib import Path

import pytest

from app.sbom.cyclonedx_parser import (
    CycloneDXFormatError,
    load_cyclonedx,
    parse_cyclonedx,
)

FIXTURE = Path(__file__).parent / "fixtures" / "cyclonedx" / "sample.cdx.json"


@pytest.fixture
def sbom():
    return load_cyclonedx(FIXTURE)


def by_name(sbom, name):
    return next(c for c in sbom.components if c.name == name)


def test_reads_tool_and_spec_version(sbom):
    assert sbom.spec_version == "1.6"
    assert sbom.tool_name == "syft"
    assert sbom.tool_version == "1.0.0-test"


def test_file_entries_are_not_packages(sbom):
    names = [c.name for c in sbom.packages()]
    assert "/.github/workflows/ci.yml" not in names
    assert len(sbom.packages()) == 5


def test_npm_component_fields(sbom):
    alpha = by_name(sbom, "alpha")
    assert alpha.version == "1.0.0"
    assert alpha.purl == "pkg:npm/alpha@1.0.0"
    assert alpha.ecosystem == "npm"
    assert alpha.licenses == (("MIT", None),)
    assert alpha.hashes == (("SHA-512", "abc123"),)
    assert alpha.found_by == "javascript-lock-cataloger"
    assert alpha.locations == ("/package-lock.json",)
    assert alpha.evidence_locator == "components[0]"


def test_license_name_and_expression(sbom):
    assert by_name(sbom, "beta").licenses == ((None, "Custom License"),)
    assert by_name(sbom, "Foo_Bar").licenses == ((None, "Apache-2.0 OR MIT"),)


def test_python_name_is_normalized_but_original_kept(sbom):
    pkg = by_name(sbom, "Foo_Bar")
    assert pkg.ecosystem == "pypi"
    assert pkg.normalized_name == "foo-bar"
    assert pkg.name == "Foo_Bar"


def test_github_action_ecosystem(sbom):
    action = by_name(sbom, "actions/checkout")
    assert action.ecosystem == "github-actions"
    assert action.package_type == "github-action"


def test_missing_optional_fields_are_none_not_invented(sbom):
    pkg = by_name(sbom, "no-version-package")
    assert pkg.version is None
    assert pkg.purl is None
    assert pkg.ecosystem is None
    assert pkg.licenses == ()
    assert pkg.hashes == ()


def test_dependencies_are_read_exactly(sbom):
    assert len(sbom.dependencies) == 1
    dep = sbom.dependencies[0]
    assert dep.ref == "pkg:npm/alpha@1.0.0"
    assert dep.depends_on == ("pkg:npm/beta@2.0.0",)


def test_wrong_bom_format_rejected():
    with pytest.raises(CycloneDXFormatError):
        parse_cyclonedx({"bomFormat": "SPDX", "components": []})


def test_components_must_be_list():
    with pytest.raises(CycloneDXFormatError):
        parse_cyclonedx({"bomFormat": "CycloneDX", "components": {}})


def test_not_json_object_rejected():
    with pytest.raises(CycloneDXFormatError):
        parse_cyclonedx(["not", "an", "object"])


def test_unreadable_file_rejected(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(CycloneDXFormatError):
        load_cyclonedx(bad)


def test_duplicate_bom_ref_is_ambiguous_not_mapped():
    data = {
        "bomFormat": "CycloneDX",
        "components": [
            {"type": "library", "bom-ref": "dup", "name": "a", "version": "1"},
            {"type": "library", "bom-ref": "dup", "name": "a", "version": "1"},
            {"type": "library", "bom-ref": "solo", "name": "b", "version": "1"},
        ],
    }
    sbom = parse_cyclonedx(data)
    assert sbom.ambiguous_bom_refs() == {"dup"}
    assert set(sbom.unique_bom_refs()) == {"solo"}
    assert any("dup" in w for w in sbom.warnings)


def test_invalid_purl_is_dropped_with_warning():
    data = {
        "bomFormat": "CycloneDX",
        "components": [{"type": "library", "name": "x", "version": "1", "purl": "not-a-purl"}],
    }
    sbom = parse_cyclonedx(data)
    assert sbom.components[0].purl is None
    assert any("invalid purl" in w for w in sbom.warnings)


def test_bad_entries_skipped_with_warnings():
    data = {
        "bomFormat": "CycloneDX",
        "components": ["junk", {"type": "library"}],
        "dependencies": [{"dependsOn": []}, {"ref": "r", "dependsOn": "nope"}],
    }
    sbom = parse_cyclonedx(data)
    assert sbom.components == []
    assert sbom.dependencies == []
    assert len(sbom.warnings) == 4


def test_legacy_tools_list_metadata():
    data = {
        "bomFormat": "CycloneDX",
        "metadata": {"tools": [{"name": "syft", "version": "0.90.0"}]},
        "components": [],
    }
    sbom = parse_cyclonedx(data)
    assert (sbom.tool_name, sbom.tool_version) == ("syft", "0.90.0")


def test_fixture_is_valid_json():
    json.loads(FIXTURE.read_text(encoding="utf-8"))
