import pytest

from app.ai import versions

OSV = {
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "qs"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "6.2.4"},
                        {"introduced": "6.3.0"},
                        {"fixed": "6.3.3"},
                    ],
                }
            ],
        },
        {
            "package": {"ecosystem": "PyPI", "name": "Werkzeug"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "2.3.7"}]}
            ],
        },
    ]
}


@pytest.mark.parametrize(
    ("spec", "version", "expected"),
    [
        ("^1.2.3", "1.9.0", True),
        ("^1.2.3", "2.0.0", False),
        ("^0.2.3", "0.2.9", True),
        ("^0.2.3", "0.3.0", False),
        ("^0.0.3", "0.0.4", False),
        ("~1.2.3", "1.2.9", True),
        ("~1.2.3", "1.3.0", False),
        ("1.x", "1.5.0", True),
        ("1.2.*", "1.3.0", False),
        (">=1.0.0 <2.0.0", "1.4.0", True),
        (">=1.0.0 <2.0.0", "2.0.0", False),
        ("1.0.0 - 1.4", "1.4.9", True),
        ("1.0.0 - 1.4", "1.5.0", False),
        ("^1.0.0 || ^3.0.0", "3.1.0", True),
        ("*", "5.0.0", True),
        ("4.17.21", "4.17.21", True),
        ("^1.2.3", "1.3.0-beta.1", False),
        ("latest", "1.0.0", None),
        ("github:user/repo", "1.0.0", None),
        ("^1.2.3", "not-a-version", None),
    ],
)
def test_npm_ranges(spec: str, version: str, expected: bool | None) -> None:
    assert versions.npm_satisfies(spec, version) is expected


def test_semver_ordering_and_prereleases() -> None:
    assert versions.compare_semver("1.0.0-alpha", "1.0.0") == -1
    assert versions.compare_semver("1.0.0-alpha.1", "1.0.0-alpha.beta") == -1
    assert versions.compare_semver("1.10.0", "1.9.0") == 1
    assert versions.sort_versions("npm", ["1.10.0", "1.2.0", "bad", "1.9.0"]) == [
        "1.2.0",
        "1.9.0",
        "1.10.0",
    ]


def test_pypi_specifiers() -> None:
    assert versions.pypi_satisfies(">=2.0,<3", "2.5.1") is True
    assert versions.pypi_satisfies("~=3.0.0", "3.1.0") is False
    assert versions.pypi_satisfies(">=2.0", "nope") is None
    assert versions.satisfies("maven", "[1,2)", "1.5") is None


def test_osv_affected_ranges_with_reintroduction() -> None:
    assert versions.osv_affected(OSV, "npm", "qs", "6.0.0") is True
    assert versions.osv_affected(OSV, "npm", "qs", "6.2.4") is False
    assert versions.osv_affected(OSV, "npm", "qs", "6.3.1") is True
    assert versions.osv_affected(OSV, "npm", "qs", "6.3.3") is False
    assert (
        versions.osv_affected(OSV, "pypi", "werkzeug", "2.3.7") is True
    )  # last_affected inclusive
    assert versions.osv_affected(OSV, "pypi", "werkzeug", "2.3.8") is False
    assert versions.osv_affected(OSV, "npm", "other", "1.0.0") is None
    assert versions.osv_fixed_versions(OSV, "npm", "qs") == ["6.2.4", "6.3.3"]
