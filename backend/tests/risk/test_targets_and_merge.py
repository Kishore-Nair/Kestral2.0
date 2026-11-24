from risk_helpers import demo_document, grype_match, osv_record

from app.graph.builder import make_networkx_graph
from app.risk.grype import GrypeResult
from app.risk.merge import vulnerability_findings
from app.risk.osv import OsvResult
from app.risk.targets import canonical_purl, select_targets

LODASH = "pkg:npm/lodash@4.17.15"
QS = "pkg:npm/qs@6.0.0"


def osv(matches: dict, records: list[dict]) -> OsvResult:
    return OsvResult(
        retrieved_at="2026-11-24T00:00:00+00:00",
        matches=matches,
        records={r["id"]: r for r in records},
    )


def grype(matches: list[dict]) -> GrypeResult:
    return GrypeResult(
        tool_version="0.122.1",
        database_built="2026-11-23T06:28:32Z",
        matches=matches,
        raw={"matches": matches},
    )


def setup():
    doc = demo_document()
    return select_targets(doc.components), make_networkx_graph(doc, "demo")


def test_canonical_purl_drops_qualifiers_and_normalizes() -> None:
    assert canonical_purl("pkg:pypi/Foo_Bar@1.0?x=1#sub") == "pkg:pypi/foo-bar@1.0"
    assert canonical_purl("pkg:npm/lodash@1.0", with_version=False) == "pkg:npm/lodash"
    assert canonical_purl("not a purl") is None
    assert canonical_purl(None) is None


def test_targets_need_exact_version_and_supported_ecosystem() -> None:
    targets, _ = setup()
    assert targets.purls == ["pkg:npm/express@4.0.0", LODASH, QS]
    # both lodash installs share one query but stay two components
    assert [c.component_id for c in targets.by_purl[LODASH]] == ["cmp:lodash", "cmp:lodash-nested"]
    # left-pad has no version; actions/checkout is a github PURL
    assert targets.not_assessed == 2


def test_aliases_merge_sources_into_one_finding_per_install() -> None:
    targets, graph = setup()
    findings = vulnerability_findings(
        targets,
        graph,
        osv(
            {LODASH: ["GHSA-aaaa", "PYSEC-1"]},
            [
                osv_record("GHSA-aaaa", "lodash", ["CVE-1"], fixed="4.17.21"),
                osv_record("PYSEC-1", "lodash", ["CVE-1"]),
            ],
        ),
        grype([grype_match("CVE-1", LODASH, [], fix=["4.17.21"])]),
    )
    assert [f.subject_id for f in findings] == ["cmp:lodash", "cmp:lodash-nested"]
    first = findings[0]
    assert first.advisory_ids == ["GHSA-aaaa", "CVE-1", "PYSEC-1"]
    assert {(s.name, s.record_id) for s in first.sources} == {
        ("OSV", "GHSA-aaaa"),
        ("OSV", "PYSEC-1"),
        ("Grype", "CVE-1"),
    }
    assert first.fixed_versions == ["4.17.21"]
    assert first.directness == "transitive"
    assert first.dependency_paths == [["root:demo", "cmp:express", "cmp:lodash"]]
    assert first.affected_projects == ["root:demo"]
    assert first.title == "GHSA-aaaa: Issue GHSA-aaaa"
    assert {(e.path, e.kind) for e in first.evidence} == {
        ("package-lock.json", "lockfile"),
        ("osv.json", "osv-record"),
        ("grype.json", "grype-match"),
    }
    assert first.uncertainty == [
        "Not reachability-checked: the vulnerable code may never be called"
    ]
    assert first.finding_id != findings[1].finding_id


def test_single_source_and_weak_matches_are_labelled() -> None:
    targets, graph = setup()
    findings = vulnerability_findings(
        targets,
        graph,
        osv({LODASH: ["GHSA-osv"]}, [osv_record("GHSA-osv", "lodash", [])]),
        grype([grype_match("CVE-9", QS, [], match_type="cpe-match")]),
    )
    by_subject = {f.subject_id: f for f in findings}
    assert "Reported by OSV only; Grype found no match" in by_subject["cmp:lodash"].uncertainty
    qs = by_subject["cmp:qs"]
    assert "Reported by Grype only; OSV found no match" in qs.uncertainty
    assert "Grype matched by cpe-match; this may be a false positive" in qs.uncertainty
    assert "Version comes from Syft's SBOM, not a lockfile" in qs.uncertainty
    assert "No proven dependency path from any project to this package" in qs.uncertainty
    assert qs.directness == "unknown" and qs.dependency_paths == []


def test_source_that_did_not_run_is_named() -> None:
    targets, graph = setup()
    findings = vulnerability_findings(
        targets, graph, None, grype([grype_match("CVE-9", "pkg:npm/express@4.0.0", [])])
    )
    assert findings[0].uncertainty[0] == "Reported by Grype only; OSV did not run"
    assert findings[0].directness == "direct"


def test_withdrawn_and_unknown_purls_are_ignored() -> None:
    targets, graph = setup()
    findings = vulnerability_findings(
        targets,
        graph,
        osv(
            {LODASH: ["GHSA-gone"]}, [osv_record("GHSA-gone", "lodash", [], withdrawn="2026-01-01")]
        ),
        grype([grype_match("CVE-x", "pkg:npm/not-in-scan@1.0.0", [])]),
    )
    assert findings == []


def test_output_is_deterministic() -> None:
    targets, graph = setup()
    args = (
        osv(
            {LODASH: ["GHSA-b", "GHSA-a"]},
            [osv_record("GHSA-a", "lodash", []), osv_record("GHSA-b", "lodash", [])],
        ),
        grype([grype_match("GHSA-b", LODASH, []), grype_match("GHSA-a", LODASH, [])]),
    )
    first = [f.model_dump() for f in vulnerability_findings(targets, graph, *args)]
    again = [f.model_dump() for f in vulnerability_findings(targets, graph, *args)]
    assert first == again
    assert [f["advisory_ids"][0] for f in first] == ["GHSA-a", "GHSA-a", "GHSA-b", "GHSA-b"]
