import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from risk_helpers import SCAN_ID, demo_document, grype_match, osv_record

from app.risk import analyze_risk
from app.risk.cvss import CvssError, score_vector
from app.risk.grype import GrypeResult
from app.risk.nvd import NvdClient, NvdLookup
from app.risk.osv import OsvResult
from app.risk.scoring import enrich_findings, priority_for
from app.schemas.findings import Finding, FindingSource
from app.schemas.inventory import Inventory

LODASH = "pkg:npm/lodash@4.17.15"
NOW = datetime(2026, 11, 24, tzinfo=UTC)


# ---------- CVSS calculator ----------


@pytest.mark.parametrize(
    ("vector", "expected", "severity"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
        ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", 5.5, "MEDIUM"),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4, "MEDIUM"),
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2, "HIGH"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL"),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "MEDIUM"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "NONE"),
        ("AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5, "HIGH"),
        ("AV:N/AC:M/Au:N/C:N/I:P/A:N", 4.3, "MEDIUM"),
    ],
)
def test_cvss_base_scores_match_first_reference_values(vector, expected, severity) -> None:
    result = score_vector(vector)
    assert result.base_score == expected
    assert result.severity == severity
    assert result.computed


def test_cvss_v4_uses_published_score_and_bad_vectors_fail() -> None:
    v4 = score_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3)
    assert (v4.base_score, v4.severity, v4.computed) == (9.3, "CRITICAL", False)
    with pytest.raises(CvssError):
        score_vector("CVSS:3.1/AV:N/AC:L")
    with pytest.raises(CvssError):
        score_vector("CVSS:9.9/AV:N")


# ---------- NVD client ----------


def nvd_record(cve_id: str, vector: str, score: float, cwe: str = "CWE-79", **extra) -> dict:
    record = {
        "id": cve_id,
        "vulnStatus": "Analyzed",
        "published": "2020-03-01T00:00:00.000",
        "lastModified": "2024-01-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": f"Description of {cve_id}"}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "security@example.org",
                    "type": "Secondary",
                    "cvssData": {
                        "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        "baseScore": 3.7,
                    },
                },
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {"vectorString": vector, "baseScore": score},
                },
            ]
        },
        "weaknesses": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "description": [{"lang": "en", "value": cwe}],
            }
        ],
    }
    record.update(extra)
    return record


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.t += seconds


def make_client(
    tmp_path: Path, responses: dict, clock: FakeClock, **kwargs
) -> tuple[NvdClient, list]:
    calls = []

    def fetch(url, headers, timeout):
        calls.append((url, headers))
        clock.t += 0.5
        cve = url.rsplit("=", 1)[1]
        response = responses[cve]
        if isinstance(response, int):
            return response, None
        return 200, {"vulnerabilities": [{"cve": response}] if response else []}

    client = NvdClient(
        tmp_path / "nvd", fetch=fetch, sleep=clock.sleep, clock=clock, now=lambda: NOW, **kwargs
    )
    return client, calls


def test_nvd_rate_limits_caches_and_never_leaks_key(tmp_path: Path) -> None:
    clock = FakeClock()
    responses = {
        "CVE-2020-0001": nvd_record(
            "CVE-2020-0001", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8
        ),
        "CVE-2020-0002": None,
    }
    client, calls = make_client(tmp_path, responses, clock)
    result = client.lookup(["CVE-2020-0002", "CVE-2020-0001", "GHSA-not-a-cve"])
    assert [c[0].rsplit("=", 1)[1] for c in calls] == ["CVE-2020-0001", "CVE-2020-0002"]
    assert clock.sleeps == [pytest.approx(5.5)]  # 6 s spacing without a key
    assert result.fetched == 2 and result.records["CVE-2020-0002"] is None
    assert all("apiKey" not in headers for _, headers in calls)

    keyed, keyed_calls = make_client(tmp_path / "k", responses, FakeClock(), api_key="secret")
    keyed.lookup(["CVE-2020-0001"])
    assert keyed_calls[0][1]["apiKey"] == "secret"
    cached_text = "".join(p.read_text() for p in (tmp_path / "k" / "nvd").iterdir())
    assert "secret" not in cached_text

    again, again_calls = make_client(tmp_path, responses, FakeClock())
    second = again.lookup(["CVE-2020-0001", "CVE-2020-0002"])
    assert again_calls == [] and second.from_cache == 2


def test_nvd_cache_expires(tmp_path: Path) -> None:
    clock = FakeClock()
    responses = {
        "CVE-2020-0001": nvd_record(
            "CVE-2020-0001", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8
        )
    }
    client, _ = make_client(tmp_path, responses, clock)
    client.lookup(["CVE-2020-0001"])
    stale = NvdClient(
        tmp_path / "nvd",
        fetch=lambda *a: (200, {"vulnerabilities": []}),
        sleep=lambda s: None,
        now=lambda: NOW + timedelta(days=8),
    )
    assert stale.lookup(["CVE-2020-0001"]).fetched == 1


def test_nvd_budget_and_errors_are_reported(tmp_path: Path) -> None:
    clock = FakeClock()
    responses = {
        f"CVE-2020-000{i}": nvd_record(f"CVE-2020-000{i}", "AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5)
        for i in range(1, 6)
    }
    client, calls = make_client(tmp_path, responses, clock)
    result = client.lookup(list(responses), budget_seconds=12)
    assert result.fetched == 2
    assert result.not_looked_up == ["CVE-2020-0003", "CVE-2020-0004", "CVE-2020-0005"]
    assert any("3 CVE(s) not looked up" in w for w in result.warnings)

    clock = FakeClock()
    down, down_calls = make_client(
        tmp_path / "down", {c: 500 for c in [f"CVE-2021-000{i}" for i in range(1, 8)]}, clock
    )
    outage = down.lookup([f"CVE-2021-000{i}" for i in range(1, 8)])
    assert len(down_calls) == 5
    assert "NVD is not responding; remaining CVEs were skipped" in outage.warnings
    assert len(outage.not_looked_up) == 7

    clock = FakeClock()
    limited = {"CVE-2022-0001": 429}
    retry, retry_calls = make_client(tmp_path / "retry", limited, clock)
    retry.lookup(["CVE-2022-0001"])
    assert len(retry_calls) == 2 and 30 in clock.sleeps


# ---------- enrichment and priority ----------


def finding(**update) -> Finding:
    base = Finding(
        finding_id="finding:1",
        kind="vulnerability",
        title="t",
        subject_id="cmp:lodash",
        subject_label="lodash@4.17.15",
        advisory_ids=["GHSA-aaaa", "CVE-2020-0001"],
        sources=[
            FindingSource(
                name="OSV",
                record_id="GHSA-aaaa",
                cvss_vectors=["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"],
            ),
            FindingSource(name="Grype", record_id="GHSA-aaaa"),
        ],
        fixed_versions=["4.17.21"],
        evidence=[{"path": "package-lock.json", "kind": "lockfile", "locator": "x"}],
        scope="runtime",
        directness="transitive",
    )
    return base.model_copy(update=update)


def grype_with_epss() -> GrypeResult:
    match = grype_match("GHSA-aaaa", LODASH, ["CVE-2020-0001"])
    match["vulnerability"]["cwes"] = [{"cve": "CVE-2020-0001", "cwe": "CWE-1321"}]
    match["relatedVulnerabilities"][0]["epss"] = [
        {"cve": "CVE-2020-0001", "epss": 0.2, "percentile": 0.95, "date": "2026-11-22"}
    ]
    return GrypeResult(tool_version="0.122.1", database_built="d", matches=[match], raw={})


def osv_with_cwe() -> OsvResult:
    record = osv_record("GHSA-aaaa", "lodash", ["CVE-2020-0001"])
    record["database_specific"]["cwe_ids"] = ["CWE-79", "CWE-1321"]
    return OsvResult(
        retrieved_at="r", matches={LODASH: ["GHSA-aaaa"]}, records={"GHSA-aaaa": record}
    )


def test_enrichment_links_cve_cwe_cvss_epss_and_priority() -> None:
    nvd = NvdLookup(
        records={
            "CVE-2020-0001": nvd_record(
                "CVE-2020-0001", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8
            )
        },
        fetched_at={"CVE-2020-0001": "2026-11-24T00:00:00+00:00"},
    )
    [result] = enrich_findings([finding()], nvd, osv_with_cwe(), grype_with_epss())
    assert result.cves[0].model_dump() == {
        "id": "CVE-2020-0001",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-0001",
        "looked_up": True,
        "in_nvd": True,
        "nvd_status": "Analyzed",
        "published": "2020-03-01T00:00:00.000",
        "last_modified": "2024-01-01T00:00:00.000",
        "description": "Description of CVE-2020-0001",
    }
    # NVD's own Primary metric wins over the CNA's Secondary one
    assert result.cvss.source == "NVD (nvd@nist.gov)" and result.cvss.source_type == "Primary"
    assert (result.cvss.base_score, result.cvss.published_score, result.cvss.matches_published) == (
        9.8,
        9.8,
        True,
    )
    assert [(c.id, c.sources) for c in result.cwes] == [
        ("CWE-79", ["NVD", "OSV"]),
        ("CWE-1321", ["Grype", "OSV"]),
    ]
    assert result.cwes[0].url == "https://cwe.mitre.org/data/definitions/79.html"
    assert result.epss.percentile == 0.95
    assert ("nvd.json", "nvd-record", "CVE-2020-0001") in {
        (e.path, e.kind, e.locator) for e in result.evidence
    }
    # 49 (CVSS 9.8) + 19 (EPSS 95th pct) + 14 (transitive runtime) + 10 (fix) = 92
    assert result.priority.score == 92 and result.priority.band == "critical"
    assert [f.points for f in result.priority.factors] == [49.0, 19.0, 14.0, 10.0]


def test_falls_back_to_ghsa_vector_when_nvd_has_no_cvss() -> None:
    nvd = NvdLookup(records={"CVE-2020-0001": None}, fetched_at={"CVE-2020-0001": "x"})
    [result] = enrich_findings([finding()], nvd, None, None)
    assert result.cvss.source == "OSV (GHSA-aaaa)"
    assert result.cvss.base_score == 6.5
    assert result.cves[0].in_nvd is False
    assert any("NVD has no CVSS" in u for u in result.uncertainty)


def test_mismatch_rejected_and_not_looked_up_are_flagged() -> None:
    record = nvd_record(
        "CVE-2020-0001", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.1, vulnStatus="Rejected"
    )
    nvd = NvdLookup(records={"CVE-2020-0001": record}, fetched_at={"CVE-2020-0001": "x"})
    [result] = enrich_findings(
        [finding(advisory_ids=["GHSA-aaaa", "CVE-2020-0001", "CVE-2020-0009"])], nvd, None, None
    )
    assert "Computed CVSS 9.8 differs from NVD's published 9.1" in result.uncertainty
    assert "NVD marks a linked CVE as Rejected" in result.uncertainty
    assert "Some CVEs were not looked up in NVD during this scan" in result.uncertainty


def test_priority_rules_without_cvss_or_epss() -> None:
    dev = finding(
        scope="dev",
        directness="direct",
        fixed_versions=[],
        advisory_ids=["GHSA-x"],
        sources=[FindingSource(name="Grype", record_id="GHSA-x")],
    )
    priority = priority_for(dev, None, None)
    assert [f.points for f in priority.factors] == [25.0, 0, 8.0, 0.0]
    assert priority.score == 33 and priority.band == "low"
    assert priority.factors[0].value == "no CVSS available; assumed 5.0"


def test_workflow_findings_are_not_scored() -> None:
    pin = Finding(
        finding_id="finding:p",
        kind="workflow_pin",
        title="t",
        subject_id=None,
        subject_label="a/b",
        advisory_ids=[],
        sources=[FindingSource(name="workflow-scan", record_id="x")],
        fixed_versions=[],
        evidence=[{"path": "w.yml", "kind": "ci-workflow", "locator": "line 1"}],
    )
    assert enrich_findings([pin], None, None, None) == [pin]


def test_analyzer_writes_nvd_evidence_and_stats(tmp_path: Path) -> None:
    clock = FakeClock()
    client, _ = make_client(
        tmp_path,
        {
            "CVE-1": None,
            "CVE-2020-0001": nvd_record(
                "CVE-2020-0001", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8
            ),
        },
        clock,
    )

    def fake_osv(purls, timeout):
        return OsvResult(
            retrieved_at="r",
            matches={LODASH: ["GHSA-1"]},
            records={"GHSA-1": osv_record("GHSA-1", "lodash", ["CVE-2020-0001"])},
        )

    inventory = Inventory(
        scan_id=SCAN_ID,
        languages=[],
        manifests=[],
        lockfiles=[],
        dockerfiles=[],
        ci_files=[],
        iac_files=[],
        existing_sboms=[],
        source_directories=[],
        file_count=1,
        partial=False,
        warnings=[],
    )
    out = tmp_path / "out"
    out.mkdir()
    result = analyze_risk(
        tmp_path,
        inventory,
        demo_document(),
        SCAN_ID,
        out,
        "demo",
        osv_query=fake_osv,
        grype_enabled=False,
        nvd_client=client,
    )
    assert result.stats.cves_linked == 1 and result.stats.nvd_scored == 2
    nvd_run = next(s for s in result.sources if s.name == "NVD")
    assert nvd_run.status == "ok" and nvd_run.message == "1 fetched, 0 from cache, 0 not looked up"
    saved = json.loads((out / "nvd.json").read_text())
    assert set(saved["records"]) == {"CVE-2020-0001"}
    assert all(f.priority is not None for f in result.findings if f.kind == "vulnerability")


def test_cvss4_only_advisory_uses_grype_published_score() -> None:
    v4 = "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
    match = grype_match("GHSA-v4", LODASH, [])
    match["vulnerability"]["cvss"] = [{"vector": v4, "metrics": {"baseScore": 9.1}}]
    grype = GrypeResult(tool_version="0.122.1", database_built="d", matches=[match], raw={})
    only_v4 = finding(
        advisory_ids=["GHSA-v4"],
        sources=[FindingSource(name="Grype", record_id="GHSA-v4", cvss_vectors=[v4])],
    )
    [result] = enrich_findings([only_v4], None, None, grype)
    assert (result.cvss.version, result.cvss.base_score, result.cvss.computed) == (
        "4.0",
        9.1,
        False,
    )
    assert result.cvss.source == "Grype (GHSA-v4), score from Grype database"
    assert result.priority.factors[0].points == 45.5

    [unscored] = enrich_findings([only_v4], None, None, None)
    assert unscored.cvss is None
    assert "No scorable CVSS from NVD, OSV or Grype; priority assumes 5.0" in unscored.uncertainty
