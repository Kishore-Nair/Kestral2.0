"""Privacy impact: CVE-LINDDUN lookups and the ENISA severity formula (no network)."""

from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.database.base import Base
from app.database.session import get_db
from app.main import app
from app.privacy import enisa, linddun
from app.privacy.service import assess, assess_finding
from app.schemas.findings import CvssScore, CweRef, EpssScore, Finding, FindingSource
from app.schemas.inventory import Evidence
from tests.ai.ai_helpers import findings_document, write_scan
from tests.risk.risk_helpers import SCAN_ID
from tests.validation.test_validation_flow import make_scan


def finding(
    cwes: list[str],
    vector: str | None = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    epss: float | None = None,
    fid: str = "finding:x",
) -> Finding:
    return Finding(
        finding_id=fid,
        kind="vulnerability",
        title="t",
        subject_id="cmp:x",
        subject_label="x@1.0.0",
        advisory_ids=["GHSA-xxxx"],
        sources=[FindingSource(name="OSV", record_id="GHSA-xxxx")],
        fixed_versions=[],
        evidence=[Evidence(path="package-lock.json", kind="lockfile", locator="x")],
        cwes=[CweRef(id=c, url=None, sources=["OSV"]) for c in cwes],
        cvss=CvssScore(
            version="3.1",
            vector=vector,
            base_score=7.5,
            severity="HIGH",
            source="nvd",
            computed=True,
        )
        if vector
        else None,
        epss=EpssScore(cve_id="CVE-1", probability=0.5, percentile=epss, source="grype")
        if epss is not None
        else None,
    )


def test_table_restates_the_dataset() -> None:
    info = linddun.dataset_info()
    assert info.dataset_rows == 280_694 and info.cwes_mapped >= 283
    log = linddun.lookup("CWE-532")  # anchor: sensitive info in log file
    assert log.status == "mapped" and "Data Disclosure" in log.linddun
    assert linddun.lookup("cwe-200").status == "mapped"  # case-insensitive
    assert linddun.lookup("CWE-400").status == "cwe_excluded"
    assert linddun.lookup("CWE-1321").status == "cwe_has_no_category"
    assert linddun.lookup("NVD-CWE-Other").status == "no_cwe"
    assert linddun.lookup("CWE-999999").status == "cwe_not_in_dataset"


def test_classify_unions_mapped_cwes_and_keeps_unmapped_reasons() -> None:
    status, classes, mappings = linddun.classify(finding(["CWE-400", "CWE-200"]))
    assert status == "mapped" and "Identifiability" in classes and len(mappings) == 2
    assert classes == [c for c in linddun.LINDDUN_CLASSES if c in classes]
    assert linddun.classify(finding(["CWE-400"]))[0] == "cwe_excluded"
    assert linddun.classify(finding(["CWE-400", "CWE-1321"]))[0] == "cwe_has_no_category"
    assert linddun.classify(finding([]))[0] == "no_cwe"


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H", ("H", "L", "H", "N", "N", "N")),
        ("AV:N/AC:L/Au:S/C:P/I:N/A:C", ("L", "N", "H", "N", "L", None)),
        (
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:A/VC:N/VI:L/VA:N/SC:H/SI:N/SA:N",
            ("H", "L", "N", "L", "H", "R"),
        ),
    ],
)
def test_parse_vector_reads_cia_and_exploitability(vector: str, expected: tuple) -> None:
    s = enisa.parse_vector(vector)
    assert s is not None
    got = (
        s.confidentiality,
        s.integrity,
        s.availability,
        s.attack_vector,
        s.privileges,
        s.user_interaction,
    )
    assert got == expected


def test_enisa_formula_and_every_term_is_explained() -> None:
    # CWE-200 maps to Identifiability -> EI 1.0; C:H 0.5; remote unauthenticated -> +0.5.
    impact = assess_finding(finding(["CWE-200"]), "sensitive")
    assert impact.ei == 1.0 and impact.cb == 1.0 and impact.dpc == 4
    assert impact.score == 5.0 and impact.band == "very_high"
    names = [f.name for f in impact.factors]
    assert names[:2] == ["DPC", "EI"] and "CB malicious intent" in names
    simple = assess_finding(finding(["CWE-200"]), "simple")
    assert simple.score == 2.0 and simple.band == "medium"


def test_malicious_intent_from_epss_or_exposure_only() -> None:
    local = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
    quiet = assess_finding(finding(["CWE-200"], local), "simple")
    assert quiet.cb == 0.25 and quiet.score == 1.25 and quiet.band == "low"
    hot = assess_finding(finding(["CWE-200"], local, epss=0.95), "simple")
    assert hot.cb == 0.75
    assert "EPSS" in next(f.basis for f in hot.factors if f.name == "CB malicious intent")


def test_no_cvss_is_estimated_and_flagged() -> None:
    impact = assess_finding(finding(["CWE-200"], vector=None), "simple")
    assert impact.cb == 0.25 and impact.uncertainty
    assert enisa.band_for(1.99) == "low" and enisa.band_for(4) == "very_high"


def test_unmapped_findings_get_no_score() -> None:
    impact = assess_finding(finding(["CWE-1321"]), "sensitive")
    assert impact.status == "cwe_has_no_category" and impact.score is None and not impact.factors


def test_assess_summarises_and_sorts() -> None:
    doc = findings_document()
    doc.findings = [
        finding(["CWE-200"], fid="finding:a"),
        finding(["CWE-1321"], fid="finding:b"),
        finding(["CWE-532"], "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", fid="finding:c"),
        *[f for f in doc.findings if f.kind != "vulnerability"],
    ]
    result = assess(doc, "financial")
    s = result.summary
    assert (s.assessed, s.mapped, s.unmapped) == (3, 2, 1)
    assert s.unmapped_reasons == {"cwe_has_no_category": 1}
    assert [i.finding_id for i in result.impacts] == ["finding:a", "finding:c", "finding:b"]
    assert s.max_score == result.impacts[0].score and s.max_band == result.impacts[0].band
    assert sum(s.by_band.values()) == 2 and result.caveats


# ---------------------------------------------------------------------------
# API


@pytest.fixture
def client(tmp_path: Path, monkeypatch) -> Generator[TestClient, None, None]:
    monkeypatch.setattr(settings, "scan_output_root", tmp_path / "scans")
    write_scan(tmp_path / "scans" / SCAN_ID)
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    with sessions() as db:
        db.add(make_scan())
        db.commit()

    def override() -> Generator[Session, None, None]:
        with sessions() as s:
            yield s

    app.dependency_overrides[get_db] = override
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_privacy_endpoint(client: TestClient) -> None:
    body = client.get(f"/api/v1/scans/{SCAN_ID}/privacy").json()
    assert body["data_context"] == settings.privacy_data_context
    assert body["summary"]["assessed"] == 1 and len(body["data_contexts"]) == 4
    assert body["dataset"]["dataset_file"] == "cve_linddun.parquet"
    sensitive = client.get(f"/api/v1/scans/{SCAN_ID}/privacy?data_context=sensitive").json()
    assert sensitive["dpc"] == 4
    bad = client.get(f"/api/v1/scans/{SCAN_ID}/privacy?data_context=medical")
    assert bad.status_code in (400, 422)
    assert client.get("/api/v1/scans/scan_" + "0" * 32 + "/privacy").status_code == 404
