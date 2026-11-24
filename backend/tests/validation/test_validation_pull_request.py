# ruff: noqa: F811 - pytest fixtures imported from the flow tests are re-declared as parameters
"""Pull requests for validated fixes, against a fake GitHub (no network)."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import SecretStr

from app.api.routes import validation as validation_routes
from app.config import settings
from app.database.models import ValidationRunRow
from app.schemas.validation import ValidationResult
from app.validation import github, service
from tests.ai.ai_helpers import COMMIT
from tests.risk.risk_helpers import SCAN_ID
from tests.validation.test_validation_flow import (  # noqa: F401 - pytest fixtures
    CHANGE,
    FINDING,
    client,
    fake_checkout,
    fake_pipeline,
    make_scan,
    roots,
)

VID = "val_" + "b" * 32


class FakeGitHub:
    def __init__(self, fail: dict | None = None, push: bool = True):
        self.calls: list[tuple[str, str, dict | None]] = []
        self.fail = fail or {}
        self.push = push

    def __call__(self, method, path, body):
        self.calls.append((method, path, body))
        for suffix, reply in self.fail.items():
            if path.endswith(suffix):
                return reply
        if path == "/repos/example/demo":
            return 200, {"default_branch": "main", "permissions": {"push": self.push}}
        if "/git/commits/" in path:
            return 200, {"sha": COMMIT, "tree": {"sha": "tree0"}}
        if path.endswith("/git/blobs"):
            return 201, {"sha": f"blob{len(self.calls)}"}
        if path.endswith("/git/trees"):
            return 201, {"sha": "tree1"}
        if path.endswith("/git/commits"):
            return 201, {"sha": "commit1"}
        if path.endswith("/git/refs"):
            return 201, {"ref": body["ref"]}
        if path.endswith("/pulls"):
            return 201, {"html_url": "https://github.com/example/demo/pull/7", "number": 7}
        return 404, {"message": "Not Found"}


def fixed_result(roots: Path) -> ValidationResult:
    return service.execute(
        settings,
        make_scan(),
        CHANGE,
        VID,
        False,
        checkout=fake_checkout,
        pipeline=fake_pipeline(),
        runtime_probe=lambda _p: None,
        lock_regenerator=lambda p, t: "npm install --package-lock-only",
    )


def test_validation_saves_the_exact_patched_files(roots: Path) -> None:
    result = fixed_result(roots)
    assert result.verdict == "FIXED"
    row = ValidationRunRow(validation_id=VID, scan_id=SCAN_ID)
    files = service.patch_files(settings, row)
    assert set(files) == {"package.json"}
    assert '"qs": "6.2.4"' in files["package.json"]


def test_open_pull_request_builds_one_commit_on_a_new_branch(roots: Path) -> None:
    result = fixed_result(roots)
    fake = FakeGitHub()
    pull = github.open_pull_request(
        fake,
        owner="example",
        repo="demo",
        base_commit=COMMIT,
        base_branch="main",
        files={"package.json": "{}\n", "package-lock.json": "{}\n"},
        change=CHANGE,
        result=result,
        finding_title="GHSA-test: qs prototype pollution",
        scan_id=SCAN_ID,
        validation_id=VID,
    )
    assert pull.url.endswith("/pull/7") and pull.base == "main"
    assert pull.branch == "kestral/fix-qs-6.2.4-bbbbbb"
    methods = [(m, p.split("/repos/example/demo")[1]) for m, p, _ in fake.calls]
    assert methods == [
        ("GET", ""),
        ("GET", f"/git/commits/{COMMIT}"),
        ("POST", "/git/blobs"),
        ("POST", "/git/blobs"),
        ("POST", "/git/trees"),
        ("POST", "/git/commits"),
        ("POST", "/git/refs"),
        ("POST", "/pulls"),
    ]
    commit_body = fake.calls[5][2]
    assert commit_body["parents"] == [COMMIT]  # branch starts at the exact scanned commit
    assert commit_body["message"].startswith("fix(deps): upgrade qs 6.0.0 -> 6.2.4")
    pr = fake.calls[7][2]
    assert pr["head"] == pull.branch and pr["base"] == "main"
    assert "Kestral \ndoes not merge it" in pr["body"] or "does not merge it" in pr["body"]
    assert "### Rollback" in pr["body"] and "Approved by:** reviewer" in pr["body"]
    assert not any(p.endswith("/merge") for _, p, _ in fake.calls)  # never merges


@pytest.mark.parametrize(
    ("fail", "push", "message"),
    [
        ({"/repos/example/demo": (401, {})}, True, "rejected the token"),
        ({"/repos/example/demo": (404, {})}, True, "cannot be read"),
        ({}, False, "no write access"),
        (
            {
                "/pulls": (
                    422,
                    {
                        "message": "Validation Failed",
                        "errors": [{"message": "A pull request already exists"}],
                    },
                )
            },
            True,
            "already exists",
        ),
    ],
)
def test_github_errors_are_clear(roots: Path, fail, push, message) -> None:
    result = fixed_result(roots)
    with pytest.raises(github.GitHubError, match=message):
        github.open_pull_request(
            FakeGitHub(fail, push),
            owner="example",
            repo="demo",
            base_commit=COMMIT,
            base_branch=None,
            files={"package.json": "{}"},
            change=CHANGE,
            result=result,
            finding_title="t",
            scan_id=SCAN_ID,
            validation_id=VID,
        )


def test_pull_request_route(client, roots: Path, monkeypatch) -> None:  # noqa: F811
    result = fixed_result(roots)
    url = f"/api/v1/scans/{SCAN_ID}/validations/{VID}/pull-request"
    with client.sessions() as db:
        db.add(
            ValidationRunRow(
                validation_id=VID,
                scan_id=SCAN_ID,
                source_type="remediation",
                source_id="rem_x",
                finding_id=FINDING,
                status="completed",
                verdict=result.verdict,
                run_tests=False,
                change_json=CHANGE.model_dump(mode="json"),
                result_json=result.model_dump(mode="json"),
                finished_at=datetime.now(UTC),
            )
        )
        db.commit()

    monkeypatch.setattr(settings, "github_token", None)
    assert client.post(url).json()["error"]["code"] == "GITHUB_NOT_CONFIGURED"

    monkeypatch.setattr(settings, "github_token", SecretStr("ghp_test_not_real"))
    fake = FakeGitHub()
    monkeypatch.setattr(validation_routes.github, "make_request", lambda token, api: fake)
    opened = client.post(url)
    assert opened.status_code == 200
    body = opened.json()
    assert body["pull_request"]["number"] == 7 and body["patch_available"] is True
    calls = len(fake.calls)
    again = client.post(url).json()  # idempotent: returns the recorded PR, no new GitHub calls
    assert again["pull_request"]["url"] == body["pull_request"]["url"] and len(fake.calls) == calls
    assert "ghp_test_not_real" not in opened.text

    failing = FakeGitHub({"/repos/example/demo": (401, {})})
    monkeypatch.setattr(validation_routes.github, "make_request", lambda token, api: failing)
    with client.sessions() as db:
        row = db.get(ValidationRunRow, VID)
        row.pull_request_json = None
        db.commit()
    error = client.post(url)
    assert error.status_code == 502 and error.json()["error"]["code"] == "GITHUB_ERROR"


def test_only_fixed_validations_can_open_a_pr(client, roots: Path, monkeypatch) -> None:  # noqa: F811
    monkeypatch.setattr(settings, "github_token", SecretStr("ghp_x"))
    result = fixed_result(roots).model_copy(update={"verdict": "NOT_FIXED"})
    with client.sessions() as db:
        db.add(
            ValidationRunRow(
                validation_id=VID,
                scan_id=SCAN_ID,
                source_type="remediation",
                source_id="rem_x",
                finding_id=FINDING,
                status="completed",
                verdict="NOT_FIXED",
                run_tests=False,
                change_json=CHANGE.model_dump(mode="json"),
                result_json=result.model_dump(mode="json"),
            )
        )
        db.commit()
    response = client.post(f"/api/v1/scans/{SCAN_ID}/validations/{VID}/pull-request")
    assert response.status_code == 409 and response.json()["error"]["code"] == "NOT_PR_READY"
