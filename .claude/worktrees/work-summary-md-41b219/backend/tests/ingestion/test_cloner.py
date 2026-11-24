import subprocess
from pathlib import Path

import pytest

from app.ingestion.cloner import clone_public_repo, inspect_checkout
from app.ingestion.url_validation import ValidatedRepository


def test_clone_uses_hardened_noninteractive_arguments(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["arguments"] = arguments
        captured.update(kwargs)
        Path(arguments[-1]).mkdir()
        return subprocess.CompletedProcess(arguments, 0, "", "")

    monkeypatch.setattr("app.ingestion.cloner.shutil.which", lambda *_args, **_kwargs: "git")
    monkeypatch.setattr("app.ingestion.cloner.subprocess.run", fake_run)
    repository = ValidatedRepository(
        owner="example",
        name="repository",
        canonical_url="https://github.com/example/repository",
        requested_ref="main",
    )

    checkout = clone_public_repo(repository, tmp_path, timeout=30)
    arguments = captured["arguments"]

    assert checkout == tmp_path / "repo"
    assert isinstance(arguments, list)
    assert "--no-recurse-submodules" in arguments
    assert "http.followRedirects=false" in arguments
    assert arguments[-3:] == ["--", repository.canonical_url, str(checkout)]
    assert captured["shell"] is False
    assert captured["timeout"] == 30
    environment = captured["env"]
    assert isinstance(environment, dict)
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert "GITHUB_TOKEN" not in environment
    assert "SSH_AUTH_SOCK" not in environment


def test_checkout_metadata_records_sha_and_branch(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def fake_run(arguments: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if "rev-parse" in arguments:
            return subprocess.CompletedProcess(arguments, 0, "a" * 40 + "\n", "")
        return subprocess.CompletedProcess(arguments, 0, "main\n", "")

    monkeypatch.setattr("app.ingestion.cloner.shutil.which", lambda *_args, **_kwargs: "git")
    monkeypatch.setattr("app.ingestion.cloner.subprocess.run", fake_run)
    metadata = inspect_checkout(repo, requested_ref=None, timeout=10)
    assert metadata.commit_sha == "a" * 40
    assert metadata.resolved_ref == "main"


def test_checkout_metadata_rejects_unsupported_object_format(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr("app.ingestion.cloner.shutil.which", lambda *_args, **_kwargs: "git")
    monkeypatch.setattr(
        "app.ingestion.cloner.subprocess.run",
        lambda arguments, **_kwargs: subprocess.CompletedProcess(arguments, 0, "b" * 64, ""),
    )
    with pytest.raises(RuntimeError, match="object format"):
        inspect_checkout(repo, requested_ref=None, timeout=10)

