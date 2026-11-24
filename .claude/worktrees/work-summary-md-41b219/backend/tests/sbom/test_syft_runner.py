import json
import shutil
import subprocess
from pathlib import Path

import pytest

from app.sbom import syft_runner
from app.sbom.syft_runner import (
    SBOM_FILENAME,
    SyftExecutionError,
    SyftNotFoundError,
    SyftOutputError,
    SyftTimeoutError,
    run_syft,
)

VALID_SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}


@pytest.fixture
def dirs(tmp_path):
    repo = tmp_path / "workspace" / "repo"
    repo.mkdir(parents=True)
    scan = tmp_path / "scans" / "scan_1"
    return repo, scan


@pytest.fixture
def fake_syft(monkeypatch):
    """Pretend syft is installed; record the subprocess call."""
    monkeypatch.setattr(syft_runner.shutil, "which", lambda name: "/usr/bin/syft")
    calls = {}

    def install(payload=VALID_SBOM, returncode=0, raw=None, exc=None):
        def fake_run(command, **kwargs):
            calls["command"] = command
            calls["kwargs"] = kwargs
            if exc is not None:
                raise exc
            out = Path(command[-1].split("=", 1)[1])
            if returncode == 0:
                out.write_text(raw if raw is not None else json.dumps(payload), encoding="utf-8")
            return subprocess.CompletedProcess(command, returncode, "", "secret /Users/x path")

        monkeypatch.setattr(syft_runner.subprocess, "run", fake_run)
        return calls

    return install


def test_success_writes_sbom_atomically(dirs, fake_syft):
    repo, scan = dirs
    calls = fake_syft()
    data = run_syft(repo, scan)
    assert data["bomFormat"] == "CycloneDX"
    assert (scan / SBOM_FILENAME).is_file()
    assert not (scan / (SBOM_FILENAME + ".tmp")).exists()
    assert calls["command"][1] == f"dir:{repo.resolve()}"


def test_subprocess_is_called_safely(dirs, fake_syft, monkeypatch):
    repo, scan = dirs
    monkeypatch.setenv("GITHUB_TOKEN", "super-secret")
    calls = fake_syft()
    run_syft(repo, scan, timeout=42)
    kwargs = calls["kwargs"]
    assert isinstance(calls["command"], list)
    assert kwargs["shell"] is False
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["timeout"] == 42
    assert "GITHUB_TOKEN" not in kwargs["env"]
    assert kwargs["env"]["HOME"] == str(scan.resolve())


def test_nonzero_exit_raises_without_leaking_stderr(dirs, fake_syft):
    repo, scan = dirs
    fake_syft(returncode=2)
    with pytest.raises(SyftExecutionError) as info:
        run_syft(repo, scan)
    assert "secret" not in str(info.value)
    assert not (scan / SBOM_FILENAME).exists()


def test_timeout_raises(dirs, fake_syft):
    repo, scan = dirs
    fake_syft(exc=subprocess.TimeoutExpired(cmd="syft", timeout=1))
    with pytest.raises(SyftTimeoutError):
        run_syft(repo, scan, timeout=1)
    assert not (scan / SBOM_FILENAME).exists()


def test_missing_syft(dirs, monkeypatch):
    repo, scan = dirs
    monkeypatch.setattr(syft_runner.shutil, "which", lambda name: None)
    with pytest.raises(SyftNotFoundError):
        run_syft(repo, scan)


def test_wrong_format_rejected_and_no_output_kept(dirs, fake_syft):
    repo, scan = dirs
    fake_syft(payload={"bomFormat": "SPDX"})
    with pytest.raises(SyftOutputError):
        run_syft(repo, scan)
    assert not (scan / SBOM_FILENAME).exists()
    assert not (scan / (SBOM_FILENAME + ".tmp")).exists()


def test_invalid_json_rejected(dirs, fake_syft):
    repo, scan = dirs
    fake_syft(raw="{broken")
    with pytest.raises(SyftOutputError):
        run_syft(repo, scan)


def test_oversized_output_rejected(dirs, fake_syft, monkeypatch):
    repo, scan = dirs
    monkeypatch.setattr(syft_runner, "MAX_SBOM_BYTES", 10)
    fake_syft()
    with pytest.raises(SyftOutputError):
        run_syft(repo, scan)


def test_scan_dir_inside_repo_rejected(tmp_path, fake_syft):
    repo = tmp_path / "repo"
    repo.mkdir()
    fake_syft()
    with pytest.raises(ValueError):
        run_syft(repo, repo / "out")


def test_missing_repo_rejected(tmp_path, fake_syft):
    fake_syft()
    with pytest.raises(ValueError):
        run_syft(tmp_path / "does-not-exist", tmp_path / "scan")


@pytest.mark.skipif(shutil.which("syft") is None, reason="syft not installed")
def test_real_syft_on_tiny_npm_fixture(tmp_path):
    """One real Syft scan on a small, locally authored, benign fixture."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"name": "demo-app", "version": "1.0.0", "dependencies": {"alpha": "1.0.0"}}),
        encoding="utf-8",
    )
    (repo / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "demo-app",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "requires": True,
                "packages": {
                    "": {
                        "name": "demo-app",
                        "version": "1.0.0",
                        "dependencies": {"alpha": "1.0.0"},
                    },
                    "node_modules/alpha": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz",
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    data = run_syft(repo, tmp_path / "scan", timeout=120)
    names = {c.get("name") for c in data.get("components", [])}
    assert "alpha" in names
