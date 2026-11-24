"""Mocked Cosign outcomes. The local CLI demo separately exercises the real binary."""

import os
import sys
from pathlib import Path

import pytest

from app.provenance import verifier
from app.provenance.local import OperationError, read_local, run_tool


@pytest.fixture
def fixture_paths(tmp_path):
    root = tmp_path / "scan"
    root.mkdir()
    artifact, bundle = root / "blob", root / "bundle"
    key, trusted_root = tmp_path / "cosign.pub", tmp_path / "trusted-root.json"
    for path in (artifact, bundle, key, trusted_root):
        path.write_bytes(path.name.encode())
    return root, artifact, bundle, key, trusted_root


@pytest.mark.parametrize(
    ("tool_result", "expected"),
    [
        ((0, b"Verified OK\r\n"), "verified"),
        ((1, b"signature verification failed: invalid signature"), "failed"),
        ((1, b"not enough verified log entries from transparency log"), "error"),
        ((0, b""), "error"),
    ],
)
def test_mocked_cosign_outcomes(monkeypatch, fixture_paths, tool_result, expected):
    monkeypatch.setattr(verifier, "tool_path", lambda *_: Path("/mock/cosign"))
    calls = []

    def mock_run(_executable, argv, stage):
        calls.append(argv)
        assert (stage / "blob").read_bytes() == b"blob"
        assert (stage / "trusted.pub").read_bytes() == b"cosign.pub"
        return (0, b"GitVersion: v3.1.4\r\n") if argv == ["version"] else tool_result

    monkeypatch.setattr(verifier, "run_tool", mock_run)
    result = verifier.verify_blob("demo", *fixture_paths)
    [artifact] = result.artifacts
    assert artifact.signature_status == expected
    assert artifact.provenance_status == "not_assessed"
    assert artifact.identity_verified is (True if expected == "verified" else None)
    assert calls[1] == [
        "verify-blob", "--trusted-root", "trusted-root.json", "--key", "trusted.pub",
        "--bundle", "bundle.json", "blob",
    ]


@pytest.mark.parametrize("message", ["Tool execution timed out", "cosign executable unavailable"])
def test_mocked_tool_error(monkeypatch, fixture_paths, message):
    def fail(*_):
        raise OperationError(message)

    if message.startswith("Tool"):
        monkeypatch.setattr(verifier, "tool_path", lambda *_: Path("/mock/cosign"))
        monkeypatch.setattr(verifier, "run_tool", fail)
    else:
        monkeypatch.setattr(verifier, "tool_path", fail)
    result = verifier.verify_blob("demo", *fixture_paths)
    assert result.assessment_status == "error"
    assert result.warnings == [message]


def test_missing_bundle_is_not_assessed(fixture_paths):
    root, artifact, _, _, _ = fixture_paths
    result = verifier.verify_blob("demo", root, artifact, None, None, None)
    assert result.assessment_status == "not_assessed"
    assert result.artifacts[0].identity_verified is None


def test_trust_inside_scan_is_rejected(fixture_paths):
    root, artifact, bundle, _, trusted_root = fixture_paths
    with pytest.raises(OperationError, match="Trust inputs"):
        verifier.verify_blob("demo", root, artifact, bundle, artifact, trusted_root)


def test_reject_outside_or_oversized_input(fixture_paths):
    root, artifact, _, key, _ = fixture_paths
    with pytest.raises(OperationError, match="authorized directory"):
        read_local(key, root)
    with pytest.raises(OperationError, match="size limit"):
        read_local(artifact, root, 1)


def test_runner_caps_real_child_output(tmp_path):
    with pytest.raises(OperationError, match="capture limits"):
        run_tool(Path(sys.executable), ["-c", "print('x' * 3000000)"], tmp_path)


def test_lookup_rejects_scanned_executable(monkeypatch, tmp_path):
    name = "cosign.exe" if os.name == "nt" else "cosign"
    candidate = tmp_path / name
    candidate.touch(mode=0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(OperationError, match="unavailable"):
        verifier.tool_path("cosign", tmp_path)


def test_pinned_signer_passes_exact_argv(monkeypatch, fixture_paths):
    root, artifact, bundle, _, trusted_root = fixture_paths
    monkeypatch.setattr(verifier, "tool_path", lambda *_: Path("/mock/cosign"))

    def mock_run(_executable, argv, stage):
        if argv == ["version"]:
            return 0, b"GitVersion: v3.1.4"
        assert not (stage / "trusted.pub").exists()
        assert argv == [
            "verify-blob", "--trusted-root", "trusted-root.json",
            "--certificate-identity=signer@example.org",
            "--certificate-oidc-issuer=https://issuer.example.org",
            "--bundle", "bundle.json", "blob",
        ]
        return 0, b"Verified OK"

    monkeypatch.setattr(verifier, "run_tool", mock_run)
    [result] = verifier.verify_blob(
        "demo", root, artifact, bundle, None, trusted_root,
        certificate_identity="signer@example.org", certificate_issuer="https://issuer.example.org",
    ).artifacts
    assert result.trust_method == "pinned_certificate_identity"
    assert result.signature_status == "verified"
    assert result.provenance_status == "not_assessed"


def test_pinned_signer_requires_both_values(fixture_paths):
    root, artifact, bundle, _, trusted_root = fixture_paths
    with pytest.raises(OperationError, match="both exact identity and issuer"):
        verifier.verify_blob(
            "demo", root, artifact, bundle, None, trusted_root,
            certificate_identity="signer@example.org",
        )
