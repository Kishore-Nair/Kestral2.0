import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from .local import OperationError, digest, read_local, run_tool, tool_path
from .models import Artifact, Provenance

NEGATIVE = (
    b"invalid signature when validating ASN.1 encoded signature",
    b"signature verification failed: crypto/rsa: verification error",
    b"message digest in bundle does not match",
    b"signature verification failed: invalid signature",
)


def verify_blob(
    scan_id: str, root: Path, artifact: Path, bundle: Path | None,
    key: Path | None, trusted_root: Path | None,
    *, certificate_identity: str | None = None, certificate_issuer: str | None = None,
) -> Provenance:
    if (certificate_identity is None) != (certificate_issuer is None):
        raise OperationError("Certificate verification requires both exact identity and issuer")
    if key is not None and certificate_identity is not None:
        raise OperationError("Select one signer trust method")
    if certificate_identity is not None and not (certificate_identity and certificate_issuer):
        raise OperationError("Certificate identity and issuer must be nonempty")
    blob = read_local(artifact, root)
    artifact_digest = digest(blob)
    evidence = [artifact_digest]
    version = None
    identity = None
    trust = None
    status = "not_assessed"
    assessment = "not_assessed"
    reason = "No signature bundle supplied"
    if bundle is not None:
        if trusted_root is None or (key is None and certificate_identity is None):
            raise OperationError("A bundle requires signer trust and a Sigstore trusted root")
        trust_path = trusted_root.resolve(strict=True)
        key_path = key.resolve(strict=True) if key is not None else None
        if trust_path.is_relative_to(root) or (key_path and key_path.is_relative_to(root)):
            raise OperationError("Trust inputs must be outside the scan directory")
        trust_data = read_local(trust_path, trust_path.parent, 1024 * 1024)
        bundle_data = read_local(bundle, root, 1024 * 1024)
        evidence.extend([digest(bundle_data), digest(trust_data)])
        if key_path is not None:
            public_key = read_local(key_path, key_path.parent, 65536)
            evidence.append(digest(public_key))
            signer_args = ["--key", "trusted.pub"]
            trust = "configured_public_key"
        else:
            assert certificate_identity is not None and certificate_issuer is not None
            public_key = None
            signer_args = [
                "--certificate-identity=" + certificate_identity,
                "--certificate-oidc-issuer=" + certificate_issuer,
            ]
            trust = "pinned_certificate_identity"
        try:
            cosign = tool_path("cosign", root)
            with tempfile.TemporaryDirectory(prefix="kestral-cosign-") as directory:
                stage = Path(directory)
                (stage / "blob").write_bytes(blob)
                (stage / "bundle.json").write_bytes(bundle_data)
                if public_key is not None:
                    (stage / "trusted.pub").write_bytes(public_key)
                (stage / "trusted-root.json").write_bytes(trust_data)
                code, output = run_tool(cosign, ["version"], stage)
                match = re.search(rb"(?m)^GitVersion:\s+(v3\.[0-9]+\.[0-9]+)[ \t\r]*$", output)
                if code or not match:
                    raise OperationError("Expected a stable Cosign v3 release")
                version = match[1].decode("ascii")
                if tuple(map(int, version[1:].split("."))) < (3, 1, 3):
                    raise OperationError("Cosign v3.1.3 or later is required")
                code, output = run_tool(
                    cosign,
                    ["verify-blob", "--trusted-root", "trusted-root.json", *signer_args,
                     "--bundle", "bundle.json", "blob"],
                    stage,
                )
                if code == 0 and b"Verified OK" in output.splitlines():
                    status, identity, assessment = "verified", True, "partial"
                    reason = "Blob signature verified under the configured signer trust"
                elif code == 1 and any(marker in output for marker in NEGATIVE):
                    status, assessment = "failed", "complete"
                    reason = "Cosign reported a cryptographic mismatch"
                elif (
                    code == 1
                    and b"not enough verified log entries from transparency log" in output
                ):
                    raise OperationError(
                        "Bundle lacks the required verified transparency-log proof"
                    )
                else:
                    raise OperationError("Cosign did not return a recognized verification outcome")
        except OperationError as error:
            status, assessment, reason = "error", "error", str(error)
        except OSError:
            status, assessment, reason = "error", "error", "Cosign could not execute locally"
    return Provenance(
        schema_version="1.0", scan_id=scan_id, timestamp=datetime.now(UTC),
        assessment_status=assessment, tool_version=version,
        warnings=[] if status == "failed" else [reason] if status != "verified" else [
            "Build provenance requires separately verified attestation evidence"
        ],
        artifacts=[Artifact(
            artifact_type="blob", reference=artifact.resolve().relative_to(root).as_posix(),
            digest=artifact_digest, signature_status=status,
            attestation_status="not_available", provenance_status="not_assessed",
            identity_verified=identity, trust_method=trust, evidence=evidence, reason=reason,
        )],
    )
