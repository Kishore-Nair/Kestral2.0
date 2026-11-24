import argparse
import sys
from pathlib import Path

from pydantic import TypeAdapter, ValidationError

from .local import OperationError, authorized_root, write_json
from .models import ScanId
from .verifier import verify_blob


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a local blob using trusted Cosign evidence")
    parser.add_argument("--scan-id", required=True)
    for flag in ("workspace", "artifact", "output"):
        parser.add_argument("--" + flag, required=True, type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--trusted-root", type=Path)
    parser.add_argument("--certificate-identity")
    parser.add_argument("--certificate-oidc-issuer")
    args = parser.parse_args()
    try:
        scan_id = TypeAdapter(ScanId).validate_python(args.scan_id)
        root = authorized_root(args.workspace)
        evidence = (args.artifact, args.bundle, args.key, args.trusted_root)
        inputs = {path.resolve() for path in evidence if path is not None}
        if args.output.resolve() in inputs:
            raise OperationError("Output must not overwrite evidence inputs")
        result = verify_blob(
            scan_id, root, args.artifact, args.bundle, args.key, args.trusted_root,
            certificate_identity=args.certificate_identity,
            certificate_issuer=args.certificate_oidc_issuer,
        )
        if args.output.parent.resolve().is_relative_to(root):
            raise OperationError("Output must be outside the authorized input directory")
        write_json(args.output, result)
        return {"verified": 0, "error": 1}.get(result.artifacts[0].signature_status, 2)
    except OperationError as error:
        print(str(error), file=sys.stderr)
    except (OSError, ValueError, ValidationError):
        print("Could not read, validate or write local provenance evidence", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
