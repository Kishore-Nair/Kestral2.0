import argparse
import sys
from pathlib import Path

from pydantic import TypeAdapter

from app.provenance.local import OperationError, authorized_root, read_local, write_json
from app.provenance.models import ScanId

from .evaluator import build_input, evaluate


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate Kestral release policy through OPA")
    parser.add_argument("--scan-id", required=True)
    for flag in ("workspace", "findings", "provenance", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--strict-release", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    args = parser.parse_args()
    try:
        scan_id = TypeAdapter(ScanId).validate_python(args.scan_id)
        root = authorized_root(args.workspace)
        if args.output.resolve() in {args.findings.resolve(), args.provenance.resolve()}:
            raise OperationError("Output must not overwrite evidence inputs")
        policy_input = build_input(
            scan_id, read_local(args.findings, root), read_local(args.provenance, root),
            args.strict_release,
        )
        result = evaluate(scan_id, root, policy_input)
        write_json(args.output, result)
        if result.evaluation_status == "error":
            return 1
        if args.enforce and result.decision != "ALLOW":
            return 2
        return 0
    except OperationError as error:
        print(str(error), file=sys.stderr)
    except (OSError, ValueError, RecursionError):
        print("Could not read, validate or write local policy evidence", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
