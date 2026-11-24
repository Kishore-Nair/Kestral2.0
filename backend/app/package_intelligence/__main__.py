import argparse
import sys
from pathlib import Path
from typing import Literal

from pydantic import AwareDatetime, BaseModel, TypeAdapter, ValidationError

from app.provenance.local import OperationError, authorized_root, read_local, validate_json
from app.provenance.local import write_json as atomic_write
from app.provenance.models import ScanId
from app.schemas.dependency import DependencyDocument
from app.schemas.findings import FindingsDocument

from .engine import assess
from .registry import Budget, Registry, canonical_name


class Report(BaseModel):
    schema_version: Literal["1.0"]
    scan_id: ScanId
    started_at: AwareDatetime
    finished_at: AwareDatetime
    registry_source: Literal["live_registry", "injected_fixture", "network_disabled"]
    coverage: dict[str, int]
    request_budget: dict[str, int | float]
    packages: list[dict]
    excluded: list[dict]
    warnings: list[str]


def main() -> int:
    parser = argparse.ArgumentParser(description="Assess bounded npm and PyPI registry evidence")
    parser.add_argument("--scan-id", required=True)
    for name in ("workspace", "normalized", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--findings", type=Path)
    parser.add_argument("--lock-root", type=Path)
    parser.add_argument("--enable-network", action="store_true")
    parser.add_argument("--allow-public", action="append", default=[], metavar="ECOSYSTEM:NAME")
    parser.add_argument("--max-packages", type=int, default=20)
    parser.add_argument("--max-requests", type=int, default=25)
    parser.add_argument("--budget-seconds", type=float, default=30)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--response-bytes", type=int, default=4 * 1024 * 1024)
    args = parser.parse_args()
    try:
        scan_id = TypeAdapter(ScanId).validate_python(args.scan_id)
        root = authorized_root(args.workspace)
        lock_root = authorized_root(args.lock_root) if args.lock_root is not None else None
        output = args.output.resolve()
        inputs = {path.resolve() for path in (args.normalized, args.findings) if path is not None}
        if output in inputs or (lock_root is not None and output.is_relative_to(lock_root)):
            raise OperationError(
                "Output must not overwrite inputs or write inside the lock checkout"
            )
        allowed = set()
        if len(args.allow_public) > 40:
            raise OperationError("Public package allowlist exceeds its limit")
        for entry in args.allow_public:
            ecosystem, _, value = entry.partition(":")
            canonical = canonical_name(ecosystem, value)
            if canonical is None:
                raise OperationError("Invalid public package authorization")
            allowed.add((ecosystem, canonical))
        if args.enable_network and not allowed:
            raise OperationError("Network use requires at least one --allow-public identity")
        document = DependencyDocument.model_validate_json(
            validate_json(read_local(args.normalized, root)), strict=True,
        )
        if document.scan_id != scan_id:
            raise OperationError("Normalized scan ID does not match requested scan ID")
        if args.findings is not None:
            existing = FindingsDocument.model_validate_json(
                validate_json(read_local(args.findings, root)), strict=True,
            )
            if existing.scan_id != scan_id:
                raise OperationError("Findings scan ID does not match requested scan ID")
        budget = Budget(
            args.max_packages, args.max_requests, args.timeout, args.budget_seconds,
            args.response_bytes,
        )
        registry = Registry(allowed, enabled=args.enable_network, budget=budget)
        report = Report.model_validate(assess(document, registry, lock_root=lock_root))
        atomic_write(args.output, report)
    except OperationError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, ValidationError, RecursionError):
        print("Could not validate input, budget, or output", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
