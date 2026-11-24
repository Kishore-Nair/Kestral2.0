"""Atomic serialization helpers for validated scan artifacts."""

import json
import os
import uuid
from pathlib import Path

from pydantic import BaseModel


def save_validated_json(
    path: Path,
    value: BaseModel,
    *,
    max_bytes: int | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(value.model_dump(mode="json"), handle, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if max_bytes is not None and temporary.stat().st_size > max_bytes:
            raise ValueError("Artifact exceeds the configured output size limit")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_validated_json[ModelT: BaseModel](
    path: Path,
    model_type: type[ModelT],
    *,
    max_bytes: int | None = None,
) -> ModelT:
    if max_bytes is not None and path.stat().st_size > max_bytes:
        raise ValueError("Artifact exceeds the configured output size limit")
    with path.open(encoding="utf-8") as handle:
        return model_type.model_validate(json.load(handle))


def resolve_artifact_path(scan_output_root: Path, stored_path: str) -> Path:
    root = scan_output_root.resolve()
    candidate = (root / Path(stored_path)).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("Stored artifact path escaped the scan output root") from exc
    if candidate == root:
        raise ValueError("Stored artifact path did not identify a file")
    return candidate


def validate_cyclonedx_artifact(path: Path, *, max_bytes: int | None = None) -> None:
    if max_bytes is not None and path.stat().st_size > max_bytes:
        raise ValueError("CycloneDX artifact exceeds the configured output size limit")
    with path.open(encoding="utf-8") as handle:
        document = json.load(handle)
    if (
        not isinstance(document, dict)
        or document.get("bomFormat") != "CycloneDX"
        or not isinstance(document.get("components", []), list)
    ):
        raise ValueError("Syft output is not a valid CycloneDX document")

