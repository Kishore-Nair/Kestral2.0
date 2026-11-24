"""Path and traversal policy for repository discovery."""

from pathlib import Path

SKIP_DIRECTORIES = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".next",
        "dist",
        "build",
        "coverage",
        "vendor",
    }
)


def to_repo_relative_posix(path: Path, root: Path) -> str:
    """Return a validated POSIX path relative to ``root``."""
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError("Discovered path escapes repository root") from exc

    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("Discovered path is not a safe repository-relative path")
    value = "/".join(parts)
    if value.startswith("/") or "\x00" in value or "\\" in value:
        raise ValueError("Discovered path is not a safe repository-relative path")
    return value
