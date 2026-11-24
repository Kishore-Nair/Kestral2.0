"""Run Grype offline against the exact PURLs we assess.

Grype reads a plain list of PURLs (``grype purl:<file>``), so it checks exactly
the same packages as OSV and never touches the cloned repository. The database
is never auto-updated during a scan; its build date is recorded as evidence.
"""

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

PURL_FILENAME = "grype-input.purls"
MAX_OUTPUT_BYTES = 50 * 1024 * 1024
_SAFE_ENV_VARS = (
    "PATH",
    "HOME",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "XDG_CACHE_HOME",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
)


class GrypeError(RuntimeError):
    """Grype could not produce results; message is safe to show users."""


@dataclass
class GrypeResult:
    tool_version: str | None
    database_built: str | None
    matches: list[dict]
    raw: dict


def _safe_env() -> dict[str, str]:
    env = {key: os.environ[key] for key in _SAFE_ENV_VARS if key in os.environ}
    env["GRYPE_DB_AUTO_UPDATE"] = "false"
    env["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"
    return env


def run_grype(
    purls: list[str],
    scan_dir: Path,
    *,
    timeout: int = 180,
    executable: str = "grype",
    runner=subprocess.run,
) -> GrypeResult:
    resolved = shutil.which(executable)
    if resolved is None:
        raise GrypeError("Grype is not installed or not on PATH")
    scan_dir.mkdir(parents=True, exist_ok=True)
    purl_file = scan_dir / PURL_FILENAME
    purl_file.write_text("".join(f"{p}\n" for p in purls), encoding="utf-8")
    try:
        completed = runner(
            [resolved, f"purl:{purl_file}", "-o", "json", "-q"],
            shell=False,
            cwd=scan_dir,
            stdin=subprocess.DEVNULL,
            env=_safe_env(),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise GrypeError(f"Grype timed out after {timeout} seconds") from exc
    except OSError as exc:
        raise GrypeError("Grype could not be started") from exc
    finally:
        purl_file.unlink(missing_ok=True)

    if completed.returncode != 0:
        # stderr is not echoed: it may contain host paths. A missing DB is the usual cause.
        raise GrypeError(
            f"Grype failed with exit code {completed.returncode}; "
            "run 'grype db update' if its database is missing"
        )
    if len(completed.stdout.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise GrypeError("Grype output is larger than the allowed limit")
    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise GrypeError("Grype output is not valid JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("matches"), list):
        raise GrypeError("Grype output has an unexpected shape")

    descriptor = data.get("descriptor") or {}
    status = (descriptor.get("db") or {}).get("status") or {}
    # Keep the evidence file small and host-neutral: drop config and local DB path.
    raw = {
        "descriptor": {
            "name": descriptor.get("name"),
            "version": descriptor.get("version"),
            "timestamp": descriptor.get("timestamp"),
            "db": {k: status.get(k) for k in ("schemaVersion", "built", "from", "valid")},
        },
        "matches": data["matches"],
    }
    return GrypeResult(
        tool_version=descriptor.get("version"),
        database_built=status.get("built"),
        matches=data["matches"],
        raw=raw,
    )
