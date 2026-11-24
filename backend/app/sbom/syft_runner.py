"""Run Syft safely and persist a validated CycloneDX SBOM.

Syft only *reads* files in the cloned repository. It never installs, builds
or executes repository code. This module:

* calls Syft as a list of arguments (no shell, no string interpolation),
* passes only a small allow-list of environment variables (no tokens/secrets),
* bounds the run with a timeout and the output with a size limit,
* writes to a temporary file first and only renames it to ``sbom.cdx.json``
  once the JSON has been validated (atomic write).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

SBOM_FILENAME = "sbom.cdx.json"
DEFAULT_TIMEOUT_SECONDS = 300
MAX_SBOM_BYTES = 40 * 1024 * 1024  # 40 MB

# Only these variables are passed to Syft. Everything else (GITHUB_TOKEN,
# AWS_*, etc.) is deliberately dropped.
_SAFE_ENV_VARS = (
    "PATH",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)


class SyftError(RuntimeError):
    """Base class for every Syft failure. Messages are safe to show users."""


class SyftNotFoundError(SyftError):
    """The ``syft`` executable is not installed or not on PATH."""


class SyftTimeoutError(SyftError):
    """Syft did not finish within the allowed time."""


class SyftExecutionError(SyftError):
    """Syft exited with a non-zero status."""


class SyftOutputError(SyftError):
    """Syft produced a missing, oversized or invalid CycloneDX document."""


def build_safe_env(scan_dir: Path) -> dict[str, str]:
    """Return the minimal environment for the Syft subprocess."""
    env = {key: os.environ[key] for key in _SAFE_ENV_VARS if key in os.environ}
    # Isolate Syft's user config/cache inside this scan's output folder.
    env["HOME"] = str(scan_dir)
    # Don't phone home to check for Syft updates during a scan.
    env["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
    return env


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def run_syft(
    repo_dir: Path,
    scan_dir: Path,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    syft_executable: str = "syft",
) -> dict:
    """Scan ``repo_dir`` with Syft and write ``scan_dir/sbom.cdx.json``.

    Returns the parsed CycloneDX JSON (a dict).
    Raises ``ValueError`` for bad input paths and ``SyftError`` subclasses for
    tool failures. Never returns a fabricated or partial success.
    """
    repo_dir = Path(repo_dir).resolve()
    scan_dir = Path(scan_dir).resolve()

    if not repo_dir.is_dir():
        raise ValueError("Repository directory does not exist")
    if _is_relative_to(scan_dir, repo_dir):
        raise ValueError("Scan output directory must be outside the repository")
    scan_dir.mkdir(parents=True, exist_ok=True)

    executable = shutil.which(syft_executable)
    if executable is None:
        raise SyftNotFoundError("Syft is not installed or not on PATH")

    output = scan_dir / SBOM_FILENAME
    temp = scan_dir / (SBOM_FILENAME + ".tmp")
    temp.unlink(missing_ok=True)

    command = [executable, f"dir:{repo_dir}", "-o", f"cyclonedx-json={temp}"]
    try:
        result = subprocess.run(
            command,
            shell=False,
            cwd=scan_dir,
            stdin=subprocess.DEVNULL,
            env=build_safe_env(scan_dir),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        temp.unlink(missing_ok=True)
        raise SyftTimeoutError(f"Syft timed out after {timeout} seconds") from exc
    except OSError as exc:
        temp.unlink(missing_ok=True)
        raise SyftExecutionError("Syft could not be started") from exc

    if result.returncode != 0:
        temp.unlink(missing_ok=True)
        # stderr is intentionally NOT included: it can contain host paths.
        raise SyftExecutionError(f"Syft failed with exit code {result.returncode}")

    try:
        data = _read_and_validate(temp)
    except SyftOutputError:
        temp.unlink(missing_ok=True)
        raise

    os.replace(temp, output)  # atomic rename in the same directory
    return data


def _read_and_validate(path: Path) -> dict:
    if not path.is_file():
        raise SyftOutputError("Syft did not produce an SBOM file")
    if path.stat().st_size > MAX_SBOM_BYTES:
        raise SyftOutputError("Syft SBOM is larger than the allowed limit")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SyftOutputError("Syft SBOM is not valid JSON") from exc
    if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX":
        raise SyftOutputError("Syft output is not a CycloneDX document")
    if not isinstance(data.get("components", []), list):
        raise SyftOutputError("CycloneDX 'components' must be a list")
    return data
