"""Non-interactive, non-recursive Git clone for validated public repositories."""

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.ingestion.url_validation import ValidatedRepository

SAFE_PROCESS_VARIABLES = (
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
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class CheckoutMetadata:
    commit_sha: str
    resolved_ref: str | None


def _safe_git_environment(workspace: Path) -> dict[str, str]:
    empty_config = workspace / "empty.gitconfig"
    empty_config.touch(exist_ok=True)
    environment = {
        key: os.environ[key] for key in SAFE_PROCESS_VARIABLES if key in os.environ
    }
    environment.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "Never",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(empty_config),
        }
    )
    return environment


def _git_executable(environment: dict[str, str]) -> str:
    executable = shutil.which("git", path=environment.get("PATH"))
    if executable is None:
        raise RuntimeError("Git executable was not found on the allowlisted PATH")
    return executable


def clone_public_repo(
    repository: ValidatedRepository,
    scan_workspace: Path,
    timeout: int,
) -> Path:
    workspace = scan_workspace.resolve(strict=True)
    if not workspace.is_dir():
        raise ValueError("Scan workspace must be a directory")
    if timeout <= 0:
        raise ValueError("Clone timeout must be positive")

    target = workspace / "repo"
    if target.exists():
        raise FileExistsError("Clone target must not already exist")

    hooks = workspace / "disabled-hooks"
    hooks.mkdir(exist_ok=False)
    environment = _safe_git_environment(workspace)
    git_executable = _git_executable(environment)

    arguments = [
        git_executable,
        "-c",
        f"core.hooksPath={hooks}",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "http.followRedirects=false",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-recurse-submodules",
    ]
    if repository.requested_ref:
        arguments.extend(["--branch", repository.requested_ref])
    arguments.extend(["--", repository.canonical_url, str(target)])

    subprocess.run(
        arguments,
        shell=False,
        env=environment,
        cwd=workspace,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
    )
    if not target.is_dir():
        raise RuntimeError("Git reported success without creating the checkout")
    return target


def inspect_checkout(
    repo_dir: Path,
    *,
    requested_ref: str | None,
    timeout: int,
) -> CheckoutMetadata:
    checkout = repo_dir.resolve(strict=True)
    workspace = checkout.parent
    environment = _safe_git_environment(workspace)
    git_executable = _git_executable(environment)

    common = {
        "shell": False,
        "env": environment,
        "cwd": workspace,
        "stdin": subprocess.DEVNULL,
        "capture_output": True,
        "text": True,
        "timeout": timeout,
        "check": True,
    }
    sha_result = subprocess.run(
        [git_executable, "-C", str(checkout), "rev-parse", "--verify", "HEAD"],
        **common,
    )
    commit_sha = sha_result.stdout.strip().lower()
    if not COMMIT_SHA.fullmatch(commit_sha):
        raise RuntimeError("The checkout uses an unsupported Git object format")

    branch_result = subprocess.run(
        [git_executable, "-C", str(checkout), "symbolic-ref", "--short", "-q", "HEAD"],
        shell=False,
        env=environment,
        cwd=workspace,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if branch_result.returncode not in {0, 1}:
        raise RuntimeError("Git could not determine the resolved branch")
    branch = branch_result.stdout.strip() or None
    return CheckoutMetadata(commit_sha=commit_sha, resolved_ref=branch or requested_ref)

