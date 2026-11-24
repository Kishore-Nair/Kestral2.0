"""Isolated sandbox mechanics: exact-commit checkout, lockfile regeneration, container tests.

Safety rules:
- Every sandbox is a fresh clone in its own directory; the original scan workspace and
  artifacts are never touched, and nothing is pushed anywhere.
- Git runs with hooks disabled and no user/system config (same controls as ingestion).
- ``npm install --package-lock-only --ignore-scripts`` resolves versions against the public
  registry without installing packages or running any package script.
- The scanned project's own code (dependency installs, tests) runs only inside a container
  (Podman or Docker) with dropped capabilities, no privilege escalation, memory/CPU/PID
  limits and the source mounted read-only. Without a container runtime, tests are not run.
"""

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from app.ingestion.cloner import _git_executable, _safe_git_environment, clone_public_repo
from app.ingestion.url_validation import ValidatedRepository

TEST_OUTPUT_CHARS = 4000
FRESH_LOCK = "KESTRAL_FRESH_LOCK"
NO_TESTS = "KESTRAL_NO_TESTS"
INSTALL_FAILED = "KESTRAL_INSTALL_FAILED"


class SandboxError(RuntimeError):
    """A sandbox step failed; the message is safe to show."""


def tool_error(stderr: str) -> str:
    """The tool's own error lines, without installer noise (warnings, progress)."""
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    wanted = [
        line
        for line in lines
        if line.lower().startswith(("error", "cause", "caused by", "×", "hint", "npm err"))
        or line.startswith("  ")
    ]
    text = " ".join(wanted or lines[-4:])
    return text[-600:] or "no error output"


def checkout_commit(
    repository: ValidatedRepository, workspace: Path, commit_sha: str | None, timeout: int
) -> Path:
    """Clone the repository and make sure HEAD is exactly the scanned commit."""
    repo = clone_public_repo(repository, workspace, timeout)
    environment = _safe_git_environment(workspace)
    git = _git_executable(environment)
    base = [git, "-c", f"core.hooksPath={workspace / 'disabled-hooks'}", "-C", str(repo)]

    def run(*args: str) -> str:
        completed = subprocess.run(
            [*base, *args],
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
        return completed.stdout.strip()

    head = run("rev-parse", "HEAD")
    if commit_sha and head != commit_sha:
        try:
            run("fetch", "--depth", "1", "--no-recurse-submodules", "origin", commit_sha)
            run("checkout", "--detach", "--force", commit_sha)
        except subprocess.CalledProcessError as exc:
            raise SandboxError(
                f"The scanned commit {commit_sha[:12]} is no longer fetchable from the repository"
            ) from exc
        head = run("rev-parse", "HEAD")
    if commit_sha and head != commit_sha:
        raise SandboxError("Sandbox checkout does not match the scanned commit")
    return repo


def npm_available() -> bool:
    return shutil.which("npm") is not None


def regenerate_npm_lock(project_dir: Path, timeout: int) -> str:
    """Resolve package-lock.json without installing or running package code."""
    npm = shutil.which("npm")
    if npm is None:
        raise SandboxError("npm is not installed; the lockfile was not regenerated")
    empty_rc = project_dir.parent / ".kestral-empty-npmrc"
    empty_rc.write_text("", encoding="utf-8")
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(project_dir.parent),
        "npm_config_userconfig": str(empty_rc),
        "npm_config_globalconfig": str(empty_rc),
        "npm_config_update_notifier": "false",
    }
    command = [
        npm,
        "install",
        "--package-lock-only",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--registry=https://registry.npmjs.org/",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=project_dir,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise SandboxError("npm lockfile resolution timed out") from exc
    finally:
        empty_rc.unlink(missing_ok=True)
    if completed.returncode != 0:
        detail = tool_error(completed.stderr or completed.stdout)
        raise SandboxError(f"npm could not resolve the lockfile: {detail}")
    return " ".join(command[1:])


def regenerate_uv_lock_in_container(
    runtime: str, project_dir: Path, package: str, version: str, timeout: int
) -> str:
    """Re-lock uv.lock inside a container (resolution may build sdists, so never on the host).

    The project is copied into the container's tmpfs; only the new uv.lock comes back, via
    stdout, and it is parsed before it replaces the sandbox copy.
    """
    import tomllib

    executable = shutil.which(runtime)
    if executable is None:
        raise SandboxError(f"{runtime} is not installed")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", package) or not re.fullmatch(
        r"[A-Za-z0-9.+!_-]+", version
    ):
        raise SandboxError("Unsafe package or version for uv")
    target = f"{package}=={version}"
    # Re-lock the existing file; if uv cannot read it (corrupt or hand-edited), resolve a
    # fresh lock from pyproject.toml with the same pin and say so.
    script = (
        "set -e; cp -a /src/. /work/ && cd /work && "
        "pip install -q --root-user-action=ignore --disable-pip-version-check uv >/dev/null 2>&1; "
        f"if ! uv lock --upgrade-package '{target}' 2>/tmp/uv.err; then "
        "  if grep -q 'Failed to parse' /tmp/uv.err; then "
        f"    echo {FRESH_LOCK} >&2; rm -f uv.lock; "
        f"    uv lock --upgrade-package '{target}' 2>/tmp/uv.err "
        "      || { cat /tmp/uv.err >&2; exit 1; }; "
        "  else cat /tmp/uv.err >&2; exit 1; fi; "
        "fi; cat uv.lock"
    )
    command = [
        executable,
        "run",
        "--rm",
        "--pull=missing",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--memory=2g",
        "--cpus=2",
        "--pids-limit=1024",
        "--tmpfs=/work:rw,exec,size=2g",
        "--tmpfs=/tmp:rw,exec,size=1g",
        "-e",
        "HOME=/tmp",
        "-v",
        f"{project_dir.resolve()}:/src:ro",
        "-w",
        "/work",
        "docker.io/library/python:3.12-slim",
        "sh",
        "-c",
        script,
    ]
    try:
        completed = subprocess.run(
            command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        raise SandboxError("uv lock timed out in the container") from exc
    if completed.returncode != 0:
        raise SandboxError(f"uv could not re-lock: {tool_error(completed.stderr)}")
    try:
        tomllib.loads(completed.stdout)
    except tomllib.TOMLDecodeError as exc:
        raise SandboxError("uv produced an unreadable lockfile") from exc
    (project_dir / "uv.lock").write_text(completed.stdout, encoding="utf-8")
    note = (
        "; the existing uv.lock could not be read, so a fresh lock was resolved from pyproject.toml"
        if FRESH_LOCK in completed.stderr
        else ""
    )
    return f"uv lock --upgrade-package {target} (in {runtime} container){note}"


# ---------------------------------------------------------------------------
# Container test runner
# ---------------------------------------------------------------------------


def container_runtime(preferred: str | None = None) -> str | None:
    """'podman' or 'docker' when installed and responsive, else None."""
    candidates = [preferred] if preferred else ["podman", "docker"]
    for name in candidates:
        if not name:
            continue
        executable = shutil.which(name)
        if not executable:
            continue
        try:
            probe = subprocess.run(
                [
                    executable,
                    "info",
                    "--format",
                    "{{.Host.Arch}}" if name == "podman" else "{{.Architecture}}",
                ],
                capture_output=True,
                text=True,
                timeout=20,
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return name
    return None


def start_runtime(timeout: int = 240) -> str:
    """Start the local Podman machine (macOS/Windows). Fixed command, no user input.

    Docker Desktop cannot be started this way; Kestral reports that instead of guessing.
    """
    if container_runtime():
        return "A container runtime is already running"
    podman = shutil.which("podman")
    if podman is None:
        if shutil.which("docker"):
            raise SandboxError("Docker is installed but not running; start Docker Desktop")
        raise SandboxError(
            "No container runtime is installed. Install Podman: brew install podman && "
            "podman machine init"
        )
    machines = subprocess.run(
        [podman, "machine", "list", "--format", "{{.Name}}"],
        capture_output=True,
        text=True,
        timeout=30,
        stdin=subprocess.DEVNULL,
    )
    if machines.returncode != 0 or not machines.stdout.strip():
        raise SandboxError("Podman has no machine yet. Run once: podman machine init")
    try:
        started = subprocess.run(
            [podman, "machine", "start"],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        raise SandboxError("Podman took too long to start; try again") from exc
    if started.returncode != 0 and "already running" not in (started.stderr + started.stdout):
        raise SandboxError(
            f"Podman could not start: {tool_error(started.stderr or started.stdout)}"
        )
    if not container_runtime():
        raise SandboxError("Podman started but is not responding yet; check again in a moment")
    return "Podman machine started"


@dataclass(frozen=True)
class TestPlan:
    __test__ = False  # not a pytest test class

    image: str
    script: str
    description: str


def test_plan(ecosystem: str, project_dir: Path) -> TestPlan | None:
    """Heuristic install + test commands for the project's ecosystem."""
    if ecosystem == "pypi":
        requirements = sorted(p.name for p in project_dir.glob("requirements*.txt"))
        installs = []
        if (project_dir / "pyproject.toml").is_file() or (project_dir / "setup.py").is_file():
            installs.append("pip install -q -e .")
            installs.append(
                "(pip install -q --group tests 2>/dev/null || pip install -q --group dev "
                "2>/dev/null || true)"
            )
        installs += [f"pip install -q -r {name}" for name in requirements]
        if not installs:
            return None
        has_tests = any(p.exists() for p in (project_dir / "tests", project_dir / "test")) or any(
            project_dir.glob("test_*.py")
        )
        test = (
            "python -m pytest -q -p no:cacheprovider --maxfail=20"
            if has_tests
            else f"echo {NO_TESTS}; exit 0"
        )
        script = (
            "set -u; cp -a /src/. /work/ && cd /work && "
            "python -m venv /tmp/venv && . /tmp/venv/bin/activate && "
            "pip install -q --disable-pip-version-check --upgrade pip pytest >/dev/null && "
            f"({' && '.join(installs)}) || {{ echo {INSTALL_FAILED}; exit 97; }}; "
            f"{test}"
        )
        return TestPlan("docker.io/library/python:3.12-slim", script, f"pip install; {test}")
    if ecosystem == "npm":
        if not (project_dir / "package.json").is_file():
            return None
        install = (
            "npm ci --ignore-scripts --no-audit --no-fund"
            if (project_dir / "package-lock.json").is_file()
            else "npm install --ignore-scripts --no-audit --no-fund"
        )
        script = (
            "set -u; cp -a /src/. /work/ && cd /work && "
            f"({install}) || {{ echo {INSTALL_FAILED}; exit 97; }}; "
            "if node -e \"process.exit(require('./package.json').scripts?.test ? 0 : 1)\"; "
            f"then CI=true npm test; else echo {NO_TESTS}; fi"
        )
        return TestPlan("docker.io/library/node:22-slim", script, f"{install}; npm test")
    return None


def run_tests_in_container(
    runtime: str, plan: TestPlan, project_dir: Path, timeout: int, memory: str = "2g"
) -> dict:
    """Run the plan in a locked-down container. Returns a TestRun-shaped dict (no phase)."""
    executable = shutil.which(runtime)
    if executable is None:
        raise SandboxError(f"{runtime} is not installed")
    command = [
        executable,
        "run",
        "--rm",
        "--pull=missing",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--memory={memory}",
        "--cpus=2",
        "--pids-limit=1024",
        "--tmpfs=/work:rw,exec,size=4g",
        "--tmpfs=/tmp:rw,exec,size=2g",
        "-e",
        "HOME=/tmp",
        "-e",
        "PIP_NO_INPUT=1",
        "-e",
        "npm_config_update_notifier=false",
        "-v",
        f"{project_dir.resolve()}:/src:ro",
        "-w",
        "/work",
        plan.image,
        "sh",
        "-c",
        plan.script,
    ]
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "exit_code": None,
            "duration_s": round(time.monotonic() - started, 1),
            "output_tail": f"Timed out after {timeout} s",
        }
    output = (completed.stdout or "") + (completed.stderr or "")
    if NO_TESTS in output:
        status = "no_tests"
    elif INSTALL_FAILED in output or completed.returncode == 97:
        status = "error"
    elif completed.returncode == 5 and "no tests ran" in output:
        status = "no_tests"
    elif completed.returncode in (125, 126, 127):
        status = "error"
    else:
        status = "passed" if completed.returncode == 0 else "failed"
    return {
        "status": status,
        "exit_code": completed.returncode,
        "duration_s": round(time.monotonic() - started, 1),
        "output_tail": output[-TEST_OUTPUT_CHARS:],
    }
