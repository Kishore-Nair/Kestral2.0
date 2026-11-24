import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from threading import Thread

REPO = Path(__file__).resolve().parents[3]
MAX_INPUT = 16 * 1024 * 1024
MAX_OUTPUT = 2 * 1024 * 1024


class OperationError(Exception):
    pass


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_local(path: Path, root: Path, limit: int = MAX_INPUT) -> bytes:
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise OperationError("Input must be a regular file inside the authorized directory")
    with resolved.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise OperationError("Input exceeds size limit")
    return data


def write_json(path: Path, model) -> None:
    parent = path.parent.resolve(strict=True)
    destination = parent / path.name
    if parent.is_relative_to(REPO) or destination.is_symlink():
        raise OperationError("Output must be outside the implementation repository")
    with tempfile.NamedTemporaryFile(dir=parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write((model.model_dump_json(indent=2) + "\n").encode())
            stream.close()
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)


def authorized_root(path: Path) -> Path:
    root = path.resolve(strict=True)
    if not root.is_dir() or root == root.parent:
        raise OperationError("Choose a dedicated authorized input directory")
    return root


def tool_path(name: str, root: Path) -> Path:
    # Search configured absolute PATH entries only, with no implicit current-directory lookup.
    entries = [entry for entry in os.get_exec_path() if Path(entry).is_absolute()]
    for entry in entries:
        directory = Path(entry).resolve()
        if directory.is_relative_to(root):
            continue
        candidate = directory / (name + (".exe" if os.name == "nt" else ""))
        resolved = candidate.resolve()
        if (
            resolved.is_file() and os.access(resolved, os.X_OK)
            and not resolved.is_relative_to(root)
        ):
            return resolved
    raise OperationError(f"{name} executable unavailable on trusted PATH")


def run_tool(executable: Path, args: list[str], cwd: Path) -> tuple[int, bytes]:
    # Merge both streams and drain concurrently so pipe pressure cannot bypass the timeout.
    output = bytearray()
    with subprocess.Popen(
        [str(executable), *args], cwd=cwd, shell=False, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    ) as process:
        def capture():
            assert process.stdout is not None
            while chunk := process.stdout.read1(8192):
                output.extend(chunk[: MAX_OUTPUT + 1 - len(output)])
                if len(output) > MAX_OUTPUT:
                    process.kill()
                    break

        reader = Thread(target=capture, daemon=True)
        reader.start()
        try:
            code = process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise OperationError("Tool execution timed out") from None
        finally:
            reader.join(timeout=2)
        if reader.is_alive() or len(output) > MAX_OUTPUT:
            raise OperationError("Tool output exceeded capture limits")
    return code, bytes(output)


def validate_json(data: bytes) -> bytes:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError("Invalid JSON number")

    json.loads(data, object_pairs_hook=unique_object, parse_constant=reject_constant)
    return data
