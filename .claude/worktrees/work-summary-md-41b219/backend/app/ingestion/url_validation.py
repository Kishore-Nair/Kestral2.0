"""Strict validation for the public-GitHub-only MVP input boundary."""

import re
import shutil
import subprocess
from dataclasses import dataclass
from urllib.parse import urlsplit

OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
REF = re.compile(r"^[A-Za-z0-9._/-]{1,120}$")


@dataclass(frozen=True)
class ValidatedRepository:
    owner: str
    name: str
    canonical_url: str
    requested_ref: str | None


def validate_repo_url(url: str, ref: str | None) -> ValidatedRepository:
    if any(character in url for character in ("\r", "\n", "\x00")):
        raise ValueError("Repository URL contains forbidden control characters")

    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise ValueError("Invalid repository URL") from exc

    if (
        parts.scheme != "https"
        or parts.hostname != "github.com"
        or parts.netloc != "github.com"
        or parts.username
        or parts.password
        or port is not None
        or parts.query
        or parts.fragment
    ):
        raise ValueError("Only public https://github.com/owner/repo URLs are supported")

    if "%" in parts.path or "\\" in parts.path or "//" in parts.path:
        raise ValueError("Encoded or ambiguous paths are not allowed")

    tokens = parts.path.strip("/").split("/")
    if len(tokens) != 2:
        raise ValueError("Expected a GitHub owner and repository")
    owner, name = tokens
    if name.endswith(".git"):
        name = name[:-4]
    if not OWNER.fullmatch(owner) or not REPO.fullmatch(name) or name in {".", ".."}:
        raise ValueError("Invalid GitHub owner/repository")

    if ref is not None and (
        not REF.fullmatch(ref)
        or ref.startswith(("-", "/", "."))
        or ".." in ref
        or "//" in ref
        or ref.endswith(("/", ".", ".lock"))
    ):
        raise ValueError("Invalid branch/tag")
    if ref is not None:
        git_executable = shutil.which("git")
        if git_executable is None:
            raise RuntimeError("Git executable is required to validate branch/tag names")
        result = subprocess.run(
            [git_executable, "check-ref-format", "--branch", ref],
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode != 0:
            raise ValueError("Invalid or unsupported branch/tag")

    return ValidatedRepository(
        owner=owner,
        name=name,
        canonical_url=f"https://github.com/{owner}/{name}",
        requested_ref=ref,
    )

