# ruff: noqa: E501 - the pull request description is a Markdown template
"""Open a GitHub pull request for a sandbox-validated fix. Kestral never merges it.

Uses the GitHub REST Git Data API: a new branch is created from the exact scanned commit and
one commit carries the patched files that were tested in the sandbox. The pull request
description records the finding, the approval, the validation evidence and rollback steps.
The token comes from settings only, is sent only to the configured GitHub API host, and is
never logged or returned.
"""

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from app.schemas.validation import PullRequestInfo, ValidationChange, ValidationResult

Request = Callable[[str, str, dict | None], tuple[int, Any]]
MAX_BODY = 60_000


class GitHubError(RuntimeError):
    """A safe-to-show GitHub failure."""


def make_request(token: str, api_url: str, timeout: int = 30) -> Request:
    base = api_url.rstrip("/")
    if not base.startswith("https://"):
        raise GitHubError("The GitHub API URL must use https")

    def request(method: str, path: str, body: dict | None) -> tuple[int, Any]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            base + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "kestral-guardian",
                **({"Content-Type": "application/json"} if data else {}),
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:  # noqa: S310 - fixed host
                raw = response.read(5 * 1024 * 1024)
                return response.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read(64 * 1024)
            try:
                return exc.code, json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                return exc.code, {}
        except (urllib.error.URLError, TimeoutError) as exc:
            raise GitHubError("Could not reach GitHub") from exc

    return request


def _message(payload: Any) -> str:
    if isinstance(payload, dict):
        text = str(payload.get("message") or "")
        errors = payload.get("errors")
        if isinstance(errors, list) and errors:
            first = errors[0]
            detail = first.get("message") if isinstance(first, dict) else str(first)
            if detail:
                text = f"{text}: {detail}"
        return text[:300]
    return ""


def _check(status: int, payload: Any, action: str) -> Any:
    if status in (200, 201):
        return payload
    if status == 401:
        raise GitHubError("GitHub rejected the token (expired or invalid)")
    if status in (403, 404):
        raise GitHubError(
            f"The token cannot {action} on this repository (needs Contents and Pull requests "
            "write access)"
        )
    raise GitHubError(f"GitHub could not {action}: {_message(payload) or status}")


def branch_name(change: ValidationChange, validation_id: str) -> str:
    package = re.sub(r"[^A-Za-z0-9._-]+", "-", change.package).strip("-.") or "package"
    version = re.sub(r"[^A-Za-z0-9._-]+", "-", change.to_version)
    return f"kestral/fix-{package}-{version}-{validation_id[-6:]}"


def pr_body(
    change: ValidationChange,
    result: ValidationResult,
    finding_title: str,
    scan_id: str,
    commit: str | None,
    validation_id: str,
) -> str:
    c = result.comparison
    rows = ["critical", "high", "medium", "low", "suspicious"]
    table = ""
    if c:
        table = "| | Before | After |\n|---|---|---|\n" + "\n".join(
            f"| {k} | {c.before_counts.get(k, 0)} | {c.after_counts.get(k, 0)} |" for k in rows
        )
    steps = "\n".join(f"- **{s.status}** · {s.label}: {s.detail}" for s in result.steps)
    tests = "\n".join(
        f"- {t.phase}: **{t.status}**"
        + (f" ({t.runtime}, `{t.image}`, {t.duration_s}s)" if t.runtime else "")
        for t in result.tests
    )
    residual = "\n".join(f"- {r}" for r in result.residual_risks[:15]) or "- None recorded"
    files = "\n".join(f"- `{d.path}` (+{d.lines_added} −{d.lines_removed})" for d in result.diffs)
    body = f"""## Kestral validated fix: {change.package} {change.from_version} → {change.to_version}

**Finding:** {finding_title}
**Project:** `{change.project_path or "."}` ({change.ecosystem})
**Approved by:** {change.approved_by or "unknown"} · source: {change.source_type} `{change.source_id}`
**Verdict:** {result.verdict} — {result.verdict_reason}

### Files changed
{files or "- none"}

### Sandbox validation
Applied to an isolated copy of commit `{(commit or "")[:12]}`, tested and rescanned by Kestral.

{steps}

### Build and tests
{tests or "- not run"}
{result.tests_detail}

### Before / after risk
{table or "No comparison available."}

### Remaining risk
{residual}

### Rollback
Revert this pull request (or its single commit). That restores `{change.package}` {change.from_version} \
and the previous lockfile exactly; no other files are touched.

---
This pull request was opened by Kestral after a human approval and a sandbox validation. **Kestral \
does not merge it**: review the diff and the CI results before merging. Scan `{scan_id}`, validation \
`{validation_id}`.
"""
    return body[:MAX_BODY]


def open_pull_request(
    request: Request,
    *,
    owner: str,
    repo: str,
    base_commit: str,
    base_branch: str | None,
    files: dict[str, str],
    change: ValidationChange,
    result: ValidationResult,
    finding_title: str,
    scan_id: str,
    validation_id: str,
) -> PullRequestInfo:
    if not files:
        raise GitHubError("No patched files were saved for this validation; run it again")
    root = f"/repos/{owner}/{repo}"
    info = _check(*request("GET", root, None), "be read")
    permissions = info.get("permissions") or {}
    if permissions and not permissions.get("push"):
        raise GitHubError("The token has no write access to this repository")
    base = base_branch or info.get("default_branch") or "main"

    commit = _check(*request("GET", f"{root}/git/commits/{base_commit}", None), "read the commit")
    tree_items = []
    for path, content in sorted(files.items()):
        blob = _check(
            *request("POST", f"{root}/git/blobs", {"content": content, "encoding": "utf-8"}),
            "create file contents",
        )
        tree_items.append({"path": path, "mode": "100644", "type": "blob", "sha": blob["sha"]})
    tree = _check(
        *request(
            "POST", f"{root}/git/trees", {"base_tree": commit["tree"]["sha"], "tree": tree_items}
        ),
        "create a tree",
    )
    advisory = finding_title.split(":", 1)[0]
    message = (
        f"fix(deps): upgrade {change.package} {change.from_version} -> {change.to_version}\n\n"
        f"Resolves {advisory} in {change.project_path or 'the root project'}.\n"
        f"Validated in a Kestral sandbox (verdict {result.verdict}); approved by "
        f"{change.approved_by or 'unknown'}."
    )
    new_commit = _check(
        *request(
            "POST",
            f"{root}/git/commits",
            {"message": message, "tree": tree["sha"], "parents": [base_commit]},
        ),
        "create a commit",
    )
    branch = branch_name(change, validation_id)
    _check(
        *request(
            "POST", f"{root}/git/refs", {"ref": f"refs/heads/{branch}", "sha": new_commit["sha"]}
        ),
        "create a branch",
    )
    pull = _check(
        *request(
            "POST",
            f"{root}/pulls",
            {
                "title": f"fix(deps): upgrade {change.package} to {change.to_version} ({advisory})",
                "head": branch,
                "base": base,
                "body": pr_body(change, result, finding_title, scan_id, base_commit, validation_id),
                "maintainer_can_modify": True,
            },
        ),
        "open the pull request",
    )
    return PullRequestInfo(
        url=pull["html_url"],
        number=int(pull["number"]),
        branch=branch,
        base=base,
        created_at=datetime.now(UTC),
    )
