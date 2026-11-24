import hashlib
import re

from .release_signals import HOOKS

# Indicators are intentionally conservative. Report categories and hashes, never source text.
PATTERNS = {
    "network_operation": re.compile(r"\b(?:curl|wget|invoke-webrequest)\b|https?://", re.I),
    "obfuscation": re.compile(r"\b(?:base64|frombase64string|atob)\b", re.I),
    "sensitive_environment": re.compile(
        r"\b(?:NODE_AUTH_TOKEN|NPM_TOKEN|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|SSH_AUTH_SOCK)\b", re.I
    ),
    "unusual_process": re.compile(
        r"\b(?:child_process|execSync|spawnSync|powershell|pwsh)\b|(?:\bsh|\bbash)\s+-c\b", re.I
    ),
}


def inspect_scripts(exact: dict) -> tuple[str, list[dict]]:
    scripts = exact.get("scripts")
    if not isinstance(scripts, dict):
        return "unassessed", []
    records = []
    unavailable = False
    for hook in HOOKS:
        if hook not in scripts:
            continue
        body = scripts[hook]
        if not isinstance(body, str) or len(body) > 8192:
            unavailable = True
            continue
        records.append({
            "hook": hook,
            "sha256": hashlib.sha256(body.encode("utf-8", "surrogatepass")).hexdigest(),
            "indicators": sorted(
                label for label, pattern in PATTERNS.items() if pattern.search(body)
            ),
        })
    if unavailable:
        return ("partial" if records else "unassessed"), records
    return ("signal" if any(row["indicators"] for row in records) else "assessed"), records
