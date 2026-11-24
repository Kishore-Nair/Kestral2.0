"""Reviewed application test recipes, selected by source fingerprints rather than names."""

import base64
import hashlib
from pathlib import Path

NODEGOAT_FILES = {
    "server.js": "48ec5e8f9668b230caf6af27f4a4ffbdcd8b702b376a6bbcc951217917c6ea2e",
    "app/routes/contributions.js": (
        "196bdeaa22da4cfe8a851b1b932710b2fcedd21f14ed75d70b739ba759a01003"
    ),
    "app/data/contributions-dao.js": (
        "363065e8b3c32f0997ce2dcb17341eb3e40b7f43b00b72c576dfebf73f551c85"
    ),
    "app/data/user-dao.js": "577fb140933a50e010a4bbcb74e975f678d7f3a989467e4d113926f35c042e64",
}


def nodegoat_script(project: Path) -> str | None:
    """Return the reviewed regression script only for matching NodeGoat application files."""
    for name, expected in NODEGOAT_FILES.items():
        path = project / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_000_000:
            return None
        if hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest() != expected:
            return None
    payload = base64.b64encode(
        Path(__file__).with_name("nodegoat_regression.cjs").read_bytes()
    ).decode()
    return (
        "set -e; cd /work; "
        "node --check server.js; node --check app/routes/contributions.js; "
        "echo 'BUILD: NodeGoat JavaScript syntax checks passed (no compilation step)'; "
        f"echo '{payload}' | base64 -d > kestral-regression.cjs; "
        "node --test --test-timeout=30000 kestral-regression.cjs"
    )
