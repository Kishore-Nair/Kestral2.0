"""Refresh the popular-package name lists used by the typosquat check.

The full lists are kept: the top names are typosquat targets, and every listed
name counts as an established package that is never flagged.

Sources (public, no account needed):
- PyPI: hugovk/top-pypi-packages (monthly download counts from the PyPI BigQuery dataset)
- npm:  wooorm/npm-high-impact (packages ranked by downloads and dependents)

Run from backend/:  python scripts/update_popular_packages.py
"""

import json
import re
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "app" / "risk" / "data"
PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
NPM_URL = "https://unpkg.com/npm-high-impact@1/lib/top.js"


def _get(url: str) -> tuple[str, str]:
    request = urllib.request.Request(url, headers={"User-Agent": "kestral-dataset-refresh"})
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - fixed https URLs
        return response.read().decode("utf-8"), response.geturl()


def _write(name: str, source: str, note: str, names: list[str]) -> None:
    retrieved = datetime.now(UTC).strftime("%Y-%m-%d")
    header = [
        f"# source: {source}",
        f"# {note}",
        f"# retrieved: {retrieved}",
        f"# top {len(names)} names, most popular first",
    ]
    (DATA / name).write_text("\n".join([*header, *names]) + "\n", encoding="utf-8")


def main() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    text, url = _get(PYPI_URL)
    payload = json.loads(text)
    pypi = [row["project"] for row in payload["rows"]]
    _write("popular_pypi.txt", url, f"dataset last_update: {payload['last_update']}", pypi)

    text, url = _get(NPM_URL)
    npm = re.findall(r"'([^']+)'", text)
    _write("popular_npm.txt", url, "npm-high-impact top.js (ranked by downloads)", npm)
    print(f"wrote {len(pypi)} PyPI and {len(npm)} npm names to {DATA}")


if __name__ == "__main__":
    main()
