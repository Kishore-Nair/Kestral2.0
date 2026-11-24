"""Deterministic, scan-independent identities.

IDs are ``<prefix>:<24 hex>`` where the hex is a SHA-256 prefix over a
canonical JSON encoding of an *ordered* tuple of fields. The scan UUID is never
part of an identity, so the same repository state yields byte-identical IDs
on every scan (enabling future change-intelligence diffs).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from hashlib import sha256

ID_HEX_LENGTH = 24


def stable_id(prefix: str, *fields: object) -> str:
    payload = json.dumps(list(fields), separators=(",", ":"), ensure_ascii=True)
    return f"{prefix}:{sha256(payload.encode('utf-8')).hexdigest()[:ID_HEX_LENGTH]}"


def root_id(ecosystem: str, project_path: str, manifest_path: str) -> str:
    return stable_id("root", ecosystem, project_path, manifest_path)


def component_id(
    ecosystem: str,
    normalized_name: str,
    version: str | None,
    project_path: str,
    context_path: str,
    install_path: str | None,
) -> str:
    """Identity of one package *instance*.

    ``context_path`` is the lockfile/manifest that evidences it and
    ``install_path`` the installed location (npm) or ``None``. Two copies of the
    same name@version in different install paths get different IDs.
    """
    return stable_id(
        "cmp", ecosystem, normalized_name, version, project_path, context_path, install_path
    )


def syft_only_component_id(
    ecosystem: str,
    normalized_name: str,
    version: str | None,
    purl: str | None,
    locations: Iterable[str],
) -> str:
    """Identity for a Syft-reported package with no trustworthy install context.

    Lives in an explicit ``unknown-location`` namespace so it can never collide
    with (or silently merge into) a lockfile-evidenced instance.
    """
    return stable_id(
        "cmp", "unknown-location", ecosystem, normalized_name, version, purl, sorted(locations)
    )


def relationship_id(
    from_id: str,
    to_id: str | None,
    unresolved_target: dict | None,
    resolution_status: str,
    evidence_locators: Iterable[tuple[str, str, str]],
) -> str:
    target = to_id if to_id is not None else unresolved_target
    return stable_id("rel", from_id, target, resolution_status, sorted(set(evidence_locators)))
