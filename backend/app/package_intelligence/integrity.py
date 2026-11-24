import base64
import binascii
import re

STRENGTH = {"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}
FILENAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._+-]{0,255}")


def sri(value: object) -> tuple[str, dict[str, set[bytes]]]:
    if value is None or value == "":
        return "missing", {}
    if not isinstance(value, str) or len(value) > 8192:
        return "malformed", {}
    result: dict[str, set[bytes]] = {}
    for token in value.split():
        algorithm, sep, digest = token.partition("-")
        if not sep or not digest or not re.fullmatch(r"[a-z0-9]+", algorithm):
            return "malformed", {}
        if algorithm not in STRENGTH:
            continue
        try:
            decoded = base64.b64decode(digest, validate=True)
        except (ValueError, binascii.Error):
            return "malformed", {}
        if len(decoded) != STRENGTH[algorithm]:
            return "malformed", {}
        result.setdefault(algorithm, set()).add(decoded)
    return ("ok" if result else "uncomparable"), result


def npm_compare(local: object, remote: object) -> tuple[str, str | None]:
    left_state, left = sri(local)
    right_state, right = sri(remote)
    if left_state != "ok" or right_state != "ok":
        return (left_state if left_state != "ok" else right_state), None
    shared = left.keys() & right.keys()
    if not shared:
        return "uncomparable", None
    algorithm = max(shared, key=STRENGTH.__getitem__)
    return ("match" if left[algorithm] & right[algorithm] else "mismatch"), algorithm


def digest_hex(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{64}", value) is not None


def pypi_compare(local: object, files: list, filename: str | None) -> tuple[str, str | None]:
    if local is None:
        return "missing", None
    if not digest_hex(local):
        return "malformed", None
    candidates = files if filename is None else [
        item for item in files if isinstance(item, dict) and item.get("filename") == filename
    ]
    if not candidates or (filename is not None and len(candidates) != 1):
        return "uncomparable", None
    hashes = set()
    for candidate in candidates:
        digests = candidate.get("digests") if isinstance(candidate, dict) else None
        remote = digests.get("sha256") if isinstance(digests, dict) else None
        if digest_hex(remote):
            hashes.add(remote.lower())
    if local.lower() in hashes:
        return ("match" if filename is not None else "membership_match"), "sha256"
    if not hashes:
        return "uncomparable", None
    return ("mismatch" if filename is not None else "ambiguous_distribution"), "sha256"
