import hashlib
from collections import Counter, defaultdict
from datetime import timedelta
from pathlib import Path

from app.schemas.dependency import DependencyDocument

from .integrity import FILENAME, digest_hex, npm_compare, pypi_compare, sri
from .lock_evidence import LockReader, artifact_path
from .registry import Registry, canonical_name, exact_version
from .release_signals import Thresholds, burst, release_for, withdrawal
from .script_analysis import inspect_scripts

DETECTORS = (
    "registry_integrity_mismatch", "lifecycle_script_indicator", "withdrawn_version",
    "recent_package", "recent_release", "release_pattern_anomaly",
)
MAX_COMPONENTS = 512
DEFAULT_THRESHOLDS = Thresholds()
COVERAGE_STATES = ("assessed", "partial", "unassessed", "skipped")


def _signal(category, severity, confidence, uncertainty, **evidence):
    return {
        "category": category, "severity": severity, "confidence": confidence,
        "uncertainty": uncertainty, "evidence": evidence,
    }


def _integrity(ecosystem, exact, component, lock):
    if ecosystem == "npm":
        dist = exact.get("dist")
        if not isinstance(dist, dict) or lock is None or lock.artifact is None:
            return "unbound_or_missing", None
        if artifact_path(dist.get("tarball"), "registry.npmjs.org") != lock.artifact:
            return "uncomparable_artifact", None
        return npm_compare(lock.digest, dist.get("integrity"))
    if lock is not None:
        return pypi_compare(lock.digest, exact, lock.filename)
    hashes = [
        item.content for item in component.hashes if item.alg.lower() in {"sha-256", "sha256"}
    ]
    if not hashes:
        return "missing", None
    outcomes = [pypi_compare(value, exact, None) for value in hashes[:16]]
    return next((result for result in outcomes if result[0] == "membership_match"), (
        "ambiguous_distribution", None,
    ))


def _metadata(ecosystem, exact):
    if ecosystem == "npm":
        dist = exact.get("dist")
        if not isinstance(dist, dict):
            return []
        path = artifact_path(dist.get("tarball"), "registry.npmjs.org")
        if path is None:
            return []
        _, algorithms = sri(dist.get("integrity"))
        return [{
            "artifact_id": hashlib.sha256(path.encode()).hexdigest(),
            "digests": {key: sorted(value.hex() for value in values)
                        for key, values in sorted(algorithms.items())},
        }]
    artifacts = []
    for file in exact:
        if not isinstance(file, dict):
            continue
        filename, digests = file.get("filename"), file.get("digests")
        if isinstance(filename, str) and FILENAME.fullmatch(filename):
            digest = digests.get("sha256") if isinstance(digests, dict) else None
            artifacts.append({
                "artifact_id": filename,
                "digests": {"sha256": [digest.lower()]} if digest_hex(digest) else {},
                "yanked": file["yanked"] if type(file.get("yanked")) is bool else None,
            })
    return artifacts


def _assess(row, release, components, evidence_by_id, now, thresholds):
    ecosystem = row["ecosystem"]
    exact = release.exact
    signals = row["signals"]
    status = row["detectors"]
    compared = []
    for component in components:
        lock = evidence_by_id[component.component_id]
        state, algorithm = _integrity(ecosystem, exact, component, lock)
        references = {"component_id": component.component_id, "algorithm": algorithm}
        if lock is not None:
            references.update(path=lock.path, locator=lock.locator)
        compared.append({"status": state, **references})
        if state == "mismatch":
            signals.append(_signal(
                "registry_integrity_mismatch", "high", "high",
                "Comparable metadata differs. Downloaded bytes and publishers were not verified.",
                **references,
            ))
    row["integrity"] = compared
    integrity_states = [item["status"] for item in compared]
    assessed = sum(state in {"match", "mismatch"} for state in integrity_states)
    status["registry_integrity_mismatch"] = (
        "assessed" if assessed == len(components) else
        "partial" if assessed or "membership_match" in integrity_states else "unassessed"
    )

    if ecosystem == "npm":
        script_status, scripts = inspect_scripts(exact)
        row["lifecycle_scripts"] = scripts
        status["lifecycle_script_indicator"] = (
            "assessed" if script_status == "signal" else script_status
        )
        for script in scripts:
            if script["indicators"]:
                signals.append(_signal(
                    "lifecycle_script_indicator", "medium", "medium",
                    "Static metadata text indicator. Script behavior was not established.",
                    **script,
                ))
    else:
        status["lifecycle_script_indicator"] = "not_applicable"

    # A uv lock sdist is an allowed distribution, not proof that it was installed.
    withdrawn = withdrawal(ecosystem, exact, None)
    status["withdrawn_version"] = "assessed" if withdrawn == "signal" else withdrawn
    if withdrawn == "signal":
        signals.append(_signal(
            "deprecated_version" if ecosystem == "npm" else "yanked_version", "medium", "high",
            "Exact version registry status can change and does not establish malicious behavior.",
        ))

    row["released_at"] = release.published
    row["package_age_basis"] = (
        "registry_created" if release.created else "earliest_observed" if release.earliest else None
    )
    row["package_age_from"] = release.created or release.earliest
    for category, timestamp, days in (
        ("recent_package", row["package_age_from"], thresholds.package_days),
        ("recent_release", release.published, thresholds.release_days),
    ):
        status[category] = "assessed" if timestamp else "unassessed"
        if timestamp and now - timestamp <= timedelta(days=days):
            proxy = category == "recent_package" and not release.created
            signals.append(_signal(
                category, "low", "medium" if proxy else "high",
                "Earliest observed release is a creation-date proxy." if proxy else
                "Recency is a heuristic and does not establish malicious behavior.",
                threshold_days=days,
            ))
    state, count = burst(release, now, thresholds)
    status["release_pattern_anomaly"] = "assessed" if state == "signal" else state
    if state == "signal":
        signals.append(_signal(
            "release_pattern_anomaly", "low", "medium",
            "The heuristic uses distinct stable versions in the currently available history.",
            versions=count, burst_days=thresholds.burst_days, quiet_days=thresholds.quiet_days,
        ))
    row["release_history"] = {
        "stable_versions_observed": len(release.history),
        "timestamps_complete": release.complete_history,
    }
    row["artifacts"] = _metadata(ecosystem, exact)


def assess(
    document: DependencyDocument, registry: Registry, *, lock_root: Path | None = None,
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
) -> dict:
    if len(document.components) > MAX_COMPONENTS:
        raise ValueError("Component count exceeds standalone limit")
    ids = [item.component_id for item in document.components]
    if len(ids) != len(set(ids)) or any(
        not value or len(value) > 256 or not value.isprintable() for value in ids
    ):
        raise ValueError("Invalid or duplicate component IDs")
    groups = defaultdict(list)
    excluded = []
    locks = LockReader(lock_root)
    evidence_by_id = {}
    for component in document.components:
        ecosystem = component.ecosystem
        name = canonical_name(ecosystem, component.name)
        version = exact_version(ecosystem, component.version)
        reason = None
        if ecosystem not in {"npm", "pypi"}:
            reason = "unsupported_ecosystem"
        elif not (name and version and component.resolved):
            reason = "missing_or_invalid_exact_identity"
        if reason is None:
            lock = locks.for_component(component)
            if lock is not None and lock.nonpublic_source:
                reason = "nonpublic_lock_source"
            else:
                evidence_by_id[component.component_id] = lock
        if reason:
            excluded.append({"component_id": component.component_id, "status": reason})
        else:
            groups[(ecosystem, name, version)].append(component)

    started = registry.now()
    rows = []
    coverage = Counter()
    for (ecosystem, name, version), components in groups.items():
        snapshot = registry.get(ecosystem, name)
        row = {
            "ecosystem": ecosystem, "name": name, "version": version,
            "components": [
                {"id": c.component_id, "scope": c.scope, "install_path": c.install_path}
                for c in components
            ],
            "registry": {
                "status": snapshot.status, "url": snapshot.url,
                "observed_at": snapshot.observed_at, "sha256": snapshot.sha256,
            },
            "signals": [], "detectors": dict.fromkeys(DETECTORS, "unassessed"),
        }
        if snapshot.data is not None:
            try:
                release = release_for(snapshot.data, ecosystem, name, version, started)
                _assess(row, release, components, evidence_by_id, started, thresholds)
                for signal in row["signals"]:
                    evidence = signal["evidence"]
                    evidence["registry_record_sha256"] = snapshot.sha256
                    fingerprint = repr((ecosystem, name, version, signal["category"], evidence))
                    signal["signal_id"] = "pkg-risk:" + hashlib.sha256(
                        fingerprint.encode("utf-8", "surrogatepass")
                    ).hexdigest()
            except ValueError as error:
                row["registry"]["status"] = (
                    str(error) if str(error) in {
                        "exact_version_missing", "ambiguous_exact_version",
                        "malformed_exact_version", "malformed_metadata",
                    } else "malformed_metadata"
                )
        detector_states = set(row["detectors"].values()) - {"not_applicable"}
        if snapshot.status in {"network_disabled", "not_authorized", "budget_skipped"}:
            state = "skipped"
        elif detector_states == {"assessed"}:
            state = "assessed"
        elif detector_states & {"partial", "assessed"}:
            state = "partial"
        else:
            state = "unassessed"
        row["assessment_status"] = state
        coverage[state] += len(components)
        rows.append(row)
    return {
        "schema_version": "1.0", "scan_id": document.scan_id,
        "started_at": started, "finished_at": registry.now(),
        "registry_source": registry.source if registry.enabled else "network_disabled",
        "coverage": {
            "eligible": sum(map(len, groups.values())), "excluded": len(excluded),
            **{state: coverage[state] for state in COVERAGE_STATES},
        },
        "request_budget": {
            "requests": registry.requests, "max_requests": registry.budget.requests,
            "max_packages": registry.budget.packages, "seconds": registry.budget.seconds,
            "per_request_seconds": registry.budget.timeout,
            "response_bytes": registry.budget.response_bytes,
        },
        "packages": rows, "excluded": excluded,
        "warnings": ["Normalized input is partial"] if document.partial else [],
    }
