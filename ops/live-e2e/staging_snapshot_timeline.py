"""Bounded deterministic multi-hop offline snapshot timeline, no provenance.

Each adjacent snapshot pair must satisfy the already-reviewed canonical
drift binding AND exact ordered snapshot content seal. A timeline joins
them into a reproducible portable manifest of *caller-supplied* data;
it conveys neither producer authentication nor any host/recovery authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from staging_drift_binding import build_detached_drift_artifact
from staging_snapshot_seal import (
    build_snapshot_pair_seal,
    verify_snapshot_pair_seal,
)

MAX_HOPS = 16
MAX_MANIFEST_BYTES = 8192
_FAILURE = "staging snapshot timeline rejected"
_KEYS = frozenset(
    {
        "schema_version",
        "incident",
        "snapshot_sha256s",
        "drift_artifact_sha256s",
        "seal_sha256s",
        "changed_hops",
    }
)


class TimelineError(RuntimeError):
    """Fail-closed, fixed error; no host read or recovery power."""


@dataclass(frozen=True, slots=True)
class TimelineHop:
    drift_payload: bytes
    drift_sha256: str
    seal_payload: bytes
    seal_sha256: str


@dataclass(frozen=True, slots=True)
class TimelineManifest:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class BuiltSnapshotTimeline:
    hops: tuple[TimelineHop, ...]
    manifest: TimelineManifest


@dataclass(frozen=True, slots=True)
class VerifiedSnapshotTimeline:
    incident: str
    snapshot_sha256s: tuple[str, ...]
    drift_artifact_sha256s: tuple[str, ...]
    seal_sha256s: tuple[str, ...]
    changed_hops: tuple[int, ...]
    timeline_sha256: str


def _snapshots_valid(snapshots: object) -> bool:
    return type(snapshots) is tuple and 2 <= len(snapshots) <= MAX_HOPS + 1


def _digest_valid(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _canonical(payload: dict) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in items:
        if name in result:
            raise TimelineError(_FAILURE)
        result[name] = value
    return result


def _compute_timeline(
    snapshots: tuple, hops: tuple
) -> tuple[TimelineManifest, VerifiedSnapshotTimeline]:
    if (
        not _snapshots_valid(snapshots)
        or type(hops) is not tuple
        or len(hops) != len(snapshots) - 1
    ):
        raise TimelineError(_FAILURE)

    snapshot_hashes = []
    drift_hashes = []
    seal_hashes = []
    changed_hops = []
    selector = None

    for index, hop in enumerate(hops):
        if type(hop) is not TimelineHop:
            raise TimelineError(_FAILURE)
        checked = verify_snapshot_pair_seal(
            snapshots[index],
            snapshots[index + 1],
            hop.drift_payload,
            hop.drift_sha256,
            hop.seal_payload,
            hop.seal_sha256,
        )
        if selector is None:
            selector = checked.drift_report.incident
            snapshot_hashes.append(checked.before_snapshot_sha256)
        if checked.drift_report.incident != selector:
            raise TimelineError(_FAILURE)
        snapshot_hashes.append(checked.after_snapshot_sha256)
        drift_hashes.append(hop.drift_sha256)
        seal_hashes.append(checked.seal_sha256)
        if checked.drift_report.has_drift:
            changed_hops.append(index)

    payload = _canonical(
        {
            "schema_version": 1,
            "incident": selector,
            "snapshot_sha256s": snapshot_hashes,
            "drift_artifact_sha256s": drift_hashes,
            "seal_sha256s": seal_hashes,
            "changed_hops": changed_hops,
        }
    )
    if not 1 <= len(payload) <= MAX_MANIFEST_BYTES:
        raise TimelineError(_FAILURE)
    sha = hashlib.sha256(payload).hexdigest()
    return TimelineManifest(payload=payload, sha256=sha), VerifiedSnapshotTimeline(
        incident=selector,
        snapshot_sha256s=tuple(snapshot_hashes),
        drift_artifact_sha256s=tuple(drift_hashes),
        seal_sha256s=tuple(seal_hashes),
        changed_hops=tuple(changed_hops),
        timeline_sha256=sha,
    )


def build_snapshot_timeline(snapshots: object) -> BuiltSnapshotTimeline:
    """Generate every adjacent offline hop and one deterministic manifest."""
    try:
        if not _snapshots_valid(snapshots):
            raise TimelineError(_FAILURE)
        hops = []
        for index in range(len(snapshots) - 1):
            drift = build_detached_drift_artifact(snapshots[index], snapshots[index + 1])
            seal = build_snapshot_pair_seal(
                snapshots[index], snapshots[index + 1], drift.payload, drift.sha256
            )
            hops.append(
                TimelineHop(
                    drift_payload=drift.payload,
                    drift_sha256=drift.sha256,
                    seal_payload=seal.payload,
                    seal_sha256=seal.sha256,
                )
            )
        typed_hops = tuple(hops)
        manifest, _verified = _compute_timeline(snapshots, typed_hops)
        return BuiltSnapshotTimeline(hops=typed_hops, manifest=manifest)
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise TimelineError(_FAILURE) from None


def verify_snapshot_timeline(
    snapshots: object,
    hops: object,
    manifest_raw: object,
    *,
    expected_sha256: object,
) -> VerifiedSnapshotTimeline:
    """Verify bounded canonical multi-hop manifest against exact supplied sources.

    A fully replaced coherent tuple also verifies; an unkeyed SHA-256 is
    content integrity, not trusted live provenance, freshness or authorization.
    """
    try:
        if (
            type(manifest_raw) is not bytes
            or not 1 <= len(manifest_raw) <= MAX_MANIFEST_BYTES
            or not _digest_valid(expected_sha256)
            or not hmac.compare_digest(hashlib.sha256(manifest_raw).hexdigest(), expected_sha256)
        ):
            raise TimelineError(_FAILURE)
        parsed = json.loads(manifest_raw.decode("ascii"), object_pairs_hook=_pairs)
        if type(parsed) is not dict or set(parsed) != _KEYS:
            raise TimelineError(_FAILURE)
        expected, verified = _compute_timeline(snapshots, hops)
        if not hmac.compare_digest(expected.payload, manifest_raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise TimelineError(_FAILURE)
        return verified
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise TimelineError(_FAILURE) from None
