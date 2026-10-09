"""Canonical offline snapshot-pair content seal, NOT an authenticated receipt.

A v1 drift report intentionally loses individual non-wire marker metadata
values. This separate bounded v1 seal retains SHA-256 fingerprints of *all*
supplied metadata in each independently projected snapshot and binds their
order to the drift artifact. It does not make snapshots trusted or fresh.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from staging_drift import DetachedDriftReport
from staging_drift_binding import verify_detached_drift_artifact
from staging_projection import project_detached_inventory

_FAILURE = "staging snapshot seal rejected"
_DOMAIN = b"ssh-over-mcp:detached-snapshot-content:v1\x00"
_MAX_SEAL_BYTES = 1024
_META = ("device", "inode", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns")
_KEYS = frozenset(
    {
        "schema_version",
        "incident",
        "before_snapshot_sha256",
        "after_snapshot_sha256",
        "drift_artifact_sha256",
    }
)


class SnapshotSealError(RuntimeError):
    """Fixed sanitized refusal with no recovery or inspection authority."""


@dataclass(frozen=True, slots=True)
class SnapshotPairSeal:
    """Portable canonical *content* bytes/checksum, not signed provenance."""

    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedSnapshotPair:
    """Internally coherent caller-provided data, never authenticated capture."""

    drift_report: DetachedDriftReport
    before_snapshot_sha256: str
    after_snapshot_sha256: str
    seal_sha256: str


def _canonical(value: dict) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _source_fingerprint(observation: object) -> str:
    # Projector validates all record types, incident catalog, exact marker
    # invariants, expected-commit binding and canonical inventory bounds.
    projection = project_detached_inventory(observation)
    marker = observation.marker_metadata
    expected = observation.selected.expected_metadata
    # The inventory wire omits some marker metadata. Preserve all nine
    # exact checked integer scalar values, even ones not emitted on wire.
    extra = _canonical(
        {
            "marker_metadata": {field: getattr(marker, field) for field in _META},
            "selected_expected_metadata": {field: getattr(expected, field) for field in _META},
        }
    )
    digest = hashlib.sha256()
    digest.update(_DOMAIN)
    digest.update(len(projection.payload).to_bytes(8, byteorder="big"))
    digest.update(projection.payload)
    digest.update(len(extra).to_bytes(4, byteorder="big"))
    digest.update(extra)
    return digest.hexdigest()


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in items:
        if name in result:
            raise SnapshotSealError(_FAILURE)
        result[name] = value
    return result


def _digest_valid(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _make_payload(
    before: object, after: object, report: DetachedDriftReport, artifact_sha: str
) -> SnapshotPairSeal:
    raw = _canonical(
        {
            "schema_version": 1,
            "incident": report.incident,
            "before_snapshot_sha256": _source_fingerprint(before),
            "after_snapshot_sha256": _source_fingerprint(after),
            "drift_artifact_sha256": artifact_sha,
        }
    )
    if not 1 <= len(raw) <= _MAX_SEAL_BYTES:
        raise SnapshotSealError(_FAILURE)
    return SnapshotPairSeal(payload=raw, sha256=hashlib.sha256(raw).hexdigest())


def build_snapshot_pair_seal(
    before: object, after: object, artifact_raw: object, artifact_sha256: object
) -> SnapshotPairSeal:
    """Seal ordered, supplied offline snapshots to a verified v1 drift artifact."""
    try:
        checked = verify_detached_drift_artifact(
            before, after, artifact_raw, expected_sha256=artifact_sha256
        )
        return _make_payload(before, after, checked.report, checked.artifact_sha256)
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise SnapshotSealError(_FAILURE) from None


def verify_snapshot_pair_seal(
    before: object,
    after: object,
    artifact_raw: object,
    artifact_sha256: object,
    seal_raw: object,
    seal_sha256: object,
) -> VerifiedSnapshotPair:
    """Check both ordered snapshot contents and exact drift artifact binding.

    A valid result proves matching supplied bytes and records only; an
    attacker who replaces the entire snapshot/artifact/seal tuple can still
    produce valid content hashes. No producer identity is authenticated.
    """
    try:
        if (
            type(seal_raw) is not bytes
            or not 1 <= len(seal_raw) <= _MAX_SEAL_BYTES
            or not _digest_valid(seal_sha256)
            or not hmac.compare_digest(hashlib.sha256(seal_raw).hexdigest(), seal_sha256)
        ):
            raise SnapshotSealError(_FAILURE)

        payload = json.loads(seal_raw.decode("ascii"), object_pairs_hook=_pairs)
        if (
            type(payload) is not dict
            or set(payload) != _KEYS
            or type(payload["schema_version"]) is not int
            or payload["schema_version"] != 1
            or type(payload["incident"]) is not str
            or payload["incident"] not in {"stale-target", "older-target"}
            or any(
                not _digest_valid(payload[name])
                for name in (
                    "before_snapshot_sha256",
                    "after_snapshot_sha256",
                    "drift_artifact_sha256",
                )
            )
            or _canonical(payload) != seal_raw
        ):
            raise SnapshotSealError(_FAILURE)

        checked = verify_detached_drift_artifact(
            before, after, artifact_raw, expected_sha256=artifact_sha256
        )
        expected = _make_payload(before, after, checked.report, checked.artifact_sha256)
        if not hmac.compare_digest(expected.payload, seal_raw) or not hmac.compare_digest(
            expected.sha256, seal_sha256
        ):
            raise SnapshotSealError(_FAILURE)
        return VerifiedSnapshotPair(
            drift_report=checked.report,
            before_snapshot_sha256=payload["before_snapshot_sha256"],
            after_snapshot_sha256=payload["after_snapshot_sha256"],
            seal_sha256=expected.sha256,
        )
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise SnapshotSealError(_FAILURE) from None
