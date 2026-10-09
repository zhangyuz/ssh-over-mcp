"""Bounded offline timeline change audit over untrusted supplied snapshots.

The report describes exact caller-ordered data only, without authenticated
producer identity, chronology, host access, or recovery authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from staging_snapshot_seal import verify_snapshot_pair_seal
from staging_snapshot_timeline import verify_snapshot_timeline

MAX_AUDIT_BYTES = 131072
_FAILURE = "staging timeline audit rejected"
_KEYS = frozenset(
    {
        "schema_version",
        "incident",
        "timeline_sha256",
        "net_changed",
        "changed_hops",
        "stable_hops",
        "revisited_snapshots",
        "hops",
    }
)


class AuditError(RuntimeError):
    """Fixed sanitized refusal for mismatched offline data."""


@dataclass(frozen=True, slots=True)
class TimelineAudit:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class HopAudit:
    index: int
    before_snapshot_sha256: str
    after_snapshot_sha256: str
    drift_artifact_sha256: str
    has_drift: bool
    marker_changed: bool
    parent_changed: bool
    selected_metadata_changed: bool
    added_paths: tuple[str, ...]
    removed_paths: tuple[str, ...]
    modified_entries: tuple[tuple[str, tuple[str, ...]], ...]


@dataclass(frozen=True, slots=True)
class VerifiedTimelineAudit:
    incident: str
    timeline_sha256: str
    audit_sha256: str
    net_changed: bool
    changed_hops: tuple[int, ...]
    stable_hops: tuple[int, ...]
    revisited_snapshots: tuple[tuple[int, int], ...]
    hops: tuple[HopAudit, ...]


def _canonical(value: dict) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in items:
        if name in result:
            raise AuditError(_FAILURE)
        result[name] = value
    return result


def _digest_valid(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _compute(
    snapshots: object, hops: object, manifest_raw: object, timeline_sha256: object
) -> tuple[TimelineAudit, VerifiedTimelineAudit]:
    verified = verify_snapshot_timeline(
        snapshots, hops, manifest_raw, expected_sha256=timeline_sha256
    )
    # Snapshot indices describe caller order, not acquisition time.
    hashes = verified.snapshot_sha256s
    first_seen = {hashes[0]: 0}
    revisited = []
    for index in range(1, len(hashes)):
        digest = hashes[index]
        if digest in first_seen and digest != hashes[index - 1]:
            revisited.append((index, first_seen[digest]))
        first_seen.setdefault(digest, index)

    details = []
    for index, hop in enumerate(hops):
        checked = verify_snapshot_pair_seal(
            snapshots[index],
            snapshots[index + 1],
            hop.drift_payload,
            hop.drift_sha256,
            hop.seal_payload,
            hop.seal_sha256,
        )
        if (
            checked.before_snapshot_sha256 != hashes[index]
            or checked.after_snapshot_sha256 != hashes[index + 1]
            or checked.seal_sha256 != verified.seal_sha256s[index]
        ):
            raise AuditError(_FAILURE)
        drift = checked.drift_report
        details.append(
            HopAudit(
                index=index,
                before_snapshot_sha256=hashes[index],
                after_snapshot_sha256=hashes[index + 1],
                drift_artifact_sha256=verified.drift_artifact_sha256s[index],
                has_drift=drift.has_drift,
                marker_changed=drift.marker_changed,
                parent_changed=drift.parent_changed,
                selected_metadata_changed=drift.selected_metadata_changed,
                added_paths=drift.added_paths,
                removed_paths=drift.removed_paths,
                modified_entries=tuple(
                    (entry.path, entry.changed_fields) for entry in drift.modified_entries
                ),
            )
        )

    stable = tuple(index for index, hop in enumerate(details) if not hop.has_drift)
    if tuple(index for index, hop in enumerate(details) if hop.has_drift) != verified.changed_hops:
        raise AuditError(_FAILURE)
    net_changed = hashes[0] != hashes[-1]
    document = {
        "schema_version": 1,
        "incident": verified.incident,
        "timeline_sha256": verified.timeline_sha256,
        "net_changed": net_changed,
        "changed_hops": list(verified.changed_hops),
        "stable_hops": list(stable),
        "revisited_snapshots": [
            {"snapshot_index": index, "first_matching_index": first} for index, first in revisited
        ],
        "hops": [
            {
                "index": hop.index,
                "before_snapshot_sha256": hop.before_snapshot_sha256,
                "after_snapshot_sha256": hop.after_snapshot_sha256,
                "drift_artifact_sha256": hop.drift_artifact_sha256,
                "has_drift": hop.has_drift,
                "marker_changed": hop.marker_changed,
                "parent_changed": hop.parent_changed,
                "selected_metadata_changed": hop.selected_metadata_changed,
                "added_paths": list(hop.added_paths),
                "removed_paths": list(hop.removed_paths),
                "modified_entries": [
                    {"path": path, "changed_fields": list(fields)}
                    for path, fields in hop.modified_entries
                ],
            }
            for hop in details
        ],
    }
    raw = _canonical(document)
    if not 1 <= len(raw) <= MAX_AUDIT_BYTES:
        raise AuditError(_FAILURE)
    sha = hashlib.sha256(raw).hexdigest()
    return TimelineAudit(raw, sha), VerifiedTimelineAudit(
        incident=verified.incident,
        timeline_sha256=verified.timeline_sha256,
        audit_sha256=sha,
        net_changed=net_changed,
        changed_hops=verified.changed_hops,
        stable_hops=stable,
        revisited_snapshots=tuple(revisited),
        hops=tuple(details),
    )


def build_timeline_audit(
    snapshots: object, hops: object, manifest_raw: object, *, expected_timeline_sha256: object
) -> TimelineAudit:
    """Build a deterministic report after revalidating each supplied hop."""
    try:
        audit, _verified = _compute(snapshots, hops, manifest_raw, expected_timeline_sha256)
        return audit
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise AuditError(_FAILURE) from None


def verify_timeline_audit(
    snapshots: object,
    hops: object,
    manifest_raw: object,
    audit_raw: object,
    *,
    expected_timeline_sha256: object,
    expected_audit_sha256: object,
) -> VerifiedTimelineAudit:
    """Reject any report not exactly reproducible from the supplied chain.

    All checksums are unkeyed content hashes, not trusted proof of origin.
    """
    try:
        if (
            type(audit_raw) is not bytes
            or not 1 <= len(audit_raw) <= MAX_AUDIT_BYTES
            or not _digest_valid(expected_audit_sha256)
            or not hmac.compare_digest(hashlib.sha256(audit_raw).hexdigest(), expected_audit_sha256)
        ):
            raise AuditError(_FAILURE)
        parsed = json.loads(audit_raw.decode("ascii"), object_pairs_hook=_pairs)
        if type(parsed) is not dict or set(parsed) != _KEYS:
            raise AuditError(_FAILURE)
        expected, verified = _compute(snapshots, hops, manifest_raw, expected_timeline_sha256)
        if not hmac.compare_digest(expected.payload, audit_raw) or not hmac.compare_digest(
            expected.sha256, expected_audit_sha256
        ):
            raise AuditError(_FAILURE)
        return verified
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise AuditError(_FAILURE) from None
