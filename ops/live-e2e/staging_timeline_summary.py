"""Bounded offline timeline change summary; content verification, not provenance.

Summarizes *independently verified* ordered caller-supplied timeline hops as
counts and classification flags. It never captures host state, exposes raw
inventory paths/metadata, or grants recovery/inspection authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass

from staging_drift_artifact import decode_detached_drift
from staging_snapshot_timeline import verify_snapshot_timeline

MAX_SUMMARY_BYTES = 16 * 1024
_FAILURE = "staging timeline summary rejected"


class TimelineSummaryError(RuntimeError):
    """Fixed sanitized rejection, including malformed/untrusted summary input."""


@dataclass(frozen=True, slots=True)
class HopChange:
    index: int
    before_snapshot_sha256: str
    after_snapshot_sha256: str
    drift_artifact_sha256: str
    seal_sha256: str
    changed: bool
    marker_changed: bool
    parent_changed: bool
    selected_metadata_changed: bool
    inventory_changed: bool
    added_count: int
    removed_count: int
    modified_count: int


@dataclass(frozen=True, slots=True)
class TimelineChangeSummary:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedTimelineChangeSummary:
    incident: str
    timeline_sha256: str
    summary_sha256: str
    changed_hops: tuple[int, ...]
    hops: tuple[HopChange, ...]


def _canonical(value: dict) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _no_duplicates(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise TimelineSummaryError(_FAILURE)
        result[key] = value
    return result


def _valid_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _make_summary(
    snapshots: object,
    hops: object,
    manifest_raw: object,
    expected_timeline_sha256: object,
) -> tuple[TimelineChangeSummary, VerifiedTimelineChangeSummary]:
    # This checks exact types, canonical manifest bytes/digest, every
    # independent neighboring pair, and all full-metadata content seals.
    verified = verify_snapshot_timeline(
        snapshots, hops, manifest_raw, expected_sha256=expected_timeline_sha256
    )
    changes = []
    for index, hop in enumerate(hops):
        # Already source-bound above. Strict decode only extracts verified
        # public drift flags and path counts, never raw path/value content.
        report = decode_detached_drift(hop.drift_payload, expected_sha256=hop.drift_sha256)
        changes.append(
            HopChange(
                index=index,
                before_snapshot_sha256=verified.snapshot_sha256s[index],
                after_snapshot_sha256=verified.snapshot_sha256s[index + 1],
                drift_artifact_sha256=verified.drift_artifact_sha256s[index],
                seal_sha256=verified.seal_sha256s[index],
                changed=report.has_drift,
                marker_changed=report.marker_changed,
                parent_changed=report.parent_changed,
                selected_metadata_changed=report.selected_metadata_changed,
                inventory_changed=report.before_sha256 != report.after_sha256,
                added_count=len(report.added_paths),
                removed_count=len(report.removed_paths),
                modified_count=len(report.modified_entries),
            )
        )
    if tuple(hop.index for hop in changes if hop.changed) != verified.changed_hops:
        raise TimelineSummaryError(_FAILURE)
    payload = _canonical(
        {
            "schema_version": 1,
            "incident": verified.incident,
            "timeline_sha256": verified.timeline_sha256,
            "changed_hops": verified.changed_hops,
            "hops": [asdict(hop) for hop in changes],
        }
    )
    if not 1 <= len(payload) <= MAX_SUMMARY_BYTES:
        raise TimelineSummaryError(_FAILURE)
    digest = hashlib.sha256(payload).hexdigest()
    return TimelineChangeSummary(payload, digest), VerifiedTimelineChangeSummary(
        incident=verified.incident,
        timeline_sha256=verified.timeline_sha256,
        summary_sha256=digest,
        changed_hops=verified.changed_hops,
        hops=tuple(changes),
    )


def build_timeline_change_summary(
    snapshots: object,
    hops: object,
    manifest_raw: object,
    *,
    expected_timeline_sha256: object,
) -> TimelineChangeSummary:
    """Produce canonical path-free counts/flags from a fully verified timeline."""
    try:
        summary, _verified = _make_summary(snapshots, hops, manifest_raw, expected_timeline_sha256)
        return summary
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise TimelineSummaryError(_FAILURE) from None


def verify_timeline_change_summary(
    snapshots: object,
    hops: object,
    manifest_raw: object,
    summary_raw: object,
    *,
    expected_timeline_sha256: object,
    expected_summary_sha256: object,
) -> VerifiedTimelineChangeSummary:
    """Reject forged summaries, even if their unkeyed digest was recalculated."""
    try:
        if (
            type(summary_raw) is not bytes
            or not 1 <= len(summary_raw) <= MAX_SUMMARY_BYTES
            or not _valid_sha256(expected_summary_sha256)
            or not hmac.compare_digest(
                hashlib.sha256(summary_raw).hexdigest(), expected_summary_sha256
            )
        ):
            raise TimelineSummaryError(_FAILURE)
        parsed = json.loads(summary_raw.decode("ascii"), object_pairs_hook=_no_duplicates)
        if type(parsed) is not dict:
            raise TimelineSummaryError(_FAILURE)
        expected, verified = _make_summary(snapshots, hops, manifest_raw, expected_timeline_sha256)
        if not hmac.compare_digest(expected.payload, summary_raw) or not hmac.compare_digest(
            expected.sha256, expected_summary_sha256
        ):
            raise TimelineSummaryError(_FAILURE)
        return verified
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise TimelineSummaryError(_FAILURE) from None
