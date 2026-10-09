"""Verify and summarize a bounded contiguous series of path-free offline casefiles.

All inputs are caller-ordered detached observation tuples, not verified host
events, capture times, signed receipts or recovery authorizations. Each
casefile is independently regenerated from the exact original observations.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from staging_timeline_casefiles import build_public_casefile, verify_public_casefile

MIN_SEGMENTS = 2
MAX_SEGMENTS = 8
MAX_SERIES_BYTES = 64 * 1024
_FAILURE = "staging casefile series rejected"


class SeriesError(RuntimeError):
    """One fixed, sanitized failure for malformed or inconsistent input."""


@dataclass(frozen=True, slots=True)
class PublicCasefileSeries:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicCasefileSeries:
    incident: str
    series_sha256: str
    segment_count: int
    hop_count: int
    changed_hops: tuple[int, ...]
    stable_hops: tuple[int, ...]
    net_changed: bool
    revisited_snapshots: tuple[tuple[int, int], ...]
    segment_sha256s: tuple[str, ...]


def _canonical(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _no_duplicates(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise SeriesError(_FAILURE)
        result[key] = value
    return result


def _valid_digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _revisited(hashes: tuple[str, ...]) -> tuple[tuple[int, int], ...]:
    first_seen = {hashes[0]: 0}
    revisits = []
    for index in range(1, len(hashes)):
        digest = hashes[index]
        if digest in first_seen and digest != hashes[index - 1]:
            revisits.append((index, first_seen[digest]))
        first_seen.setdefault(digest, index)
    return tuple(revisits)


def _compute(
    segments: object,
) -> tuple[PublicCasefileSeries, VerifiedPublicCasefileSeries]:
    if (
        type(segments) is not tuple
        or not MIN_SEGMENTS <= len(segments) <= MAX_SEGMENTS
        or any(type(s) is not tuple or not 2 <= len(s) <= 17 for s in segments)
    ):
        raise SeriesError(_FAILURE)

    incident = None
    snapshot_hashes: list[str] = []
    changed_hops: list[int] = []
    stable_hops: list[int] = []
    segment_records = []
    segment_sha256s = []
    totals = {"added_count": 0, "removed_count": 0, "modified_count": 0}
    offset = 0

    for index, snapshots in enumerate(segments):
        # The public path reconstructs sealed pairwise sources and verified
        # path-free summary; it never calls the sensitive path-bearing audit.
        public = build_public_casefile(snapshots)
        verified = verify_public_casefile(snapshots, public.payload, expected_sha256=public.sha256)
        casefile = json.loads(public.payload.decode("ascii"))
        timeline = casefile["timeline"]
        summary = casefile["summary"]
        hashes = tuple(timeline["snapshot_sha256s"])
        if (
            verified.incident != timeline["incident"]
            or summary["incident"] != timeline["incident"]
            or verified.changed_hops != tuple(timeline["changed_hops"])
            or len(hashes) != len(snapshots)
            or len(summary["hops"]) != len(snapshots) - 1
            or (incident is not None and incident != verified.incident)
            or (snapshot_hashes and snapshot_hashes[-1] != hashes[0])
        ):
            raise SeriesError(_FAILURE)
        if incident is None:
            incident = verified.incident
            snapshot_hashes.append(hashes[0])
        snapshot_hashes.extend(hashes[1:])

        # These counts and flags originate in the verified, path-free
        # public summary, not arbitrary caller-provided aggregate labels.
        counts = {key: 0 for key in totals}
        local_changed = []
        for hop_index, hop in enumerate(summary["hops"]):
            changed = hop["changed"]
            if changed:
                changed_hops.append(offset + hop_index)
                local_changed.append(hop_index)
            else:
                stable_hops.append(offset + hop_index)
            for key in totals:
                counts[key] += hop[key]
                totals[key] += hop[key]
        if tuple(local_changed) != verified.changed_hops:
            raise SeriesError(_FAILURE)
        segment_records.append(
            {
                "index": index,
                "public_casefile_sha256": public.sha256,
                "timeline_sha256": verified.timeline_sha256,
                "summary_sha256": verified.summary_sha256,
                "start_snapshot_sha256": hashes[0],
                "end_snapshot_sha256": hashes[-1],
                "hop_count": len(hashes) - 1,
                "changed_hops": local_changed,
                **counts,
            }
        )
        segment_sha256s.append(public.sha256)
        offset += len(hashes) - 1

    global_hashes = tuple(snapshot_hashes)
    revisits = _revisited(global_hashes)
    net_changed = global_hashes[0] != global_hashes[-1]
    document = {
        "schema_version": 1,
        "audience": "public",
        "incident": incident,
        "segment_count": len(segments),
        "hop_count": offset,
        "snapshot_sha256s": global_hashes,
        "segments": segment_records,
        "changed_hops": changed_hops,
        "stable_hops": stable_hops,
        "aggregate": totals,
        "net_changed": net_changed,
        "revisited_snapshots": [
            {"snapshot_index": current, "first_matching_index": first}
            for current, first in revisits
        ],
    }
    raw = _canonical(document)
    if not 1 <= len(raw) <= MAX_SERIES_BYTES:
        raise SeriesError(_FAILURE)
    sha256 = hashlib.sha256(raw).hexdigest()
    return PublicCasefileSeries(raw, sha256), VerifiedPublicCasefileSeries(
        incident=incident,
        series_sha256=sha256,
        segment_count=len(segments),
        hop_count=offset,
        changed_hops=tuple(changed_hops),
        stable_hops=tuple(stable_hops),
        net_changed=net_changed,
        revisited_snapshots=revisits,
        segment_sha256s=tuple(segment_sha256s),
    )


def build_verified_public_casefile_series(
    segments: object,
) -> tuple[PublicCasefileSeries, VerifiedPublicCasefileSeries]:
    """Build one source-sealed public casefile series and its verified facts.

    This is one complete validation pass, not a shortcut around verification.
    Every source snapshot, pair seal, incident selector and segment is checked.
    """
    try:
        return _compute(segments)
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise SeriesError(_FAILURE) from None


def build_public_casefile_series(segments: object) -> PublicCasefileSeries:
    """Stitch 2–8 public casefiles with exact shared endpoint fingerprints."""
    return build_verified_public_casefile_series(segments)[0]


def verify_public_casefile_series(
    segments: object, raw: object, *, expected_sha256: object
) -> VerifiedPublicCasefileSeries:
    """Recreate every public casefile, enforce boundaries and compare exact bytes."""
    try:
        if (
            type(raw) is not bytes
            or not 1 <= len(raw) <= MAX_SERIES_BYTES
            or not _valid_digest(expected_sha256)
            or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
        ):
            raise SeriesError(_FAILURE)
        parsed = json.loads(raw.decode("ascii"), object_pairs_hook=_no_duplicates)
        if type(parsed) is not dict or raw != _canonical(parsed):
            raise SeriesError(_FAILURE)
        expected, checked = _compute(segments)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise SeriesError(_FAILURE)
        return checked
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise SeriesError(_FAILURE) from None
