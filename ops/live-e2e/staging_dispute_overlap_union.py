"""Canonical public union coverage for source-derived dispute hop ranges.

Union counts are deterministic offline navigation, not trusted chronology,
incident severity, provenance, authorization or native provider state.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_dispute_index as index

MAX_DISPUTE_OVERLAP_UNION_RANGES = 8
MAX_PUBLIC_DISPUTE_OVERLAP_UNION_BYTES = 4 * 1024
_FAILURE = "staging dispute overlap union rejected"


class DisputeOverlapUnionError(RuntimeError):
    """Fixed nonsensitive rejection of invalid or forged union output."""


@dataclass(frozen=True, slots=True)
class PublicDisputeOverlapUnion:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicDisputeOverlapUnion:
    public_sha256: str
    source_index_sha256: str
    query_ranges: tuple[tuple[int, int], ...]
    merged_ranges: tuple[tuple[int, int], ...]
    requested_hops: int
    matched_windows: int
    matched_hops: int


def _canonical(body: dict) -> bytes:
    return json.dumps(
        body, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    body = {}
    for key, value in pairs:
        if key in body:
            raise DisputeOverlapUnionError(_FAILURE)
        body[key] = value
    return body


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_OVERLAP_UNION_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise DisputeOverlapUnionError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise DisputeOverlapUnionError(_FAILURE)
    return body


def _compute(
    runs: object, queries: object
) -> tuple[PublicDisputeOverlapUnion, VerifiedPublicDisputeOverlapUnion]:
    if type(queries) not in (tuple, list):
        raise DisputeOverlapUnionError(_FAILURE)
    # Bounded immutable snapshots avoid validation/use races on caller lists.
    outer = tuple(queries[: MAX_DISPUTE_OVERLAP_UNION_RANGES + 1])
    if not 1 <= len(outer) <= MAX_DISPUTE_OVERLAP_UNION_RANGES:
        raise DisputeOverlapUnionError(_FAILURE)
    frozen = []
    for item in outer:
        if type(item) not in (tuple, list):
            raise DisputeOverlapUnionError(_FAILURE)
        frozen.append(tuple(item[:3]))
    selected = tuple(frozen)
    if any(
        len(pair) != 2
        or type(pair[0]) is not int
        or type(pair[1]) is not int
        or pair[0] < 0
        or pair[1] <= pair[0]
        for pair in selected
    ):
        raise DisputeOverlapUnionError(_FAILURE)

    # One source-index rebuild per call, not a caller-provided digest/cache.
    original = index.build_public_dispute_index(runs)
    source = json.loads(original.payload.decode("ascii"))
    if any(end > source["hop_count"] for _, end in selected):
        raise DisputeOverlapUnionError(_FAILURE)

    merged: list[tuple[int, int]] = []
    for start, end in sorted(selected):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            prev_start, prev_end = merged[-1]
            merged[-1] = (prev_start, max(prev_end, end))
    ranges = tuple(merged)
    requested = sum(end - start for start, end in ranges)
    count = 0
    disputed = 0
    for window in source["ranked_windows"]:
        covered = sum(
            max(
                0,
                min(end, window["end_hop_exclusive"]) - max(start, window["start_hop"]),
            )
            for start, end in ranges
        )
        if covered:
            count += 1
            disputed += covered
    if disputed > requested or count > source["window_count"]:
        raise DisputeOverlapUnionError(_FAILURE)

    body = {
        "schema_version": 1,
        "audience": "public",
        "incident": source["incident"],
        "source_dispute_index_sha256": original.sha256,
        "hop_count": source["hop_count"],
        "window_count": source["window_count"],
        "queries": [{"start_hop": start, "end_hop_exclusive": end} for start, end in selected],
        "merged_ranges": [{"start_hop": start, "end_hop_exclusive": end} for start, end in ranges],
        "requested_hops": requested,
        "matched_window_count": count,
        "matched_disputed_hops": disputed,
        "unmatched_hops": requested - disputed,
    }
    raw = _canonical(body)
    if not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_OVERLAP_UNION_BYTES:
        raise DisputeOverlapUnionError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return (
        PublicDisputeOverlapUnion(raw, digest),
        VerifiedPublicDisputeOverlapUnion(
            public_sha256=digest,
            source_index_sha256=original.sha256,
            query_ranges=selected,
            merged_ranges=ranges,
            requested_hops=requested,
            matched_windows=count,
            matched_hops=disputed,
        ),
    )


def build_public_dispute_overlap_union(runs: object, queries: object) -> PublicDisputeOverlapUnion:
    """Return a bounded canonical disputed-coverage union from original sources."""
    try:
        return _compute(runs, queries)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeOverlapUnionError(_FAILURE) from None


def verify_public_dispute_overlap_union(
    runs: object, queries: object, raw: object, *, expected_sha256: object
) -> VerifiedPublicDisputeOverlapUnion:
    """Independently rebuild and verify byte-exact canonical union coverage."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs, queries)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise DisputeOverlapUnionError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeOverlapUnionError(_FAILURE) from None
