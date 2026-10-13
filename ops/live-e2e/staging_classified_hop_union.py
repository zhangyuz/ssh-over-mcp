"""Canonical public union of classified hops across bounded original-source queries.

Union totals count each original hop exactly once, not once per input query.
The counts are public navigation, never a certified safety or trust signal.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_consensus_intervals as intervals

MAX_CLASSIFIED_HOP_UNION_RANGES = 8
MAX_PUBLIC_CLASSIFIED_HOP_UNION_BYTES = 4 * 1024
_FAILURE = "staging classified hop union rejected"
_CLASSES = ("unanimous", "majority", "disputed")


class ClassifiedHopUnionError(RuntimeError):
    """Fixed sanitized error for an invalid or inconsistent public union."""


@dataclass(frozen=True, slots=True)
class PublicClassifiedHopUnion:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicClassifiedHopUnion:
    public_sha256: str
    source_intervals_sha256: str
    query_ranges: tuple[tuple[int, int], ...]
    merged_ranges: tuple[tuple[int, int], ...]
    classified_hops: tuple[int, int, int]


def _canonical(body: dict) -> bytes:
    return json.dumps(
        body, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    body = {}
    for key, value in pairs:
        if key in body:
            raise ClassifiedHopUnionError(_FAILURE)
        body[key] = value
    return body


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_CLASSIFIED_HOP_UNION_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise ClassifiedHopUnionError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise ClassifiedHopUnionError(_FAILURE)
    return body


def _compute(
    runs: object, queries: object
) -> tuple[PublicClassifiedHopUnion, VerifiedPublicClassifiedHopUnion]:
    if type(queries) not in (tuple, list):
        raise ClassifiedHopUnionError(_FAILURE)
    # Bounded freeze of every caller-mutable level before shape/value checks.
    outer = tuple(queries[: MAX_CLASSIFIED_HOP_UNION_RANGES + 1])
    if not 1 <= len(outer) <= MAX_CLASSIFIED_HOP_UNION_RANGES:
        raise ClassifiedHopUnionError(_FAILURE)
    frozen = []
    for pair in outer:
        if type(pair) not in (list, tuple):
            raise ClassifiedHopUnionError(_FAILURE)
        frozen.append(tuple(pair[:3]))
    selected = tuple(frozen)
    if any(
        len(pair) != 2
        or type(pair[0]) is not int
        or type(pair[1]) is not int
        or pair[0] < 0
        or pair[1] <= pair[0]
        for pair in selected
    ):
        raise ClassifiedHopUnionError(_FAILURE)

    # Full public intervals rebuilt exactly once per independent call.
    # Never accept caller-supplied detached intervals or cached digests.
    public = intervals.build_public_intervals(runs)
    source = json.loads(public.payload.decode("ascii"))
    if any(end > source["hop_count"] for _, end in selected):
        raise ClassifiedHopUnionError(_FAILURE)

    merged: list[tuple[int, int]] = []
    for start, end in sorted(selected):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
    counts = {kind: 0 for kind in _CLASSES}
    for start, end in merged:
        for interval in source["intervals"]:
            clip_start = max(start, interval["start_hop"])
            clip_end = min(end, interval["end_hop_exclusive"])
            if clip_end > clip_start:
                counts[interval["classification"]] += clip_end - clip_start
    unique_hops = sum(end - start for start, end in merged)
    if sum(counts.values()) != unique_hops:
        raise ClassifiedHopUnionError(_FAILURE)

    body = {
        "schema_version": 1,
        "audience": "public",
        "incident": source["incident"],
        "hop_count": source["hop_count"],
        "source_intervals_sha256": public.sha256,
        "queries": [{"start_hop": start, "end_hop_exclusive": end} for start, end in selected],
        "merged_ranges": [{"start_hop": start, "end_hop_exclusive": end} for start, end in merged],
        "unique_hops": unique_hops,
        "unanimous_hops": counts["unanimous"],
        "majority_hops": counts["majority"],
        "disputed_hops": counts["disputed"],
        "non_disputed_hops": counts["unanimous"] + counts["majority"],
    }
    raw = _canonical(body)
    if not 1 <= len(raw) <= MAX_PUBLIC_CLASSIFIED_HOP_UNION_BYTES:
        raise ClassifiedHopUnionError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return PublicClassifiedHopUnion(raw, digest), VerifiedPublicClassifiedHopUnion(
        public_sha256=digest,
        source_intervals_sha256=public.sha256,
        query_ranges=selected,
        merged_ranges=tuple(merged),
        classified_hops=tuple(counts[kind] for kind in _CLASSES),
    )


def build_public_classified_hop_union(runs: object, queries: object) -> PublicClassifiedHopUnion:
    """Return unique classified hop coverage of up to eight input queries."""
    try:
        return _compute(runs, queries)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ClassifiedHopUnionError(_FAILURE) from None


def verify_public_classified_hop_union(
    runs: object, queries: object, raw: object, *, expected_sha256: object
) -> VerifiedPublicClassifiedHopUnion:
    """Verify exact canonical bytes by independently rebuilding original sources."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs, queries)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise ClassifiedHopUnionError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ClassifiedHopUnionError(_FAILURE) from None
