"""Canonical bounded public-only batch of source-verified hop classifications.

Each query independently counts unanimous, majority and disputed hops from
original ordered source cohorts. No authenticated provenance, trusted
chronology, security severity or host/provider authority is implied.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_consensus_intervals as intervals

MAX_CLASSIFIED_HOP_COVERAGES = 8
MAX_PUBLIC_CLASSIFIED_HOP_COVERAGES_BYTES = 8 * 1024
_FAILURE = "staging classified hop coverages rejected"
_CLASSES = ("unanimous", "majority", "disputed")


class ClassifiedHopCoveragesError(RuntimeError):
    """Sanitized rejection of an invalid or inconsistent public batch."""


@dataclass(frozen=True, slots=True)
class PublicClassifiedHopCoverages:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicClassifiedHopCoverages:
    public_sha256: str
    source_intervals_sha256: str
    query_ranges: tuple[tuple[int, int], ...]
    classified_counts: tuple[tuple[int, int, int], ...]


def _canonical(body: dict) -> bytes:
    return json.dumps(
        body, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    body = {}
    for key, value in pairs:
        if key in body:
            raise ClassifiedHopCoveragesError(_FAILURE)
        body[key] = value
    return body


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_CLASSIFIED_HOP_COVERAGES_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise ClassifiedHopCoveragesError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise ClassifiedHopCoveragesError(_FAILURE)
    return body


def _compute(
    runs: object, queries: object
) -> tuple[PublicClassifiedHopCoverages, VerifiedPublicClassifiedHopCoverages]:
    if type(queries) not in (tuple, list):
        raise ClassifiedHopCoveragesError(_FAILURE)

    # Snapshot both mutable levels once, *before* validating or selecting.
    # Nine outer entries / three inner entries detect the first excess item
    # without copying unbounded caller-owned input.
    outer = tuple(queries[: MAX_CLASSIFIED_HOP_COVERAGES + 1])
    if not 1 <= len(outer) <= MAX_CLASSIFIED_HOP_COVERAGES:
        raise ClassifiedHopCoveragesError(_FAILURE)
    frozen = []
    for item in outer:
        if type(item) not in (tuple, list):
            raise ClassifiedHopCoveragesError(_FAILURE)
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
        raise ClassifiedHopCoveragesError(_FAILURE)

    # Full source verification once per builder or verifier call, never
    # caller-supplied digests or detached/cached classification intervals.
    source = intervals.build_public_intervals(runs)
    original = json.loads(source.payload.decode("ascii"))
    if any(end > original["hop_count"] for _, end in selected):
        raise ClassifiedHopCoveragesError(_FAILURE)

    result_rows = []
    class_counts: list[tuple[int, int, int]] = []
    for start, end in selected:
        counts = {name: 0 for name in _CLASSES}
        for item in original["intervals"]:
            left = max(start, item["start_hop"])
            right = min(end, item["end_hop_exclusive"])
            if right > left:
                counts[item["classification"]] += right - left
        query_hops = end - start
        if sum(counts.values()) != query_hops:
            raise ClassifiedHopCoveragesError(_FAILURE)
        row = {
            "query_hops": query_hops,
            "unanimous_hops": counts["unanimous"],
            "majority_hops": counts["majority"],
            "disputed_hops": counts["disputed"],
            "non_disputed_hops": counts["unanimous"] + counts["majority"],
        }
        result_rows.append(row)
        class_counts.append(tuple(counts[name] for name in _CLASSES))

    document = {
        "schema_version": 1,
        "audience": "public",
        "incident": original["incident"],
        "hop_count": original["hop_count"],
        "source_intervals_sha256": source.sha256,
        "queries": [{"start_hop": start, "end_hop_exclusive": end} for start, end in selected],
        "results": result_rows,
    }
    raw = _canonical(document)
    if not 1 <= len(raw) <= MAX_PUBLIC_CLASSIFIED_HOP_COVERAGES_BYTES:
        raise ClassifiedHopCoveragesError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return (
        PublicClassifiedHopCoverages(raw, digest),
        VerifiedPublicClassifiedHopCoverages(
            public_sha256=digest,
            source_intervals_sha256=source.sha256,
            query_ranges=selected,
            classified_counts=tuple(class_counts),
        ),
    )


def build_public_classified_hop_coverages(
    runs: object, queries: object
) -> PublicClassifiedHopCoverages:
    """Return up to eight independent caller-ordered classification queries."""
    try:
        return _compute(runs, queries)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ClassifiedHopCoveragesError(_FAILURE) from None


def verify_public_classified_hop_coverages(
    runs: object, queries: object, raw: object, *, expected_sha256: object
) -> VerifiedPublicClassifiedHopCoverages:
    """Verify exact source-derived canonical bytes and query consistency."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs, queries)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise ClassifiedHopCoveragesError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ClassifiedHopCoveragesError(_FAILURE) from None
