"""Source-verified public batch coverage of 1–8 caller-ordered hop ranges.

A bounded navigation aid only, never trusted chronology, severity, incident
provenance, authorization or host/provider evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_dispute_index as index

MAX_DISPUTE_OVERLAP_COVERAGES = 8
MAX_PUBLIC_DISPUTE_OVERLAP_COVERAGES_BYTES = 8 * 1024
_FAILURE = "staging dispute overlap coverages rejected"


class DisputeOverlapCoveragesError(RuntimeError):
    """Fixed nonsensitive rejection of bad batch queries or output."""


@dataclass(frozen=True, slots=True)
class PublicDisputeOverlapCoverages:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicDisputeOverlapCoverages:
    public_sha256: str
    source_index_sha256: str
    query_ranges: tuple[tuple[int, int], ...]
    matching_windows: tuple[int, ...]
    disputed_hops: tuple[int, ...]


def _canonical(body: dict) -> bytes:
    return json.dumps(
        body, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    body = {}
    for key, value in pairs:
        if key in body:
            raise DisputeOverlapCoveragesError(_FAILURE)
        body[key] = value
    return body


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_OVERLAP_COVERAGES_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise DisputeOverlapCoveragesError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise DisputeOverlapCoveragesError(_FAILURE)
    return body


def _compute(
    runs: object, queries: object
) -> tuple[PublicDisputeOverlapCoverages, VerifiedPublicDisputeOverlapCoverages]:
    if type(queries) not in (tuple, list):
        raise DisputeOverlapCoveragesError(_FAILURE)

    # One bounded snapshot of each mutable level. Keep at most one
    # over-limit item to reject huge caller collections before rebuilding.
    # All subsequent validation/selection uses only frozen data.
    outer = tuple(queries[: MAX_DISPUTE_OVERLAP_COVERAGES + 1])
    if not 1 <= len(outer) <= MAX_DISPUTE_OVERLAP_COVERAGES:
        raise DisputeOverlapCoveragesError(_FAILURE)
    frozen = []
    for item in outer:
        if type(item) not in (tuple, list):
            raise DisputeOverlapCoveragesError(_FAILURE)
        # Three captured entries suffice to reject a non-pair, even if the
        # source list is huge or changes while the snapshot is taken.
        frozen.append(tuple(item[:3]))
    selected = tuple(frozen)
    if any(len(pair) != 2 for pair in selected):
        raise DisputeOverlapCoveragesError(_FAILURE)
    if any(
        type(start) is not int or type(end) is not int or start < 0 or end <= start
        for start, end in selected
    ):
        raise DisputeOverlapCoveragesError(_FAILURE)

    # Exactly one rebuild of the full ranked index from original ordered
    # source cohorts per builder/verifier call; never trust detached index wire.
    original = index.build_public_dispute_index(runs)
    source = json.loads(original.payload.decode("ascii"))
    if any(end > source["hop_count"] for _, end in selected):
        raise DisputeOverlapCoveragesError(_FAILURE)

    rows = []
    for start_hop, end_hop_exclusive in selected:
        count = 0
        covered = 0
        for window in source["ranked_windows"]:
            lower = max(start_hop, window["start_hop"])
            upper = min(end_hop_exclusive, window["end_hop_exclusive"])
            if lower < upper:
                count += 1
                covered += upper - lower
        span = end_hop_exclusive - start_hop
        if count > source["window_count"] or covered > span:
            raise DisputeOverlapCoveragesError(_FAILURE)
        rows.append(
            {
                "matched_window_count": count,
                "matched_disputed_hops": covered,
                "unmatched_hops": span - covered,
            }
        )
    body = {
        "schema_version": 1,
        "audience": "public",
        "incident": source["incident"],
        "source_dispute_index_sha256": original.sha256,
        "hop_count": source["hop_count"],
        "window_count": source["window_count"],
        "queries": [{"start_hop": start, "end_hop_exclusive": end} for start, end in selected],
        "results": rows,
    }
    raw = _canonical(body)
    if not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_OVERLAP_COVERAGES_BYTES:
        raise DisputeOverlapCoveragesError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return (
        PublicDisputeOverlapCoverages(raw, digest),
        VerifiedPublicDisputeOverlapCoverages(
            public_sha256=digest,
            source_index_sha256=original.sha256,
            query_ranges=selected,
            matching_windows=tuple(row["matched_window_count"] for row in rows),
            disputed_hops=tuple(row["matched_disputed_hops"] for row in rows),
        ),
    )


def build_public_dispute_overlap_coverages(
    runs: object, queries: object
) -> PublicDisputeOverlapCoverages:
    """Build a bounded source-verified count batch with caller-ordered ranges."""
    try:
        return _compute(runs, queries)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeOverlapCoveragesError(_FAILURE) from None


def verify_public_dispute_overlap_coverages(
    runs: object, queries: object, raw: object, *, expected_sha256: object
) -> VerifiedPublicDisputeOverlapCoverages:
    """Require byte-exact equality to a fresh original-source index rebuild."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs, queries)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise DisputeOverlapCoveragesError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeOverlapCoveragesError(_FAILURE) from None
