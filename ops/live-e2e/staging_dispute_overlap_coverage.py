"""Bounded public-only coverage of disputed windows across a hop query.

This is offline source-verified navigation, not severity, chronology,
provenance, native provider authority, or an authenticated host observation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_dispute_index as index

MAX_PUBLIC_DISPUTE_OVERLAP_COVERAGE_BYTES = 4 * 1024
_FAILURE = "staging dispute overlap coverage rejected"


class DisputeOverlapCoverageError(RuntimeError):
    """One fixed sanitized rejection for invalid or inconsistent coverage."""


@dataclass(frozen=True, slots=True)
class PublicDisputeOverlapCoverage:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicDisputeOverlapCoverage:
    public_sha256: str
    source_index_sha256: str
    start_hop: int
    end_hop_exclusive: int
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
            raise DisputeOverlapCoverageError(_FAILURE)
        body[key] = value
    return body


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_OVERLAP_COVERAGE_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise DisputeOverlapCoverageError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise DisputeOverlapCoverageError(_FAILURE)
    return body


def _compute(
    runs: object, start_hop: object, end_hop_exclusive: object
) -> tuple[PublicDisputeOverlapCoverage, VerifiedPublicDisputeOverlapCoverage]:
    if (
        type(start_hop) is not int
        or type(end_hop_exclusive) is not int
        or start_hop < 0
        or end_hop_exclusive <= start_hop
    ):
        raise DisputeOverlapCoverageError(_FAILURE)

    # Independently rebuild all source-bound ranked windows every time.
    original = index.build_public_dispute_index(runs)
    source = json.loads(original.payload.decode("ascii"))
    if end_hop_exclusive > source["hop_count"]:
        raise DisputeOverlapCoverageError(_FAILURE)

    count = 0
    covered = 0
    for window in source["ranked_windows"]:
        start = max(start_hop, window["start_hop"])
        end = min(end_hop_exclusive, window["end_hop_exclusive"])
        if start < end:
            count += 1
            covered += end - start
    query_hops = end_hop_exclusive - start_hop
    if count > source["window_count"] or covered > query_hops:
        raise DisputeOverlapCoverageError(_FAILURE)

    body = {
        "schema_version": 1,
        "audience": "public",
        "incident": source["incident"],
        "source_dispute_index_sha256": original.sha256,
        "hop_count": source["hop_count"],
        "window_count": source["window_count"],
        "query": {"start_hop": start_hop, "end_hop_exclusive": end_hop_exclusive},
        "matched_window_count": count,
        "matched_disputed_hops": covered,
        "unmatched_hops": query_hops - covered,
    }
    raw = _canonical(body)
    if not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_OVERLAP_COVERAGE_BYTES:
        raise DisputeOverlapCoverageError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return (
        PublicDisputeOverlapCoverage(raw, digest),
        VerifiedPublicDisputeOverlapCoverage(
            public_sha256=digest,
            source_index_sha256=original.sha256,
            start_hop=start_hop,
            end_hop_exclusive=end_hop_exclusive,
            matched_windows=count,
            matched_hops=covered,
        ),
    )


def build_public_dispute_overlap_coverage(
    runs: object, start_hop: object, end_hop_exclusive: object
) -> PublicDisputeOverlapCoverage:
    """Count clipped disputed coverage without returning the window list."""
    try:
        return _compute(runs, start_hop, end_hop_exclusive)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeOverlapCoverageError(_FAILURE) from None


def verify_public_dispute_overlap_coverage(
    runs: object,
    start_hop: object,
    end_hop_exclusive: object,
    raw: object,
    *,
    expected_sha256: object,
) -> VerifiedPublicDisputeOverlapCoverage:
    """Compare bounded canonical bytes against a full original-source rebuild."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs, start_hop, end_hop_exclusive)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise DisputeOverlapCoverageError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeOverlapCoverageError(_FAILURE) from None
