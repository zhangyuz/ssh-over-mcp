"""Exact public disputed-window boundary lookup from original verified sources.

A matching range is a navigation key, not authenticated chronology, severity,
incident authority, provenance, or permission for native provider operations.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_dispute_index as index

MAX_PUBLIC_DISPUTE_RANGE_BYTES = 4 * 1024
_FAILURE = "staging dispute range rejected"


class DisputeRangeError(RuntimeError):
    """Fixed nonsensitive rejection of invalid or inconsistent public ranges."""


@dataclass(frozen=True, slots=True)
class PublicDisputeRange:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicDisputeRange:
    public_sha256: str
    source_index_sha256: str
    start_hop: int
    end_hop_exclusive: int
    rank: int | None


def _canonical(body: dict) -> bytes:
    return json.dumps(
        body, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    body = {}
    for key, value in pairs:
        if key in body:
            raise DisputeRangeError(_FAILURE)
        body[key] = value
    return body


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_RANGE_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise DisputeRangeError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise DisputeRangeError(_FAILURE)
    return body


def _compute(
    runs: object, start_hop: object, end_hop_exclusive: object
) -> tuple[PublicDisputeRange, VerifiedPublicDisputeRange]:
    if (
        type(start_hop) is not int
        or type(end_hop_exclusive) is not int
        or start_hop < 0
        or end_hop_exclusive <= start_hop
    ):
        raise DisputeRangeError(_FAILURE)

    # Full index rebuilt from ORIGINAL ordered 3–5 source cohorts per call;
    # detached digests, cached windows and host/provider I/O are not trusted.
    original = index.build_public_dispute_index(runs)
    source = json.loads(original.payload.decode("ascii"))
    if end_hop_exclusive > source["hop_count"]:
        raise DisputeRangeError(_FAILURE)

    matches = [
        (rank, window)
        for rank, window in enumerate(source["ranked_windows"])
        if window["start_hop"] == start_hop and window["end_hop_exclusive"] == end_hop_exclusive
    ]
    if len(matches) > 1:
        raise DisputeRangeError(_FAILURE)
    found_rank, found_window = matches[0] if matches else (None, None)
    body = {
        "schema_version": 1,
        "audience": "public",
        "incident": source["incident"],
        "source_dispute_index_sha256": original.sha256,
        "hop_count": source["hop_count"],
        "window_count": source["window_count"],
        "query": {"start_hop": start_hop, "end_hop_exclusive": end_hop_exclusive},
        "rank": found_rank,
        "window": found_window,
    }
    raw = _canonical(body)
    if not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_RANGE_BYTES:
        raise DisputeRangeError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return (
        PublicDisputeRange(raw, digest),
        VerifiedPublicDisputeRange(
            public_sha256=digest,
            source_index_sha256=original.sha256,
            start_hop=start_hop,
            end_hop_exclusive=end_hop_exclusive,
            rank=found_rank,
        ),
    )


def build_public_dispute_range(
    runs: object, start_hop: object, end_hop_exclusive: object
) -> PublicDisputeRange:
    """Find one exact disputed window or explicit null from original sources."""
    try:
        return _compute(runs, start_hop, end_hop_exclusive)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeRangeError(_FAILURE) from None


def verify_public_dispute_range(
    runs: object,
    start_hop: object,
    end_hop_exclusive: object,
    raw: object,
    *,
    expected_sha256: object,
) -> VerifiedPublicDisputeRange:
    """Reject forged, oversized, noncanonical or source-inconsistent range wire."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs, start_hop, end_hop_exclusive)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise DisputeRangeError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeRangeError(_FAILURE) from None
