"""Offline source-verified overlap navigation over bounded public dispute windows.

Overlap is a deterministic navigation relation, not trusted chronology,
severity, provenance, incident authority, or permission for provider actions.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_dispute_index as index

MAX_PUBLIC_DISPUTE_OVERLAP_BYTES = 8 * 1024
_FAILURE = "staging dispute overlap rejected"


class DisputeOverlapError(RuntimeError):
    """Fixed nonsensitive rejection of invalid or inconsistent overlap queries."""


@dataclass(frozen=True, slots=True)
class PublicDisputeOverlap:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicDisputeOverlap:
    public_sha256: str
    source_index_sha256: str
    start_hop: int
    end_hop_exclusive: int
    ranks: tuple[int, ...]


def _canonical(body: dict) -> bytes:
    return json.dumps(
        body, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    body = {}
    for key, value in pairs:
        if key in body:
            raise DisputeOverlapError(_FAILURE)
        body[key] = value
    return body


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_OVERLAP_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise DisputeOverlapError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise DisputeOverlapError(_FAILURE)
    return body


def _compute(
    runs: object, start_hop: object, end_hop_exclusive: object
) -> tuple[PublicDisputeOverlap, VerifiedPublicDisputeOverlap]:
    if (
        type(start_hop) is not int
        or type(end_hop_exclusive) is not int
        or start_hop < 0
        or end_hop_exclusive <= start_hop
    ):
        raise DisputeOverlapError(_FAILURE)

    # Rebuild the entire original ordered 3–5-cohort index every time.
    # Never trust caller-supplied detached index bytes, cache, or host state.
    original = index.build_public_dispute_index(runs)
    source = json.loads(original.payload.decode("ascii"))
    if end_hop_exclusive > source["hop_count"]:
        raise DisputeOverlapError(_FAILURE)
    matches = [
        {
            "rank": rank,
            "window": window,
            "overlap_start_hop": max(start_hop, window["start_hop"]),
            "overlap_end_hop_exclusive": min(end_hop_exclusive, window["end_hop_exclusive"]),
        }
        for rank, window in enumerate(source["ranked_windows"])
        if window["start_hop"] < end_hop_exclusive and window["end_hop_exclusive"] > start_hop
    ]
    body = {
        "schema_version": 1,
        "audience": "public",
        "incident": source["incident"],
        "source_dispute_index_sha256": original.sha256,
        "hop_count": source["hop_count"],
        "window_count": source["window_count"],
        "query": {"start_hop": start_hop, "end_hop_exclusive": end_hop_exclusive},
        "matches": matches,
    }
    raw = _canonical(body)
    if not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_OVERLAP_BYTES:
        raise DisputeOverlapError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return (
        PublicDisputeOverlap(raw, digest),
        VerifiedPublicDisputeOverlap(
            public_sha256=digest,
            source_index_sha256=original.sha256,
            start_hop=start_hop,
            end_hop_exclusive=end_hop_exclusive,
            ranks=tuple(row["rank"] for row in matches),
        ),
    )


def build_public_dispute_overlap(
    runs: object, start_hop: object, end_hop_exclusive: object
) -> PublicDisputeOverlap:
    """Select all overlapping public windows in deterministic index-rank order."""
    try:
        return _compute(runs, start_hop, end_hop_exclusive)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeOverlapError(_FAILURE) from None


def verify_public_dispute_overlap(
    runs: object,
    start_hop: object,
    end_hop_exclusive: object,
    raw: object,
    *,
    expected_sha256: object,
) -> VerifiedPublicDisputeOverlap:
    """Fail closed on forged/noncanonical or original-source-inconsistent wire."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs, start_hop, end_hop_exclusive)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise DisputeOverlapError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeOverlapError(_FAILURE) from None
