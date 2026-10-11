"""Bounded public-only overlap pages in source-verified index rank order.

Pagination is deterministic navigation, never trusted chronology, severity,
provenance, provider authority or host observation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_dispute_index as index

MAX_PUBLIC_DISPUTE_OVERLAP_PAGE_BYTES = 8 * 1024
MAX_DISPUTE_OVERLAP_PAGE_LIMIT = 16
_FAILURE = "staging dispute overlap page rejected"


class DisputeOverlapPageError(RuntimeError):
    """Sanitized failure for invalid or inconsistent public overlap pages."""


class DisputeOverlapPageCapacityError(DisputeOverlapPageError):
    """A single complete match cannot fit within one bounded public page."""


@dataclass(frozen=True, slots=True)
class PublicDisputeOverlapPage:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicDisputeOverlapPage:
    public_sha256: str
    source_index_sha256: str
    offset: int
    limit: int
    total_matches: int
    next_offset: int | None
    ranks: tuple[int, ...]


def _canonical(body: dict) -> bytes:
    return json.dumps(
        body, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    body = {}
    for key, value in pairs:
        if key in body:
            raise DisputeOverlapPageError(_FAILURE)
        body[key] = value
    return body


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_OVERLAP_PAGE_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise DisputeOverlapPageError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise DisputeOverlapPageError(_FAILURE)
    return body


def _compute(
    runs: object,
    start_hop: object,
    end_hop_exclusive: object,
    offset: object,
    limit: object,
) -> tuple[PublicDisputeOverlapPage, VerifiedPublicDisputeOverlapPage]:
    if (
        type(start_hop) is not int
        or type(end_hop_exclusive) is not int
        or start_hop < 0
        or end_hop_exclusive <= start_hop
        or type(offset) is not int
        or offset < 0
        or type(limit) is not int
        or not 1 <= limit <= MAX_DISPUTE_OVERLAP_PAGE_LIMIT
    ):
        raise DisputeOverlapPageError(_FAILURE)

    # Rebuild the entire ranked index from original caller-ordered sources
    # independently for every build/verify. Never trust detached index wire.
    original = index.build_public_dispute_index(runs)
    source = json.loads(original.payload.decode("ascii"))
    if end_hop_exclusive > source["hop_count"]:
        raise DisputeOverlapPageError(_FAILURE)
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
    total = len(matches)
    if offset > total:
        raise DisputeOverlapPageError(_FAILURE)

    eligible = matches[offset : offset + limit]
    # Shrink only at complete match boundaries. The next offset always
    # advances; never return an empty page with a nonterminal cursor.
    for count in range(len(eligible), -1, -1):
        next_offset = offset + count if offset + count < total else None
        if not count and next_offset is not None:
            break
        body = {
            "schema_version": 1,
            "audience": "public",
            "incident": source["incident"],
            "source_dispute_index_sha256": original.sha256,
            "hop_count": source["hop_count"],
            "window_count": source["window_count"],
            "query": {"start_hop": start_hop, "end_hop_exclusive": end_hop_exclusive},
            "offset": offset,
            "limit": limit,
            "total_matches": total,
            "next_offset": next_offset,
            "matches": eligible[:count],
        }
        raw = _canonical(body)
        if 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_OVERLAP_PAGE_BYTES:
            digest = hashlib.sha256(raw).hexdigest()
            return PublicDisputeOverlapPage(raw, digest), VerifiedPublicDisputeOverlapPage(
                public_sha256=digest,
                source_index_sha256=original.sha256,
                offset=offset,
                limit=limit,
                total_matches=total,
                next_offset=next_offset,
                ranks=tuple(row["rank"] for row in eligible[:count]),
            )
    raise DisputeOverlapPageCapacityError(_FAILURE)


def build_public_dispute_overlap_page(
    runs: object, start_hop: object, end_hop_exclusive: object, offset: object, limit: object
) -> PublicDisputeOverlapPage:
    """Return full matches in a canonical bounded page with explicit cursor."""
    try:
        return _compute(runs, start_hop, end_hop_exclusive, offset, limit)[0]
    except DisputeOverlapPageCapacityError:
        raise DisputeOverlapPageCapacityError(_FAILURE) from None
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeOverlapPageError(_FAILURE) from None


def verify_public_dispute_overlap_page(
    runs: object,
    start_hop: object,
    end_hop_exclusive: object,
    offset: object,
    limit: object,
    raw: object,
    *,
    expected_sha256: object,
) -> VerifiedPublicDisputeOverlapPage:
    """Compare exact canonical bytes against a fresh original-source rebuild."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs, start_hop, end_hop_exclusive, offset, limit)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise DisputeOverlapPageError(_FAILURE)
        return facts
    except DisputeOverlapPageCapacityError:
        raise DisputeOverlapPageCapacityError(_FAILURE) from None
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeOverlapPageError(_FAILURE) from None
