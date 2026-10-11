"""Bounded source-verified pages of non-disputed hop gaps.

Gaps are the complement of public disputed windows within a hop query;
they include unanimous/majority hops. Public-only deterministic navigation,
not trusted chronology, severity, provenance or native provider authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_dispute_index as index

MAX_PUBLIC_DISPUTE_GAP_PAGE_BYTES = 4 * 1024
MAX_DISPUTE_GAP_PAGE_LIMIT = 8
_FAILURE = "staging dispute gap page rejected"


class DisputeGapPageError(RuntimeError):
    """Fixed sanitized failure for invalid or inconsistent public gap pages."""


@dataclass(frozen=True, slots=True)
class PublicDisputeGapPage:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicDisputeGapPage:
    public_sha256: str
    source_index_sha256: str
    offset: int
    limit: int
    total_gaps: int
    next_offset: int | None
    gap_ranges: tuple[tuple[int, int], ...]


def _canonical(body: dict) -> bytes:
    return json.dumps(
        body, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    body = {}
    for key, value in pairs:
        if key in body:
            raise DisputeGapPageError(_FAILURE)
        body[key] = value
    return body


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_GAP_PAGE_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(char not in "0123456789abcdef" for char in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise DisputeGapPageError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise DisputeGapPageError(_FAILURE)
    return body


def _compute(
    runs: object,
    start_hop: object,
    end_hop_exclusive: object,
    offset: object,
    limit: object,
) -> tuple[PublicDisputeGapPage, VerifiedPublicDisputeGapPage]:
    if (
        type(start_hop) is not int
        or type(end_hop_exclusive) is not int
        or start_hop < 0
        or end_hop_exclusive <= start_hop
        or type(offset) is not int
        or offset < 0
        or type(limit) is not int
        or not 1 <= limit <= MAX_DISPUTE_GAP_PAGE_LIMIT
    ):
        raise DisputeGapPageError(_FAILURE)

    # Every build/verify rebuilds the *complete* original caller-ordered
    # 3–5 cohort source index. Never trust a detached index or cached digest.
    original = index.build_public_dispute_index(runs)
    source = json.loads(original.payload.decode("ascii"))
    if end_hop_exclusive > source["hop_count"]:
        raise DisputeGapPageError(_FAILURE)

    # Ranked windows are length-first, so explicitly sort by hop position
    # to enumerate their complement without inventing temporal ordering.
    cursor = start_hop
    gaps: list[tuple[int, int]] = []
    windows = sorted(source["ranked_windows"], key=lambda window: window["start_hop"])
    for window in windows:
        left = max(start_hop, window["start_hop"])
        right = min(end_hop_exclusive, window["end_hop_exclusive"])
        if left < right:
            if cursor < left:
                gaps.append((cursor, left))
            cursor = max(cursor, right)
    if cursor < end_hop_exclusive:
        gaps.append((cursor, end_hop_exclusive))

    total = len(gaps)
    if offset > total:
        raise DisputeGapPageError(_FAILURE)
    page = gaps[offset : offset + limit]
    next_offset = offset + len(page) if offset + len(page) < total else None
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
        "total_gaps": total,
        "next_offset": next_offset,
        "gaps": [{"start_hop": start, "end_hop_exclusive": end} for start, end in page],
    }
    raw = _canonical(body)
    if not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_GAP_PAGE_BYTES:
        raise DisputeGapPageError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return PublicDisputeGapPage(raw, digest), VerifiedPublicDisputeGapPage(
        public_sha256=digest,
        source_index_sha256=original.sha256,
        offset=offset,
        limit=limit,
        total_gaps=total,
        next_offset=next_offset,
        gap_ranges=tuple(page),
    )


def build_public_dispute_gap_page(
    runs: object, start_hop: object, end_hop_exclusive: object, offset: object, limit: object
) -> PublicDisputeGapPage:
    """Return bounded public non-disputed gap navigation page."""
    try:
        return _compute(runs, start_hop, end_hop_exclusive, offset, limit)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeGapPageError(_FAILURE) from None


def verify_public_dispute_gap_page(
    runs: object,
    start_hop: object,
    end_hop_exclusive: object,
    offset: object,
    limit: object,
    raw: object,
    *,
    expected_sha256: object,
) -> VerifiedPublicDisputeGapPage:
    """Compare canonical wire byte-for-byte to a fresh original-source rebuild."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs, start_hop, end_hop_exclusive, offset, limit)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise DisputeGapPageError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeGapPageError(_FAILURE) from None
