"""Bounded original-source public pages of classified hop interval segments.

Segments are clipped source-interval rows, not necessarily maximally
merged by class. Labels describe public cohort agreement only; no
safety, trust, incident severity or trusted chronology is asserted.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_consensus_intervals as intervals

MAX_CLASSIFIED_HOP_PAGE_LIMIT = 8
MAX_PUBLIC_CLASSIFIED_HOP_PAGE_BYTES = 4 * 1024
_FAILURE = "staging classified hop page rejected"


class ClassifiedHopPageError(RuntimeError):
    """Sanitized rejection of invalid or source-inconsistent public pages."""


@dataclass(frozen=True, slots=True)
class PublicClassifiedHopPage:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicClassifiedHopPage:
    public_sha256: str
    source_intervals_sha256: str
    offset: int
    limit: int
    total_segments: int
    next_offset: int | None
    segments: tuple[tuple[int, int, str], ...]


def _canonical(body: dict) -> bytes:
    return json.dumps(
        body, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    body = {}
    for key, value in pairs:
        if key in body:
            raise ClassifiedHopPageError(_FAILURE)
        body[key] = value
    return body


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_CLASSIFIED_HOP_PAGE_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise ClassifiedHopPageError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise ClassifiedHopPageError(_FAILURE)
    return body


def _compute(
    runs: object,
    start_hop: object,
    end_hop_exclusive: object,
    offset: object,
    limit: object,
) -> tuple[PublicClassifiedHopPage, VerifiedPublicClassifiedHopPage]:
    if (
        type(start_hop) is not int
        or type(end_hop_exclusive) is not int
        or start_hop < 0
        or end_hop_exclusive <= start_hop
        or type(offset) is not int
        or offset < 0
        or type(limit) is not int
        or not 1 <= limit <= MAX_CLASSIFIED_HOP_PAGE_LIMIT
    ):
        raise ClassifiedHopPageError(_FAILURE)

    # Reconstruct source-bound public intervals once from the original
    # ordered 3-5 cohorts on *every* independent build/verify invocation.
    source = intervals.build_public_intervals(runs)
    original = json.loads(source.payload.decode("ascii"))
    if end_hop_exclusive > original["hop_count"]:
        raise ClassifiedHopPageError(_FAILURE)
    clipped = []
    for item in original["intervals"]:
        left = max(start_hop, item["start_hop"])
        right = min(end_hop_exclusive, item["end_hop_exclusive"])
        if left < right:
            clipped.append((left, right, item["classification"]))
    total = len(clipped)
    if offset > total:
        raise ClassifiedHopPageError(_FAILURE)
    page = tuple(clipped[offset : offset + limit])
    next_offset = offset + len(page) if offset + len(page) < total else None
    body = {
        "schema_version": 1,
        "audience": "public",
        "incident": original["incident"],
        "hop_count": original["hop_count"],
        "source_intervals_sha256": source.sha256,
        "query": {"start_hop": start_hop, "end_hop_exclusive": end_hop_exclusive},
        "offset": offset,
        "limit": limit,
        "total_segments": total,
        "next_offset": next_offset,
        "segments": [
            {"start_hop": start, "end_hop_exclusive": end, "classification": kind}
            for start, end, kind in page
        ],
    }
    raw = _canonical(body)
    if not 1 <= len(raw) <= MAX_PUBLIC_CLASSIFIED_HOP_PAGE_BYTES:
        raise ClassifiedHopPageError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return PublicClassifiedHopPage(raw, digest), VerifiedPublicClassifiedHopPage(
        public_sha256=digest,
        source_intervals_sha256=source.sha256,
        offset=offset,
        limit=limit,
        total_segments=total,
        next_offset=next_offset,
        segments=page,
    )


def build_public_classified_hop_page(
    runs: object, start_hop: object, end_hop_exclusive: object, offset: object, limit: object
) -> PublicClassifiedHopPage:
    """Return a bounded page of original-source-classified hop segments."""
    try:
        return _compute(runs, start_hop, end_hop_exclusive, offset, limit)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ClassifiedHopPageError(_FAILURE) from None


def verify_public_classified_hop_page(
    runs: object,
    start_hop: object,
    end_hop_exclusive: object,
    offset: object,
    limit: object,
    raw: object,
    *,
    expected_sha256: object,
) -> VerifiedPublicClassifiedHopPage:
    """Fail closed unless the page matches an independently rebuilt original source."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs, start_hop, end_hop_exclusive, offset, limit)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise ClassifiedHopPageError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ClassifiedHopPageError(_FAILURE) from None
