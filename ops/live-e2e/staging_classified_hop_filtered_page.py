"""Source-bound bounded pages filtered by public cohort agreement category.

Class labels are offline navigation, not trusted safety, severity, time,
authenticated provenance, host authority, or private provider state.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_consensus_intervals as intervals

MAX_CLASSIFIED_HOP_FILTERED_PAGE_LIMIT = 8
MAX_PUBLIC_CLASSIFIED_HOP_FILTERED_PAGE_BYTES = 4 * 1024
_FAILURE = "staging classified hop filtered page rejected"
_CLASSES = ("unanimous", "majority", "disputed")


class ClassifiedHopFilteredPageError(RuntimeError):
    """Sanitized rejection for invalid or inconsistent public pages."""


@dataclass(frozen=True, slots=True)
class PublicClassifiedHopFilteredPage:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicClassifiedHopFilteredPage:
    public_sha256: str
    source_intervals_sha256: str
    classification: str
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
            raise ClassifiedHopFilteredPageError(_FAILURE)
        body[key] = value
    return body


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_CLASSIFIED_HOP_FILTERED_PAGE_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise ClassifiedHopFilteredPageError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise ClassifiedHopFilteredPageError(_FAILURE)
    return body


def _compute(
    runs: object,
    start_hop: object,
    end_hop_exclusive: object,
    classification: object,
    offset: object,
    limit: object,
) -> tuple[PublicClassifiedHopFilteredPage, VerifiedPublicClassifiedHopFilteredPage]:
    if (
        type(start_hop) is not int
        or type(end_hop_exclusive) is not int
        or start_hop < 0
        or end_hop_exclusive <= start_hop
        or type(classification) is not str
        or classification not in _CLASSES
        or type(offset) is not int
        or offset < 0
        or type(limit) is not int
        or not 1 <= limit <= MAX_CLASSIFIED_HOP_FILTERED_PAGE_LIMIT
    ):
        raise ClassifiedHopFilteredPageError(_FAILURE)

    # Never trust detached pages, hashes or cached intervals. Rebuild the
    # complete original ordered 3-5 cohort source once on every call.
    source = intervals.build_public_intervals(runs)
    original = json.loads(source.payload.decode("ascii"))
    if end_hop_exclusive > original["hop_count"]:
        raise ClassifiedHopFilteredPageError(_FAILURE)

    rows: list[tuple[int, int, str]] = []
    for item in original["intervals"]:
        if item["classification"] != classification:
            continue
        left = max(start_hop, item["start_hop"])
        right = min(end_hop_exclusive, item["end_hop_exclusive"])
        if left < right:
            rows.append((left, right, classification))
    total = len(rows)
    if offset > total:
        raise ClassifiedHopFilteredPageError(_FAILURE)
    selected = tuple(rows[offset : offset + limit])
    next_offset = offset + len(selected) if offset + len(selected) < total else None
    body = {
        "schema_version": 1,
        "audience": "public",
        "incident": original["incident"],
        "hop_count": original["hop_count"],
        "source_intervals_sha256": source.sha256,
        "query": {"start_hop": start_hop, "end_hop_exclusive": end_hop_exclusive},
        "classification": classification,
        "offset": offset,
        "limit": limit,
        "total_segments": total,
        "next_offset": next_offset,
        "segments": [
            {"start_hop": start, "end_hop_exclusive": end, "classification": category}
            for start, end, category in selected
        ],
    }
    raw = _canonical(body)
    if not 1 <= len(raw) <= MAX_PUBLIC_CLASSIFIED_HOP_FILTERED_PAGE_BYTES:
        raise ClassifiedHopFilteredPageError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return (
        PublicClassifiedHopFilteredPage(raw, digest),
        VerifiedPublicClassifiedHopFilteredPage(
            public_sha256=digest,
            source_intervals_sha256=source.sha256,
            classification=classification,
            offset=offset,
            limit=limit,
            total_segments=total,
            next_offset=next_offset,
            segments=selected,
        ),
    )


def build_public_classified_hop_filtered_page(
    runs: object,
    start_hop: object,
    end_hop_exclusive: object,
    classification: object,
    offset: object,
    limit: object,
) -> PublicClassifiedHopFilteredPage:
    """Build a bounded page of one selected public classification."""
    try:
        return _compute(runs, start_hop, end_hop_exclusive, classification, offset, limit)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ClassifiedHopFilteredPageError(_FAILURE) from None


def verify_public_classified_hop_filtered_page(
    runs: object,
    start_hop: object,
    end_hop_exclusive: object,
    classification: object,
    offset: object,
    limit: object,
    raw: object,
    *,
    expected_sha256: object,
) -> VerifiedPublicClassifiedHopFilteredPage:
    """Independently rebuild exact public source bytes before verification."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(
            runs, start_hop, end_hop_exclusive, classification, offset, limit
        )
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise ClassifiedHopFilteredPageError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ClassifiedHopFilteredPageError(_FAILURE) from None
