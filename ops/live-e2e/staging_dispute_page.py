"""Canonical bounded pages of original-source-verified public dispute windows.

Page positions refer to navigation rank, never chronology, risk or authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_dispute_index as index

MAX_PUBLIC_DISPUTE_PAGE_BYTES = 16 * 1024
MAX_DISPUTE_PAGE_LIMIT = 16
_FAILURE = "staging dispute page rejected"


class DisputePageError(RuntimeError):
    """Fixed nonsensitive rejection of invalid public page data."""


@dataclass(frozen=True, slots=True)
class PublicDisputePage:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicDisputePage:
    public_sha256: str
    source_index_sha256: str
    offset: int
    limit: int
    total_windows: int
    next_offset: int | None
    ranked_ranges: tuple[tuple[int, int], ...]


def _canonical(document: dict) -> bytes:
    return json.dumps(
        document, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    document = {}
    for key, value in pairs:
        if key in document:
            raise DisputePageError(_FAILURE)
        document[key] = value
    return document


def _checked(raw: object, expected_sha256: object) -> dict:
    # Reject oversized untrusted inputs before decoding or parsing.
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_PAGE_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise DisputePageError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise DisputePageError(_FAILURE)
    return body


def _compute(
    runs: object, offset: object, limit: object
) -> tuple[PublicDisputePage, VerifiedPublicDisputePage]:
    if (
        type(offset) is not int
        or offset < 0
        or type(limit) is not int
        or not 1 <= limit <= MAX_DISPUTE_PAGE_LIMIT
    ):
        raise DisputePageError(_FAILURE)

    # The complete public index is independently rebuilt from ORIGINAL sources
    # for every call. No detached index, private data or cross-request cache.
    original = index.build_public_dispute_index(runs)
    content = json.loads(original.payload.decode("ascii"))
    total = content["window_count"]
    if offset > total:
        raise DisputePageError(_FAILURE)

    windows = content["ranked_windows"][offset : offset + limit]
    end = offset + len(windows)
    next_offset = end if end < total else None
    page = {
        "schema_version": 1,
        "audience": "public",
        "incident": content["incident"],
        "source_dispute_index_sha256": original.sha256,
        "offset": offset,
        "limit": limit,
        "total_window_count": total,
        "next_offset": next_offset,
        "ranked_windows": windows,
    }
    raw = _canonical(page)
    if not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_PAGE_BYTES:
        raise DisputePageError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    ranges = tuple((w["start_hop"], w["end_hop_exclusive"]) for w in windows)
    return (
        PublicDisputePage(raw, digest),
        VerifiedPublicDisputePage(
            public_sha256=digest,
            source_index_sha256=original.sha256,
            offset=offset,
            limit=limit,
            total_windows=total,
            next_offset=next_offset,
            ranked_ranges=ranges,
        ),
    )


def build_public_dispute_page(runs: object, offset: object, limit: object) -> PublicDisputePage:
    """Build a bounded public navigation page from original verified sources."""
    try:
        return _compute(runs, offset, limit)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputePageError(_FAILURE) from None


def verify_public_dispute_page(
    runs: object,
    offset: object,
    limit: object,
    raw: object,
    *,
    expected_sha256: object,
) -> VerifiedPublicDisputePage:
    """Reject noncanonical, forged, reordered or source-inconsistent pages."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs, offset, limit)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise DisputePageError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputePageError(_FAILURE) from None
