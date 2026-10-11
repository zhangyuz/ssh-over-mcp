"""Public bounded pages of original-source intervals selected by 1-3 classifications.

The projection is deterministic navigation, not time, provider state,
authenticated provenance, authorization or certification of safety.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_consensus_intervals as intervals

MAX_CLASSIFIED_HOP_MULTIFILTER_CLASSES = 3
MAX_CLASSIFIED_HOP_MULTIFILTER_PAGE_LIMIT = 8
MAX_PUBLIC_CLASSIFIED_HOP_MULTIFILTER_PAGE_BYTES = 4 * 1024
_FAILURE = "staging classified hop multifilter page rejected"
_CLASSES = ("unanimous", "majority", "disputed")


class ClassifiedHopMultifilterPageError(RuntimeError):
    """Fixed sanitized error for rejected public class-filtered pages."""


@dataclass(frozen=True, slots=True)
class PublicClassifiedHopMultifilterPage:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicClassifiedHopMultifilterPage:
    public_sha256: str
    source_intervals_sha256: str
    selected_classes: tuple[str, ...]
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
    result = {}
    for key, value in pairs:
        if key in result:
            raise ClassifiedHopMultifilterPageError(_FAILURE)
        result[key] = value
    return result


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_CLASSIFIED_HOP_MULTIFILTER_PAGE_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise ClassifiedHopMultifilterPageError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise ClassifiedHopMultifilterPageError(_FAILURE)
    return body


def _compute(
    runs: object,
    start_hop: object,
    end_hop_exclusive: object,
    categories: object,
    offset: object,
    limit: object,
) -> tuple[PublicClassifiedHopMultifilterPage, VerifiedPublicClassifiedHopMultifilterPage]:
    if (
        type(start_hop) is not int
        or type(end_hop_exclusive) is not int
        or start_hop < 0
        or end_hop_exclusive <= start_hop
        or type(categories) not in (tuple, list)
        or type(offset) is not int
        or offset < 0
        or type(limit) is not int
        or not 1 <= limit <= MAX_CLASSIFIED_HOP_MULTIFILTER_PAGE_LIMIT
    ):
        raise ClassifiedHopMultifilterPageError(_FAILURE)

    # Snapshot bounded caller-owned mutable collection once before
    # source reconstruction. Reject duplicates rather than silently
    # changing the intended class query semantics.
    selected_classes = tuple(categories[: MAX_CLASSIFIED_HOP_MULTIFILTER_CLASSES + 1])
    if (
        not 1 <= len(selected_classes) <= MAX_CLASSIFIED_HOP_MULTIFILTER_CLASSES
        or any(type(kind) is not str or kind not in _CLASSES for kind in selected_classes)
        or len(set(selected_classes)) != len(selected_classes)
    ):
        raise ClassifiedHopMultifilterPageError(_FAILURE)

    # Rebuild the entire original 3–5 ordered source cohorts' public
    # intervals once for each independent build or verify invocation.
    original = intervals.build_public_intervals(runs)
    source = json.loads(original.payload.decode("ascii"))
    if end_hop_exclusive > source["hop_count"]:
        raise ClassifiedHopMultifilterPageError(_FAILURE)
    rows = []
    for item in source["intervals"]:
        if item["classification"] not in selected_classes:
            continue
        left = max(start_hop, item["start_hop"])
        right = min(end_hop_exclusive, item["end_hop_exclusive"])
        if left < right:
            rows.append((left, right, item["classification"]))
    total = len(rows)
    if offset > total:
        raise ClassifiedHopMultifilterPageError(_FAILURE)
    selected = tuple(rows[offset : offset + limit])
    next_offset = offset + len(selected) if offset + len(selected) < total else None
    wire = {
        "schema_version": 1,
        "audience": "public",
        "incident": source["incident"],
        "hop_count": source["hop_count"],
        "source_intervals_sha256": original.sha256,
        "query": {"start_hop": start_hop, "end_hop_exclusive": end_hop_exclusive},
        "selected_classes": list(selected_classes),
        "offset": offset,
        "limit": limit,
        "total_segments": total,
        "next_offset": next_offset,
        "segments": [
            {"start_hop": start, "end_hop_exclusive": end, "classification": kind}
            for start, end, kind in selected
        ],
    }
    raw = _canonical(wire)
    if not 1 <= len(raw) <= MAX_PUBLIC_CLASSIFIED_HOP_MULTIFILTER_PAGE_BYTES:
        raise ClassifiedHopMultifilterPageError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return (
        PublicClassifiedHopMultifilterPage(raw, digest),
        VerifiedPublicClassifiedHopMultifilterPage(
            public_sha256=digest,
            source_intervals_sha256=original.sha256,
            selected_classes=selected_classes,
            offset=offset,
            limit=limit,
            total_segments=total,
            next_offset=next_offset,
            segments=selected,
        ),
    )


def build_public_classified_hop_multifilter_page(
    runs: object,
    start_hop: object,
    end_hop_exclusive: object,
    categories: object,
    offset: object,
    limit: object,
) -> PublicClassifiedHopMultifilterPage:
    """Build a bounded page after original-source class-set filtering."""
    try:
        return _compute(runs, start_hop, end_hop_exclusive, categories, offset, limit)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ClassifiedHopMultifilterPageError(_FAILURE) from None


def verify_public_classified_hop_multifilter_page(
    runs: object,
    start_hop: object,
    end_hop_exclusive: object,
    categories: object,
    offset: object,
    limit: object,
    raw: object,
    *,
    expected_sha256: object,
) -> VerifiedPublicClassifiedHopMultifilterPage:
    """Verify byte-exact public interval page from the unchanged original cohorts."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs, start_hop, end_hop_exclusive, categories, offset, limit)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise ClassifiedHopMultifilterPageError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ClassifiedHopMultifilterPageError(_FAILURE) from None
