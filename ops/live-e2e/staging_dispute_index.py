"""Ranked, path-free disputed-interval index over fully verified source cohorts.

Sorting by interval length supports navigation, not incident severity,
trusted chronology, authorization or host/provider recovery decisions.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_consensus_intervals as intervals

MAX_PUBLIC_DISPUTE_INDEX_BYTES = 32 * 1024
_FAILURE = "staging dispute index rejected"


class DisputeIndexError(RuntimeError):
    """Fixed nonsensitive validation failure for public dispute navigation."""


@dataclass(frozen=True, slots=True)
class PublicDisputeIndex:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicDisputeIndex:
    public_sha256: str
    source_intervals_sha256: str
    incident: str
    run_count: int
    total_disputed_hops: int
    ranked_ranges: tuple[tuple[int, int], ...]


def _canonical(data: dict) -> bytes:
    return json.dumps(
        data, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(items: list[tuple[str, object]]) -> dict:
    document = {}
    for key, value in items:
        if key in document:
            raise DisputeIndexError(_FAILURE)
        document[key] = value
    return document


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_INDEX_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise DisputeIndexError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise DisputeIndexError(_FAILURE)
    return body


def _compute(
    runs: object,
) -> tuple[PublicDisputeIndex, VerifiedPublicDisputeIndex]:
    # Fully verify the ORIGINAL source tuples in this invocation; detached
    # caller-produced interval payloads are never trusted as an input.
    source = intervals.build_public_intervals(runs)
    content = json.loads(source.payload.decode("ascii"))
    ranked = [
        {
            "start_hop": row["start_hop"],
            "end_hop_exclusive": row["end_hop_exclusive"],
            "length_hops": row["end_hop_exclusive"] - row["start_hop"],
            "agreement_groups": row["agreement_groups"],
            "absent_members": row["absent_members"],
        }
        for row in content["intervals"]
        if row["classification"] == "disputed"
    ]
    # Length is only a stable navigation key; never infer incident severity.
    ranked.sort(key=lambda item: (-item["length_hops"], item["start_hop"]))
    ranges = tuple((item["start_hop"], item["end_hop_exclusive"]) for item in ranked)
    if sum(item["length_hops"] for item in ranked) != content["counts"]["disputed"]:
        raise DisputeIndexError(_FAILURE)
    report = {
        "schema_version": 1,
        "audience": "public",
        "incident": content["incident"],
        "run_count": content["run_count"],
        "hop_count": content["hop_count"],
        "source_intervals_sha256": source.sha256,
        "window_count": len(ranked),
        "total_disputed_hops": content["counts"]["disputed"],
        "ranked_windows": ranked,
    }
    raw = _canonical(report)
    if not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_INDEX_BYTES:
        raise DisputeIndexError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return (
        PublicDisputeIndex(raw, digest),
        VerifiedPublicDisputeIndex(
            public_sha256=digest,
            source_intervals_sha256=source.sha256,
            incident=content["incident"],
            run_count=content["run_count"],
            total_disputed_hops=content["counts"]["disputed"],
            ranked_ranges=ranges,
        ),
    )


def build_public_dispute_index(runs: object) -> PublicDisputeIndex:
    """Build a bounded public-only dispute index from original cohort sources."""
    try:
        return _compute(runs)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeIndexError(_FAILURE) from None


def verify_public_dispute_index(
    runs: object, raw: object, *, expected_sha256: object
) -> VerifiedPublicDisputeIndex:
    """Fail closed on forged, noncanonical or source-inconsistent indexes."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise DisputeIndexError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeIndexError(_FAILURE) from None
