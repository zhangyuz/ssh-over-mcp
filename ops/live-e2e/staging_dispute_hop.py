"""Bounded public dispute-window lookup by source hop, without host authority.

Hop is a zero-based position in caller-supplied snapshots, not trusted time.
The rank is navigation order, not severity. No private paths or provider I/O.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_dispute_index as index

MAX_PUBLIC_DISPUTE_HOP_BYTES = 4 * 1024
_FAILURE = "staging dispute hop rejected"


class DisputeHopError(RuntimeError):
    """Fixed nonsensitive error for invalid or source-inconsistent lookups."""


@dataclass(frozen=True, slots=True)
class PublicDisputeHop:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicDisputeHop:
    public_sha256: str
    source_index_sha256: str
    hop: int
    rank: int | None
    range: tuple[int, int] | None


def _canonical(body: dict) -> bytes:
    return json.dumps(
        body, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    body = {}
    for key, value in pairs:
        if key in body:
            raise DisputeHopError(_FAILURE)
        body[key] = value
    return body


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_HOP_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise DisputeHopError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise DisputeHopError(_FAILURE)
    return body


def _compute(runs: object, hop: object) -> tuple[PublicDisputeHop, VerifiedPublicDisputeHop]:
    if type(hop) is not int or hop < 0:
        raise DisputeHopError(_FAILURE)

    # Rebuild and validate the full index from ORIGINAL sources every call.
    # Never accept a detached caller-supplied index as authority.
    original = index.build_public_dispute_index(runs)
    source = json.loads(original.payload.decode("ascii"))
    if hop >= source["hop_count"]:
        raise DisputeHopError(_FAILURE)

    matches = [
        (rank, window)
        for rank, window in enumerate(source["ranked_windows"])
        if window["start_hop"] <= hop < window["end_hop_exclusive"]
    ]
    # The source index represents disjoint intervals; fail closed if violated.
    if len(matches) > 1:
        raise DisputeHopError(_FAILURE)
    rank, window = matches[0] if matches else (None, None)
    body = {
        "schema_version": 1,
        "audience": "public",
        "incident": source["incident"],
        "source_dispute_index_sha256": original.sha256,
        "hop": hop,
        "hop_count": source["hop_count"],
        "rank": rank,
        "window": window,
    }
    raw = _canonical(body)
    if not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_HOP_BYTES:
        raise DisputeHopError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    facts = VerifiedPublicDisputeHop(
        public_sha256=digest,
        source_index_sha256=original.sha256,
        hop=hop,
        rank=rank,
        range=(window["start_hop"], window["end_hop_exclusive"]) if window else None,
    )
    return PublicDisputeHop(raw, digest), facts


def build_public_dispute_hop(runs: object, hop: object) -> PublicDisputeHop:
    """Select the one disputed public interval containing the requested hop."""
    try:
        return _compute(runs, hop)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeHopError(_FAILURE) from None


def verify_public_dispute_hop(
    runs: object, hop: object, raw: object, *, expected_sha256: object
) -> VerifiedPublicDisputeHop:
    """Check canonical bytes, digest and exact rebuild from original sources."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs, hop)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise DisputeHopError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeHopError(_FAILURE) from None
