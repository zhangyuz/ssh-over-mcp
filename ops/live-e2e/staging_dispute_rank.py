"""Offline source-verified public disputed-window lookup by navigation rank.

Rank is positional within the full public index, never incident severity,
trusted chronology, authorization or provider-recovery permission.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_dispute_index as index

MAX_PUBLIC_DISPUTE_RANK_BYTES = 4 * 1024
_FAILURE = "staging dispute rank rejected"


class DisputeRankError(RuntimeError):
    """Fixed nonsensitive error for invalid or source-inconsistent lookups."""


@dataclass(frozen=True, slots=True)
class PublicDisputeRank:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicDisputeRank:
    public_sha256: str
    source_index_sha256: str
    rank: int
    start_hop: int
    end_hop_exclusive: int


def _canonical(body: dict) -> bytes:
    return json.dumps(
        body, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    body = {}
    for key, value in pairs:
        if key in body:
            raise DisputeRankError(_FAILURE)
        body[key] = value
    return body


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_RANK_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise DisputeRankError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise DisputeRankError(_FAILURE)
    return body


def _compute(runs: object, rank: object) -> tuple[PublicDisputeRank, VerifiedPublicDisputeRank]:
    if type(rank) is not int or rank < 0:
        raise DisputeRankError(_FAILURE)

    # Never trust a detached index or a caller-provided rank/window pairing.
    original = index.build_public_dispute_index(runs)
    source = json.loads(original.payload.decode("ascii"))
    windows = source["ranked_windows"]
    if rank >= len(windows):
        raise DisputeRankError(_FAILURE)
    window = windows[rank]
    body = {
        "schema_version": 1,
        "audience": "public",
        "incident": source["incident"],
        "source_dispute_index_sha256": original.sha256,
        "hop_count": source["hop_count"],
        "window_count": len(windows),
        "rank": rank,
        "window": window,
    }
    raw = _canonical(body)
    if not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_RANK_BYTES:
        raise DisputeRankError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return PublicDisputeRank(raw, digest), VerifiedPublicDisputeRank(
        public_sha256=digest,
        source_index_sha256=original.sha256,
        rank=rank,
        start_hop=window["start_hop"],
        end_hop_exclusive=window["end_hop_exclusive"],
    )


def build_public_dispute_rank(runs: object, rank: object) -> PublicDisputeRank:
    """Return the exact ranked disputed public window from original cohorts."""
    try:
        return _compute(runs, rank)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeRankError(_FAILURE) from None


def verify_public_dispute_rank(
    runs: object, rank: object, raw: object, *, expected_sha256: object
) -> VerifiedPublicDisputeRank:
    """Validate bounded canonical bytes and exact original-source reconstruction."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs, rank)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise DisputeRankError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeRankError(_FAILURE) from None
