"""Offline bounded sparse-rank selection over original-source public disputes.

Rank is only a deterministic navigation position, never chronology,
incident severity, authorization, provenance or provider recovery.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from itertools import pairwise

import staging_dispute_index as index

MAX_PUBLIC_DISPUTE_RANKS_BYTES = 16 * 1024
MAX_DISPUTE_RANKS = 16
_FAILURE = "staging dispute ranks rejected"


class DisputeRanksError(RuntimeError):
    """Fixed nonsensitive error for invalid or inconsistent public rank batches."""


@dataclass(frozen=True, slots=True)
class PublicDisputeRanks:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicDisputeRanks:
    public_sha256: str
    source_index_sha256: str
    ranks: tuple[int, ...]
    ranked_ranges: tuple[tuple[int, int], ...]


def _canonical(body: dict) -> bytes:
    return json.dumps(
        body, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    body = {}
    for key, value in pairs:
        if key in body:
            raise DisputeRanksError(_FAILURE)
        body[key] = value
    return body


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_RANKS_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise DisputeRanksError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise DisputeRanksError(_FAILURE)
    return body


def _compute(runs: object, ranks: object) -> tuple[PublicDisputeRanks, VerifiedPublicDisputeRanks]:
    if type(ranks) not in (tuple, list):
        raise DisputeRanksError(_FAILURE)
    # Snapshot once: mutable caller input must not change during source rebuild.
    selected = tuple(ranks)
    if (
        not 1 <= len(selected) <= MAX_DISPUTE_RANKS
        or any(type(value) is not int or value < 0 for value in selected)
        or any(a >= b for a, b in pairwise(selected))
    ):
        raise DisputeRanksError(_FAILURE)

    # Rebuild from the ORIGINAL caller-ordered 3–5 source cohorts, never a
    # detached index, cached window or caller-provided digest.
    original = index.build_public_dispute_index(runs)
    source = json.loads(original.payload.decode("ascii"))
    windows = source["ranked_windows"]
    if selected[-1] >= len(windows):
        raise DisputeRanksError(_FAILURE)

    rows = [{"rank": value, "window": windows[value]} for value in selected]
    body = {
        "schema_version": 1,
        "audience": "public",
        "incident": source["incident"],
        "source_dispute_index_sha256": original.sha256,
        "hop_count": source["hop_count"],
        "window_count": len(windows),
        "ranks": list(selected),
        "results": rows,
    }
    raw = _canonical(body)
    if not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_RANKS_BYTES:
        raise DisputeRanksError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return (
        PublicDisputeRanks(raw, digest),
        VerifiedPublicDisputeRanks(
            public_sha256=digest,
            source_index_sha256=original.sha256,
            ranks=selected,
            ranked_ranges=tuple(
                (row["window"]["start_hop"], row["window"]["end_hop_exclusive"]) for row in rows
            ),
        ),
    )


def build_public_dispute_ranks(runs: object, ranks: object) -> PublicDisputeRanks:
    """Select 1–16 ordered unique public navigation ranks from original sources."""
    try:
        return _compute(runs, ranks)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeRanksError(_FAILURE) from None


def verify_public_dispute_ranks(
    runs: object, ranks: object, raw: object, *, expected_sha256: object
) -> VerifiedPublicDisputeRanks:
    """Reject oversized, forged, noncanonical or source-inconsistent batches."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs, ranks)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise DisputeRanksError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeRanksError(_FAILURE) from None
