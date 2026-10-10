"""Bounded public batch lookup of disputed windows by strictly ordered hops.

No private paths, provider I/O, trusted chronology, severity or authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from itertools import pairwise

import staging_dispute_index as index

MAX_PUBLIC_DISPUTE_HOPS_BYTES = 16 * 1024
MAX_DISPUTE_HOPS = 16
_FAILURE = "staging dispute hops rejected"


class DisputeHopsError(RuntimeError):
    """Fixed nonsensitive rejection for invalid public batch lookups."""


@dataclass(frozen=True, slots=True)
class PublicDisputeHops:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicDisputeHops:
    public_sha256: str
    source_index_sha256: str
    hops: tuple[int, ...]
    ranks: tuple[int | None, ...]


def _canonical(body: dict) -> bytes:
    return json.dumps(
        body, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    body = {}
    for key, value in pairs:
        if key in body:
            raise DisputeHopsError(_FAILURE)
        body[key] = value
    return body


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_HOPS_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise DisputeHopsError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise DisputeHopsError(_FAILURE)
    return body


def _compute(runs: object, hops: object) -> tuple[PublicDisputeHops, VerifiedPublicDisputeHops]:
    if type(hops) not in (tuple, list):
        raise DisputeHopsError(_FAILURE)
    # Freeze the caller's mutable list once, before validation or expensive
    # source reconstruction. Never reread it after this boundary.
    selected = tuple(hops)
    if (
        not 1 <= len(selected) <= MAX_DISPUTE_HOPS
        or any(type(hop) is not int or hop < 0 for hop in selected)
        or any(a >= b for a, b in pairwise(selected))
    ):
        raise DisputeHopsError(_FAILURE)

    # Rebuild the full original-source index once per call, without cache,
    # detached index, private portfolio, host or provider access.
    original = index.build_public_dispute_index(runs)
    source = json.loads(original.payload.decode("ascii"))
    if selected[-1] >= source["hop_count"]:
        raise DisputeHopsError(_FAILURE)

    rows = []
    for hop in selected:
        matches = [
            (rank, window)
            for rank, window in enumerate(source["ranked_windows"])
            if window["start_hop"] <= hop < window["end_hop_exclusive"]
        ]
        if len(matches) > 1:
            raise DisputeHopsError(_FAILURE)
        rank, window = matches[0] if matches else (None, None)
        rows.append({"hop": hop, "rank": rank, "window": window})
    body = {
        "schema_version": 1,
        "audience": "public",
        "incident": source["incident"],
        "source_dispute_index_sha256": original.sha256,
        "hop_count": source["hop_count"],
        "hops": list(selected),
        "results": rows,
    }
    raw = _canonical(body)
    if not 1 <= len(raw) <= MAX_PUBLIC_DISPUTE_HOPS_BYTES:
        raise DisputeHopsError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return (
        PublicDisputeHops(raw, digest),
        VerifiedPublicDisputeHops(
            public_sha256=digest,
            source_index_sha256=original.sha256,
            hops=selected,
            ranks=tuple(row["rank"] for row in rows),
        ),
    )


def build_public_dispute_hops(runs: object, hops: object) -> PublicDisputeHops:
    """Batch up to 16 ordered distinct hop lookups from original source cohorts."""
    try:
        return _compute(runs, hops)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeHopsError(_FAILURE) from None


def verify_public_dispute_hops(
    runs: object, hops: object, raw: object, *, expected_sha256: object
) -> VerifiedPublicDisputeHops:
    """Reject forged/noncanonical batches and mismatched original sources."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs, hops)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise DisputeHopsError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise DisputeHopsError(_FAILURE) from None
