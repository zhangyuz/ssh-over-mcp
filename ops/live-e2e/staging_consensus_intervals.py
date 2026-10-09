"""Bounded, path-free positional consensus interval summary of verified sources.

Intervals are an offline navigation aid across caller-ordered snapshots.
They do not establish authenticated time, process lineage, incident severity,
producer identity, or permission to perform native provider operations.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_cohort_consensus as consensus

MAX_PUBLIC_INTERVALS_BYTES = 64 * 1024
_FAILURE = "staging intervals rejected"


class IntervalsError(RuntimeError):
    """Sanitized rejection of untrusted consensus interval data."""


@dataclass(frozen=True, slots=True)
class PublicIntervals:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicIntervals:
    incident: str
    sha256: str
    source_consensus_sha256: str
    run_count: int
    hop_count: int
    disputed_ranges: tuple[tuple[int, int], ...]


def _canonical(data: dict) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise IntervalsError(_FAILURE)
        result[key] = value
    return result


def _checked(raw: object, digest: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_INTERVALS_BYTES
        or type(digest) is not str
        or len(digest) != 64
        or any(c not in "0123456789abcdef" for c in digest)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), digest)
    ):
        raise IntervalsError(_FAILURE)
    result = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(result) is not dict or raw != _canonical(result):
        raise IntervalsError(_FAILURE)
    return result


def _compute(
    runs: object,
) -> tuple[PublicIntervals, VerifiedPublicIntervals]:
    # The builder fully source-verifies the exact original caller tuples and
    # all lower-layer casefile/series/portfolio provenance *consistency*.
    # The returned digest is unkeyed and never treated as host authority.
    original = consensus.build_public_consensus(runs)
    source = json.loads(original.payload.decode("ascii"))
    intervals: list[dict] = []
    counts = {"unanimous": 0, "majority": 0, "disputed": 0}
    for hop in source["hops"]:
        classification = (
            "unanimous" if hop["unanimous"] else "majority" if hop["quorum_members"] else "disputed"
        )
        counts[classification] += 1
        supporters = list(hop["quorum_members"])
        absent = list(hop["absent_members"])
        previous = intervals[-1] if intervals else None
        if (
            previous is not None
            and previous["classification"] == classification
            and previous["supporting_members"] == supporters
            and previous["absent_members"] == absent
        ):
            previous["end_hop_exclusive"] += 1
        else:
            intervals.append(
                {
                    "start_hop": hop["index"],
                    "end_hop_exclusive": hop["index"] + 1,
                    "classification": classification,
                    "supporting_members": supporters,
                    "absent_members": absent,
                }
            )
    disputed = tuple(
        (x["start_hop"], x["end_hop_exclusive"])
        for x in intervals
        if x["classification"] == "disputed"
    )
    longest = max((end - start for start, end in disputed), default=0)
    document = {
        "schema_version": 1,
        "audience": "public",
        "incident": source["incident"],
        "run_count": source["run_count"],
        "source_consensus_sha256": original.sha256,
        "hop_count": len(source["hops"]),
        "counts": counts,
        "longest_disputed_length": longest,
        "intervals": intervals,
    }
    raw = _canonical(document)
    if not 1 <= len(raw) <= MAX_PUBLIC_INTERVALS_BYTES:
        raise IntervalsError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return PublicIntervals(raw, digest), VerifiedPublicIntervals(
        incident=source["incident"],
        sha256=digest,
        source_consensus_sha256=original.sha256,
        run_count=source["run_count"],
        hop_count=len(source["hops"]),
        disputed_ranges=disputed,
    )


def build_public_intervals(runs: object) -> PublicIntervals:
    """Generate source-sealed offline contiguous intervals with no private paths."""
    try:
        return _compute(runs)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise IntervalsError(_FAILURE) from None


def verify_public_intervals(
    runs: object, raw: object, *, expected_sha256: object
) -> VerifiedPublicIntervals:
    """Rebuild exact canonical intervals from original sources, fail closed."""
    try:
        _checked(raw, expected_sha256)
        expected, verified = _compute(runs)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise IntervalsError(_FAILURE)
        return verified
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise IntervalsError(_FAILURE) from None
