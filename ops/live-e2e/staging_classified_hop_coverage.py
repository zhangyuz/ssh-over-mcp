"""Bounded source-verified counts of unanimous, majority and disputed hops.

Classification is only deterministic public navigation evidence; majority
is not a certification of safety, chronology, severity, or host authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_consensus_intervals as intervals

MAX_PUBLIC_CLASSIFIED_HOP_COVERAGE_BYTES = 4 * 1024
_FAILURE = "staging classified hop coverage rejected"
_CLASSES = ("unanimous", "majority", "disputed")


class ClassifiedHopCoverageError(RuntimeError):
    """Fixed sanitized rejection of invalid or forged public coverage."""


@dataclass(frozen=True, slots=True)
class PublicClassifiedHopCoverage:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicClassifiedHopCoverage:
    public_sha256: str
    source_intervals_sha256: str
    query_start_hop: int
    query_end_hop_exclusive: int
    classified_hops: tuple[int, int, int]


def _canonical(body: dict) -> bytes:
    return json.dumps(
        body, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    body = {}
    for key, value in pairs:
        if key in body:
            raise ClassifiedHopCoverageError(_FAILURE)
        body[key] = value
    return body


def _checked(raw: object, expected_sha256: object) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= MAX_PUBLIC_CLASSIFIED_HOP_COVERAGE_BYTES
        or type(expected_sha256) is not str
        or len(expected_sha256) != 64
        or any(c not in "0123456789abcdef" for c in expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise ClassifiedHopCoverageError(_FAILURE)
    body = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(body) is not dict or raw != _canonical(body):
        raise ClassifiedHopCoverageError(_FAILURE)
    return body


def _compute(
    runs: object, start_hop: object, end_hop_exclusive: object
) -> tuple[PublicClassifiedHopCoverage, VerifiedPublicClassifiedHopCoverage]:
    if (
        type(start_hop) is not int
        or type(end_hop_exclusive) is not int
        or start_hop < 0
        or end_hop_exclusive <= start_hop
    ):
        raise ClassifiedHopCoverageError(_FAILURE)

    # Trust only the public intervals rebuilt from original caller-ordered
    # 3–5 cohort sources. Detached interval wire and source digests are not
    # inputs; every verifier call independently repeats this computation.
    source = intervals.build_public_intervals(runs)
    original = json.loads(source.payload.decode("ascii"))
    if end_hop_exclusive > original["hop_count"]:
        raise ClassifiedHopCoverageError(_FAILURE)

    counts = {key: 0 for key in _CLASSES}
    for item in original["intervals"]:
        left = max(start_hop, item["start_hop"])
        right = min(end_hop_exclusive, item["end_hop_exclusive"])
        if right > left:
            counts[item["classification"]] += right - left
    queried_hops = end_hop_exclusive - start_hop
    if sum(counts.values()) != queried_hops:
        raise ClassifiedHopCoverageError(_FAILURE)

    body = {
        "schema_version": 1,
        "audience": "public",
        "incident": original["incident"],
        "hop_count": original["hop_count"],
        "source_intervals_sha256": source.sha256,
        "query": {
            "start_hop": start_hop,
            "end_hop_exclusive": end_hop_exclusive,
        },
        "query_hops": queried_hops,
        "unanimous_hops": counts["unanimous"],
        "majority_hops": counts["majority"],
        "disputed_hops": counts["disputed"],
        "non_disputed_hops": counts["unanimous"] + counts["majority"],
    }
    raw = _canonical(body)
    if not 1 <= len(raw) <= MAX_PUBLIC_CLASSIFIED_HOP_COVERAGE_BYTES:
        raise ClassifiedHopCoverageError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return PublicClassifiedHopCoverage(raw, digest), VerifiedPublicClassifiedHopCoverage(
        public_sha256=digest,
        source_intervals_sha256=source.sha256,
        query_start_hop=start_hop,
        query_end_hop_exclusive=end_hop_exclusive,
        classified_hops=tuple(counts[key] for key in _CLASSES),
    )


def build_public_classified_hop_coverage(
    runs: object, start_hop: object, end_hop_exclusive: object
) -> PublicClassifiedHopCoverage:
    """Build one bounded original-source public hop classification summary."""
    try:
        return _compute(runs, start_hop, end_hop_exclusive)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ClassifiedHopCoverageError(_FAILURE) from None


def verify_public_classified_hop_coverage(
    runs: object,
    start_hop: object,
    end_hop_exclusive: object,
    raw: object,
    *,
    expected_sha256: object,
) -> VerifiedPublicClassifiedHopCoverage:
    """Verify byte-exact canonical summary by rebuilding the original source."""
    try:
        _checked(raw, expected_sha256)
        expected, facts = _compute(runs, start_hop, end_hop_exclusive)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise ClassifiedHopCoverageError(_FAILURE)
        return facts
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ClassifiedHopCoverageError(_FAILURE) from None
