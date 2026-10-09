"""Bounded source-verified quorum and raw private effect consensus for a cohort.

Quorum is a positional content fingerprint classification over caller-supplied
source order. It is NOT verified provenance, incident chronology, site policy,
a recovery authorization or an authenticated provider observation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_comparison_dossier as dossier
import staging_comparison_portfolio as portfolio

MAX_PUBLIC_CONSENSUS_BYTES = 256 * 1024
MAX_PRIVATE_CONSENSUS_BYTES = 24 * 1024 * 1024
_FAILURE = "staging consensus rejected"


class ConsensusError(RuntimeError):
    """Sanitized rejection for malformed or source-inconsistent cohort consensus."""


@dataclass(frozen=True, slots=True)
class PublicConsensus:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True, repr=False)
class PrivateConsensus:
    """Contains sensitive raw inventory path and changed-field effects."""

    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicConsensus:
    incident: str
    public_sha256: str
    source_portfolio_sha256: str
    run_count: int
    quorum_hops: tuple[int, ...]
    unanimous_hops: tuple[int, ...]


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedPrivateConsensus:
    public: VerifiedPublicConsensus
    private_sha256: str
    source_private_portfolio_sha256: str


def _canonical(data: dict) -> bytes:
    return json.dumps(
        data, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise ConsensusError(_FAILURE)
        result[key] = value
    return result


def _valid_digest(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _checked(raw: object, digest: object, *, max_bytes: int) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= max_bytes
        or not _valid_digest(digest)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), digest)
    ):
        raise ConsensusError(_FAILURE)
    data = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(data) is not dict or raw != _canonical(data):
        raise ConsensusError(_FAILURE)
    return data


def _from_public_portfolio(
    source: portfolio.PublicPortfolio,
) -> tuple[PublicConsensus, VerifiedPublicConsensus]:
    """Summarize a portfolio verified in the same call; never accept raw input here.

    Only internal callers pass a just-built, source-checked portfolio. Externally
    provided bytes must instead go through the exact-source verifier below.
    """
    data = json.loads(source.payload.decode("ascii"))
    members = data["members"]
    run_count = len(members)
    threshold = run_count // 2 + 1
    pair_reports = [x["comparison"] for x in members[1:]]
    hops: list[dict] = []
    quorum_hops: list[int] = []
    unanimous_hops: list[int] = []
    for index, _partition in enumerate(data["hop_frequency"]):
        states: list[dict | None] = []
        baseline = pair_reports[0]["hops"]
        states.append(baseline[index]["left"] if index < len(baseline) else None)
        for pair in pair_reports:
            rows = pair["hops"]
            states.append(rows[index]["right"] if index < len(rows) else None)
        groups: dict[tuple[str, str, bool], list[int]] = {}
        absent: list[int] = []
        for member_index, hop in enumerate(states):
            if hop is None:
                absent.append(member_index)
            else:
                key = (hop["before_sha256"], hop["after_sha256"], hop["changed"])
                groups.setdefault(key, []).append(member_index)
        entries = [
            {
                "before_sha256": key[0],
                "after_sha256": key[1],
                "changed": key[2],
                "member_indices": indices,
            }
            for key, indices in groups.items()
        ]
        winners = [indices for indices in groups.values() if len(indices) >= threshold]
        if len(winners) > 1:
            raise ConsensusError(_FAILURE)
        quorum = winners[0] if winners else []
        unanimous = len(groups) == 1 and not absent
        if quorum:
            quorum_hops.append(index)
        if unanimous:
            unanimous_hops.append(index)
        hops.append(
            {
                "index": index,
                "groups": entries,
                "absent_members": absent,
                "quorum_members": quorum,
                "unanimous": unanimous,
            }
        )
    report = {
        "schema_version": 1,
        "audience": "public",
        "incident": data["incident"],
        "run_count": run_count,
        "quorum_threshold": threshold,
        "source_portfolio_sha256": source.sha256,
        "hops": hops,
    }
    raw = _canonical(report)
    if not 1 <= len(raw) <= MAX_PUBLIC_CONSENSUS_BYTES:
        raise ConsensusError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return (
        PublicConsensus(raw, digest),
        VerifiedPublicConsensus(
            incident=data["incident"],
            public_sha256=digest,
            source_portfolio_sha256=source.sha256,
            run_count=run_count,
            quorum_hops=tuple(quorum_hops),
            unanimous_hops=tuple(unanimous_hops),
        ),
    )


def _compute_public(runs: object) -> tuple[PublicConsensus, VerifiedPublicConsensus]:
    source = portfolio.build_public_portfolio(runs)
    return _from_public_portfolio(source)


def _compute_private(
    runs: object,
) -> tuple[PublicConsensus, PrivateConsensus, VerifiedPrivateConsensus]:
    # Both portfolios are regenerated from the original caller source tuples;
    # derive the public quorum from this already verified public result ONCE.
    public_source, private_source = portfolio.build_private_portfolio(
        runs, allow_sensitive_paths=True
    )
    public, verified = _from_public_portfolio(public_source)
    private_doc = json.loads(private_source.payload.decode("ascii"))
    paired = [x["private_comparison"] for x in private_doc["members"]]
    effects = [dossier._effects_for(paired[0]["left_private_series"])]
    effects.extend(dossier._effects_for(pair["right_private_series"]) for pair in paired)
    hop_count = len(json.loads(public.payload.decode("ascii"))["hops"])
    rows: list[dict] = []
    for index in range(hop_count):
        grouped: dict[tuple[str, str, tuple[str, ...]], list[int]] = {}
        absent: list[int] = []
        for member_index, member_effects in enumerate(effects):
            if index >= len(member_effects):
                absent.append(member_index)
                continue
            for record in member_effects[index]:
                key = (record["effect"], record["path"], tuple(record["fields"]))
                grouped.setdefault(key, []).append(member_index)
        rows.append(
            {
                "index": index,
                "absent_members": absent,
                "effects": [
                    {
                        "effect": key[0],
                        "path": key[1],
                        "fields": list(key[2]),
                        "member_indices": positions,
                    }
                    for key, positions in sorted(grouped.items())
                ],
            }
        )
    report = {
        "schema_version": 1,
        "audience": "private",
        "incident": verified.incident,
        "run_count": verified.run_count,
        "public_consensus_sha256": public.sha256,
        "source_private_portfolio_sha256": private_source.sha256,
        "hops": rows,
    }
    raw = _canonical(report)
    if not 1 <= len(raw) <= MAX_PRIVATE_CONSENSUS_BYTES:
        raise ConsensusError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return (
        public,
        PrivateConsensus(raw, digest),
        VerifiedPrivateConsensus(
            public=verified,
            private_sha256=digest,
            source_private_portfolio_sha256=private_source.sha256,
        ),
    )


def build_public_consensus(runs: object) -> PublicConsensus:
    """Path-free per-hop strict majority, absence and unanimity over 3–5 runs."""
    try:
        return _compute_public(runs)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ConsensusError(_FAILURE) from None


def verify_public_consensus(
    runs: object, raw: object, *, expected_sha256: object
) -> VerifiedPublicConsensus:
    """Verify canonical bytes against the complete original source tuples."""
    try:
        _checked(raw, expected_sha256, max_bytes=MAX_PUBLIC_CONSENSUS_BYTES)
        expected, verified = _compute_public(runs)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise ConsensusError(_FAILURE)
        return verified
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ConsensusError(_FAILURE) from None


def build_private_consensus(
    runs: object, *, allow_sensitive_paths: object = False
) -> tuple[PublicConsensus, PrivateConsensus]:
    """Exact-True opt-in private raw path/changed-field effect support counts."""
    try:
        if allow_sensitive_paths is not True:
            raise ConsensusError(_FAILURE)
        return _compute_private(runs)[:2]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ConsensusError(_FAILURE) from None


def verify_private_consensus(
    runs: object,
    public_raw: object,
    private_raw: object,
    *,
    expected_public_sha256: object,
    expected_private_sha256: object,
    allow_sensitive_paths: object = False,
) -> VerifiedPrivateConsensus:
    """Regenerate all private source effects and paired public quorum bytes."""
    try:
        if allow_sensitive_paths is not True:
            raise ConsensusError(_FAILURE)
        _checked(public_raw, expected_public_sha256, max_bytes=MAX_PUBLIC_CONSENSUS_BYTES)
        _checked(private_raw, expected_private_sha256, max_bytes=MAX_PRIVATE_CONSENSUS_BYTES)
        public, private, checked = _compute_private(runs)
        if (
            not hmac.compare_digest(public.payload, public_raw)
            or not hmac.compare_digest(public.sha256, expected_public_sha256)
            or not hmac.compare_digest(private.payload, private_raw)
            or not hmac.compare_digest(private.sha256, expected_private_sha256)
        ):
            raise ConsensusError(_FAILURE)
        return checked
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ConsensusError(_FAILURE) from None
