"""Bounded public/private cohort comparison of caller-supplied offline series.

A positional baseline and 2–4 candidates each carry a 2–8-segment verified
casefile series. These are detached data, not attested chronology, authorized
host observations, workflow receipts, or provider-recovery permission.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_comparison_dossier as dossier

MIN_RUNS = 3
MAX_RUNS = 5
MAX_PUBLIC_PORTFOLIO_BYTES = 768 * 1024
MAX_PRIVATE_PORTFOLIO_BYTES = 24 * 1024 * 1024
_FAILURE = "staging portfolio rejected"


class PortfolioError(RuntimeError):
    """Fixed, nonsensitive failure for invalid offline comparison portfolios."""


@dataclass(frozen=True, slots=True)
class PublicPortfolio:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True, repr=False)
class PrivatePortfolio:
    """Private payload carries raw caller-provided paths and changed fields."""

    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicPortfolio:
    incident: str
    public_sha256: str
    baseline_series_sha256: str
    run_count: int
    distinct_series_count: int
    different_member_counts: tuple[int, ...]
    public_comparison_sha256s: tuple[str, ...]


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedPrivatePortfolio:
    public: VerifiedPublicPortfolio
    private_sha256: str
    private_comparison_sha256s: tuple[str, ...]


def _canonical(document: dict) -> bytes:
    return json.dumps(
        document, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise PortfolioError(_FAILURE)
        result[key] = value
    return result


def _valid_sha(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _checked(raw: object, expected_sha256: object, *, max_bytes: int) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= max_bytes
        or not _valid_sha(expected_sha256)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)
    ):
        raise PortfolioError(_FAILURE)
    document = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(document) is not dict or raw != _canonical(document):
        raise PortfolioError(_FAILURE)
    return document


def _runs(value: object) -> tuple:
    if type(value) is not tuple or not MIN_RUNS <= len(value) <= MAX_RUNS:
        raise PortfolioError(_FAILURE)
    return value


def _compute_public(
    runs: object,
) -> tuple[PublicPortfolio, VerifiedPublicPortfolio, tuple[dossier.PublicComparison, ...]]:
    sources = _runs(runs)
    members: list[dict] = []
    all_pairs: list[dossier.PublicComparison] = []
    pair_docs: list[dict] = []
    baseline_sha: str | None = None
    incident: str | None = None
    # Pair comparison verifies original tuples and every source-bound segment.
    for index, candidate in enumerate(sources[1:], 1):
        pair = dossier.build_public_comparison(sources[0], candidate)
        doc = json.loads(pair.payload.decode("ascii"))
        if index == 1:
            baseline_sha = doc["left_series_sha256"]
            incident = doc["incident"]
            members.append(
                {
                    "index": 0,
                    "series_sha256": baseline_sha,
                    "comparison_sha256": None,
                    "comparison": None,
                }
            )
        elif doc["left_series_sha256"] != baseline_sha or doc["incident"] != incident:
            raise PortfolioError(_FAILURE)
        members.append(
            {
                "index": index,
                "series_sha256": doc["right_series_sha256"],
                "comparison_sha256": pair.sha256,
                "comparison": doc,
            }
        )
        pair_docs.append(doc)
        all_pairs.append(pair)

    # Each matrix index is zero-based within the source tuple's caller order;
    # absence is distinguished from a changed overlapping hop.
    max_hops = max(max(x["left_hop_count"], x["right_hop_count"]) for x in pair_docs)
    frequency = []
    for hop_index in range(max_hops):
        equal: list[int] = []
        different: list[int] = []
        missing: list[int] = []
        extra: list[int] = []
        absent: list[int] = []
        for member_index, pair in enumerate(pair_docs, 1):
            if hop_index in pair["identical_hops"]:
                equal.append(member_index)
            elif hop_index in pair["different_hops"]:
                different.append(member_index)
            elif hop_index in pair["left_only_hops"]:
                missing.append(member_index)
            elif hop_index in pair["right_only_hops"]:
                extra.append(member_index)
            elif hop_index >= pair["left_hop_count"] and hop_index >= pair["right_hop_count"]:
                # Both baseline and candidate end before a longer member.
                # This is neither missing-on-right nor candidate-extra.
                absent.append(member_index)
            else:
                raise PortfolioError(_FAILURE)
        frequency.append(
            {
                "index": hop_index,
                "identical_members": equal,
                "different_members": different,
                "missing_members": missing,
                "extra_members": extra,
                "absent_members": absent,
            }
        )

    clusters_by_digest: dict[str, list[int]] = {}
    for member in members:
        clusters_by_digest.setdefault(member["series_sha256"], []).append(member["index"])
    clusters = [
        {"series_sha256": sha, "member_indices": positions}
        for sha, positions in clusters_by_digest.items()
    ]
    report = {
        "schema_version": 1,
        "audience": "public",
        "incident": incident,
        "run_count": len(sources),
        "candidate_count": len(sources) - 1,
        "baseline_series_sha256": baseline_sha,
        "distinct_series_count": len(clusters),
        "series_clusters": clusters,
        "members": members,
        "hop_frequency": frequency,
    }
    raw = _canonical(report)
    if not 1 <= len(raw) <= MAX_PUBLIC_PORTFOLIO_BYTES:
        raise PortfolioError(_FAILURE)
    sha = hashlib.sha256(raw).hexdigest()
    public = PublicPortfolio(raw, sha)
    return (
        public,
        VerifiedPublicPortfolio(
            incident=incident,
            public_sha256=sha,
            baseline_series_sha256=baseline_sha,
            run_count=len(sources),
            distinct_series_count=len(clusters),
            different_member_counts=tuple(len(x["different_hops"]) for x in pair_docs),
            public_comparison_sha256s=tuple(x.sha256 for x in all_pairs),
        ),
        tuple(all_pairs),
    )


def _compute_private(
    runs: object,
) -> tuple[PublicPortfolio, PrivatePortfolio, VerifiedPrivatePortfolio]:
    sources = _runs(runs)
    public, verified, public_pairs = _compute_public(sources)
    members = []
    private_digests: list[str] = []
    for index, candidate in enumerate(sources[1:], 1):
        # Explicitly keep each pair's source-by-source private verification;
        # do not export or construct this information in public mode.
        paired_public, paired_private = dossier.build_private_comparison(
            sources[0], candidate, allow_sensitive_paths=True
        )
        if (
            paired_public.payload != public_pairs[index - 1].payload
            or paired_public.sha256 != public_pairs[index - 1].sha256
        ):
            raise PortfolioError(_FAILURE)
        pair_doc = json.loads(paired_private.payload.decode("ascii"))
        if pair_doc["public_comparison_sha256"] != paired_public.sha256:
            raise PortfolioError(_FAILURE)
        members.append(
            {
                "index": index,
                "public_comparison_sha256": paired_public.sha256,
                "private_comparison_sha256": paired_private.sha256,
                "private_comparison": pair_doc,
            }
        )
        private_digests.append(paired_private.sha256)

    report = {
        "schema_version": 1,
        "audience": "private",
        "incident": verified.incident,
        "run_count": verified.run_count,
        "candidate_count": verified.run_count - 1,
        "public_portfolio_sha256": public.sha256,
        "members": members,
    }
    raw = _canonical(report)
    if not 1 <= len(raw) <= MAX_PRIVATE_PORTFOLIO_BYTES:
        raise PortfolioError(_FAILURE)
    sha = hashlib.sha256(raw).hexdigest()
    return (
        public,
        PrivatePortfolio(raw, sha),
        VerifiedPrivatePortfolio(
            public=verified,
            private_sha256=sha,
            private_comparison_sha256s=tuple(private_digests),
        ),
    )


def build_public_portfolio(runs: object) -> PublicPortfolio:
    """Compare baseline against 2–4 candidates without accessing private paths."""
    try:
        return _compute_public(runs)[0]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise PortfolioError(_FAILURE) from None


def verify_public_portfolio(
    runs: object, raw: object, *, expected_sha256: object
) -> VerifiedPublicPortfolio:
    """Verify a canonical public cohort through exact source regeneration."""
    try:
        _runs(runs)
        _checked(raw, expected_sha256, max_bytes=MAX_PUBLIC_PORTFOLIO_BYTES)
        expected, verified, _pairs = _compute_public(runs)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise PortfolioError(_FAILURE)
        return verified
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise PortfolioError(_FAILURE) from None


def build_private_portfolio(
    runs: object, *, allow_sensitive_paths: object = False
) -> tuple[PublicPortfolio, PrivatePortfolio]:
    """Return source-verified public/private cohort only with exact-True opt-in."""
    try:
        if allow_sensitive_paths is not True:
            raise PortfolioError(_FAILURE)
        return _compute_private(runs)[:2]
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise PortfolioError(_FAILURE) from None


def verify_private_portfolio(
    runs: object,
    public_raw: object,
    private_raw: object,
    *,
    expected_public_sha256: object,
    expected_private_sha256: object,
    allow_sensitive_paths: object = False,
) -> VerifiedPrivatePortfolio:
    """Rebuild all public/private comparisons; reject forged or mixed cohorts."""
    try:
        if allow_sensitive_paths is not True:
            raise PortfolioError(_FAILURE)
        _runs(runs)
        _checked(public_raw, expected_public_sha256, max_bytes=MAX_PUBLIC_PORTFOLIO_BYTES)
        _checked(private_raw, expected_private_sha256, max_bytes=MAX_PRIVATE_PORTFOLIO_BYTES)
        expected_public, expected_private, checked = _compute_private(runs)
        if (
            not hmac.compare_digest(expected_public.payload, public_raw)
            or not hmac.compare_digest(expected_public.sha256, expected_public_sha256)
            or not hmac.compare_digest(expected_private.payload, private_raw)
            or not hmac.compare_digest(expected_private.sha256, expected_private_sha256)
        ):
            raise PortfolioError(_FAILURE)
        return checked
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise PortfolioError(_FAILURE) from None
