"""End-to-end offline comparison dossier for two verified caller-supplied series.

Public comparison is path-free; opt-in private comparison contains full raw
path-bearing audits and field-level differences. Neither mode authenticates
source chronology, issuer, workflow receipts or authorizes host recovery.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

import staging_private_casefile_series as private_series
from staging_casefile_series import build_verified_public_casefile_series

MAX_PUBLIC_COMPARISON_BYTES = 128 * 1024
MAX_PRIVATE_COMPARISON_BYTES = 6 * 1024 * 1024
_FAILURE = "staging comparison rejected"
_COUNT_FIELDS = ("added_count", "removed_count", "modified_count")


class ComparisonError(RuntimeError):
    """Fixed sanitized rejection for untrusted offline comparison data."""


@dataclass(frozen=True, slots=True)
class PublicComparison:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True, repr=False)
class PrivateComparison:
    """Contains untrusted sensitive caller-provided path and field detail."""

    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicComparison:
    incident: str
    public_sha256: str
    left_series_sha256: str
    right_series_sha256: str
    identical_hops: tuple[int, ...]
    different_hops: tuple[int, ...]
    left_only_hops: tuple[int, ...]
    right_only_hops: tuple[int, ...]
    shared_prefix_snapshots: int
    different_snapshot_indices: tuple[int, ...]


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedPrivateComparison:
    public: VerifiedPublicComparison
    private_sha256: str


def _canonical(document: dict) -> bytes:
    return json.dumps(
        document, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _unique_pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise ComparisonError(_FAILURE)
        result[key] = value
    return result


def _valid_sha(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _checked(raw: object, sha: object, max_size: int) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= max_size
        or not _valid_sha(sha)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), sha)
    ):
        raise ComparisonError(_FAILURE)
    doc = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    if type(doc) is not dict or raw != _canonical(doc):
        raise ComparisonError(_FAILURE)
    return doc


def _hop_rows(public_doc: dict) -> list[dict]:
    # All fields originate from independently source-reverified #184 public
    # series, never from a caller-supplied free-form classification.
    result = []
    for segment in public_doc["segments"]:
        for _ in range(segment["hop_count"]):
            result.append({})
    hashes = public_doc["snapshot_sha256s"]
    changed = set(public_doc["changed_hops"])
    # Only per-segment aggregate count data exist in the source public
    # series; do not invent per-hop path counts from those aggregates.
    for index in range(public_doc["hop_count"]):
        result[index] = {
            "before_sha256": hashes[index],
            "after_sha256": hashes[index + 1],
            "changed": index in changed,
        }
    return result


def _compute_public_from_verified(
    left_series: object, lv: object, right_series: object, rv: object
) -> tuple[PublicComparison, VerifiedPublicComparison, dict, dict]:
    """Compose a pair only from two *already independently source-verified* builds.

    Internal trusted caller contract: NEVER use for external raw reports or
    bypass source validation. Public entry points still verify both inputs.
    """
    if lv.incident != rv.incident:
        raise ComparisonError(_FAILURE)
    left_doc = json.loads(left_series.payload.decode("ascii"))
    right_doc = json.loads(right_series.payload.decode("ascii"))
    left_hops = _hop_rows(left_doc)
    right_hops = _hop_rows(right_doc)
    identical, different, left_only, right_only, rows = [], [], [], [], []
    for index in range(max(len(left_hops), len(right_hops))):
        a = left_hops[index] if index < len(left_hops) else None
        b = right_hops[index] if index < len(right_hops) else None
        if a is None:
            classification = "right_only"
            right_only.append(index)
        elif b is None:
            classification = "left_only"
            left_only.append(index)
        elif a == b:
            classification = "identical"
            identical.append(index)
        else:
            classification = "different"
            different.append(index)
        rows.append({"index": index, "classification": classification, "left": a, "right": b})

    lh = left_doc["snapshot_sha256s"]
    rh = right_doc["snapshot_sha256s"]
    shared_prefix = 0
    for a, b in zip(lh, rh):
        if a != b:
            break
        shared_prefix += 1
    differing_positions = tuple(i for i, (a, b) in enumerate(zip(lh, rh)) if a != b)
    counts_delta = {
        key: right_doc["aggregate"][key] - left_doc["aggregate"][key] for key in _COUNT_FIELDS
    }
    document = {
        "schema_version": 1,
        "audience": "public",
        "incident": lv.incident,
        "left_series_sha256": left_series.sha256,
        "right_series_sha256": right_series.sha256,
        "left_hop_count": lv.hop_count,
        "right_hop_count": rv.hop_count,
        "shared_prefix_snapshots": shared_prefix,
        "different_snapshot_indices": differing_positions,
        "identical_hops": identical,
        "different_hops": different,
        "left_only_hops": left_only,
        "right_only_hops": right_only,
        "left_aggregate": left_doc["aggregate"],
        "right_aggregate": right_doc["aggregate"],
        "counts_delta": counts_delta,
        "left_net_changed": lv.net_changed,
        "right_net_changed": rv.net_changed,
        "hops": rows,
    }
    raw = _canonical(document)
    if not 1 <= len(raw) <= MAX_PUBLIC_COMPARISON_BYTES:
        raise ComparisonError(_FAILURE)
    sha = hashlib.sha256(raw).hexdigest()
    return (
        PublicComparison(raw, sha),
        VerifiedPublicComparison(
            incident=lv.incident,
            public_sha256=sha,
            left_series_sha256=left_series.sha256,
            right_series_sha256=right_series.sha256,
            identical_hops=tuple(identical),
            different_hops=tuple(different),
            left_only_hops=tuple(left_only),
            right_only_hops=tuple(right_only),
            shared_prefix_snapshots=shared_prefix,
            different_snapshot_indices=differing_positions,
        ),
        left_doc,
        right_doc,
    )


def _compute_public(
    left: object, right: object
) -> tuple[PublicComparison, VerifiedPublicComparison, dict, dict]:
    # The source-sealed builders validate every original snapshot/segment.
    left_series, lv = build_verified_public_casefile_series(left)
    right_series, rv = build_verified_public_casefile_series(right)
    return _compute_public_from_verified(left_series, lv, right_series, rv)


def _effects_for(private_doc: dict) -> list[list[dict]]:
    # Each embedded audit was already recomputed from every exact supplied
    # snapshot and linked to its full-content seal by #185.
    effects = []
    for segment in private_doc["segments"]:
        audit = segment["audit"]
        for hop in audit["hops"]:
            group = []
            for effect, key in (("added", "added_paths"), ("removed", "removed_paths")):
                group.extend({"effect": effect, "path": path, "fields": []} for path in hop[key])
            group.extend(
                {
                    "effect": "modified",
                    "path": record["path"],
                    "fields": record["changed_fields"],
                }
                for record in hop["modified_entries"]
            )
            group.sort(key=lambda record: (record["effect"], record["path"], record["fields"]))
            effects.append(group)
    return effects


def _compute_private(
    left: object, right: object
) -> tuple[PublicComparison, PrivateComparison, VerifiedPrivateComparison]:
    public, verified, left_doc, right_doc = _compute_public(left, right)
    # A verified build recomputes every private source audit and exact
    # public binding once. Verifying the just-generated bytes again would
    # be a redundant second full multi-segment source traversal.
    left_public_series, left_private_series, checked_left = (
        private_series.build_verified_private_casefile_series(left, allow_sensitive_paths=True)
    )
    right_public_series, right_private_series, checked_right = (
        private_series.build_verified_private_casefile_series(right, allow_sensitive_paths=True)
    )
    if (
        checked_left.public.series_sha256 != verified.left_series_sha256
        or checked_right.public.series_sha256 != verified.right_series_sha256
        or checked_left.public.incident != verified.incident
        or checked_right.public.incident != verified.incident
        or left_public_series.sha256 != verified.left_series_sha256
        or right_public_series.sha256 != verified.right_series_sha256
    ):
        raise ComparisonError(_FAILURE)
    private_left = json.loads(left_private_series.payload.decode("ascii"))
    private_right = json.loads(right_private_series.payload.decode("ascii"))
    left_effects = _effects_for(private_left)
    right_effects = _effects_for(private_right)
    if len(left_effects) != left_doc["hop_count"] or len(right_effects) != right_doc["hop_count"]:
        raise ComparisonError(_FAILURE)
    records = []
    for index in range(max(len(left_effects), len(right_effects))):
        a = left_effects[index] if index < len(left_effects) else []
        b = right_effects[index] if index < len(right_effects) else []
        # Compare canonical structural triples; filenames may contain Unicode
        # and even unusual separators. Never use an ambiguous string key.
        a_map = {(x["effect"], x["path"], tuple(x["fields"])): x for x in a}
        b_map = {(x["effect"], x["path"], tuple(x["fields"])): x for x in b}
        records.append(
            {
                "index": index,
                "left_only_effects": [a_map[key] for key in sorted(a_map.keys() - b_map.keys())],
                "right_only_effects": [b_map[key] for key in sorted(b_map.keys() - a_map.keys())],
                "shared_effect_count": len(a_map.keys() & b_map.keys()),
            }
        )
    report = {
        "schema_version": 1,
        "audience": "private",
        "incident": verified.incident,
        "public_comparison_sha256": public.sha256,
        "left_private_series_sha256": left_private_series.sha256,
        "right_private_series_sha256": right_private_series.sha256,
        "left_private_series": private_left,
        "right_private_series": private_right,
        "hops": records,
    }
    raw = _canonical(report)
    if not 1 <= len(raw) <= MAX_PRIVATE_COMPARISON_BYTES:
        raise ComparisonError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return (
        public,
        PrivateComparison(raw, digest),
        VerifiedPrivateComparison(public=verified, private_sha256=digest),
    )


def build_public_comparison(left: object, right: object) -> PublicComparison:
    """Public path-free full-series comparison without private audit work."""
    try:
        public, _verified, _left_doc, _right_doc = _compute_public(left, right)
        return public
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ComparisonError(_FAILURE) from None


def verify_public_comparison(
    left: object, right: object, raw: object, *, expected_sha256: object
) -> VerifiedPublicComparison:
    """Rebuild source-bound public comparison and compare exact canonical bytes."""
    try:
        _checked(raw, expected_sha256, MAX_PUBLIC_COMPARISON_BYTES)
        expected, checked, _l, _r = _compute_public(left, right)
        if not hmac.compare_digest(expected.payload, raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise ComparisonError(_FAILURE)
        return checked
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ComparisonError(_FAILURE) from None


def build_private_comparison(
    left: object, right: object, *, allow_sensitive_paths: object = False
) -> tuple[PublicComparison, PrivateComparison]:
    """Opt-in forensic path differences and independently bound public report."""
    try:
        if allow_sensitive_paths is not True:
            raise ComparisonError(_FAILURE)
        public, private, _verified = _compute_private(left, right)
        return public, private
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ComparisonError(_FAILURE) from None


def verify_private_comparison(
    left: object,
    right: object,
    public_raw: object,
    private_raw: object,
    *,
    expected_public_sha256: object,
    expected_private_sha256: object,
    allow_sensitive_paths: object = False,
) -> VerifiedPrivateComparison:
    """Reject forged/private swaps by full public/private source regeneration."""
    try:
        if allow_sensitive_paths is not True:
            raise ComparisonError(_FAILURE)
        _checked(public_raw, expected_public_sha256, MAX_PUBLIC_COMPARISON_BYTES)
        _checked(private_raw, expected_private_sha256, MAX_PRIVATE_COMPARISON_BYTES)
        expected_public, expected_private, checked = _compute_private(left, right)
        if (
            not hmac.compare_digest(expected_public.payload, public_raw)
            or not hmac.compare_digest(expected_public.sha256, expected_public_sha256)
            or not hmac.compare_digest(expected_private.payload, private_raw)
            or not hmac.compare_digest(expected_private.sha256, expected_private_sha256)
        ):
            raise ComparisonError(_FAILURE)
        return checked
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise ComparisonError(_FAILURE) from None
