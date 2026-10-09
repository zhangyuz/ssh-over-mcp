"""Bounded opt-in private path-bearing audit for a verified public casefile series.

The caller supplies all original frozen snapshots; this code accesses no host,
process, provider, network or trusted workflow authority. Unkeyed digests
authenticate neither the capture origin nor ordering of those snapshots.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from staging_casefile_series import (
    PublicCasefileSeries,
    VerifiedPublicCasefileSeries,
    build_verified_public_casefile_series,
)
from staging_timeline_casefiles import (
    build_private_casefile,
    build_public_casefile,
    verify_private_casefile,
)

MAX_PRIVATE_SERIES_BYTES = 2 * 1024 * 1024
_FAILURE = "staging private series rejected"


class PrivateSeriesError(RuntimeError):
    """Sanitized rejection for invalid private/paired casefile series."""


@dataclass(frozen=True, slots=True, repr=False)
class PrivateCasefileSeries:
    """Sensitive raw caller path strings may occur in payload."""

    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedPrivateCasefileSeries:
    """Verification carries private segment digest bindings; suppress repr."""

    public: VerifiedPublicCasefileSeries
    private_series_sha256: str
    private_segment_sha256s: tuple[str, ...]


def _canonical(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise PrivateSeriesError(_FAILURE)
        result[key] = value
    return result


def _valid_sha(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _validate(raw: object, digest: object, *, max_bytes: int) -> dict:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= max_bytes
        or not _valid_sha(digest)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), digest)
    ):
        raise PrivateSeriesError(_FAILURE)
    document = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs)
    if type(document) is not dict or raw != _canonical(document):
        raise PrivateSeriesError(_FAILURE)
    return document


def _compute(
    segments: object,
) -> tuple[PublicCasefileSeries, PrivateCasefileSeries, VerifiedPrivateCasefileSeries]:
    # Public cross-segment verifier enforces 2–8 segments, 2–17 source
    # snapshots each, equal incident and exact shared full-content endpoint.
    public, verified_public = build_verified_public_casefile_series(segments)
    public_doc = json.loads(public.payload.decode("ascii"))
    records = []
    digests = []
    hop_offset = 0
    for index, snapshots in enumerate(segments):
        segment_public = build_public_casefile(snapshots)
        segment_private = build_private_casefile(snapshots, allow_sensitive_paths=True)
        checked = verify_private_casefile(
            snapshots,
            segment_public.payload,
            segment_private.payload,
            expected_public_sha256=segment_public.sha256,
            expected_private_sha256=segment_private.sha256,
            allow_sensitive_paths=True,
        )
        public_segment = public_doc["segments"][index]
        private_doc = json.loads(segment_private.payload.decode("ascii"))
        audit = private_doc["audit"]
        if (
            segment_public.sha256 != public_segment["public_casefile_sha256"]
            or checked.public.incident != verified_public.incident
            or checked.public.timeline_sha256 != public_segment["timeline_sha256"]
            or checked.public.summary_sha256 != public_segment["summary_sha256"]
            or checked.audit.changed_hops != tuple(public_segment["changed_hops"])
            or checked.audit.audit_sha256 != private_doc["audit_sha256"]
            or private_doc["public_casefile_sha256"] != segment_public.sha256
            or hop_offset != sum(record["hop_count"] for record in public_doc["segments"][:index])
            or len(audit["hops"]) != public_segment["hop_count"]
        ):
            raise PrivateSeriesError(_FAILURE)

        # The private path-details must be numerically consistent with the
        # same verified segment's public *count-only* totals.
        counts = {
            "added_count": sum(len(hop["added_paths"]) for hop in audit["hops"]),
            "removed_count": sum(len(hop["removed_paths"]) for hop in audit["hops"]),
            "modified_count": sum(len(hop["modified_entries"]) for hop in audit["hops"]),
        }
        if any(value != public_segment[name] for name, value in counts.items()):
            raise PrivateSeriesError(_FAILURE)
        records.append(
            {
                "index": index,
                "hop_offset": hop_offset,
                "public_casefile_sha256": segment_public.sha256,
                "private_casefile_sha256": segment_private.sha256,
                "audit_sha256": checked.audit.audit_sha256,
                "audit": audit,
            }
        )
        digests.append(segment_private.sha256)
        hop_offset += public_segment["hop_count"]

    if hop_offset != verified_public.hop_count:
        raise PrivateSeriesError(_FAILURE)
    document = {
        "schema_version": 1,
        "audience": "private",
        "public_series_sha256": public.sha256,
        "incident": verified_public.incident,
        "segment_count": verified_public.segment_count,
        "hop_count": verified_public.hop_count,
        "changed_hops": list(verified_public.changed_hops),
        "net_changed": verified_public.net_changed,
        "segments": records,
    }
    payload = _canonical(document)
    if not 1 <= len(payload) <= MAX_PRIVATE_SERIES_BYTES:
        raise PrivateSeriesError(_FAILURE)
    sha = hashlib.sha256(payload).hexdigest()
    return (
        public,
        PrivateCasefileSeries(payload, sha),
        VerifiedPrivateCasefileSeries(
            public=verified_public,
            private_series_sha256=sha,
            private_segment_sha256s=tuple(digests),
        ),
    )


def build_verified_private_casefile_series(
    segments: object, *, allow_sensitive_paths: object = False
) -> tuple[PublicCasefileSeries, PrivateCasefileSeries, VerifiedPrivateCasefileSeries]:
    """Build one source-verified public/private pair and verified facts.

    Exact-True opt-in prevents accidental export, NOT caller authorization.
    Every source, full-content seal, private audit and count is verified.
    """
    try:
        if allow_sensitive_paths is not True:
            raise PrivateSeriesError(_FAILURE)
        return _compute(segments)
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise PrivateSeriesError(_FAILURE) from None


def build_private_casefile_series(
    segments: object, *, allow_sensitive_paths: object = False
) -> tuple[PublicCasefileSeries, PrivateCasefileSeries]:
    """Return exact matching public and private series; explicit opt-in only."""
    public, private, _verified = build_verified_private_casefile_series(
        segments, allow_sensitive_paths=allow_sensitive_paths
    )
    return public, private


def verify_private_casefile_series(
    segments: object,
    public_raw: object,
    private_raw: object,
    *,
    expected_public_sha256: object,
    expected_private_sha256: object,
    allow_sensitive_paths: object = False,
) -> VerifiedPrivateCasefileSeries:
    """Independently verify public series, every private audit and pairing."""
    try:
        if allow_sensitive_paths is not True:
            raise PrivateSeriesError(_FAILURE)
        from staging_casefile_series import MAX_SERIES_BYTES

        _validate(public_raw, expected_public_sha256, max_bytes=MAX_SERIES_BYTES)
        _validate(private_raw, expected_private_sha256, max_bytes=MAX_PRIVATE_SERIES_BYTES)
        expected_public, expected_private, checked = _compute(segments)
        if (
            not hmac.compare_digest(expected_public.payload, public_raw)
            or not hmac.compare_digest(expected_public.sha256, expected_public_sha256)
            or not hmac.compare_digest(expected_private.payload, private_raw)
            or not hmac.compare_digest(expected_private.sha256, expected_private_sha256)
        ):
            raise PrivateSeriesError(_FAILURE)
        return checked
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise PrivateSeriesError(_FAILURE) from None
