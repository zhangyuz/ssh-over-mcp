"""One-call detached timeline casefiles with explicit public/private separation.

Both artifacts describe only the supplied snapshot tuple. Even exact checksums
are not authenticated capture, time ordering, workflow receipts or recovery
permissions. No host, file, process, network or provider access is performed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from staging_snapshot_timeline import (
    BuiltSnapshotTimeline,
    build_snapshot_timeline,
    verify_snapshot_timeline,
)
from staging_timeline_audit import (
    VerifiedTimelineAudit,
    build_timeline_audit,
    verify_timeline_audit,
)
from staging_timeline_summary import (
    build_timeline_change_summary,
    verify_timeline_change_summary,
)

MAX_PUBLIC_CASEFILE_BYTES = 32 * 1024
MAX_PRIVATE_CASEFILE_BYTES = 160 * 1024
_FAILURE = "staging timeline casefile rejected"


class CasefileError(RuntimeError):
    """One sanitized failure for all malformed, untrusted or disallowed inputs."""


@dataclass(frozen=True, slots=True)
class PublicCasefile:
    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True, repr=False)
class PrivateCasefile:
    """Contains caller-supplied raw inventory paths; never implicitly log/repr it."""

    payload: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedPublicCasefile:
    incident: str
    timeline_sha256: str
    summary_sha256: str
    public_sha256: str
    changed_hops: tuple[int, ...]


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedPrivateCasefile:
    """Path-bearing verification result; sensitive by default."""

    public: VerifiedPublicCasefile
    audit: VerifiedTimelineAudit
    private_sha256: str


def _canonical(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in items:
        if name in result:
            raise CasefileError(_FAILURE)
        result[name] = value
    return result


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _checked_document(raw: object, digest: object, bound: int) -> dict:
    # Size and checksum checks precede parsing attacker-supplied JSON.
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= bound
        or not _is_sha256(digest)
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), digest)
    ):
        raise CasefileError(_FAILURE)
    document = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs)
    if type(document) is not dict or raw != _canonical(document):
        raise CasefileError(_FAILURE)
    return document


def _public(
    snapshots: object,
) -> tuple[PublicCasefile, VerifiedPublicCasefile, BuiltSnapshotTimeline]:
    # A single tuple feeds the original sealed timeline AND the verified,
    # path-free change summary. No path-bearing audit is created here.
    chain = build_snapshot_timeline(snapshots)
    timeline = verify_snapshot_timeline(
        snapshots, chain.hops, chain.manifest.payload, expected_sha256=chain.manifest.sha256
    )
    summary = build_timeline_change_summary(
        snapshots,
        chain.hops,
        chain.manifest.payload,
        expected_timeline_sha256=chain.manifest.sha256,
    )
    checked = verify_timeline_change_summary(
        snapshots,
        chain.hops,
        chain.manifest.payload,
        summary.payload,
        expected_timeline_sha256=chain.manifest.sha256,
        expected_summary_sha256=summary.sha256,
    )
    if checked.timeline_sha256 != timeline.timeline_sha256 or (
        checked.changed_hops != timeline.changed_hops
    ):
        raise CasefileError(_FAILURE)
    document = {
        "schema_version": 1,
        "audience": "public",
        "timeline_sha256": chain.manifest.sha256,
        "summary_sha256": summary.sha256,
        "timeline": json.loads(chain.manifest.payload.decode("ascii")),
        "summary": json.loads(summary.payload.decode("ascii")),
    }
    raw = _canonical(document)
    if not 1 <= len(raw) <= MAX_PUBLIC_CASEFILE_BYTES:
        raise CasefileError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return (
        PublicCasefile(raw, digest),
        VerifiedPublicCasefile(
            incident=timeline.incident,
            timeline_sha256=timeline.timeline_sha256,
            summary_sha256=summary.sha256,
            public_sha256=digest,
            changed_hops=timeline.changed_hops,
        ),
        chain,
    )


def _private(
    snapshots: object,
) -> tuple[PublicCasefile, PrivateCasefile, VerifiedPrivateCasefile]:
    public, verified_public, chain = _public(snapshots)
    audit = build_timeline_audit(
        snapshots,
        chain.hops,
        chain.manifest.payload,
        expected_timeline_sha256=chain.manifest.sha256,
    )
    verified_audit = verify_timeline_audit(
        snapshots,
        chain.hops,
        chain.manifest.payload,
        audit.payload,
        expected_timeline_sha256=chain.manifest.sha256,
        expected_audit_sha256=audit.sha256,
    )
    if (
        verified_audit.timeline_sha256 != verified_public.timeline_sha256
        or verified_audit.incident != verified_public.incident
        or verified_audit.changed_hops != verified_public.changed_hops
    ):
        raise CasefileError(_FAILURE)
    # The private payload is neither included in the public output nor
    # reachable from the public builder. The explicit opt-in belongs to
    # public entry points, never silently defaulted by this helper.
    raw = _canonical(
        {
            "schema_version": 1,
            "audience": "private",
            "public_casefile_sha256": public.sha256,
            "audit_sha256": audit.sha256,
            "audit": json.loads(audit.payload.decode("ascii")),
        }
    )
    if not 1 <= len(raw) <= MAX_PRIVATE_CASEFILE_BYTES:
        raise CasefileError(_FAILURE)
    digest = hashlib.sha256(raw).hexdigest()
    return (
        public,
        PrivateCasefile(raw, digest),
        VerifiedPrivateCasefile(
            public=verified_public, audit=verified_audit, private_sha256=digest
        ),
    )


def build_public_casefile(snapshots: object) -> PublicCasefile:
    """Export canonical path-free timeline + change summary in one call."""
    try:
        public, _verified, _chain = _public(snapshots)
        return public
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise CasefileError(_FAILURE) from None


def verify_public_casefile(
    snapshots: object, public_raw: object, *, expected_sha256: object
) -> VerifiedPublicCasefile:
    """Rebuild a public casefile byte-for-byte from the original source tuple."""
    try:
        _checked_document(public_raw, expected_sha256, MAX_PUBLIC_CASEFILE_BYTES)
        expected, verified, _chain = _public(snapshots)
        if not hmac.compare_digest(expected.payload, public_raw) or not hmac.compare_digest(
            expected.sha256, expected_sha256
        ):
            raise CasefileError(_FAILURE)
        return verified
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise CasefileError(_FAILURE) from None


def build_private_casefile(
    snapshots: object, *, allow_sensitive_paths: object = False
) -> PrivateCasefile:
    """Export path-bearing audit only on exact True. Opt-in is not access control."""
    try:
        if type(allow_sensitive_paths) is not bool or allow_sensitive_paths is not True:
            raise CasefileError(_FAILURE)
        _public_record, private, _verified = _private(snapshots)
        return private
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise CasefileError(_FAILURE) from None


def verify_private_casefile(
    snapshots: object,
    public_raw: object,
    private_raw: object,
    *,
    expected_public_sha256: object,
    expected_private_sha256: object,
    allow_sensitive_paths: object = False,
) -> VerifiedPrivateCasefile:
    """Recheck exact public binding AND private audit from supplied sources."""
    try:
        if type(allow_sensitive_paths) is not bool or allow_sensitive_paths is not True:
            raise CasefileError(_FAILURE)
        _checked_document(public_raw, expected_public_sha256, MAX_PUBLIC_CASEFILE_BYTES)
        _checked_document(private_raw, expected_private_sha256, MAX_PRIVATE_CASEFILE_BYTES)
        expected_public, expected_private, checked = _private(snapshots)
        if (
            not hmac.compare_digest(expected_public.payload, public_raw)
            or not hmac.compare_digest(expected_public.sha256, expected_public_sha256)
            or not hmac.compare_digest(expected_private.payload, private_raw)
            or not hmac.compare_digest(expected_private.sha256, expected_private_sha256)
        ):
            raise CasefileError(_FAILURE)
        return checked
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise CasefileError(_FAILURE) from None
