"""Offline drift-artifact/source consistency check; NEVER provenance authentication.

A canonical drift artifact may carry a valid hash while falsely describing
the supplied source snapshots. Compare independently recomputed canonical
reports and bytes against the supplied artifact. Sources are caller-provided
detached records and are not trusted or authenticated by this function.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from staging_drift import DetachedDriftReport, compare_detached_observations
from staging_drift_artifact import (
    DriftArtifact,
    decode_detached_drift,
    encode_detached_drift,
)

_FAILURE = "staging drift binding rejected"


class BindingError(RuntimeError):
    """Sanitized failure to bind a claimed artifact to supplied offline data."""


@dataclass(frozen=True, slots=True)
class ConsistentDetachedDrift:
    """Only *internal* source/artifact coherence; not trusted incident evidence."""

    report: DetachedDriftReport
    artifact_sha256: str


def build_detached_drift_artifact(before: object, after: object) -> DriftArtifact:
    """Build a canonical artifact from two independent frozen offline records.

    No host observation, file access, trusted workflow context, or receipt.
    In particular this function does not imply the supplied records came
    from the real UID-502 host.
    """
    try:
        report = compare_detached_observations(before, after)
        return encode_detached_drift(report)
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise BindingError(_FAILURE) from None


def verify_detached_drift_artifact(
    before: object,
    after: object,
    raw: object,
    *,
    expected_sha256: object,
) -> ConsistentDetachedDrift:
    """Fail closed unless v1 artifact equals fresh offline recomputation.

    Strict decoding/checksum validation precedes comparison. Both snapshots
    are independently validated through the existing projection. Equality
    covers the *reported drift flags* for non-wire marker metadata and
    expected-metadata changes, plus encoded paths and content SHA digests.
    The v1 drift report is lossy: it does NOT bind exact omitted marker
    metadata values or their before/after direction when both report only
    marker_changed=True. A matching report proves only consistency at v1
    report granularity, not unique snapshot-pair identity, provenance, or
    freshness.
    """
    try:
        supplied = decode_detached_drift(raw, expected_sha256=expected_sha256)
        calculated = compare_detached_observations(before, after)
        expected = encode_detached_drift(calculated)
        if (
            supplied != calculated
            or type(raw) is not bytes
            or not hmac.compare_digest(raw, expected.payload)
            or not hmac.compare_digest(expected_sha256, expected.sha256)
        ):
            raise BindingError(_FAILURE)
        return ConsistentDetachedDrift(
            report=calculated,
            artifact_sha256=expected.sha256,
        )
    except (Exception, KeyboardInterrupt, SystemExit, GeneratorExit):  # noqa: BLE001
        raise BindingError(_FAILURE) from None
