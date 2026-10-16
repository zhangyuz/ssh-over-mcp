"""Untrusted-bundle digest preflight only; NO Sigstore signature verification.

This module never executes/imports a verifier, chooses trust roots, or returns
signature/identity authorization. Genuine T5B trust and verifier are unapproved.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import json

from gate_b0_immutable_bytes import (
    B0aInputRefused,
    SealedMeasurement,
    authenticated_measurement_for_handoff,
)

_MAX_BUNDLE_BYTES = 1024 * 1024
_BUNDLE_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise B0aInputRefused("BUNDLE_JSON_AMBIGUOUS")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise B0aInputRefused("BUNDLE_JSON_INVALID")


def check_bundle_digest_consistency(
    measurement: SealedMeasurement, bundle_bytes: bytes
) -> None:
    """Check a minimum test-bundle envelope and sealed-byte digest equality.

    Matching fields are NOT validated signatures, certificates, Rekor logs,
    timestamps, or trust and MUST NOT generate SYNTHETIC_ONLY or exit success.
    """
    if type(bundle_bytes) is not bytes or not 0 < len(bundle_bytes) <= _MAX_BUNDLE_BYTES:
        raise B0aInputRefused("BUNDLE_BYTES_INVALID")

    # Accept only an issued, still-registered exact sealed measurement.
    _, expected_digest, _ = authenticated_measurement_for_handoff(measurement)

    try:
        bundle = json.loads(
            bundle_bytes.decode("utf-8"),
            object_pairs_hook=_unique_fields,
            parse_constant=_reject_constant,
        )
        if type(bundle) is not dict or bundle.get("mediaType") != _BUNDLE_TYPE:
            raise B0aInputRefused("BUNDLE_FORMAT_REFUSED")
        signed = bundle.get("messageSignature")
        if type(signed) is not dict:
            raise B0aInputRefused("BUNDLE_FORMAT_REFUSED")
        # This is only an envelope shape guard for the fixed test-only
        # conformance bundle, not cryptographic validation of these fields.
        material = bundle.get("verificationMaterial")
        if type(material) is not dict:
            raise B0aInputRefused("BUNDLE_FORMAT_REFUSED")
        cert = material.get("certificate")
        log_entries = material.get("tlogEntries")
        timestamp = material.get("timestampVerificationData")
        if (
            type(cert) is not dict
            or type(log_entries) is not list
            or not log_entries
            or any(type(entry) is not dict for entry in log_entries)
            or type(timestamp) is not dict
            or type(timestamp.get("rfc3161Timestamps")) is not list
            or not timestamp["rfc3161Timestamps"]
        ):
            raise B0aInputRefused("BUNDLE_FORMAT_REFUSED")

        def present_b64(value: object) -> bool:
            if type(value) is not str or not 0 < len(value) <= 16384:
                return False
            try:
                return bool(base64.b64decode(value, validate=True))
            except (ValueError, binascii.Error):
                return False

        if not present_b64(signed.get("signature")) or not present_b64(cert.get("rawBytes")):
            raise B0aInputRefused("BUNDLE_FORMAT_REFUSED")
        if any(
            type(entry) is not dict or not present_b64(entry.get("signedTimestamp"))
            for entry in timestamp["rfc3161Timestamps"]
        ):
            raise B0aInputRefused("BUNDLE_FORMAT_REFUSED")

        declared = signed.get("messageDigest")
        if (
            type(declared) is not dict
            or declared.get("algorithm") != "SHA2_256"
            or type(declared.get("digest")) is not str
        ):
            raise B0aInputRefused("BUNDLE_FORMAT_REFUSED")
        encoded = declared["digest"]
        if len(encoded) != 44:
            raise B0aInputRefused("BUNDLE_DIGEST_INVALID")
        actual = base64.b64decode(encoded, validate=True)
        if len(actual) != 32:
            raise B0aInputRefused("BUNDLE_DIGEST_INVALID")
    except B0aInputRefused:
        raise
    except (UnicodeError, ValueError, RecursionError, binascii.Error):
        raise B0aInputRefused("BUNDLE_FORMAT_REFUSED") from None

    if not hmac.compare_digest(actual, bytes.fromhex(expected_digest)):
        raise B0aInputRefused("BUNDLE_DIGEST_MISMATCH")
    # Deliberately no signature-verification/authorization return value.
