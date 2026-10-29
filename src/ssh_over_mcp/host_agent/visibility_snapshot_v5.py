"""Inactive authenticated visibility snapshot contract for future SMCP v2.

This module intentionally does NOT hook into the live host-agent, SSH transport
or MCP registry. The runtime must still supply a *trusted* key separate from
Ledger's key, atomic persistent nonce consumption, monotonic epoch/revocation
ACK state and local host policy before calling verify_snapshot. This is NOT a
substitute for central compilation/reauthorization or for mount/race validation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .visibility_policy_v5 import (
    VisibilityOperation,
    VisibilityPolicyV5,
    VisibilityRules,
    _within,
    canonical_visibility_path,
)

_SNAPSHOT_DOMAIN = b"SOM:SMCPv2:FS-VISIBILITY-SNAPSHOT:HMAC-SHA256:v1\0"
MAX_SNAPSHOT_TTL_SECONDS = 60


class SnapshotVerificationError(ValueError):
    """An untrusted visibility grant was refused, without disclosing details."""


class SnapshotBinding(BaseModel):
    """Exact identity of ONE expected request.

    `host`, `host_key_sha256`, `profile`, `policy_epoch` and
    `central_policy_sha256` MUST come from trusted local host configuration.
    `request_id`, `operation`, `root` and `max_entries` come from the outer
    request frame and are bound by requiring equality with the MAC'd payload.
    `principal` and `snapshot_id` are centrally chosen MAC-authenticated
    payload values; the principal is NOT derived from the SSH identity.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    request_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    host: str = Field(min_length=1, max_length=128)
    host_key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    principal: str = Field(min_length=1, max_length=256)
    profile: str = Field(min_length=1, max_length=128)
    operation: VisibilityOperation
    root: str
    policy_epoch: int = Field(strict=True, ge=1)
    central_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    max_entries: int = Field(strict=True, ge=1, le=64)

    @field_validator("root")
    @classmethod
    def validate_root(cls, value: str) -> str:
        return canonical_visibility_path(value)


class VisibilitySnapshotV5(SnapshotBinding):
    """Complete signed rule shape; digest metadata alone has no authority."""

    version: Literal[5]
    issued_at: int = Field(strict=True, ge=1)
    expires_at: int = Field(strict=True, ge=1)
    rules: VisibilityRules

    @model_validator(mode="after")
    def validate_snapshot(self) -> VisibilitySnapshotV5:
        if not 0 < self.expires_at - self.issued_at <= MAX_SNAPSHOT_TTL_SECONDS:
            raise ValueError("visibility snapshot lifetime invalid")
        if not self.rules.matches(self.root):
            raise ValueError("listing root must be inside visible central roots")
        return self


class SignedVisibilitySnapshot(BaseModel):
    """Snapshot and domain-separated HMAC, without distribution of raw keys."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    payload: VisibilitySnapshotV5
    mac_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class VerifiedVisibilitySnapshot:
    """Verified rules against active host policy, not a general authority token."""

    snapshot: VisibilitySnapshotV5
    active_host_policy: VisibilityPolicyV5

    def may_inspect(self, path: str) -> bool:
        try:
            path = canonical_visibility_path(path)
        except ValueError:
            return False
        return (
            _within(path, self.snapshot.root)
            and self.snapshot.rules.matches(path)
            and self.active_host_policy.operations[self.snapshot.operation].matches(path)
        )

    def may_traverse(self, path: str) -> bool:
        try:
            path = canonical_visibility_path(path)
        except ValueError:
            return False
        # Opening an ancestor through O_PATH is needed to reach the root,
        # but it cannot authorize enumeration or disclosure of that ancestor.
        if _within(self.snapshot.root, path):
            return True
        return self.may_inspect(path)


def _require_key(key: bytes) -> bytes:
    if type(key) is not bytes or len(key) != 32:
        raise SnapshotVerificationError("trusted visibility signer key unavailable")
    return key


def _serialize(payload: VisibilitySnapshotV5) -> bytes:
    return _SNAPSHOT_DOMAIN + json.dumps(
        payload.model_dump(mode="json"),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


_KEY_ID_DOMAIN = b"ssh-over-mcp/v5/hmac-key-id/v1\x00"


def visibility_key_id(key: bytes) -> str:
    """Identify a v5 HMAC key without revealing it: SHA-256(domain || key).

    The central signer and each host verifier MUST derive their key ID with
    this one function from the real key bytes. The domain tag keeps the value
    distinct from host-key pins and any untagged digest.

    This is an IDENTIFIER, not proof of possession: the value is not secret,
    so any party that is handed the expected ID can echo it. A production
    attestation must additionally prove possession (for example an HMAC over
    a fresh verifier nonce). Keys MUST come from a CSPRNG; a low-entropy key
    could be recovered by brute force from its ID.
    """

    if type(key) is not bytes or len(key) != 32:
        raise ValueError("v5 HMAC key must be exactly 32 bytes")
    return hashlib.sha256(_KEY_ID_DOMAIN + key).hexdigest()


def sign_snapshot(payload: VisibilitySnapshotV5, *, key: bytes) -> SignedVisibilitySnapshot:
    """Sign only an already-compiled central policy snapshot using a distinct key.

    Caller MUST evaluate the actual central policy and operation-specific deny
    subtrees first; merely possessing a signing key is not policy evaluation.
    """

    key = _require_key(key)
    if not isinstance(payload, VisibilitySnapshotV5):
        raise TypeError("invalid visibility snapshot")
    return SignedVisibilitySnapshot(
        payload=payload,
        mac_sha256=hmac.new(key, _serialize(payload), hashlib.sha256).hexdigest(),
    )


class SnapshotStateUnavailable(RuntimeError):
    """Trusted replay/epoch state could not be consulted: unavailable, not deny."""


def verify_snapshot(
    signed: SignedVisibilitySnapshot,
    *,
    trusted_key: bytes,
    expected: SnapshotBinding,
    active_host_policy: VisibilityPolicyV5,
    now: int,
    consume_snapshot_id: Callable[[str], bool],
) -> VerifiedVisibilitySnapshot:
    """Verify one exact signed request, active local policy and atomic replay gate.

    `active_host_policy`, `trusted_key` and `consume_snapshot_id` MUST be
    supplied from trusted local/configured sources, never from the envelope.
    See `SnapshotBinding` for which `expected` fields are trusted-local and
    which are request values that only the MAC authenticates. Replay-store
    failures must surface as `SnapshotStateUnavailable` (unavailable, not a
    denial). The only caller is the inactive, uninstalled `cli_v2` entrypoint.
    """

    try:
        key = _require_key(trusted_key)
        if (
            not isinstance(signed, SignedVisibilitySnapshot)
            or not isinstance(expected, SnapshotBinding)
            or not isinstance(active_host_policy, VisibilityPolicyV5)
            or type(now) is not int
            or not callable(consume_snapshot_id)
        ):
            raise SnapshotVerificationError("visibility snapshot verification unavailable")
        actual = hmac.new(key, _serialize(signed.payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(actual, signed.mac_sha256):
            raise SnapshotVerificationError("invalid visibility snapshot signature")

        snap = signed.payload
        for name in SnapshotBinding.model_fields:
            if getattr(snap, name) != getattr(expected, name):
                raise SnapshotVerificationError("visibility snapshot request mismatch")

        if not (snap.issued_at <= now < snap.expires_at):
            raise SnapshotVerificationError("visibility snapshot expired or not active")

        if (
            active_host_policy.enabled is not True
            or active_host_policy.host != snap.host
            or active_host_policy.profile != snap.profile
            or active_host_policy.policy_epoch != snap.policy_epoch
            or active_host_policy.central_policy_sha256 != snap.central_policy_sha256
            or not active_host_policy.operations[snap.operation].matches(snap.root)
        ):
            raise SnapshotVerificationError("host visibility policy unavailable")

        # A trusted persistent store must perform a single atomic consume
        # after all authenticity/binding checks and before filesystem IO.
        if consume_snapshot_id(snap.snapshot_id) is not True:
            raise SnapshotVerificationError("visibility snapshot replay refused")
        return VerifiedVisibilitySnapshot(snapshot=snap, active_host_policy=active_host_policy)
    except (SnapshotVerificationError, SnapshotStateUnavailable):
        raise
    except Exception as exc:
        raise SnapshotVerificationError("visibility snapshot verification unavailable") from exc
