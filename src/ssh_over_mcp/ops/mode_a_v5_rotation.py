"""Candidate Mode A v5 rotation ordering; no production/live adapter is installed.

The injected, separately trusted operator adapter must *prove* that ingress
closure is durable and all in-flight requests have terminated. A boolean
returned by an untrusted adapter is not an acknowledgement.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

_GENERATION_DOMAIN = b"ssh-over-mcp/v5/generation/v1\x00"


def generation_id(
    *,
    epoch: int,
    policy_sha256: str,
    host_keys: dict[str, str],
    signer_key_ids: dict[str, str],
) -> str:
    """The generation fingerprint, derived only from values hosts can attest.

    It is not an opaque manifest label: every input is something each host
    reports from its own protected files (epoch, policy digest, host-key pin,
    verifier key ID), so a receipt can only carry it after those were verified.
    """

    body = json.dumps(
        {
            "epoch": epoch,
            "policy_sha256": policy_sha256,
            "hosts": {
                host: {"host_key_sha256": host_keys[host], "signer_key_id": signer_key_ids[host]}
                for host in sorted(host_keys)
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(_GENERATION_DOMAIN + body).hexdigest()


class RotationFailure(RuntimeError):
    """A prerequisite failed: keep ingress closed and do not retry blindly."""


class RotationSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    epoch: int = Field(strict=True, ge=1)
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    generation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    host_keys: dict[str, str]
    # Per-host signer/verifier key fingerprints (never key bytes); ADR0028
    # steps 6 and 7 require proving control and hosts use exactly these keys.
    signer_key_ids: dict[str, str]

    @model_validator(mode="after")
    def require_distinct_pinned_hosts(self) -> RotationSpec:
        for values in (self.host_keys, self.signer_key_ids):
            if (
                set(values) != {"node01", "node02"}
                or len(set(values.values())) != 2
                or any(re.fullmatch(r"[0-9a-f]{64}", v) is None for v in values.values())
            ):
                raise ValueError("two distinct pinned Mode A hosts and signer keys are required")
        if set(self.host_keys.values()) & set(self.signer_key_ids.values()):
            raise ValueError("signer key identity must differ from host-key pins")
        if self.generation_sha256 != generation_id(
            epoch=self.epoch,
            policy_sha256=self.policy_sha256,
            host_keys=self.host_keys,
            signer_key_ids=self.signer_key_ids,
        ):
            raise ValueError("generation must be derived from the attested fields")
        return self


class HostReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    host: str
    host_key_sha256: str
    epoch: int = Field(strict=True, ge=1)
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    generation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verifier_key_id: str = Field(pattern=r"^[0-9a-f]{64}$")


class ControlReceipt(BaseModel):
    """Post-start control evidence gathered while ingress is still fenced."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    epoch: int = Field(strict=True, ge=1)
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    generation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    host_keys: dict[str, str]
    signer_key_ids: dict[str, str]
    ledger_available: bool
    audit_available: bool


class TrustedRotationOps(Protocol):
    """Operator-specific, privileged implementation is NOT provided here."""

    async def freeze_ingress(self) -> bool: ...
    async def drain_inflight(self) -> bool: ...
    async def stop_control(self) -> bool: ...
    async def stop_host(self, host: str) -> bool: ...
    async def install(self, host: str, spec: RotationSpec) -> bool: ...
    async def start_host(self, host: str) -> bool: ...
    async def attest_host(self, host: str, spec: RotationSpec) -> HostReceipt: ...
    async def start_control(self) -> bool: ...
    async def attest_control(self, spec: RotationSpec) -> ControlReceipt: ...
    async def open_ingress(self) -> bool: ...


async def _require_ack(value: bool) -> None:
    if value is not True:
        raise RotationFailure("required maintenance proof unavailable")


async def _attest_both_hosts(expected: RotationSpec, ops: TrustedRotationOps) -> None:
    for host in ("node01", "node02"):
        attestation = expected.model_copy(deep=True)
        receipt = await ops.attest_host(host, attestation)
        if (
            attestation != expected
            or not isinstance(receipt, HostReceipt)
            or receipt.host != host
            or receipt.host_key_sha256 != expected.host_keys[host]
            or receipt.epoch != expected.epoch
            or receipt.policy_sha256 != expected.policy_sha256
            or receipt.generation_sha256 != expected.generation_sha256
            or receipt.verifier_key_id != expected.signer_key_ids[host]
        ):
            raise RotationFailure("host attestation does not match expected generation")


async def run_rotation(spec: RotationSpec, ops: TrustedRotationOps) -> None:
    """Gate reopening on quiescence and two exact host/generation ACKs.

    Never auto-rollback to a prior epoch; the controller must be fenced
    from new ingress for every stage, even after process failure.
    """
    # Frozen Pydantic models do not deep-freeze dict fields. Snapshot the
    # operator-authorized release before calling a potentially faulty adapter.
    # Never pass the original or the reference snapshot to the adapter.
    # model_copy(update=...) and model_construct skip validation, so validate
    # again before anything runs; a failure here is raised before the fence.
    expected = RotationSpec.model_validate(spec.model_dump())
    try:
        await _require_ack(await ops.freeze_ingress())
        await _require_ack(await ops.drain_inflight())
        await _require_ack(await ops.stop_control())
        for host in ("node01", "node02"):
            await _require_ack(await ops.stop_host(host))
        for host in ("node01", "node02"):
            installation = expected.model_copy(deep=True)
            await _require_ack(await ops.install(host, installation))
            if installation != expected:
                raise RotationFailure("installation mutated approved release")
        for host in ("node01", "node02"):
            await _require_ack(await ops.start_host(host))
        await _attest_both_hosts(expected, ops)
        await _require_ack(await ops.start_control())
        # ADR0028 step 7: verify control post-start evidence and re-check both
        # hosts while ingress is still fenced; only then may it be unfrozen.
        attestation = expected.model_copy(deep=True)
        control = await ops.attest_control(attestation)
        if (
            attestation != expected
            or not isinstance(control, ControlReceipt)
            or control.epoch != expected.epoch
            or control.policy_sha256 != expected.policy_sha256
            or control.generation_sha256 != expected.generation_sha256
            or control.host_keys != expected.host_keys
            or control.signer_key_ids != expected.signer_key_ids
            or control.ledger_available is not True
            or control.audit_available is not True
        ):
            raise RotationFailure("control attestation does not match expected generation")
        await _attest_both_hosts(expected, ops)
        await _require_ack(await ops.open_ingress())
    except RotationFailure:
        raise
    except Exception as exc:
        raise RotationFailure("rotation incomplete; ingress must remain closed") from exc
