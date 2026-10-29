"""Attestation half of the Mode A rotation adapter (ADR0028 ruling), source only.

Runs the read-only ``attest_v5`` entrypoint inside a running node container as
the Host Agent's own identity through the already-approved
``limactl shell ... docker exec`` path, and verifies the nonce-bound reports.
It has no CLI, no ``install`` and does not start anything: it is one piece of a
future ``TrustedRotationOps`` and is exercised only through fakes.

Two rounds, because a stopped container cannot be exec'd:
* before control starts a host is checked against the release (fields only);
* once ``attest_control`` has succeeded, every host proof must additionally
  EQUAL the control's proof for the same fresh nonce, which only two parties
  holding the same key bytes can produce.
The control-side report comes from an injected source; the control-side
entrypoint that produces it does not exist yet.
"""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, field_validator

from ssh_over_mcp.host_agent.attest_v5 import new_nonce, proofs_equal, require_nonce

from .mode_a_v5_lima_primitives import AdapterConfig, CommandResult, CommandRunner
from .mode_a_v5_rotation import (
    ControlReceipt,
    HostReceipt,
    RotationFailure,
    RotationSpec,
    generation_id,
)

CentralReports = Callable[[str, str], Awaitable[Mapping[str, Mapping[str, object]]]]

_PATH = re.compile(r"^/[A-Za-z0-9_.@+-]+(/[A-Za-z0-9_.@+-]+)*$")
_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_EXEC_USER = re.compile(r"^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$")  # never uid or gid 0
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_REPORT_BYTES = 4096
_NODES = ("node01", "node02")
_COMMON_KEYS = frozenset(
    {
        "version",
        "host",
        "host_key_sha256",
        "profile",
        "policy_epoch",
        "central_policy_sha256",
        "verifier_key_id",
        "nonce",
        "proof",
    }
)
# Everything the central side can reproduce; `proof` is compared separately.
_PROVEN_FIELDS = tuple(sorted(_COMMON_KEYS - {"proof"}))


class AttestationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    profile: str
    python_path: str
    policy_path: str = "/etc/ssh-over-mcp/v5/host-visibility.json"
    exec_user: str = "2201:3201"

    @field_validator("profile")
    @classmethod
    def _safe_profile(cls, value: str) -> str:
        if _PROFILE.fullmatch(value) is None:
            raise ValueError("unsafe profile")
        return value

    @field_validator("python_path", "policy_path")
    @classmethod
    def _safe_path(cls, value: str) -> str:
        if _PATH.fullmatch(value) is None or any(p in {".", ".."} for p in value.split("/")):
            raise ValueError("path must be absolute without traversal")
        return value

    @field_validator("exec_user")
    @classmethod
    def _unprivileged_user(cls, value: str) -> str:
        if _EXEC_USER.fullmatch(value) is None:
            raise ValueError("exec user must be numeric uid:gid, neither zero")
        return value


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate member")
        result[key] = value
    return result


def _reject_constant(_: str) -> object:
    raise ValueError("non-finite number")


def _validate_shape(obj: object, *, host_side: bool) -> dict[str, object]:
    keys = _COMMON_KEYS | ({"config_model_sha256"} if host_side else frozenset())
    if type(obj) is not dict or set(obj) != keys:
        raise ValueError("unexpected member set")
    if type(obj["version"]) is not int or obj["version"] != 1:
        raise ValueError("unsupported version")
    if type(obj["policy_epoch"]) is not int or obj["policy_epoch"] < 1:
        raise ValueError("invalid epoch")
    for name in ("host", "profile"):
        if type(obj[name]) is not str or not 1 <= len(obj[name]) <= 128:
            raise ValueError("invalid text member")
    hex_members = [
        "host_key_sha256",
        "central_policy_sha256",
        "verifier_key_id",
        "proof",
        *(["config_model_sha256"] if host_side else []),
    ]
    for name in hex_members:
        if type(obj[name]) is not str or _HEX64.fullmatch(obj[name]) is None:
            raise ValueError("invalid digest member")
    require_nonce(obj["nonce"])
    return obj


def _parse_host_report(raw: bytes) -> dict[str, object]:
    if len(raw) > _MAX_REPORT_BYTES or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise ValueError("report must be one bounded line")
    text = raw.decode("ascii")
    return _validate_shape(
        json.loads(text, object_pairs_hook=_unique, parse_constant=_reject_constant), host_side=True
    )


class LimaDockerAttestor:
    def __init__(
        self,
        adapter_config: AdapterConfig,
        attestation_config: AttestationConfig,
        *,
        runner: CommandRunner,
        central_reports: CentralReports,
        nonce_factory: Callable[[], str] = new_nonce,
    ) -> None:
        # Re-validate: model_copy(update=...) and model_construct skip validators.
        self._cfg = AdapterConfig.model_validate(adapter_config.model_dump())
        self._att = AttestationConfig.model_validate(attestation_config.model_dump())
        self._runner = runner
        self._central_reports = central_reports
        self._nonce_factory = nonce_factory
        self._used_nonces: set[str] = set()
        self._control_attested = False

    # ------------------------------------------------------------- plumbing

    def _docker(self, *args: str) -> tuple[str, ...]:
        return (self._cfg.limactl_path, "shell", self._cfg.vm_name, "--", "sudo", "docker", *args)

    def _fresh_nonce(self) -> str:
        try:
            nonce = require_nonce(self._nonce_factory())
        except ValueError:
            raise RotationFailure("nonce source produced an invalid nonce") from None
        if nonce in self._used_nonces:
            raise RotationFailure("nonce source repeated a nonce")
        self._used_nonces.add(nonce)
        return nonce

    async def _run(self, argv: Sequence[str]) -> CommandResult:
        result = await self._runner.run(tuple(argv), timeout=self._cfg.command_timeout_seconds)
        if result.timed_out or result.truncated or result.returncode != 0 or result.stderr:
            raise RotationFailure("attestation command did not complete cleanly")
        return result

    async def _health(self, container: str) -> bool:
        result = await self._run(
            self._docker("inspect", "--format", "{{.State.Health.Status}}", container)
        )
        return result.stdout.decode("ascii", errors="replace").strip() == "healthy"

    def _validated_central(self, reports: object, nonce: str) -> dict[str, dict[str, object]]:
        if not isinstance(reports, Mapping) or set(reports) != set(_NODES):
            raise RotationFailure("control report set is not exactly the two hosts")
        checked: dict[str, dict[str, object]] = {}
        for host in _NODES:
            try:
                report = _validate_shape(dict(reports[host]), host_side=False)
            except (ValueError, TypeError):
                raise RotationFailure("control report is malformed") from None
            if report["nonce"] != nonce or report["host"] != host:
                raise RotationFailure("control report is not bound to this round")
            checked[host] = report
        return checked

    async def _central_for_round(self, nonce: str) -> dict[str, dict[str, object]]:
        try:
            reports = await self._central_reports(nonce, self._att.profile)
        except RotationFailure:
            raise
        except Exception:  # noqa: BLE001 - any control-side fault leaves ingress closed
            raise RotationFailure("control report unavailable") from None
        return self._validated_central(reports, nonce)

    # ------------------------------------------------------------- hosts

    async def attest_host(self, host: str, spec: RotationSpec) -> HostReceipt:
        """Verify one node against the release; require equal control proof once control is attested.

        The generation in the receipt is the release's derived value: it is only
        returned after this host's own contributions to it (epoch, digest, pin,
        key ID) were verified; the other host proves its own in its own round.
        """

        expected = RotationSpec.model_validate(spec.model_dump())
        container = self._cfg.node_containers.get(host)
        if container is None:
            raise RotationFailure("unknown host")
        nonce = self._fresh_nonce()
        result = await self._run(
            self._docker(
                "exec",
                "--user",
                self._att.exec_user,
                container,
                self._att.python_path,
                "-I",
                "-m",
                "ssh_over_mcp.host_agent.attest_v5",
                "--policy",
                self._att.policy_path,
                "--nonce",
                nonce,
            )
        )
        try:
            report = _parse_host_report(result.stdout)
        except (ValueError, UnicodeError):
            raise RotationFailure("host report is malformed") from None
        wanted = {
            "version": 1,
            "host": host,
            "host_key_sha256": expected.host_keys[host],
            "profile": self._att.profile,
            "policy_epoch": expected.epoch,
            "central_policy_sha256": expected.policy_sha256,
            "verifier_key_id": expected.signer_key_ids[host],
            "nonce": nonce,
        }
        if any(report[name] != value for name, value in wanted.items()):
            raise RotationFailure("host report does not match the release")
        if self._control_attested:
            central = (await self._central_for_round(nonce))[host]
            if any(report[name] != central[name] for name in _PROVEN_FIELDS) or not proofs_equal(
                report["proof"], central["proof"]
            ):
                raise RotationFailure("host proof does not equal the control proof")
        return HostReceipt(
            host=host,
            host_key_sha256=str(report["host_key_sha256"]),
            epoch=int(report["policy_epoch"]),
            policy_sha256=str(report["central_policy_sha256"]),
            generation_sha256=expected.generation_sha256,
            verifier_key_id=str(report["verifier_key_id"]),
        )

    # ------------------------------------------------------------- control

    async def attest_control(self, spec: RotationSpec) -> ControlReceipt:
        """Describe what the running control reports, not what the release says.

        The receipt is built from the control's own values; ``run_rotation``
        compares it to the release. Must be called after control has started.
        """

        RotationSpec.model_validate(spec.model_dump())
        nonce = self._fresh_nonce()
        reports = await self._central_for_round(nonce)
        epochs = {r["policy_epoch"] for r in reports.values()}
        digests = {r["central_policy_sha256"] for r in reports.values()}
        profiles = {r["profile"] for r in reports.values()}
        if len(epochs) != 1 or len(digests) != 1 or profiles != {self._att.profile}:
            raise RotationFailure("control reports disagree with each other")
        epoch, digest = epochs.pop(), digests.pop()
        host_keys = {h: str(reports[h]["host_key_sha256"]) for h in _NODES}
        signer_ids = {h: str(reports[h]["verifier_key_id"]) for h in _NODES}
        ledger_ok = await self._health(self._cfg.ledger_container)
        mcp_ok = await self._health(self._cfg.mcp_container)
        try:
            generation = generation_id(
                epoch=int(epoch), policy_sha256=str(digest), host_keys=host_keys, signer_key_ids=signer_ids
            )
            receipt = ControlReceipt(
                epoch=int(epoch),
                policy_sha256=str(digest),
                generation_sha256=generation,
                host_keys=host_keys,
                signer_key_ids=signer_ids,
                ledger_available=ledger_ok,
                audit_available=ledger_ok and mcp_ok,
            )
        except ValueError:
            raise RotationFailure("control report is not a valid receipt") from None
        self._control_attested = True
        return receipt
