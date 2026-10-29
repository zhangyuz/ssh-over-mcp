"""Fixed-argv maintenance primitives for the Mode A Lima/Docker guest (ADR0028).

NOT a complete ``TrustedRotationOps``: ``install`` and ``attest_*`` are
deliberately absent because their trust-boundary design (how a host proves its
running state) is undecided. Without them this object cannot be handed to
``run_rotation``, so it cannot strand the pilot half-rotated. There is no CLI
and nothing here runs on import; every command is an exact argv built from a
validated configuration and executed without a shell.

Verification is by observed state (launchd service absent and disabled, port
refused, zero established connections, container status), never by a command's
exit status alone. Any unproven condition raises ``RotationFailure`` and leaves
ingress fenced.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from collections.abc import Awaitable, Callable, Sequence
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .mode_a_v5_rotation import RotationFailure

_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_PLIST = re.compile(r"^/[A-Za-z0-9_.@-]+(/[A-Za-z0-9_.@-]+)*\.plist$")
_NODES = ("node01", "node02")
_LAUNCHD_NOT_FOUND = 113  # `launchctl print` for a service that is not loaded


class CommandResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    truncated: bool = False


class CommandRunner(Protocol):
    async def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult: ...


class PortProbe(Protocol):
    async def is_listening(self, host: str, port: int) -> bool:
        """True if a connection is accepted, False only if actively refused;
        anything else (timeout, unreachable) must raise: it proves nothing."""


class AdapterConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    vm_name: str
    launchd_label: str
    launchd_plist: str
    uid: int = Field(strict=True, ge=0)
    tunnel_port: int = Field(strict=True, ge=1, le=65535)
    mcp_container: str
    ledger_container: str
    node_containers: dict[str, str]
    mcp_port: int = Field(default=8000, strict=True, ge=1, le=65535)
    node_ssh_port: int = Field(default=2222, strict=True, ge=1, le=65535)
    stop_timeout_seconds: int = Field(default=30, strict=True, ge=1, le=300)
    drain_attempts: int = Field(default=10, strict=True, ge=1, le=600)
    drain_interval_seconds: float = Field(default=1.0, gt=0, le=60)
    command_timeout_seconds: float = Field(default=60.0, gt=0, le=600)

    @field_validator("vm_name", "mcp_container", "ledger_container")
    @classmethod
    def _safe_name(cls, value: str) -> str:
        if _NAME.fullmatch(value) is None:
            raise ValueError("unsafe name")
        return value

    @field_validator("launchd_label")
    @classmethod
    def _safe_label(cls, value: str) -> str:
        if _LABEL.fullmatch(value) is None:
            raise ValueError("unsafe launchd label")
        return value

    @field_validator("launchd_plist")
    @classmethod
    def _safe_plist(cls, value: str) -> str:
        if _PLIST.fullmatch(value) is None or any(p in {".", ".."} for p in value.split("/")):
            raise ValueError("unsafe plist path")
        return value

    @model_validator(mode="after")
    def _validate_topology(self) -> AdapterConfig:
        if set(self.node_containers) != set(_NODES) or any(
            _NAME.fullmatch(name) is None for name in self.node_containers.values()
        ):
            raise ValueError("exactly node01 and node02 containers are required")
        names = [self.mcp_container, self.ledger_container, *self.node_containers.values()]
        if len(set(names)) != len(names):
            raise ValueError("container names must be distinct")
        return self


class SubprocessRunner:
    """Run one exact argv with no shell, a deadline and bounded output."""

    def __init__(self, *, max_output_bytes: int = 256 * 1024) -> None:
        self._limit = max_output_bytes

    async def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult:
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError:
            return CommandResult(returncode=127, stdout=b"", stderr=b"", timed_out=False)

        async def read(stream: asyncio.StreamReader) -> tuple[bytes, bool]:
            data = await stream.read(self._limit + 1)
            return data[: self._limit], len(data) > self._limit

        try:
            (out, out_cut), (err, err_cut), _ = await asyncio.wait_for(
                asyncio.gather(read(process.stdout), read(process.stderr), process.wait()),
                timeout,
            )
        except TimeoutError:
            process.kill()
            await process.wait()
            return CommandResult(
                returncode=process.returncode if process.returncode is not None else -9,
                stdout=b"",
                stderr=b"",
                timed_out=True,
            )
        truncated = out_cut or err_cut
        if truncated and process.returncode is None:
            process.kill()
            await process.wait()
        return CommandResult(
            returncode=process.returncode if process.returncode is not None else -9,
            stdout=out,
            stderr=err,
            timed_out=False,
            truncated=truncated,
        )


class TcpPortProbe:
    def __init__(self, *, timeout: float = 3.0) -> None:
        self._timeout = timeout

    async def is_listening(self, host: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), self._timeout)
        except ConnectionRefusedError:
            return False
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True


def _established_on_port(table: bytes, port: int) -> int:
    """Count ESTABLISHED (state 01) sockets whose local port matches."""

    try:
        lines = table.decode("ascii").splitlines()
        if not lines or not lines[0].split()[:1] == ["sl"]:
            raise ValueError("not a tcp table")
        count = 0
        for line in lines[1:]:
            if not line.strip():
                continue
            fields = line.split()
            if len(fields) < 4:
                raise ValueError("malformed row")
            _, _, local_port = fields[1].partition(":")
            state = fields[3]
            if int(state, 16) < 0 or len(state) != 2:
                raise ValueError("malformed state")
            if int(local_port, 16) == port and state == "01":
                count += 1
        return count
    except (ValueError, UnicodeError, IndexError):
        raise RotationFailure("connection table unreadable; drain unproven") from None


class LimaDockerPrimitives:
    def __init__(
        self,
        config: AdapterConfig,
        *,
        runner: CommandRunner,
        probe: PortProbe,
        operator_confirms_open: Callable[[], Awaitable[bool]],
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._cfg = config
        self._runner = runner
        self._probe = probe
        self._confirm = operator_confirms_open
        self._sleep = sleep
        self._fenced = False
        self._drained = False
        self._control_stopped = False

    # ------------------------------------------------------------- plumbing

    def _docker(self, *args: str) -> tuple[str, ...]:
        return ("limactl", "shell", self._cfg.vm_name, "--", "sudo", "docker", *args)

    async def _run(self, argv: tuple[str, ...]) -> CommandResult:
        result = await self._runner.run(argv, timeout=self._cfg.command_timeout_seconds)
        if result.timed_out or result.truncated:
            raise RotationFailure("maintenance command did not complete cleanly")
        return result

    async def _ok(self, argv: tuple[str, ...]) -> CommandResult:
        result = await self._run(argv)
        if result.returncode != 0:
            raise RotationFailure("maintenance command failed")
        return result

    @staticmethod
    def _require(condition: bool) -> None:
        if not condition:
            raise RotationFailure("maintenance precondition not proven")

    def _node(self, host: str) -> str:
        name = self._cfg.node_containers.get(host)
        if name is None:
            raise RotationFailure("unknown host")
        return name

    async def _expect_status(self, container: str, wanted: str) -> None:
        result = await self._ok(self._docker("inspect", "--format", "{{.State.Status}}", container))
        if result.stdout.decode("ascii", errors="replace").strip() != wanted:
            raise RotationFailure("container state not as required")

    @property
    def _target(self) -> str:
        return f"gui/{self._cfg.uid}/{self._cfg.launchd_label}"

    async def _service_marked_disabled(self) -> bool:
        result = await self._ok(("launchctl", "print-disabled", f"gui/{self._cfg.uid}"))
        pattern = rb'"' + re.escape(self._cfg.launchd_label.encode()) + rb'"\s*=>\s*(disabled|true)'
        return re.search(pattern, result.stdout) is not None

    async def _listening(self) -> bool:
        try:
            return await self._probe.is_listening("127.0.0.1", self._cfg.tunnel_port)
        except OSError:
            raise RotationFailure("ingress port state unproven") from None

    # ------------------------------------------------------------- ingress

    async def freeze_ingress(self) -> bool:
        self._fenced = self._drained = self._control_stopped = False
        await self._ok(("launchctl", "disable", self._target))
        # The result is verified by observation below; a not-loaded service is fine.
        await self._run(("launchctl", "bootout", self._target))
        printed = await self._run(("launchctl", "print", self._target))
        if printed.returncode != _LAUNCHD_NOT_FOUND:
            raise RotationFailure("ingress service still loaded or state unproven")
        if not await self._service_marked_disabled():
            raise RotationFailure("ingress fence is not durable")
        if await self._listening():
            raise RotationFailure("ingress port still accepts connections")
        self._fenced = True
        return True

    async def open_ingress(self) -> bool:
        self._require(self._fenced)
        for name in (
            self._cfg.ledger_container,
            self._cfg.mcp_container,
            *self._cfg.node_containers.values(),
        ):
            await self._expect_status(name, "running")
        try:
            confirmed = await self._confirm()
        except Exception:  # noqa: BLE001 - any confirmation fault keeps ingress closed
            raise RotationFailure("operator confirmation unavailable") from None
        if confirmed is not True:
            raise RotationFailure("operator did not confirm opening ingress")
        try:
            await self._ok(("launchctl", "enable", self._target))
            await self._ok(
                ("launchctl", "bootstrap", f"gui/{self._cfg.uid}", self._cfg.launchd_plist)
            )
            if await self._service_marked_disabled():
                raise RotationFailure("ingress service is still disabled")
            if not await self._listening():
                raise RotationFailure("ingress did not come up")
        except Exception:
            await self._refence_best_effort()
            raise
        self._fenced = self._drained = self._control_stopped = False
        return True

    async def _refence_best_effort(self) -> None:
        for argv in (("launchctl", "disable", self._target), ("launchctl", "bootout", self._target)):
            # Best effort: the original failure is re-raised by the caller.
            with contextlib.suppress(Exception):
                await self._runner.run(argv, timeout=self._cfg.command_timeout_seconds)

    # ------------------------------------------------------------- drain

    async def _established(self, container: str, port: int) -> int:
        total = 0
        for table in ("/proc/net/tcp", "/proc/net/tcp6"):
            result = await self._ok(self._docker("exec", container, "cat", table))
            total += _established_on_port(result.stdout, port)
        return total

    async def drain_inflight(self) -> bool:
        self._require(self._fenced)
        self._drained = False
        targets = (
            (self._cfg.mcp_container, self._cfg.mcp_port),
            *((name, self._cfg.node_ssh_port) for name in self._cfg.node_containers.values()),
        )
        for attempt in range(self._cfg.drain_attempts):
            open_connections = 0
            for name, port in targets:
                open_connections += await self._established(name, port)
            if open_connections == 0:
                self._drained = True
                return True
            if attempt + 1 < self._cfg.drain_attempts:
                await self._sleep(self._cfg.drain_interval_seconds)
        raise RotationFailure("in-flight work did not drain")

    # ------------------------------------------------------------- stop / start

    async def _stop(self, container: str) -> None:
        await self._ok(self._docker("stop", "-t", str(self._cfg.stop_timeout_seconds), container))
        await self._expect_status(container, "exited")

    async def _start(self, container: str) -> None:
        await self._ok(self._docker("start", container))
        await self._expect_status(container, "running")

    async def stop_control(self) -> bool:
        self._require(self._fenced and self._drained)
        for name in (self._cfg.mcp_container, self._cfg.ledger_container):
            await self._stop(name)
        self._control_stopped = True
        return True

    async def stop_host(self, host: str) -> bool:
        name = self._node(host)
        self._require(self._fenced and self._control_stopped)
        await self._stop(name)
        return True

    async def start_host(self, host: str) -> bool:
        name = self._node(host)
        self._require(self._fenced)
        await self._start(name)
        return True

    async def start_control(self) -> bool:
        self._require(self._fenced)
        for name in (self._cfg.ledger_container, self._cfg.mcp_container):
            await self._start(name)
        return True
