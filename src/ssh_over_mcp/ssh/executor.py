from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict

from ssh_over_mcp.policy.models import Decision, EvaluationRequest

from .connection import SSHConnectionManager
from .errors import SSHApprovalRequired, SSHPolicyDenied
from .protocol import (
    ExecEnvelope,
    ExecutionLimits,
    REMOTE_PROTOCOL_COMMAND,
    encode_request,
)


class PolicyEvaluator(Protocol):
    def evaluate(self, request: EvaluationRequest): ...


class SSHExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    host: str
    exit_status: int | None = None
    exit_signal: str | None = None
    stdout: bytes = b""
    stderr: bytes = b""
    duration_ms: int
    timed_out: bool = False
    truncated: bool = False


@dataclass(slots=True)
class _OutputBudget:
    remaining: int
    truncated: bool = False

    def take(self, chunk: bytes) -> bytes:
        if self.remaining <= 0:
            if chunk:
                self.truncated = True
            return b""

        accepted = chunk[: self.remaining]
        self.remaining -= len(accepted)
        if len(accepted) < len(chunk):
            self.truncated = True
        return accepted


class SSHExecutor:
    """Policy-gated structured execution over a pooled SSH connection."""

    def __init__(
        self,
        *,
        policy: PolicyEvaluator,
        connections: SSHConnectionManager,
        default_timeout_seconds: float = 60.0,
        default_max_output_bytes: int = 1024 * 1024,
        default_max_stdin_bytes: int = 1024 * 1024,
        cleanup_timeout_seconds: float = 2.0,
    ) -> None:
        self.policy = policy
        self.connections = connections
        self.default_timeout_seconds = default_timeout_seconds
        self.default_max_output_bytes = default_max_output_bytes
        self.default_max_stdin_bytes = default_max_stdin_bytes
        self.cleanup_timeout_seconds = cleanup_timeout_seconds

    async def execute(
        self,
        request: EvaluationRequest,
        *,
        stdin: bytes = b"",
        request_id: str | None = None,
        timeout_seconds: float | None = None,
        max_output_bytes: int | None = None,
        max_stdin_bytes: int | None = None,
    ) -> SSHExecutionResult:
        if request.tool != "ssh_exec":
            raise ValueError(
                "SSHExecutor only accepts ssh_exec policy requests"
            )

        # The network path cannot be reached before an allow decision.
        decision = self.policy.evaluate(request)
        if decision.decision == Decision.DENY:
            raise SSHPolicyDenied(decision)
        if decision.decision == Decision.APPROVAL_REQUIRED:
            raise SSHApprovalRequired(decision)
        if not decision.normalized_executable:
            raise SSHPolicyDenied(decision)

        timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else self.default_timeout_seconds
        )
        output_limit = (
            max_output_bytes
            if max_output_bytes is not None
            else self.default_max_output_bytes
        )
        stdin_limit = (
            max_stdin_bytes
            if max_stdin_bytes is not None
            else self.default_max_stdin_bytes
        )
        req_id = request_id or f"req_{uuid.uuid4().hex}"

        envelope = ExecEnvelope(
            request_id=req_id,
            profile=request.profile,
            executable=decision.normalized_executable,
            argv=request.args,
            cwd=decision.normalized_cwd,
            env=request.env,
            limits=ExecutionLimits(
                timeout_seconds=timeout,
                max_output_bytes=output_limit,
                max_stdin_bytes=stdin_limit,
            ),
        )
        payload = encode_request(envelope, stdin)

        started = time.monotonic()
        async with self.connections.session_slot(request.host):
            connection = await self.connections.get_connection(
                request.host
            )
            process = await connection.create_process(
                REMOTE_PROTOCOL_COMMAND,
                input=payload,
                request_pty=False,
                term_type=None,
                # Env is carried inside the encrypted structured frame and
                # interpreted by the Phase 3 host agent after policy checks.
                env={},
                send_env=(),
                x11_forwarding=False,
                encoding=None,
            )

            try:
                return await self._collect(
                    process,
                    request_id=req_id,
                    host=request.host,
                    timeout_seconds=timeout,
                    max_output_bytes=output_limit,
                    started=started,
                )
            except asyncio.CancelledError:
                await self._abort_process(process)
                raise

    async def _collect(
        self,
        process: Any,
        *,
        request_id: str,
        host: str,
        timeout_seconds: float,
        max_output_bytes: int,
        started: float,
    ) -> SSHExecutionResult:
        # stdout and stderr share one total byte budget.
        budget = _OutputBudget(max_output_bytes)
        overflow = asyncio.Event()
        aborting = asyncio.Event()

        async def read_stream(stream: Any) -> bytes:
            chunks: list[bytes] = []
            try:
                while True:
                    chunk = await stream.read(16 * 1024)
                    if not chunk:
                        break

                    accepted = budget.take(chunk)
                    if accepted:
                        chunks.append(accepted)
                    if budget.truncated:
                        overflow.set()
            except Exception:
                if not aborting.is_set():
                    raise

            return b"".join(chunks)

        stdout_task = asyncio.create_task(
            read_stream(process.stdout)
        )
        stderr_task = asyncio.create_task(
            read_stream(process.stderr)
        )
        wait_task = asyncio.create_task(process.wait(check=False))
        overflow_task = asyncio.create_task(overflow.wait())

        timed_out = False
        completed = None

        try:
            done, _ = await asyncio.wait(
                {wait_task, overflow_task},
                timeout=timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )

            if not done:
                timed_out = True
                aborting.set()
                await self._abort_process(process)
            elif (
                overflow_task in done
                and overflow.is_set()
                and not wait_task.done()
            ):
                # Stop a process which exceeds its allowed output. Signals can
                # be ignored by some OpenSSH servers, so _abort_process also
                # closes the SSH channel.
                aborting.set()
                await self._abort_process(process)

            if wait_task.done() and not wait_task.cancelled():
                with contextlib.suppress(Exception):
                    completed = wait_task.result()
        except asyncio.CancelledError:
            aborting.set()
            await self._abort_process(process)
            raise
        finally:
            overflow_task.cancel()
            if not wait_task.done():
                wait_task.cancel()

            try:
                stdout, stderr = await asyncio.wait_for(
                    asyncio.gather(stdout_task, stderr_task),
                    timeout=self.cleanup_timeout_seconds,
                )
            except (TimeoutError, asyncio.CancelledError):
                stdout_task.cancel()
                stderr_task.cancel()
                await asyncio.gather(
                    stdout_task,
                    stderr_task,
                    return_exceptions=True,
                )
                stdout = b""
                stderr = b""

        exit_status = (
            getattr(completed, "exit_status", None)
            if completed
            else None
        )
        exit_signal = (
            _signal_name(getattr(completed, "exit_signal", None))
            if completed
            else None
        )

        return SSHExecutionResult(
            request_id=request_id,
            host=host,
            exit_status=exit_status,
            exit_signal=exit_signal,
            stdout=stdout,
            stderr=stderr,
            duration_ms=max(
                0, int((time.monotonic() - started) * 1000)
            ),
            timed_out=timed_out,
            truncated=budget.truncated,
        )

    async def _abort_process(self, process: Any) -> None:
        with contextlib.suppress(Exception):
            process.terminate()

        await asyncio.sleep(0)

        # Channel close is the reliable fallback when SSH signal delivery is
        # not supported by the remote OpenSSH version.
        with contextlib.suppress(Exception):
            process.close()

        with contextlib.suppress(Exception):
            await asyncio.wait_for(
                process.wait_closed(),
                timeout=self.cleanup_timeout_seconds,
            )


def _signal_name(exit_signal: Any) -> str | None:
    if exit_signal is None:
        return None
    if isinstance(exit_signal, tuple) and exit_signal:
        return str(exit_signal[0])
    return str(exit_signal)
