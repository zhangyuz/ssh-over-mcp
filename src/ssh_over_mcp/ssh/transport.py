from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .connection import SSHConnectionManager
from .errors import SSHConnectionError, SSHRequestOutcomeUncertain
from .protocol import REMOTE_PROTOCOL_COMMAND


class SSHExecutionResult(BaseModel):
    """Control-plane view of one SSH execution.

    ``timed_out`` and ``truncated`` describe limits enforced while collecting
    the SSH channel on the control plane. SMCP v1 has no response-metadata
    frame, so a host-agent supervisor timeout or output overflow is represented
    by the bounded stdout/stderr bytes plus the SSH process exit semantics,
    rather than being inferred into these two local collection flags.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    host: str
    exit_status: int | None = None
    exit_signal: str | None = None
    stdout: bytes = b""
    stderr: bytes = b""
    duration_ms: int
    timed_out: bool = Field(
        default=False,
        description="The control-plane SSH channel exceeded its collection timeout.",
    )
    truncated: bool = Field(
        default=False,
        description=(
            "The control-plane SSH reader discarded bytes beyond its shared stdout/stderr budget."
        ),
    )


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


class StructuredSSHTransport:
    """Run one pre-framed SMCP request over a hardened pooled SSH channel."""

    def __init__(
        self,
        *,
        connections: SSHConnectionManager,
        cleanup_timeout_seconds: float = 2.0,
    ) -> None:
        self.connections = connections
        self.cleanup_timeout_seconds = cleanup_timeout_seconds

    async def run(
        self,
        *,
        host: str,
        payload: bytes,
        request_id: str,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> SSHExecutionResult:
        return await self._run(
            command=REMOTE_PROTOCOL_COMMAND,
            host=host,
            payload=payload,
            request_id=request_id,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    async def run_v2(
        self,
        *,
        host: str,
        payload: bytes,
        request_id: str,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> SSHExecutionResult:
        """Send a pre-framed v2 request using only the fixed v2 command."""
        return await self._run(
            command="mcp-v2",
            host=host,
            payload=payload,
            request_id=request_id,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    async def _run(
        self,
        *,
        command: Literal["mcp-v1", "mcp-v2"],
        host: str,
        payload: bytes,
        request_id: str,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> SSHExecutionResult:
        if command not in ("mcp-v1", "mcp-v2"):
            raise ValueError("unsupported structured SSH command")

        started = time.monotonic()
        async with self.connections.session_slot(host):
            connection = await self.connections.get_connection(host)
            try:
                process = await connection.create_process(
                    command,
                    input=payload,
                    request_pty=False,
                    term_type=None,
                    # Application metadata belongs only in the framed SMCP payload.
                    # Never inherit or forward ambient SSH environment state.
                    env={},
                    send_env=[],
                    x11_forwarding=False,
                    encoding=None,
                )
            except Exception as exc:  # noqa: BLE001
                if _is_asyncssh_channel_open_error(exc):
                    raise SSHConnectionError("SSH structured channel open failed") from None
                raise SSHRequestOutcomeUncertain(
                    "structured SSH request outcome is uncertain"
                ) from None

            try:
                return await self._collect(
                    process,
                    request_id=request_id,
                    host=host,
                    timeout_seconds=timeout_seconds,
                    max_output_bytes=max_output_bytes,
                    started=started,
                )
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                raise SSHRequestOutcomeUncertain(
                    "structured SSH request outcome is uncertain"
                ) from None

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
        # stdout and stderr share one total control-plane byte budget.
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

        stdout_task = asyncio.create_task(read_stream(process.stdout))
        stderr_task = asyncio.create_task(read_stream(process.stderr))
        close_task = asyncio.create_task(process.wait_closed())
        overflow_task = asyncio.create_task(overflow.wait())

        timed_out = False
        completed = None

        try:
            done, _ = await asyncio.wait(
                {close_task, overflow_task},
                timeout=timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )

            if not done:
                timed_out = True
                aborting.set()
                await self._abort_process(process)
            elif overflow_task in done and overflow.is_set() and not close_task.done():
                aborting.set()
                await self._abort_process(process)

            if close_task.done() and not close_task.cancelled():
                with contextlib.suppress(Exception):
                    close_task.result()
                completed = process
        except asyncio.CancelledError:
            aborting.set()
            await self._abort_process(process)
            raise
        finally:
            overflow_task.cancel()
            await asyncio.gather(overflow_task, return_exceptions=True)
            if not close_task.done():
                close_task.cancel()
                await asyncio.gather(close_task, return_exceptions=True)

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

        exit_status = getattr(completed, "exit_status", None) if completed else None
        exit_signal = _signal_name(getattr(completed, "exit_signal", None)) if completed else None

        return SSHExecutionResult(
            request_id=request_id,
            host=host,
            exit_status=exit_status,
            exit_signal=exit_signal,
            stdout=stdout,
            stderr=stderr,
            duration_ms=max(0, int((time.monotonic() - started) * 1000)),
            timed_out=timed_out,
            truncated=budget.truncated,
        )

    async def _abort_process(self, process: Any) -> None:
        with contextlib.suppress(Exception):
            process.terminate()

        await asyncio.sleep(0)

        # Channel close is the reliable fallback when SSH signal delivery is
        # unsupported or ignored by the remote OpenSSH implementation.
        with contextlib.suppress(Exception):
            process.close()

        with contextlib.suppress(Exception):
            await asyncio.wait_for(
                process.wait_closed(),
                timeout=self.cleanup_timeout_seconds,
            )


def _is_asyncssh_channel_open_error(exc: BaseException) -> bool:
    try:
        import asyncssh
    except ImportError:
        return exc.__class__.__name__ == "ChannelOpenError"

    return isinstance(exc, asyncssh.ChannelOpenError)


def _signal_name(exit_signal: Any) -> str | None:
    if exit_signal is None:
        return None
    if isinstance(exit_signal, tuple) and exit_signal:
        return str(exit_signal[0])
    return str(exit_signal)
