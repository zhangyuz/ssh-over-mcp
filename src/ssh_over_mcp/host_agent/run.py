from __future__ import annotations

import errno
import os
import selectors
import signal
import time
from dataclasses import dataclass

from ssh_over_mcp.ssh.protocol import ExecutionLimits

from .prepare import PreparedCommand
from .supervisor import ChildSupervisorError, SpawnedChild, spawn_prepared_native


class BoundedExecutionError(RuntimeError):
    """A bounded child execution could not be supervised safely."""


@dataclass(frozen=True, slots=True)
class SupervisedExecutionResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_exceeded: bool
    duration_seconds: float


def _signal_process_group(pid: int, sig: int) -> None:
    try:
        os.killpg(pid, sig)
        return
    except ProcessLookupError:
        return
    except OSError as exc:
        if exc.errno != errno.ESRCH:
            # The child may not have reached setsid() yet. Fall back to the
            # direct pid only for group-lookup failures.
            if exc.errno not in {errno.EPERM, errno.EINVAL}:
                raise BoundedExecutionError(
                    "cannot signal child process group"
                ) from exc

    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        return
    except OSError as exc:
        if exc.errno != errno.ESRCH:
            raise BoundedExecutionError(
                "cannot signal supervised child"
            ) from exc


def _unregister_close(
    selector: selectors.BaseSelector,
    child: SpawnedChild,
    attr: str,
) -> None:
    fd = getattr(child, attr)
    if fd < 0:
        return

    try:
        selector.unregister(fd)
    except Exception:
        pass

    try:
        os.close(fd)
    except OSError:
        pass
    setattr(child, attr, -1)


def _read_output(
    fd: int,
    sink: bytearray,
    *,
    total: int,
    limit: int,
) -> tuple[int, bool, bool]:
    try:
        chunk = os.read(fd, 65536)
    except BlockingIOError:
        return total, False, False
    except OSError as exc:
        if exc.errno == errno.EINTR:
            return total, False, False
        raise BoundedExecutionError("cannot read child output") from exc

    if not chunk:
        return total, True, False

    remaining = max(0, limit - total)
    if remaining:
        sink.extend(chunk[:remaining])

    exceeded = len(chunk) > remaining
    return total + min(len(chunk), remaining), False, exceeded


def _write_stdin(
    fd: int,
    data: memoryview,
    offset: int,
) -> tuple[int, bool]:
    try:
        written = os.write(fd, data[offset:])
    except BlockingIOError:
        return offset, False
    except BrokenPipeError:
        return offset, True
    except OSError as exc:
        if exc.errno == errno.EINTR:
            return offset, False
        if exc.errno == errno.EPIPE:
            return offset, True
        raise BoundedExecutionError("cannot write child stdin") from exc

    offset += written
    return offset, offset >= len(data)


def _drain_or_discard(
    fd: int,
    sink: bytearray,
    *,
    total: int,
    limit: int,
    capture: bool,
) -> tuple[int, bool, bool]:
    if capture:
        return _read_output(fd, sink, total=total, limit=limit)

    try:
        chunk = os.read(fd, 65536)
    except BlockingIOError:
        return total, False, False
    except OSError as exc:
        if exc.errno == errno.EINTR:
            return total, False, False
        raise BoundedExecutionError("cannot drain child output") from exc

    return total, not chunk, False


def run_prepared_native(
    prepared: PreparedCommand,
    stdin: bytes,
    limits: ExecutionLimits,
    *,
    term_grace_seconds: float = 0.20,
    kill_cleanup_seconds: float = 1.0,
) -> SupervisedExecutionResult:
    """Run one prepared native child under wall/output limits.

    This function still has no ForceCommand CLI integration.
    """

    if len(stdin) > limits.max_stdin_bytes:
        raise BoundedExecutionError("stdin exceeds execution limit")
    if term_grace_seconds < 0:
        raise BoundedExecutionError("termination grace must be non-negative")
    if kill_cleanup_seconds <= 0:
        raise BoundedExecutionError("kill cleanup window must be positive")

    start = time.monotonic()
    deadline = start + limits.timeout_seconds

    try:
        child = spawn_prepared_native(prepared)
    except ChildSupervisorError as exc:
        raise BoundedExecutionError("cannot spawn supervised child") from exc

    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    total_output = 0
    stdin_view = memoryview(stdin)
    stdin_offset = 0
    timed_out = False
    output_exceeded = False
    terminating = False
    term_sent_at: float | None = None
    kill_sent_at: float | None = None

    try:
        for fd in (child.stdin_fd, child.stdout_fd, child.stderr_fd):
            os.set_blocking(fd, False)

        selector.register(child.stdout_fd, selectors.EVENT_READ, "stdout")
        selector.register(child.stderr_fd, selectors.EVENT_READ, "stderr")

        if stdin:
            selector.register(child.stdin_fd, selectors.EVENT_WRITE, "stdin")
        else:
            child.close_stdin()

        while True:
            now = time.monotonic()
            returncode = child.poll()

            if not terminating and now >= deadline:
                timed_out = True
                terminating = True
                term_sent_at = now
                if child.stdin_fd >= 0:
                    _unregister_close(selector, child, "stdin_fd")
                _signal_process_group(child.pid, signal.SIGTERM)

            if (
                terminating
                and term_sent_at is not None
                and kill_sent_at is None
                and now >= term_sent_at + term_grace_seconds
            ):
                _signal_process_group(child.pid, signal.SIGKILL)
                kill_sent_at = now

            stdout_open = child.stdout_fd >= 0
            stderr_open = child.stderr_fd >= 0
            if returncode is not None and not stdout_open and not stderr_open:
                break

            if (
                kill_sent_at is not None
                and now >= kill_sent_at + kill_cleanup_seconds
            ):
                if child.stdout_fd >= 0:
                    _unregister_close(selector, child, "stdout_fd")
                if child.stderr_fd >= 0:
                    _unregister_close(selector, child, "stderr_fd")
                if child.poll() is None:
                    _signal_process_group(child.pid, signal.SIGKILL)
                    returncode = child.wait()
                else:
                    returncode = child.poll()
                break

            wake_at = deadline if not terminating else None
            if terminating and term_sent_at is not None and kill_sent_at is None:
                wake_at = term_sent_at + term_grace_seconds
            elif kill_sent_at is not None:
                wake_at = kill_sent_at + kill_cleanup_seconds

            if wake_at is None:
                timeout = 0.05
            else:
                timeout = max(0.0, min(0.05, wake_at - now))

            events = selector.select(timeout)
            for key, _mask in events:
                kind = key.data
                fd = key.fd

                if kind == "stdin":
                    stdin_offset, done = _write_stdin(
                        fd,
                        stdin_view,
                        stdin_offset,
                    )
                    if done:
                        _unregister_close(selector, child, "stdin_fd")
                    continue

                sink = stdout if kind == "stdout" else stderr
                total_output, eof, exceeded = _drain_or_discard(
                    fd,
                    sink,
                    total=total_output,
                    limit=limits.max_output_bytes,
                    capture=not output_exceeded,
                )

                if exceeded and not output_exceeded:
                    output_exceeded = True
                    terminating = True
                    term_sent_at = time.monotonic()
                    if child.stdin_fd >= 0:
                        _unregister_close(selector, child, "stdin_fd")
                    _signal_process_group(child.pid, signal.SIGTERM)

                if eof:
                    attr = "stdout_fd" if kind == "stdout" else "stderr_fd"
                    _unregister_close(selector, child, attr)

        returncode = child.wait()
        return SupervisedExecutionResult(
            returncode=returncode,
            stdout=bytes(stdout),
            stderr=bytes(stderr),
            timed_out=timed_out,
            output_exceeded=output_exceeded,
            duration_seconds=max(0.0, time.monotonic() - start),
        )
    except BaseException as exc:
        try:
            _signal_process_group(child.pid, signal.SIGKILL)
        except Exception:
            pass
        try:
            child.close_stdin()
            child.close_pipes()
        finally:
            try:
                child.wait()
            except Exception:
                pass

        if isinstance(exc, BoundedExecutionError):
            raise
        raise BoundedExecutionError("bounded child supervision failed") from exc
    finally:
        selector.close()
        child.close_pipes()
