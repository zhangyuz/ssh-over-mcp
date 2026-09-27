from __future__ import annotations

import errno
import os
import selectors
import signal
import time
from dataclasses import dataclass

from ssh_over_mcp.ssh.protocol import ExecutionLimits

from .containment import (
    ContainmentBackend,
    ContainmentError,
    ContainmentRequest,
    ContainmentStats,
)
from .prepare import PreparedCommand
from .supervisor import (
    ChildSupervisorError,
    SpawnedChild,
    spawn_prepared_native_contained,
)


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
    containment_stats: ContainmentStats


def _signal_process_group(pid: int, sig: int) -> None:
    group_error: OSError | None = None
    try:
        os.killpg(pid, sig)
        return
    except ProcessLookupError as exc:
        # The child may not have reached setsid() yet.
        group_error = exc
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            group_error = exc
        elif exc.errno in {errno.EPERM, errno.EINVAL}:
            group_error = exc
        else:
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

    # group_error is intentionally retained only for debugging/chaining in a
    # future audit layer; a successful direct-pid fallback is acceptable here.
    _ = group_error


def _reap_until(
    child: SpawnedChild,
    deadline: float,
) -> int | None:
    while True:
        returncode = child.poll()
        if returncode is not None:
            return returncode

        now = time.monotonic()
        if now >= deadline:
            return None

        time.sleep(min(0.005, max(0.0, deadline - now)))


def _hard_kill_contained(child: SpawnedChild) -> None:
    if child.containment is None:
        raise BoundedExecutionError(
            "supervised child lacks containment"
        )

    containment_error: ContainmentError | None = None
    try:
        child.containment.kill_all()
    except ContainmentError as exc:
        containment_error = exc

    # Keep the process-group kill as defense-in-depth and as a direct-child
    # fallback if containment control itself fails.
    try:
        _signal_process_group(child.pid, signal.SIGKILL)
    except BoundedExecutionError:
        if containment_error is None:
            raise

    if containment_error is not None:
        raise BoundedExecutionError(
            "cannot kill child containment scope"
        ) from containment_error


def _close_containment_bounded(
    child: SpawnedChild,
    deadline: float,
) -> ContainmentStats:
    if child.containment is None:
        raise BoundedExecutionError(
            "supervised child lacks containment"
        )

    handle = child.containment

    while True:
        try:
            stats = handle.stats()
        except ContainmentError as exc:
            raise BoundedExecutionError(
                "cannot read containment accounting"
            ) from exc

        if stats.populated is False:
            break
        if stats.populated is None:
            raise BoundedExecutionError(
                "containment populated state is unavailable"
            )

        now = time.monotonic()
        if now >= deadline:
            raise BoundedExecutionError(
                "containment did not become empty"
            )

        time.sleep(min(0.005, max(0.0, deadline - now)))

    try:
        handle.close()
    except ContainmentError as exc:
        raise BoundedExecutionError(
            "cannot close containment scope"
        ) from exc

    child.containment = None
    return stats


def _finalize_containment(
    child: SpawnedChild,
    deadline: float,
) -> ContainmentStats:
    if child.containment is None:
        raise BoundedExecutionError(
            "supervised child lacks containment"
        )

    try:
        stats = child.containment.stats()
    except ContainmentError as exc:
        raise BoundedExecutionError(
            "cannot read containment accounting"
        ) from exc

    # A direct child may exit while descendants remain. Never return while the
    # request cgroup is still populated.
    if stats.populated is not False:
        _hard_kill_contained(child)

    return _close_containment_bounded(child, deadline)


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
    containment_backend: ContainmentBackend,
    containment_request: ContainmentRequest,
    term_grace_seconds: float = 0.20,
    kill_cleanup_seconds: float = 1.0,
) -> SupervisedExecutionResult:
    """Run one prepared native child under mandatory containment.

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
        selector = selectors.DefaultSelector()
    except Exception as exc:
        raise BoundedExecutionError("cannot create I/O selector") from exc

    try:
        child = spawn_prepared_native_contained(
            prepared,
            containment_backend,
            containment_request,
        )
    except ChildSupervisorError as exc:
        selector.close()
        raise BoundedExecutionError("cannot spawn supervised child") from exc
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
                _hard_kill_contained(child)
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
                    _hard_kill_contained(child)

                returncode = _reap_until(
                    child,
                    time.monotonic() + 0.05,
                )
                if returncode is None:
                    raise BoundedExecutionError(
                        "child could not be reaped within cleanup window"
                    )
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
                    if not terminating:
                        terminating = True
                        term_sent_at = time.monotonic()
                        if child.stdin_fd >= 0:
                            _unregister_close(selector, child, "stdin_fd")
                        _signal_process_group(child.pid, signal.SIGTERM)

                if eof:
                    attr = "stdout_fd" if kind == "stdout" else "stderr_fd"
                    _unregister_close(selector, child, attr)

        returncode = child.wait()
        containment_stats = _finalize_containment(
            child,
            time.monotonic() + kill_cleanup_seconds,
        )
        return SupervisedExecutionResult(
            returncode=returncode,
            stdout=bytes(stdout),
            stderr=bytes(stderr),
            timed_out=timed_out,
            output_exceeded=output_exceeded,
            duration_seconds=max(0.0, time.monotonic() - start),
            containment_stats=containment_stats,
        )
    except BaseException as exc:
        cleanup_failed = False

        try:
            _hard_kill_contained(child)
        except Exception:
            cleanup_failed = True

        child.close_stdin()
        child.close_pipes()

        try:
            reaped = _reap_until(
                child,
                time.monotonic() + min(0.20, kill_cleanup_seconds),
            )
            if reaped is None:
                cleanup_failed = True
        except Exception:
            cleanup_failed = True

        try:
            _close_containment_bounded(
                child,
                time.monotonic() + min(0.20, kill_cleanup_seconds),
            )
        except Exception:
            cleanup_failed = True

        if cleanup_failed:
            raise BoundedExecutionError(
                "bounded contained-child cleanup failed"
            ) from exc
        if isinstance(exc, BoundedExecutionError):
            raise
        raise BoundedExecutionError("bounded child supervision failed") from exc
    finally:
        selector.close()
        child.close_pipes()
