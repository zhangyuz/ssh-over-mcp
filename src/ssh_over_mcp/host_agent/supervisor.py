from __future__ import annotations

import os
import resource
import signal
from dataclasses import dataclass

from .execute import (
    NativeExecutionError,
    build_native_exec_spec,
    exec_prepared_native_in_child,
)
from .prepare import PreparedCommand


class ChildSupervisorError(RuntimeError):
    """A supervised native child could not be created safely."""


@dataclass(slots=True)
class SpawnedChild:
    pid: int
    stdin_fd: int
    stdout_fd: int
    stderr_fd: int
    _returncode: int | None = None

    def close_stdin(self) -> None:
        if self.stdin_fd >= 0:
            try:
                os.close(self.stdin_fd)
            except OSError:
                pass
            finally:
                self.stdin_fd = -1

    def close_pipes(self) -> None:
        for name in ("stdin_fd", "stdout_fd", "stderr_fd"):
            fd = getattr(self, name)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, name, -1)

    def poll(self) -> int | None:
        if self._returncode is not None:
            return self._returncode

        while True:
            try:
                pid, status = os.waitpid(self.pid, os.WNOHANG)
                break
            except InterruptedError:
                continue
            except OSError as exc:
                raise ChildSupervisorError("cannot poll child") from exc

        if pid == 0:
            return None

        self._returncode = os.waitstatus_to_exitcode(status)
        return self._returncode

    def wait(self) -> int:
        if self._returncode is not None:
            return self._returncode

        while True:
            try:
                _, status = os.waitpid(self.pid, 0)
                break
            except InterruptedError:
                continue
            except OSError as exc:
                raise ChildSupervisorError("cannot wait for child") from exc

        self._returncode = os.waitstatus_to_exitcode(status)
        return self._returncode


def _require_standard_fds() -> None:
    for fd in (0, 1, 2):
        try:
            os.fstat(fd)
        except OSError as exc:
            raise ChildSupervisorError(
                "standard file descriptors must be open"
            ) from exc


def _pipe_cloexec() -> tuple[int, int]:
    if not hasattr(os, "pipe2") or not hasattr(os, "O_CLOEXEC"):
        raise ChildSupervisorError("atomic close-on-exec pipes are unavailable")

    try:
        return os.pipe2(os.O_CLOEXEC)
    except OSError as exc:
        raise ChildSupervisorError("cannot create child pipe") from exc


def _close_many(fds: tuple[int, ...]) -> None:
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass


def _reset_child_signals() -> None:
    if not hasattr(signal, "pthread_sigmask"):
        raise ChildSupervisorError("signal-mask reset is unavailable")

    signal.pthread_sigmask(signal.SIG_SETMASK, set())

    uncatchable = {signal.SIGKILL, signal.SIGSTOP}
    for sig in signal.valid_signals():
        if sig in uncatchable:
            continue
        try:
            signal.signal(sig, signal.SIG_DFL)
        except (OSError, RuntimeError, ValueError):
            # valid_signals() can include platform-specific values which Python
            # cannot install through signal.signal(). Fail closed only for the
            # common process-control signals below.
            if sig in {
                signal.SIGHUP,
                signal.SIGINT,
                signal.SIGQUIT,
                signal.SIGPIPE,
                signal.SIGTERM,
                signal.SIGCHLD,
            }:
                raise ChildSupervisorError("cannot reset child signal state")


def _close_unrelated_fds(keep: set[int]) -> None:
    keep = {fd for fd in keep if fd >= 0}

    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft == resource.RLIM_INFINITY:
            soft = 1_048_576
        soft = min(int(soft), 1_048_576)

        cursor = 3
        for fd in sorted(fd for fd in keep if fd >= 3):
            if cursor < fd:
                os.closerange(cursor, fd)
            cursor = fd + 1
        if cursor < soft:
            os.closerange(cursor, soft)
        return

    for name in names:
        try:
            fd = int(name)
        except ValueError:
            continue
        if fd < 3 or fd in keep:
            continue
        try:
            os.close(fd)
        except OSError:
            pass


def _dup_stdio(
    stdin_read: int,
    stdout_write: int,
    stderr_write: int,
) -> None:
    for source, target in (
        (stdin_read, 0),
        (stdout_write, 1),
        (stderr_write, 2),
    ):
        if source == target:
            os.set_inheritable(target, True)
        else:
            os.dup2(source, target, inheritable=True)


def _child_main(
    prepared: PreparedCommand,
    *,
    stdin_read: int,
    stdin_write: int,
    stdout_read: int,
    stdout_write: int,
    stderr_read: int,
    stderr_write: int,
) -> None:
    try:
        os.setsid()
        _reset_child_signals()
        os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        _dup_stdio(stdin_read, stdout_write, stderr_write)

        keep = {
            0,
            1,
            2,
            prepared.executable_fd,
        }
        if prepared.cwd_fd is not None:
            keep.add(prepared.cwd_fd)

        _close_unrelated_fds(keep)
        exec_prepared_native_in_child(prepared)
    except BaseException:
        try:
            os.write(2, b"ssh-over-mcp-host-agent: child exec failed\n")
        except OSError:
            pass
        os._exit(125)

    os._exit(126)


def spawn_prepared_native(prepared: PreparedCommand) -> SpawnedChild:
    """Fork a sanitized child wired to three parent-side stdio pipes.

    This does not enforce wall-clock timeout or output byte limits yet.
    """

    if not hasattr(os, "fork") or not hasattr(os, "setsid"):
        raise ChildSupervisorError("POSIX fork/session support is unavailable")
    if prepared._closed:
        raise ChildSupervisorError("prepared command is closed")

    _require_standard_fds()

    try:
        build_native_exec_spec(prepared)
    except NativeExecutionError as exc:
        raise ChildSupervisorError(
            "prepared command cannot enter native execution"
        ) from exc

    stdin_read = stdin_write = -1
    stdout_read = stdout_write = -1
    stderr_read = stderr_write = -1

    try:
        stdin_read, stdin_write = _pipe_cloexec()
        stdout_read, stdout_write = _pipe_cloexec()
        stderr_read, stderr_write = _pipe_cloexec()

        pid = os.fork()
    except BaseException as exc:
        _close_many(
            (
                stdin_read,
                stdin_write,
                stdout_read,
                stdout_write,
                stderr_read,
                stderr_write,
            )
        )
        if isinstance(exc, ChildSupervisorError):
            raise
        raise ChildSupervisorError("cannot fork supervised child") from exc

    if pid == 0:
        _child_main(
            prepared,
            stdin_read=stdin_read,
            stdin_write=stdin_write,
            stdout_read=stdout_read,
            stdout_write=stdout_write,
            stderr_read=stderr_read,
            stderr_write=stderr_write,
        )
        os._exit(127)

    _close_many((stdin_read, stdout_write, stderr_write))

    return SpawnedChild(
        pid=pid,
        stdin_fd=stdin_write,
        stdout_fd=stdout_read,
        stderr_fd=stderr_read,
    )
