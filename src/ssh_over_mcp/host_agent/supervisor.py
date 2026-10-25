from __future__ import annotations

import os
import resource
import signal
import time
from dataclasses import dataclass

from .containment import (
    ContainmentBackend,
    ContainmentError,
    ContainmentHandle,
    ContainmentRequest,
    PidfdContainmentHandle,
)
from .containment_manager_identity import LinuxProcessIdentityPolicy
from .execute import (
    NativeExecutionError,
    build_native_exec_spec,
    exec_prepared_native_in_child,
)
from .policy import HostChildLimits
from .prepare import PreparedCommand
from .workload_identity import transition_to_workload_identity


class ChildSupervisorError(RuntimeError):
    """A supervised native child could not be created safely."""


@dataclass(slots=True)
class SpawnedChild:
    pid: int
    stdin_fd: int
    stdout_fd: int
    stderr_fd: int
    containment: ContainmentHandle | None = None
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

    def close_containment(self) -> None:
        if self.containment is None:
            return

        try:
            self.containment.close()
        except ContainmentError as exc:
            raise ChildSupervisorError("cannot close child containment scope") from exc
        self.containment = None

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
            raise ChildSupervisorError("standard file descriptors must be open") from exc


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


_START_BARRIER_RELEASE = b"R"


def _wait_start_barrier(fd: int) -> None:
    while True:
        try:
            token = os.read(fd, 1)
            break
        except InterruptedError:
            continue
        except OSError as exc:
            raise ChildSupervisorError("cannot read child start barrier") from exc

    if token != _START_BARRIER_RELEASE:
        raise ChildSupervisorError("child start barrier was not released")


def _release_start_barrier(fd: int) -> None:
    while True:
        try:
            written = os.write(fd, _START_BARRIER_RELEASE)
            break
        except InterruptedError:
            continue
        except OSError as exc:
            raise ChildSupervisorError("cannot release child start barrier") from exc

    if written != len(_START_BARRIER_RELEASE):
        raise ChildSupervisorError("cannot release child start barrier")


def _reap_pid_bounded(pid: int, timeout_seconds: float = 0.20) -> bool:
    deadline = time.monotonic() + timeout_seconds

    while True:
        try:
            waited, _status = os.waitpid(pid, os.WNOHANG)
        except InterruptedError:
            continue
        except ChildProcessError:
            return True
        except OSError:
            return False

        if waited == pid:
            return True
        if time.monotonic() >= deadline:
            return False

        time.sleep(0.005)


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


def _set_bounded_rlimit(resource_id: int, requested: int) -> None:
    try:
        _soft, inherited_hard = resource.getrlimit(resource_id)
    except (OSError, ValueError) as exc:
        raise ChildSupervisorError("cannot read inherited resource limit") from exc

    if inherited_hard == resource.RLIM_INFINITY:
        effective = requested
    else:
        effective = min(requested, int(inherited_hard))

    try:
        resource.setrlimit(resource_id, (effective, effective))
    except (OSError, ValueError) as exc:
        raise ChildSupervisorError("cannot apply child resource limit") from exc


def _apply_child_rlimits(limits: HostChildLimits) -> None:
    required = {
        "RLIMIT_CPU": limits.cpu_seconds,
        "RLIMIT_AS": limits.address_space_bytes,
        "RLIMIT_NPROC": limits.max_processes,
        "RLIMIT_FSIZE": limits.file_size_bytes,
        "RLIMIT_NOFILE": limits.open_files,
    }

    for name, requested in required.items():
        if not hasattr(resource, name):
            raise ChildSupervisorError(f"required child resource limit is unavailable: {name}")
        _set_bounded_rlimit(getattr(resource, name), requested)


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
    workload_identity_policy: LinuxProcessIdentityPolicy,
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
        _apply_child_rlimits(prepared.child_limits)
        transition_to_workload_identity(workload_identity_policy)
        exec_prepared_native_in_child(prepared)
    except BaseException:  # noqa: BLE001
        # Fork children must never unwind through the Python runtime.
        try:
            os.write(2, b"ssh-over-mcp-host-agent: child exec failed\n")
        except OSError:
            pass
        os._exit(125)

    os._exit(126)


def _validate_spawn_preconditions(prepared: PreparedCommand) -> None:
    if not hasattr(os, "fork") or not hasattr(os, "setsid"):
        raise ChildSupervisorError("POSIX fork/session support is unavailable")
    if prepared._closed:
        raise ChildSupervisorError("prepared command is closed")

    _require_standard_fds()

    try:
        build_native_exec_spec(prepared)
    except NativeExecutionError as exc:
        raise ChildSupervisorError("prepared command cannot enter native execution") from exc


def _contained_child_entry(
    prepared: PreparedCommand,
    *,
    workload_identity_policy: LinuxProcessIdentityPolicy,
    barrier_read: int,
    barrier_write: int,
    stdin_read: int,
    stdin_write: int,
    stdout_read: int,
    stdout_write: int,
    stderr_read: int,
    stderr_write: int,
) -> None:
    # Close all parent-owned pipe endpoints before waiting. No untrusted code
    # executes before the parent releases the one-byte start barrier.
    _close_many(
        (
            barrier_write,
            stdin_write,
            stdout_read,
            stderr_read,
        )
    )

    try:
        _wait_start_barrier(barrier_read)
    except BaseException:  # noqa: BLE001
        # A broken start barrier must terminate before any untrusted code runs.
        os._exit(125)
    finally:
        try:
            os.close(barrier_read)
        except OSError:
            pass

    _child_main(
        prepared,
        workload_identity_policy=workload_identity_policy,
        stdin_read=stdin_read,
        stdin_write=-1,
        stdout_read=-1,
        stdout_write=stdout_write,
        stderr_read=-1,
        stderr_write=stderr_write,
    )
    os._exit(127)


def spawn_prepared_native(
    prepared: PreparedCommand,
    *,
    workload_identity_policy: LinuxProcessIdentityPolicy,
) -> SpawnedChild:
    """Fork a sanitized child wired to three parent-side stdio pipes.

    This does not enforce wall-clock timeout or output byte limits yet.
    """

    _validate_spawn_preconditions(prepared)

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
            workload_identity_policy=workload_identity_policy,
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


def _cleanup_failed_contained_spawn(
    *,
    pid: int,
    barrier_write: int,
    child: SpawnedChild,
    containment: ContainmentHandle,
) -> None:
    # Closing without the release byte makes a correctly blocked child fail
    # closed. cgroup.kill covers a partially successful attach; direct SIGKILL
    # is a fallback for failures before cgroup membership was established.
    _close_many((barrier_write,))
    child.close_stdin()
    child.close_pipes()

    cleanup_failed = False

    try:
        containment.kill_all()
    except ContainmentError:
        cleanup_failed = True

    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        cleanup_failed = True

    if not _reap_pid_bounded(pid):
        cleanup_failed = True

    try:
        containment.close()
    except ContainmentError:
        cleanup_failed = True

    if cleanup_failed:
        raise ChildSupervisorError("cannot clean failed contained child")


def spawn_prepared_native_contained(
    prepared: PreparedCommand,
    backend: ContainmentBackend,
    request: ContainmentRequest,
    *,
    workload_identity_policy: LinuxProcessIdentityPolicy,
) -> SpawnedChild:
    """Fork a child which cannot exec before successful containment attach."""

    _validate_spawn_preconditions(prepared)

    if request.request_id != prepared.request_id:
        raise ChildSupervisorError("containment request id does not match prepared command")

    try:
        containment = backend.create(request)
    except ContainmentError as exc:
        raise ChildSupervisorError("cannot create child containment scope") from exc

    stdin_read = stdin_write = -1
    stdout_read = stdout_write = -1
    stderr_read = stderr_write = -1
    barrier_read = barrier_write = -1

    try:
        stdin_read, stdin_write = _pipe_cloexec()
        stdout_read, stdout_write = _pipe_cloexec()
        stderr_read, stderr_write = _pipe_cloexec()
        barrier_read, barrier_write = _pipe_cloexec()
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
                barrier_read,
                barrier_write,
            )
        )
        try:
            containment.close()
        except ContainmentError as cleanup_exc:
            raise ChildSupervisorError("cannot clean unstarted containment scope") from cleanup_exc

        if isinstance(exc, ChildSupervisorError):
            raise
        raise ChildSupervisorError("cannot fork contained child") from exc

    if pid == 0:
        _contained_child_entry(
            prepared,
            workload_identity_policy=workload_identity_policy,
            barrier_read=barrier_read,
            barrier_write=barrier_write,
            stdin_read=stdin_read,
            stdin_write=stdin_write,
            stdout_read=stdout_read,
            stdout_write=stdout_write,
            stderr_read=stderr_read,
            stderr_write=stderr_write,
        )
        os._exit(127)

    _close_many(
        (
            barrier_read,
            stdin_read,
            stdout_write,
            stderr_write,
        )
    )

    child = SpawnedChild(
        pid=pid,
        stdin_fd=stdin_write,
        stdout_fd=stdout_read,
        stderr_fd=stderr_read,
        containment=containment,
    )

    try:
        if isinstance(containment, PidfdContainmentHandle):
            # Explicit OCI-only capability, never the legacy integer attach.
            # While the forked child is blocked and unreaped, its pidfd pins
            # the process identity until the manager confirms containment.
            try:
                pinned_fd = os.pidfd_open(pid, 0)
            except (AttributeError, OSError) as exc:
                raise ContainmentError("cannot pin OCI child before attach") from exc
            try:
                try:
                    containment.attach_pinned(pinned_fd)
                except BaseException as exc:
                    # OCI manager adapters must never bypass the existing
                    # kill/reap path with an unexpected exception.
                    raise ContainmentError("OCI pinned child attach failed") from exc
            finally:
                try:
                    os.close(pinned_fd)
                except OSError as exc:
                    raise ContainmentError("cannot close OCI child pidfd") from exc
        else:
            containment.attach(pid)
        _release_start_barrier(barrier_write)
    except (ContainmentError, ChildSupervisorError) as exc:
        try:
            _cleanup_failed_contained_spawn(
                pid=pid,
                barrier_write=barrier_write,
                child=child,
                containment=containment,
            )
        except ChildSupervisorError as cleanup_exc:
            raise cleanup_exc from exc
        raise ChildSupervisorError("cannot attach contained child") from exc
    finally:
        _close_many((barrier_write,))

    return child
