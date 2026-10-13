"""Fixed diagnostics; approved forensic caller under ADR 0014, no staging access."""

from __future__ import annotations

import errno
import fcntl
import grp
import hashlib
import math
import os
import platform
import pwd
import select
import signal
import stat
import sys
import threading
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import Literal

AUTHORITY_COMMIT = "1ddebe541ee80c0febc4cd35072f3a5046fac5cb"
AUTHORITY_FILES = (
    ("docs/decisions/0011-incident-bound-e2e-staging-recovery.md", 11227,
     "c98f99d29f8e02bae4c90f56565241818f23e10a229afcecafbebd2a91b43e3b"),
    ("docs/decisions/0012-owned-diagnostic-child-lifecycle.md", 11238,
     "980801f685dba9eee8a8e76c0e39641fd7aa61d5c3453ecd6e10d9ba5f4a51a3"),
    ("docs/superpowers/specs/2026-10-06-incident-staging-inspection-design.md", 22821,
     "650d65243e023f647e4c7424357ad1e2b19d6317eb603cfa1bebde388e358882"),
)
GETCONF_ARGV = ("/usr/bin/getconf", "DARWIN_USER_TEMP_DIR")
PS_ARGV = ("/bin/ps", "-ww", "-U", "502", "-o", "pid=,comm=")
GETCONF_SECONDS = 5
PS_SECONDS = 10
CLEANUP_SECONDS = 2
GETCONF_STREAM_BYTES = 1024
GETCONF_COMBINED_BYTES = 2048
PS_COMBINED_BYTES = 65536
MAX_FD_NAMES = 1024
_FAILURE = "staging diagnostic rejected"
# Known stdlib/context/cancellation failures are sanitized. Assertion failures
# are programming/test defects, not substitutes for the intended OS outcome.
_LIFECYCLE_ERRORS = (
    OSError, RuntimeError, ValueError, TypeError, AttributeError, OverflowError,
    MemoryError, KeyboardInterrupt, SystemExit, GeneratorExit,
)


class DiagnosticError(RuntimeError):
    """Fixed safe failure; uncertainty never authorizes a diagnostic retry."""

    def __init__(self, *, cleanup_uncertain: bool = False):
        if type(cleanup_uncertain) is not bool:
            raise TypeError(_FAILURE)
        super().__init__(_FAILURE)
        self._cleanup_uncertain = cleanup_uncertain

    @property
    def cleanup_uncertain(self) -> bool:
        return self._cleanup_uncertain


def _require_identity() -> None:
    try:
        uid = os.geteuid()
        account = pwd.getpwuid(uid)
        admin = grp.getgrnam("admin").gr_gid
        if (
            uid != 502
            or account.pw_uid != uid
            or account.pw_name != "gha-e2e-orchestrator"
            or account.pw_dir != "/Users/gha-e2e-orchestrator"
            or os.getegid() == admin
            or account.pw_gid == admin
            or admin in os.getgroups()
        ):
            raise DiagnosticError()
    except (OSError, KeyError, TypeError, ValueError, AttributeError):
        raise DiagnosticError() from None


def _require_wait_context() -> None:
    # These checks do not discover native reapers. A trusted standalone parent
    # must also guarantee no competing reaper or FD-mutating signal handler.
    try:
        if (
            sys.platform != "darwin"
            or platform.machine() != "x86_64"
            or os.geteuid() == 0
            or threading.active_count() != 1
            or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
        ):
            raise DiagnosticError()
    except (OSError, TypeError, ValueError, AttributeError):
        raise DiagnosticError() from None


def _dir_meta(info: os.stat_result, uid: int) -> tuple[int, ...]:
    values = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)
    if (
        any(type(value) is not int for value in values)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid not in {0, uid}
        or stat.S_IMODE(info.st_mode) not in {0o700, 0o750, 0o755}
    ):
        raise DiagnosticError()
    return values


def _file_meta(info: os.stat_result, uid: int, size: int) -> tuple[int, ...]:
    values = (
        info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )
    if (
        any(type(value) is not int for value in values)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid not in {0, uid}
        or stat.S_IMODE(info.st_mode) not in {0o600, 0o644}
        or info.st_nlink != 1
        or info.st_size != size
    ):
        raise DiagnosticError()
    return values


def _verify_authority() -> None:
    """Verify the three fixed documents; owned-close uncertainty is sticky."""
    cleanup_uncertain = False

    def owned_close(fd: int) -> None:
        nonlocal cleanup_uncertain
        # Never retry an FD after an ambiguous close: the OS may have reused it.
        try:
            os.close(fd)
        except _LIFECYCLE_ERRORS:
            cleanup_uncertain = True

    try:
        module = Path(__file__)
        if not module.is_absolute() or str(module) != __file__ or ".." in module.parts:
            raise DiagnosticError()
        checkout = module.parents[2].parts[1:]
        uid = os.geteuid()
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        with ExitStack() as owned:
            root_fd = os.open("/", directory_flags)
            owned.callback(owned_close, root_fd)
            nodes = {(): (root_fd, _dir_meta(os.fstat(root_fd), uid))}

            def directory(parts: tuple[str, ...]) -> int:
                if parts not in nodes:
                    parent = directory(parts[:-1])
                    before = _dir_meta(os.stat(parts[-1], dir_fd=parent,
                                               follow_symlinks=False), uid)
                    fd = os.open(parts[-1], directory_flags, dir_fd=parent)
                    owned.callback(owned_close, fd)
                    if _dir_meta(os.fstat(fd), uid) != before:
                        raise DiagnosticError()
                    nodes[parts] = fd, before
                return nodes[parts][0]

            files = []
            for path, size, digest in AUTHORITY_FILES:
                parts = checkout + tuple(path.split("/"))
                parent = directory(parts[:-1])
                before = _file_meta(os.stat(parts[-1], dir_fd=parent,
                                            follow_symlinks=False), uid, size)
                fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                             os.O_CLOEXEC, dir_fd=parent)
                owned.callback(owned_close, fd)
                if _file_meta(os.fstat(fd), uid, size) != before:
                    raise DiagnosticError()
                chunks = bytearray()
                while True:
                    raw = os.read(fd, min(8192, size - len(chunks) + 1))
                    if not raw:
                        break
                    if len(chunks) + len(raw) > size:
                        raise DiagnosticError()
                    chunks.extend(raw)
                if (
                    len(chunks) != size
                    or hashlib.sha256(chunks).hexdigest() != digest
                    or _file_meta(os.fstat(fd), uid, size) != before
                ):
                    raise DiagnosticError()
                files.append((parts, fd, before, size))

            for parts, (fd, before) in nodes.items():
                if _dir_meta(os.fstat(fd), uid) != before:
                    raise DiagnosticError()
                if parts:
                    parent = nodes[parts[:-1]][0]
                    fresh = os.open(parts[-1], directory_flags, dir_fd=parent)
                    try:
                        if _dir_meta(os.fstat(fresh), uid) != before:
                            raise DiagnosticError()
                    finally:
                        owned_close(fresh)
                elif _dir_meta(os.stat("/", follow_symlinks=False), uid) != before:
                    raise DiagnosticError()
            for parts, fd, before, size in files:
                if (
                    _file_meta(os.fstat(fd), uid, size) != before
                    or _file_meta(os.stat(parts[-1], dir_fd=nodes[parts[:-1]][0],
                                          follow_symlinks=False), uid, size) != before
                ):
                    raise DiagnosticError()
        if cleanup_uncertain:
            raise DiagnosticError(cleanup_uncertain=True)
    except DiagnosticError:
        # Deterministic validation errors stay certain only if every close
        # was settled, including closes after a validation failure.
        if cleanup_uncertain:
            raise DiagnosticError(cleanup_uncertain=True) from None
        raise
    except _LIFECYCLE_ERRORS + (IndexError, RecursionError):
        raise DiagnosticError(cleanup_uncertain=cleanup_uncertain) from None


@dataclass(slots=True)
class _Launch:
    stdin_fd: int
    stdout_read: int
    stdout_write: int
    stderr_read: int
    stderr_write: int
    file_actions: tuple[tuple[int, ...], ...]
    _owned: set[int]

    def _close(self, fds: tuple[int, ...]) -> None:
        failed = False
        for fd in fds:
            if fd in self._owned:
                self._owned.remove(fd)  # Never retry an ambiguously closed FD.
                try:
                    os.close(fd)
                except OSError:
                    failed = True
        if failed:
            raise DiagnosticError(cleanup_uncertain=True)

    def close_child_ends(self) -> None:
        self._close((self.stdin_fd, self.stdout_write, self.stderr_write))

    def close_readers(self) -> None:
        self._close((self.stdout_read, self.stderr_read))

def _check_deadline(deadline: float) -> None:
    if type(deadline) is not float or not math.isfinite(deadline) or monotonic() >= deadline:
        raise DiagnosticError()


@contextmanager
def _prepare_launch(*, deadline: float):
    owned: set[int] = set()
    launch = None
    try:
        _check_deadline(deadline)

        def moved(fd: int) -> int:
            if fd < 3:
                duplicate = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
                owned.add(duplicate)
                owned.remove(fd)  # An ambiguous close must never be retried.
                try:
                    os.close(fd)
                except OSError:
                    raise DiagnosticError(cleanup_uncertain=True) from None
                return duplicate
            return fd

        before_null = os.stat("/dev/null", follow_symlinks=False)
        if not stat.S_ISCHR(before_null.st_mode) or before_null.st_uid != 0:
            raise DiagnosticError()
        null = os.open("/dev/null", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        owned.add(null)
        info = os.fstat(null)
        if (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_rdev) != (
            before_null.st_dev, before_null.st_ino, before_null.st_mode,
            before_null.st_uid, before_null.st_rdev,
        ):
            raise DiagnosticError()
        null = moved(null)
        _check_deadline(deadline)
        stdout_read, stdout_write = os.pipe()
        owned.update((stdout_read, stdout_write))
        stdout_read, stdout_write = moved(stdout_read), moved(stdout_write)
        stderr_read, stderr_write = os.pipe()
        owned.update((stderr_read, stderr_write))
        stderr_read, stderr_write = moved(stderr_read), moved(stderr_write)
        names: set[int] = set()
        count = 0
        with os.scandir("/dev/fd") as entries:
            for entry in entries:
                _check_deadline(deadline)
                count += 1
                name = entry.name
                if (
                    count > MAX_FD_NAMES
                    or not isinstance(name, str)
                    or len(name) > 10
                    or not name.isascii()
                    or not name.isdecimal()
                ):
                    raise DiagnosticError()
                fd = int(name)
                if fd > 2147483647 or str(fd) != name or fd in names:
                    raise DiagnosticError()
                names.add(fd)
        _check_deadline(deadline)
        live: set[int] = set()
        for fd in names | owned:
            _check_deadline(deadline)
            if fd < 3:
                continue
            try:
                os.fstat(fd)
            except OSError as error:
                if error.errno != errno.EBADF or fd in owned:
                    raise DiagnosticError() from None
                # The scanner's own FD is now closed. Darwin rejects a CLOSE
                # action for it; it cannot be inherited. No FD allocations or
                # competing FD mutation are permitted before this spawn.
            else:
                live.add(fd)
        actions = (
            (os.POSIX_SPAWN_DUP2, null, 0),
            (os.POSIX_SPAWN_DUP2, stdout_write, 1),
            (os.POSIX_SPAWN_DUP2, stderr_write, 2),
        ) + tuple((os.POSIX_SPAWN_CLOSE, fd) for fd in sorted(live))
        launch = _Launch(null, stdout_read, stdout_write, stderr_read, stderr_write,
                         actions, owned)
        yield launch
    except (OSError, ValueError, TypeError, AttributeError, OverflowError):
        raise DiagnosticError() from None
    finally:
        if launch is None:
            launch = _Launch(-1, -1, -1, -1, -1, (), owned)
        launch._close(tuple(owned))


@dataclass(frozen=True, slots=True)
class DiagnosticCapture:
    kind: Literal["getconf", "ps"]
    stdout: bytes
    child_pid: int


def capture_getconf() -> DiagnosticCapture:
    _require_identity()
    return _capture_fixed("getconf")


def capture_ps() -> DiagnosticCapture:
    _require_identity()
    return _capture_fixed("ps")


def _capture_fixed(kind: Literal["getconf", "ps"]) -> DiagnosticCapture:
    if type(kind) is not str or kind not in {"getconf", "ps"}:
        raise DiagnosticError()
    _require_wait_context()
    _verify_authority()
    argv = GETCONF_ARGV if kind == "getconf" else PS_ARGV
    deadline = monotonic() + (GETCONF_SECONDS if kind == "getconf" else PS_SECONDS)
    total_limit = GETCONF_COMBINED_BYTES if kind == "getconf" else PS_COMBINED_BYTES
    stream_limit = GETCONF_STREAM_BYTES if kind == "getconf" else PS_COMBINED_BYTES
    pid = None
    status = None
    unknown = False
    attempted_spawn = False
    signal_sent = False
    queue = None
    process_notification = False

    def owned_wait(until: float) -> bool:
        nonlocal status, unknown
        if unknown:
            raise DiagnosticError(cleanup_uncertain=True)
        if status is not None:
            return True  # Reaped is terminal: never wait or signal this PID again.
        while True:
            _check_deadline(until)
            try:
                _require_wait_context()
                result = os.waitpid(pid, os.WNOHANG)
            except InterruptedError:
                continue
            except _LIFECYCLE_ERRORS:
                unknown = True
                raise DiagnosticError(cleanup_uncertain=True) from None
            if (
                type(result) is not tuple or len(result) != 2
                or any(type(value) is not int for value in result)
            ):
                unknown = True
                raise DiagnosticError(cleanup_uncertain=True)
            observed_pid, observed_status = result
            if observed_pid == 0 and observed_status == 0:
                return False
            if observed_pid != pid or not 0 <= observed_status <= 2147483647 or not (
                os.WIFEXITED(observed_status) or os.WIFSIGNALED(observed_status)
            ):
                unknown = True
                raise DiagnosticError(cleanup_uncertain=True)
            status = observed_status
            return True

    with _prepare_launch(deadline=deadline) as launch:
        def cleanup() -> bool:
            nonlocal signal_sent
            until = monotonic() + CLEANUP_SECONDS
            uncertain = False
            try:
                launch.close_readers()
            except _LIFECYCLE_ERRORS:
                uncertain = True
            if pid is None:
                return uncertain or attempted_spawn
            try:
                if owned_wait(until):
                    return uncertain
                if signal_sent:  # No repeated signal under any failure path.
                    return True
                _check_deadline(until)
                signal_sent = True
                try:
                    os.kill(pid, signal.SIGKILL)
                except _LIFECYCLE_ERRORS:
                    uncertain = True  # ESRCH is not proof of reap.
                while not owned_wait(until):
                    if queue is None or not process_notification:
                        return True
                    remaining = until - monotonic()
                    if remaining <= 0:
                        return True
                    events = queue.control(None, 3, remaining)
                    if any(event.flags & select.KQ_EV_ERROR for event in events):
                        return True
                return uncertain
            except _LIFECYCLE_ERRORS:
                return True

        try:
            _check_deadline(deadline)
            attempted_spawn = True
            created = os.posix_spawn(argv[0], argv, {"LC_ALL": "C"},
                                     file_actions=launch.file_actions,
                                     setsigdef=(signal.SIGPIPE, signal.SIGCHLD))
            if type(created) is not int or created <= 0:
                raise DiagnosticError(cleanup_uncertain=True)
            pid = created  # This invocation alone owns its wait status.
            launch.close_child_ends()
            os.set_blocking(launch.stdout_read, False)
            os.set_blocking(launch.stderr_read, False)
            exited = owned_wait(deadline)
            queue = select.kqueue()  # Created after spawn; cannot enter that child.
            if not exited:
                try:
                    queue.control([select.kevent(
                        pid, filter=select.KQ_FILTER_PROC,
                        flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_ONESHOT,
                        fflags=select.KQ_NOTE_EXIT,
                    )], 0, 0)
                    process_notification = True
                except OSError as error:
                    # Exit may win the registration race. Only an exact owned
                    # terminal wait settles it; no PID lookup or setup retry.
                    if error.errno != errno.ESRCH or not owned_wait(deadline):
                        raise DiagnosticError() from None
            readers = {launch.stdout_read, launch.stderr_read}
            output = {fd: bytearray() for fd in readers}
            queue.control([select.kevent(fd, filter=select.KQ_FILTER_READ,
                                          flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE)
                           for fd in readers], 0, 0)
            while True:
                _check_deadline(deadline)
                _require_wait_context()
                exited = owned_wait(deadline)
                if exited and not readers:
                    if status != 0 or output[launch.stderr_read]:
                        raise DiagnosticError()
                    _check_deadline(deadline)
                    return DiagnosticCapture(kind, bytes(output[launch.stdout_read]), pid)
                remaining = deadline - monotonic()
                if remaining <= 0:
                    raise DiagnosticError()
                events = queue.control(None, 3, remaining)
                _check_deadline(deadline)
                for event in events:
                    if event.flags & select.KQ_EV_ERROR:
                        raise DiagnosticError()
                    if event.filter == select.KQ_FILTER_PROC and event.ident == pid:
                        continue  # Notification is never the owned wait result.
                    if event.filter != select.KQ_FILTER_READ or event.ident not in readers:
                        raise DiagnosticError()
                    fd = event.ident
                    while True:
                        _check_deadline(deadline)
                        available = min(stream_limit - len(output[fd]),
                                        total_limit - sum(map(len, output.values())))
                        try:
                            raw = os.read(fd, min(8192, available + 1))
                        except BlockingIOError:
                            break
                        except InterruptedError:
                            continue
                        if type(raw) is not bytes:
                            raise DiagnosticError()
                        if not raw:
                            queue.control([select.kevent(fd, filter=select.KQ_FILTER_READ,
                                                          flags=select.KQ_EV_DELETE)], 0, 0)
                            readers.remove(fd)
                            break
                        if len(raw) > available:
                            raise DiagnosticError()
                        output[fd].extend(raw)
        except _LIFECYCLE_ERRORS as error:
            uncertain = cleanup()
            if isinstance(error, DiagnosticError):
                uncertain = uncertain or error.cleanup_uncertain
            raise DiagnosticError(cleanup_uncertain=uncertain) from None
        finally:
            if queue is not None:
                try:
                    queue.close()
                except _LIFECYCLE_ERRORS:
                    raise DiagnosticError(cleanup_uncertain=True) from None
