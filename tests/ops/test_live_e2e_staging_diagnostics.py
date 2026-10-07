from __future__ import annotations

import errno
import fcntl
import hashlib
import importlib.util
import os
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from collections import deque
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "ops/live-e2e/staging_diagnostics.py"
AUTHORITY = "1ddebe541ee80c0febc4cd35072f3a5046fac5cb"
BINDING = (
    ("docs/decisions/0011-incident-bound-e2e-staging-recovery.md", 11227,
     "c98f99d29f8e02bae4c90f56565241818f23e10a229afcecafbebd2a91b43e3b"),
    ("docs/decisions/0012-owned-diagnostic-child-lifecycle.md", 11238,
     "980801f685dba9eee8a8e76c0e39641fd7aa61d5c3453ecd6e10d9ba5f4a51a3"),
    ("docs/superpowers/specs/2026-10-06-incident-staging-inspection-design.md", 22821,
     "650d65243e023f647e4c7424357ad1e2b19d6317eb603cfa1bebde388e358882"),
)


def _load_module() -> ModuleType:
    assert MODULE.is_file(), "dormant fixed diagnostic module is not implemented"
    name = "ssh_over_mcp_staging_diagnostics"
    spec = importlib.util.spec_from_file_location(name, MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


@pytest.fixture
def diagnostics():
    return _load_module()


@pytest.fixture
def authority_tree(diagnostics, monkeypatch):
    # The production chain refuses shared writable /tmp ancestors.
    scratch = ROOT / ".superpowers"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="diagnostic-authority-", dir=scratch) as name:
        root = Path(name)
        for path, _, _ in BINDING:
            destination = root / path
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(ROOT / path, destination)
            destination.chmod(0o644)
        monkeypatch.setattr(diagnostics, "__file__", str(root / "ops/live-e2e/module.py"))
        yield root


def test_binding_matches_exact_main_blobs(diagnostics):
    assert diagnostics.AUTHORITY_COMMIT == AUTHORITY
    assert diagnostics.AUTHORITY_FILES == BINDING
    for path, size, digest in BINDING:
        blob = subprocess.run(
            ["git", "show", f"{AUTHORITY}:{path}"], cwd=ROOT, check=True, capture_output=True
        ).stdout
        assert len(blob) == size and hashlib.sha256(blob).hexdigest() == digest
    diagnostics._verify_authority()


def test_fixed_constants(diagnostics):
    # Literal constraints are also exercised through the capture consumers in
    # Task 2; these vectors pin the approved authority values independently.
    assert diagnostics.GETCONF_ARGV == ("/usr/bin/getconf", "DARWIN_USER_TEMP_DIR")
    assert diagnostics.PS_ARGV == ("/bin/ps", "-ww", "-U", "502", "-o", "pid=,comm=")
    assert diagnostics.GETCONF_SECONDS == 5
    assert diagnostics.PS_SECONDS == 10
    assert diagnostics.CLEANUP_SECONDS == 2
    assert diagnostics.GETCONF_STREAM_BYTES == 1024
    assert diagnostics.GETCONF_COMBINED_BYTES == 2048
    assert diagnostics.PS_COMBINED_BYTES == 65536
    assert diagnostics.MAX_FD_NAMES == 1024


@pytest.mark.parametrize("change", ["changed", "missing", "symlink", "fifo", "hardlink", "mode"])
def test_binding_refuses_changed_symlink_special_or_unstable_documents(
    diagnostics, authority_tree, monkeypatch, change
):
    path = authority_tree / BINDING[0][0]
    secret = authority_tree / "unrelated-file"
    secret.write_bytes(b"must-not-read-this-canary")
    if change == "changed":
        raw = path.read_bytes()
        path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
    elif change == "mode":
        path.chmod(0o666)
    elif change == "hardlink":
        os.link(path, authority_tree / "alias")
    else:
        path.unlink()
        if change == "symlink":
            path.symlink_to(secret)
        elif change == "fifo":
            os.mkfifo(path, 0o600)
    real_read = os.read
    secret_identity = (secret.stat().st_dev, secret.stat().st_ino)

    def read(fd, size):
        info = os.fstat(fd)
        assert (info.st_dev, info.st_ino) != secret_identity
        assert stat.S_ISREG(info.st_mode), "non-regular authority object read"
        return real_read(fd, size)

    monkeypatch.setattr(diagnostics.os, "read", read)
    with pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"):
        diagnostics._verify_authority()


def test_binding_rejects_namespace_replacement_during_read(
    diagnostics, authority_tree, monkeypatch
):
    path = authority_tree / BINDING[0][0]
    before = path.stat()
    real_read = os.read
    replaced = False

    def read(fd, size):
        nonlocal replaced
        info = os.fstat(fd)
        result = real_read(fd, size)
        if info.st_ino == before.st_ino and not replaced:
            replacement = path.with_suffix(".replacement")
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o644)
            replacement.replace(path)
            replaced = True
        return result

    monkeypatch.setattr(diagnostics.os, "read", read)
    with pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"):
        diagnostics._verify_authority()
    assert replaced


def test_binding_accepts_complete_short_reads(diagnostics, authority_tree, monkeypatch):
    real_read = os.read
    monkeypatch.setattr(diagnostics.os, "read", lambda fd, size: real_read(fd, min(size, 17)))
    diagnostics._verify_authority()


@pytest.mark.parametrize("change", ["directory_mode", "directory_symlink", "owner", "file_size"])
def test_binding_rejects_unsafe_chain_or_file_metadata(
    diagnostics, authority_tree, monkeypatch, change
):
    parent = authority_tree / "docs/decisions"
    path = authority_tree / BINDING[0][0]
    if change == "directory_mode":
        parent.chmod(0o777)
    elif change == "directory_symlink":
        target = parent.with_name("other")
        parent.rename(target)
        parent.symlink_to(target, target_is_directory=True)
    elif change == "file_size":
        path.write_bytes(path.read_bytes()[:-1])
    else:
        real_fstat = os.fstat

        def fstat(fd):
            info = real_fstat(fd)
            if stat.S_ISREG(info.st_mode):
                values = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
                values["st_uid"] = 900001
                return SimpleNamespace(**values)
            return info

        monkeypatch.setattr(diagnostics.os, "fstat", fstat)
    with pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"):
        diagnostics._verify_authority()


def _identity(monkeypatch, diagnostics):
    monkeypatch.setattr(diagnostics.os, "geteuid", lambda: 502)
    monkeypatch.setattr(diagnostics.os, "getegid", lambda: 20)
    monkeypatch.setattr(diagnostics.os, "getgroups", lambda: [20, 12])
    monkeypatch.setattr(diagnostics.pwd, "getpwuid", lambda uid: SimpleNamespace(
        pw_uid=502, pw_gid=20, pw_name="gha-e2e-orchestrator",
        pw_dir="/Users/gha-e2e-orchestrator"
    ))
    monkeypatch.setattr(diagnostics.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=80))


@pytest.mark.parametrize("change", ["uid", "name", "home", "primary_admin", "extra_admin", "lookup"])
def test_context_refuses_wrong_platform_identity_admin_or_reaper_state(
    diagnostics, monkeypatch, change
):
    _identity(monkeypatch, diagnostics)
    diagnostics._require_identity()
    if change == "uid":
        monkeypatch.setattr(diagnostics.os, "geteuid", lambda: 501)
    elif change == "name" or change == "home":
        monkeypatch.setattr(diagnostics.pwd, "getpwuid", lambda uid: SimpleNamespace(
            pw_uid=502, pw_gid=20,
            pw_name="other" if change == "name" else "gha-e2e-orchestrator",
            pw_dir="/tmp/other" if change == "home" else "/Users/gha-e2e-orchestrator"
        ))
    elif change == "primary_admin":
        monkeypatch.setattr(diagnostics.os, "getegid", lambda: 80)
    elif change == "extra_admin":
        monkeypatch.setattr(diagnostics.os, "getgroups", lambda: [20, 80])
    else:
        monkeypatch.setattr(diagnostics.grp, "getgrnam", lambda _: (_ for _ in ()).throw(KeyError()))
    with pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"):
        diagnostics._require_identity()


@pytest.mark.parametrize("change", ["platform", "machine", "root", "threads", "sigchld"])
def test_wait_context_refuses_unsupported_ownership_state(diagnostics, monkeypatch, change):
    monkeypatch.setattr(diagnostics.sys, "platform", "darwin")
    monkeypatch.setattr(diagnostics.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(diagnostics.os, "geteuid", lambda: 501)
    monkeypatch.setattr(diagnostics.threading, "active_count", lambda: 1)
    monkeypatch.setattr(diagnostics.signal, "getsignal", lambda _: signal.SIG_DFL)
    diagnostics._require_wait_context()
    if change == "platform":
        monkeypatch.setattr(diagnostics.sys, "platform", "linux")
    elif change == "machine":
        monkeypatch.setattr(diagnostics.platform, "machine", lambda: "arm64")
    elif change == "root":
        monkeypatch.setattr(diagnostics.os, "geteuid", lambda: 0)
    elif change == "threads":
        monkeypatch.setattr(diagnostics.threading, "active_count", lambda: 2)
    else:
        monkeypatch.setattr(diagnostics.signal, "getsignal", lambda _: signal.SIG_IGN)
    with pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"):
        diagnostics._require_wait_context()


def test_launch_excludes_inheritable_parent_fds_without_mutation(diagnostics, tmp_path):
    fd = os.open(tmp_path / "borrowed", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, b"canary")
        os.set_inheritable(fd, True)
        flags = fcntl.fcntl(fd, fcntl.F_GETFD), fcntl.fcntl(fd, fcntl.F_GETFL)
        before = os.fstat(fd)
        with diagnostics._prepare_launch(deadline=diagnostics.monotonic() + 5) as launch:
            assert (os.POSIX_SPAWN_CLOSE, fd) in launch.file_actions
            assert launch.file_actions[:3] == (
                (os.POSIX_SPAWN_DUP2, launch.stdin_fd, 0),
                (os.POSIX_SPAWN_DUP2, launch.stdout_write, 1),
                (os.POSIX_SPAWN_DUP2, launch.stderr_write, 2),
            )
            for own in (launch.stdin_fd, launch.stdout_read, launch.stdout_write,
                        launch.stderr_read, launch.stderr_write):
                assert own >= 3 and (os.POSIX_SPAWN_CLOSE, own) in launch.file_actions
            launch.close_child_ends()
            assert os.fstat(fd).st_ino == before.st_ino
        assert flags == (fcntl.fcntl(fd, fcntl.F_GETFD), fcntl.fcntl(fd, fcntl.F_GETFL))
        assert os.lseek(fd, 0, os.SEEK_CUR) == 6
        assert os.fstat(fd).st_ino == before.st_ino
    finally:
        os.close(fd)


class _Names:
    def __init__(self, names):
        self.names = names

    def __enter__(self):
        return (SimpleNamespace(name=name) for name in self.names)

    def __exit__(self, *args):
        pass


@pytest.mark.parametrize("count", [1024, 1025])
def test_fd_enumeration_overflow_refuses_before_spawn(diagnostics, monkeypatch, count):
    monkeypatch.setattr(diagnostics.os, "scandir", lambda path: _Names(map(str, range(count))))
    if count == 1024:
        with diagnostics._prepare_launch(deadline=diagnostics.monotonic() + 5) as launch:
            assert (os.POSIX_SPAWN_CLOSE, launch.stdout_read) in launch.file_actions
    else:
        with (
            pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"),
            diagnostics._prepare_launch(deadline=diagnostics.monotonic() + 5),
        ):
            pytest.fail("FD count overflow accepted")


@pytest.mark.parametrize("names", [["03"], ["-1"], ["x"], ["1", "1"], ["2147483648"]])
def test_fd_enumeration_refuses_ambiguous_names(diagnostics, monkeypatch, names):
    monkeypatch.setattr(diagnostics.os, "scandir", lambda path: _Names(names))
    with (
        pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"),
        diagnostics._prepare_launch(deadline=diagnostics.monotonic() + 5),
    ):
        pytest.fail("ambiguous FD accepted")


def test_resource_deadline_equality_refuses_without_mutating_borrowed_fd(diagnostics, tmp_path):
    fd = os.open(tmp_path / "borrowed", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with (
            pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"),
            diagnostics._prepare_launch(deadline=diagnostics.monotonic()),
        ):
            pytest.fail("expired launch accepted")
        assert stat.S_ISREG(os.fstat(fd).st_mode)
    finally:
        os.close(fd)


def test_import_produces_no_host_action_or_output(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("import performed a host action")

    monkeypatch.setattr(os, "posix_spawn", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    _load_module()
    assert capsys.readouterr() == ("", "")


def test_launch_omits_only_proven_closed_scanner_slot(diagnostics):
    with diagnostics._prepare_launch(deadline=diagnostics.monotonic() + 5) as launch:
        for action in launch.file_actions[3:]:
            assert action[0] == os.POSIX_SPAWN_CLOSE
            # EBADF for a scanner-owned transient slot must not make Darwin's
            # spawn fail. Every *open* descriptor still gets a CLOSE action.
            os.fstat(action[1])


def test_fd_verification_other_error_refuses_preserving_borrowed_fd(
    diagnostics, tmp_path, monkeypatch
):
    fd = os.open(tmp_path / "borrowed", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    real_fstat = os.fstat

    def fstat(value):
        if value == fd:
            raise OSError(errno.EIO, "private canary error must not escape")
        return real_fstat(value)

    try:
        monkeypatch.setattr(diagnostics.os, "fstat", fstat)
        with (
            pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"),
            diagnostics._prepare_launch(deadline=diagnostics.monotonic() + 5),
        ):
            pytest.fail("unknown descriptor state accepted")
        assert stat.S_ISREG(real_fstat(fd).st_mode)
    finally:
        os.close(fd)


@pytest.mark.parametrize("number", [errno.EINTR, errno.EIO])
def test_low_fd_close_error_preserves_uncertainty_without_retry(
    diagnostics, monkeypatch, number, capsys
):
    # OS-boundary simulation owns only these fake slots; it never closes parent stdio.
    null_info = os.stat("/dev/null")
    closed = []

    def close(fd):
        closed.append(fd)
        if fd == 0:
            raise OSError(number, "private close detail")
        assert fd == 900001

    def forbidden(*args, **kwargs):
        pytest.fail("close uncertainty must refuse before spawning")

    with monkeypatch.context() as fault:
        fault.setattr(diagnostics.os, "open", lambda *args, **kwargs: 0)
        fault.setattr(diagnostics.os, "fstat", lambda fd: null_info)
        fault.setattr(diagnostics.fcntl, "fcntl", lambda *args: 900001)
        fault.setattr(diagnostics.os, "close", close)
        fault.setattr(diagnostics.os, "posix_spawn", forbidden)
        with (
            pytest.raises(diagnostics.DiagnosticError) as error,
            diagnostics._prepare_launch(deadline=diagnostics.monotonic() + 5),
        ):
            pytest.fail("ambiguous low-FD close accepted")
    assert str(error.value) == "staging diagnostic rejected"
    assert error.value.cleanup_uncertain is True
    assert closed == [0, 900001]  # One ambiguous close, then known duplicate cleanup.
    assert capsys.readouterr() == ("", "")


class _Backend:
    """OS-boundary simulator; real authority reads and launch resources stay real."""

    def __init__(self, module, monkeypatch):
        self.module, self.monkeypatch = module, monkeypatch
        self.now = 100.0
        self.pid = 900001  # Never used with the real OS wait/kill implementations.
        self.stdout, self.stderr = b"bounded\n", b""
        self.reader = {}
        self.pipes = []
        self.read_budget_records = []
        self.delivered = 0
        self.registered = set()
        self.spawns, self.waits, self.kill_calls, self.read_sizes, self.timeouts = [], [], [], [], []
        self.wait_errors = deque()
        self.wait_mode = "exit"
        self.exit_status = 0
        self.reaped = False
        self.killed = False
        self.kill_at = None
        self.keep_running = False
        self.retained = False
        self.stalled = False
        self.spawn_error = self.queue_error = self.registration_error = self.kill_error = None
        self.spawn_result = self.pid
        self.advance_to_deadline = False
        self.changed_sigchld = False
        self.proc_registered = False
        real_read, real_pipe = os.read, os.pipe

        def pipe():
            pair = real_pipe()
            self.pipes.append(pair)
            return pair

        def read(fd, size):
            if fd not in self.reader:
                return real_read(fd, size)
            self.read_sizes.append(size)
            stream = self.reader[fd]
            self.read_budget_records.append((size, self.delivered))
            data = getattr(self, stream)
            if self.stalled or (not data and self.retained):
                raise BlockingIOError(errno.EAGAIN, "fixture not ready")
            result = data[:size]
            self.delivered += len(result)
            setattr(self, stream, data[size:])
            return result

        monkeypatch.setattr(module, "_require_identity", lambda: None)
        monkeypatch.setattr(module.sys, "platform", "darwin")
        monkeypatch.setattr(module.platform, "machine", lambda: "x86_64")
        monkeypatch.setattr(module.threading, "active_count", lambda: 1)
        monkeypatch.setattr(module.signal, "getsignal", lambda _: signal.SIG_DFL)
        monkeypatch.setattr(module, "monotonic", lambda: self.now)
        monkeypatch.setattr(module, "select", select, raising=False)
        for name, value in {"KQ_FILTER_READ": -1, "KQ_FILTER_PROC": -5, "KQ_EV_ADD": 1,
                            "KQ_EV_ENABLE": 4, "KQ_EV_ONESHOT": 16, "KQ_EV_DELETE": 2,
                            "KQ_EV_ERROR": 0x4000, "KQ_NOTE_EXIT": 0x80000000}.items():
            monkeypatch.setattr(select, name, value, raising=False)
        monkeypatch.setattr(select, "kevent", lambda ident, filter, flags=0, fflags=0:
                            SimpleNamespace(ident=ident, filter=filter, flags=flags,
                                            fflags=fflags, data=0), raising=False)
        monkeypatch.setattr(select, "kqueue", self.queue, raising=False)
        monkeypatch.setattr(module.os, "posix_spawn", self.spawn)
        monkeypatch.setattr(module.os, "waitpid", self.wait)
        monkeypatch.setattr(module.os, "kill", self.kill)
        monkeypatch.setattr(module.os, "read", read)
        monkeypatch.setattr(module.os, "pipe", pipe)

    def spawn(self, executable, argv, env, **kwargs):
        self.spawns.append((executable, tuple(argv), env, kwargs))
        if self.spawn_error:
            raise self.spawn_error
        actions = kwargs["file_actions"]
        for stream, action in zip(("stdout", "stderr"), actions[1:3], strict=True):
            writer = action[1]
            matches = [read for read, write in self.pipes if write == writer]
            assert len(matches) == 1
            self.reader[matches[0]] = stream
        return self.spawn_result

    def wait(self, pid, options):
        self.waits.append((pid, options))
        assert pid == self.pid and options == os.WNOHANG
        assert not self.reaped, "owned child waited again after terminal reap"
        if self.wait_errors:
            value = self.wait_errors.popleft()
            if isinstance(value, BaseException):
                raise value
            return value
        if self.wait_mode == "running" and (not self.killed or self.keep_running):
            return 0, 0
        self.reaped = True
        return self.pid, 9 if self.killed else self.exit_status

    def kill(self, pid, number):
        assert pid == self.pid and number == signal.SIGKILL and not self.reaped
        assert not self.kill_calls, "duplicate signal"
        self.kill_calls.append((pid, number))
        self.kill_at = self.now
        self.killed = True
        if self.kill_error:
            raise self.kill_error

    def queue(self):
        if self.queue_error:
            raise self.queue_error
        owner = self

        class Queue:
            def control(self, changes, max_events, timeout=None):
                assert timeout is not None and 0 <= timeout <= 10
                owner.timeouts.append(timeout)
                if changes:
                    for event in changes:
                        if event.filter == select.KQ_FILTER_PROC:
                            assert event.ident == owner.pid
                            if owner.registration_error:
                                raise owner.registration_error
                            owner.proc_registered = True
                        elif event.flags & select.KQ_EV_DELETE:
                            owner.registered.discard(event.ident)
                        else:
                            assert event.ident in owner.reader
                            owner.registered.add(event.ident)
                    return []
                owner.now += timeout if owner.advance_to_deadline else min(timeout, 0.25)
                if owner.changed_sigchld:
                    owner.monkeypatch.setattr(owner.module.signal, "getsignal",
                                              lambda _: signal.SIG_IGN)
                result = [SimpleNamespace(ident=fd, filter=select.KQ_FILTER_READ,
                                          flags=0, fflags=0, data=0)
                          for fd in sorted(owner.registered)]
                if owner.proc_registered:
                    result.append(SimpleNamespace(ident=owner.pid, filter=select.KQ_FILTER_PROC,
                                                  flags=0, fflags=0, data=0))
                return result[:max_events]

            def close(self):
                pass

        return Queue()


@pytest.fixture
def backend(diagnostics, monkeypatch):
    return _Backend(diagnostics, monkeypatch)


@pytest.mark.parametrize("kind,argv,budget", [
    ("getconf", ("/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"), 5),
    ("ps", ("/bin/ps", "-ww", "-U", "502", "-o", "pid=,comm="), 10),
])
def test_fixed_argv_env_and_no_public_overrides(diagnostics, backend, kind, argv, budget):
    call = diagnostics.capture_getconf if kind == "getconf" else diagnostics.capture_ps
    with pytest.raises(TypeError):
        call(pid=123)
    assert backend.spawns == []
    result = call()
    assert result.kind == kind and result.stdout == b"bounded\n" and result.child_pid == 900001
    executable, actual, env, kwargs = backend.spawns[0]
    assert actual == argv and executable == argv[0] and env == {"LC_ALL": "C"}
    assert set(kwargs) == {"file_actions", "setsigdef"}
    assert kwargs["setsigdef"] == (signal.SIGPIPE, signal.SIGCHLD)
    assert all(0 <= timeout <= budget for timeout in backend.timeouts)
    assert backend.kill_calls == []
    with pytest.raises((AttributeError, TypeError)):
        result.stdout = b"changed"


@pytest.mark.parametrize("status,stderr,retained", [(0, b"", False), (256, b"", False),
                                                  (9, b"", False), (0, b"secret", False),
                                                  (0, b"", True)])
def test_exact_own_wait_zero_and_both_eof_required(diagnostics, backend, status, stderr, retained):
    backend.exit_status, backend.stderr, backend.retained = status, stderr, retained
    if status == 0 and not stderr and not retained:
        assert diagnostics.capture_getconf().stdout == b"bounded\n"
    else:
        with pytest.raises(diagnostics.DiagnosticError) as error:
            diagnostics.capture_getconf()
        assert error.value.cleanup_uncertain is False
    assert backend.kill_calls == []  # Already-reaped state cannot authorize a signal.


@pytest.mark.parametrize("kind,size,accepted", [
    ("getconf", 1024, True), ("getconf", 1025, False),
    ("ps", 65536, True), ("ps", 65537, False),
])
def test_each_getconf_stream_and_combined_ps_byte_bounds(diagnostics, backend, kind, size, accepted):
    backend.stdout = b"x" * size
    call = diagnostics.capture_getconf if kind == "getconf" else diagnostics.capture_ps
    if accepted:
        assert call().stdout == b"x" * size
    else:
        with pytest.raises(diagnostics.DiagnosticError):
            call()
    assert max(backend.read_sizes) <= (1025 if kind == "getconf" else 65537)


def test_deadline_equality_is_refusal(diagnostics, backend):
    backend.advance_to_deadline = True
    with pytest.raises(diagnostics.DiagnosticError):
        diagnostics.capture_getconf()
    assert backend.now == 105.0


@pytest.mark.parametrize("wait", [ChildProcessError(errno.ECHILD, "private detail"),
                                  (900002, 0), (0, 256), (900001, 0x7f),
                                  (900001, -256), (900001, 1 << 40)])
def test_echild_or_wrong_wait_pid_never_signals_or_succeeds(diagnostics, backend, wait, capsys):
    backend.wait_errors.append(wait)
    with pytest.raises(diagnostics.DiagnosticError) as error:
        diagnostics.capture_getconf()
    assert str(error.value) == "staging diagnostic rejected"
    assert error.value.cleanup_uncertain is True
    assert backend.waits, "failure did not reach the scripted owned-wait boundary"
    assert backend.kill_calls == []
    assert capsys.readouterr() == ("", "")


def test_one_kill_only_for_current_unreaped_child(diagnostics, backend):
    backend.wait_mode, backend.stdout = "running", b"x" * 1025
    with pytest.raises(diagnostics.DiagnosticError) as error:
        diagnostics.capture_getconf()
    assert error.value.cleanup_uncertain is False
    assert backend.kill_calls == [(900001, signal.SIGKILL)]
    assert len(backend.spawns) == 1 and backend.reaped


def test_reaped_or_unknown_child_cannot_be_signalled(diagnostics, backend):
    backend.retained = True
    with pytest.raises(diagnostics.DiagnosticError):
        diagnostics.capture_getconf()
    assert backend.reaped and backend.kill_calls == []


@pytest.mark.parametrize("fault", ["expiry", "esrch", "signal_failure", "reap_failure", "queue"])
def test_two_second_cleanup_and_failed_signal_reap_are_uncertain(diagnostics, backend, fault):
    backend.wait_mode, backend.stdout = "running", b"x" * 1025
    if fault == "expiry":
        backend.keep_running = True
    elif fault == "esrch":
        backend.kill_error = ProcessLookupError(errno.ESRCH, "private detail")
    elif fault == "signal_failure":
        backend.kill_error = PermissionError(errno.EPERM, "private detail")
    elif fault == "reap_failure":
        real_kill = backend.kill

        def kill(pid, number):
            real_kill(pid, number)
            backend.wait_errors.append(ChildProcessError(errno.ECHILD, "private detail"))

        backend.monkeypatch.setattr(diagnostics.os, "kill", kill)
    else:
        backend.queue_error = OSError(errno.EMFILE, "private detail")
        backend.keep_running = True
    with pytest.raises(diagnostics.DiagnosticError) as error:
        diagnostics.capture_getconf()
    assert error.value.cleanup_uncertain is True
    assert len(backend.kill_calls) <= 1 and len(backend.spawns) == 1
    assert backend.now <= 107.0
    if backend.kill_calls:
        assert backend.now - backend.kill_at <= 2.0


@pytest.mark.parametrize("fault", ["spawn", "invalid_pid", "changed_sigchld", "registration"])
def test_no_partial_return_printing_state_access_or_diagnostic_retry(
    diagnostics, backend, fault, capsys
):
    if fault == "spawn":
        backend.spawn_error = OSError(errno.EIO, "private spawn detail")
    elif fault == "invalid_pid":
        backend.spawn_result = -1
    elif fault == "changed_sigchld":
        backend.wait_mode, backend.changed_sigchld = "running", True
    else:
        backend.wait_mode = "running"
        backend.registration_error = OSError(errno.EINVAL, "private registration detail")
    with pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"):
        diagnostics.capture_getconf()
    assert len(backend.spawns) == 1 and capsys.readouterr() == ("", "")
    if fault != "registration":
        assert backend.kill_calls == []


def test_interrupted_wait_preserves_owned_pid_without_command_retry(diagnostics, backend):
    backend.wait_errors.append(InterruptedError(errno.EINTR, "interrupted"))
    assert diagnostics.capture_getconf().stdout == b"bounded\n"
    assert len(backend.spawns) == 1 and backend.kill_calls == []


@pytest.mark.parametrize("value", [None, bytearray(), "", 0])
def test_nonbyte_read_cannot_manufacture_eof(diagnostics, backend, monkeypatch, value):
    original = diagnostics.os.read

    def read(fd, size):
        return value if fd in backend.reader else original(fd, size)

    monkeypatch.setattr(diagnostics.os, "read", read)
    with pytest.raises(diagnostics.DiagnosticError):
        diagnostics.capture_getconf()
    assert backend.reaped and backend.kill_calls == []


def test_registration_exit_race_requires_exact_terminal_owned_wait(diagnostics, backend):
    backend.wait_errors.extend([(0, 0), (900001, 0)])
    backend.registration_error = ProcessLookupError(errno.ESRCH, "exit race")
    result = diagnostics.capture_getconf()
    assert result.stdout == b"bounded\n" and backend.waits == [(900001, os.WNOHANG)] * 2
    assert backend.kill_calls == [] and len(backend.spawns) == 1


@pytest.mark.parametrize("kind,per_stream,total", [("getconf", 1024, 2048),
                                                ("ps", 65536, 65536)])
def test_both_stream_reads_share_fixed_combined_budget(diagnostics, backend, kind, per_stream, total):
    backend.stdout, backend.stderr = b"x" * per_stream, b"x" * (per_stream + 1)
    call = diagnostics.capture_getconf if kind == "getconf" else diagnostics.capture_ps
    with pytest.raises(diagnostics.DiagnosticError):
        call()
    assert all(size <= min(8192, per_stream + 1, total - delivered + 1)
               for size, delivered in backend.read_budget_records)
    assert backend.delivered <= total + 1 and len(backend.spawns) == 1


def test_reaper_change_after_terminal_wait_still_refuses_capture(diagnostics, backend):
    backend.changed_sigchld = True
    with pytest.raises(diagnostics.DiagnosticError) as error:
        diagnostics.capture_getconf()
    assert backend.reaped and backend.kill_calls == []
    assert error.value.cleanup_uncertain is False  # Exact reap remains known.
