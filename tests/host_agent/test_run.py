import errno
import os
import shutil
import signal
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from ssh_over_mcp.host_agent.containment import (
    ContainmentBackend,
    ContainmentError,
    ContainmentHandle,
    ContainmentLimits,
    ContainmentRequest,
    ContainmentStats,
)
from ssh_over_mcp.host_agent.containment_manager import (
    ContainmentManagerClient,
    ContainmentManagerDispatcher,
    ContainmentManagerTransport,
)
from ssh_over_mcp.host_agent.containment_manager_identity import (
    LinuxProcessIdentity,
    LinuxProcessIdentityPolicy,
)
from ssh_over_mcp.host_agent.containment_manager_peer import (
    LinuxPeerCredentialPolicy,
)
from ssh_over_mcp.host_agent.containment_manager_unix import (
    UnixContainmentManagerTransport,
    serve_containment_manager_connection,
)
from ssh_over_mcp.host_agent.policy import HostChildLimits, HostObjectIdentity
from ssh_over_mcp.host_agent.prepare import PreparedCommand
from ssh_over_mcp.host_agent.run import (
    BoundedExecutionError,
    _hard_kill_contained,
    _read_output,
    _reap_until,
    _signal_process_group,
    _SignalOutcome,
    _unregister_close,
    run_prepared_native,
)
from ssh_over_mcp.host_agent.supervisor import ChildSupervisorError
from ssh_over_mcp.ssh.protocol import ExecutionLimits

pytestmark = pytest.mark.skipif(
    os.name != "posix"
    or not hasattr(os, "fork")
    or not hasattr(os, "pipe2")
    or os.execve not in os.supports_fd,
    reason="requires Linux/POSIX fork, pipe2, and fd-based execve",
)


def _workload_policy() -> LinuxProcessIdentityPolicy:
    return LinuxProcessIdentityPolicy(
        identity=LinuxProcessIdentity(uid=2103, gid=3103),
        supplementary_gids=frozenset(),
    )


@pytest.fixture(autouse=True)
def _stub_workload_identity_transition(monkeypatch):
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor.transition_to_workload_identity",
        lambda _policy: None,
    )


def _child_limits() -> HostChildLimits:
    return HostChildLimits(
        cpu_seconds=10,
        address_space_bytes=512 * 1024 * 1024,
        max_processes=64,
        file_size_bytes=64 * 1024 * 1024,
        open_files=128,
    )


def _source(*candidates: str) -> Path:
    for candidate in candidates:
        path = Path(candidate)
        if path.exists():
            return path.resolve()
    pytest.skip(f"required native command not found: {candidates}")


def _prepared(
    tmp_path: Path,
    source: Path,
    *,
    argv: tuple[str, ...] = (),
) -> PreparedCommand:
    target = tmp_path / source.name
    shutil.copyfile(source, target)
    target.chmod(0o755)

    cwd = tmp_path / "work"
    cwd.mkdir(exist_ok=True)

    executable_fd = os.open(
        target,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    cwd_fd = os.open(
        cwd,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
    )

    executable_info = os.fstat(executable_fd)
    cwd_info = os.fstat(cwd_fd)

    return PreparedCommand(
        request_id="req_12345678",
        executable_fd=executable_fd,
        cwd_fd=cwd_fd,
        executable_path=str(target),
        executable_identity=HostObjectIdentity(
            device=executable_info.st_dev,
            inode=executable_info.st_ino,
            ctime_ns=executable_info.st_ctime_ns,
            mtime_ns=executable_info.st_mtime_ns,
            size=executable_info.st_size,
        ),
        cwd_path=str(cwd),
        cwd_identity=HostObjectIdentity(
            device=cwd_info.st_dev,
            inode=cwd_info.st_ino,
            ctime_ns=cwd_info.st_ctime_ns,
            mtime_ns=cwd_info.st_mtime_ns,
            size=cwd_info.st_size,
        ),
        executable_format="elf",
        argv=argv,
        env={},
        fd_exec_supported=True,
        child_limits=_child_limits(),
    )


class RunContainmentHandle(ContainmentHandle):
    def __init__(self, *, populated_until_kill: bool = False) -> None:
        self.attached_pid: int | None = None
        self.kill_count = 0
        self.closed = False
        self.populated_until_kill = populated_until_kill

    @property
    def scope_id(self) -> str:
        return "run-test"

    def attach(self, pid: int) -> None:
        self.attached_pid = pid

    def kill_all(self) -> None:
        self.kill_count += 1

    def stats(self) -> ContainmentStats:
        # Unit tests exercise lifecycle/ordering without writable host cgroups.
        # Direct process cleanup remains covered by the process-group fallback.
        return ContainmentStats(
            memory_current_bytes=0,
            pids_current=0,
            cpu_usage_usec=123,
            populated=self.populated_until_kill and self.kill_count == 0,
        )

    def close(self) -> None:
        self.closed = True


class RunContainmentBackend(ContainmentBackend):
    def __init__(self, *, populated_until_kill: bool = False) -> None:
        self.requests: list[ContainmentRequest] = []
        self.handles: list[RunContainmentHandle] = []
        self.populated_until_kill = populated_until_kill

    @property
    def name(self) -> str:
        return "run-test"

    def create(self, request: ContainmentRequest) -> ContainmentHandle:
        self.requests.append(request)
        handle = RunContainmentHandle(
            populated_until_kill=self.populated_until_kill,
        )
        self.handles.append(handle)
        return handle


def _containment(
    prepared: PreparedCommand,
    *,
    populated_until_kill: bool = False,
) -> tuple[RunContainmentBackend, ContainmentRequest]:
    backend = RunContainmentBackend(
        populated_until_kill=populated_until_kill,
    )
    request = ContainmentRequest(
        request_id=prepared.request_id,
        limits=ContainmentLimits(
            memory_max_bytes=512 * 1024 * 1024,
            pids_max=64,
            cpu_quota_us=50_000,
            cpu_period_us=100_000,
        ),
    )
    return backend, request


def _limits(
    *,
    timeout: float = 2.0,
    output: int = 4096,
    stdin: int = 4096,
) -> ExecutionLimits:
    return ExecutionLimits(
        timeout_seconds=timeout,
        max_output_bytes=output,
        max_stdin_bytes=stdin,
    )


def test_bounded_cat_round_trip(tmp_path: Path):
    prepared = _prepared(tmp_path, _source("/bin/cat", "/usr/bin/cat"))
    backend, request = _containment(prepared)
    try:
        result = run_prepared_native(
            prepared,
            b"hello bounded runner\n",
            _limits(),
            workload_identity_policy=_workload_policy(),
            containment_backend=backend,
            containment_request=request,
            term_grace_seconds=0.05,
            kill_cleanup_seconds=0.5,
        )

        assert result.returncode == 0
        assert result.stdout == b"hello bounded runner\n"
        assert result.stderr == b""
        assert result.timed_out is False
        assert result.output_exceeded is False
        assert result.containment_stats.cpu_usage_usec == 123
        assert backend.handles[0].closed is True
    finally:
        prepared.close()


def test_wall_timeout_can_finish_during_grace_period(tmp_path: Path):
    prepared = _prepared(
        tmp_path,
        _source("/bin/sleep", "/usr/bin/sleep"),
        argv=("5",),
    )
    backend, request = _containment(prepared)
    try:
        result = run_prepared_native(
            prepared,
            b"",
            _limits(timeout=0.05),
            workload_identity_policy=_workload_policy(),
            containment_backend=backend,
            containment_request=request,
            term_grace_seconds=0.02,
            kill_cleanup_seconds=0.5,
        )

        assert result.timed_out is True
        assert result.output_exceeded is False
        assert result.returncode < 0
        assert backend.handles[0].kill_count == 0
        assert backend.handles[0].closed is True
        assert result.duration_seconds < 2.0
    finally:
        prepared.close()


def test_output_budget_is_hard_combined_ceiling(tmp_path: Path):
    prepared = _prepared(
        tmp_path,
        _source("/usr/bin/yes", "/bin/yes"),
    )
    backend, request = _containment(prepared)
    try:
        result = run_prepared_native(
            prepared,
            b"",
            _limits(timeout=2.0, output=1024),
            workload_identity_policy=_workload_policy(),
            containment_backend=backend,
            containment_request=request,
            term_grace_seconds=0.02,
            kill_cleanup_seconds=0.5,
        )

        assert result.output_exceeded is True
        assert result.timed_out is False
        assert len(result.stdout) + len(result.stderr) == 1024
        assert result.returncode < 0
    finally:
        prepared.close()


def test_stderr_is_captured(tmp_path: Path):
    prepared = _prepared(
        tmp_path,
        _source("/bin/ls", "/usr/bin/ls"),
        argv=("/definitely-not-present-ssh-over-mcp",),
    )
    backend, request = _containment(prepared)
    try:
        result = run_prepared_native(
            prepared,
            b"",
            _limits(),
            workload_identity_policy=_workload_policy(),
            containment_backend=backend,
            containment_request=request,
            term_grace_seconds=0.05,
            kill_cleanup_seconds=0.5,
        )

        assert result.returncode != 0
        assert result.stdout == b""
        assert result.stderr
        assert result.timed_out is False
        assert result.output_exceeded is False
    finally:
        prepared.close()


def test_oversized_stdin_is_rejected_before_spawn(tmp_path: Path):
    prepared = _prepared(tmp_path, _source("/bin/cat", "/usr/bin/cat"))
    backend, request = _containment(prepared)

    try:
        with pytest.raises(BoundedExecutionError, match="stdin"):
            run_prepared_native(
                prepared,
                b"too large",
                _limits(stdin=1),
                workload_identity_policy=_workload_policy(),
                containment_backend=backend,
                containment_request=request,
            )
        assert backend.requests == []
    finally:
        prepared.close()


def test_combined_budget_helper_counts_across_streams():
    out_read, out_write = os.pipe()
    err_read, err_write = os.pipe()
    try:
        os.write(out_write, b"a" * 700)
        os.write(err_write, b"b" * 700)
        os.close(out_write)
        out_write = -1
        os.close(err_write)
        err_write = -1

        stdout = bytearray()
        stderr = bytearray()

        total, eof, exceeded = _read_output(
            out_read,
            stdout,
            total=0,
            limit=1000,
        )
        assert eof is False
        assert exceeded is False
        assert total == 700

        total, eof, exceeded = _read_output(
            err_read,
            stderr,
            total=total,
            limit=1000,
        )
        assert eof is False
        assert exceeded is True
        assert total == 1000
        assert len(stdout) + len(stderr) == 1000
    finally:
        for fd in (out_read, out_write, err_read, err_write):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def test_signal_group_falls_back_to_pid_before_setsid(monkeypatch):
    calls: list[tuple[str, int, int]] = []

    def fake_killpg(pid: int, sig: int):
        calls.append(("killpg", pid, sig))
        raise ProcessLookupError()

    def fake_kill(pid: int, sig: int):
        calls.append(("kill", pid, sig))

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.os.killpg",
        fake_killpg,
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.os.kill",
        fake_kill,
    )

    outcome = _signal_process_group(1234, signal.SIGTERM)

    assert outcome is _SignalOutcome.DELIVERED
    assert calls == [
        ("killpg", 1234, signal.SIGTERM),
        ("kill", 1234, signal.SIGTERM),
    ]


@pytest.mark.parametrize("group_errno", [errno.ESRCH, errno.EPERM, errno.EINVAL])
def test_signal_group_falls_back_to_pid_for_expected_group_errno(
    monkeypatch,
    group_errno: int,
):
    calls: list[tuple[str, int, int]] = []

    def fake_killpg(pid: int, sig: int):
        calls.append(("killpg", pid, sig))
        raise OSError(group_errno, "group unavailable")

    def fake_kill(pid: int, sig: int):
        calls.append(("kill", pid, sig))

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.os.killpg",
        fake_killpg,
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.os.kill",
        fake_kill,
    )

    outcome = _signal_process_group(1234, signal.SIGTERM)

    assert outcome is _SignalOutcome.DELIVERED
    assert calls == [
        ("killpg", 1234, signal.SIGTERM),
        ("kill", 1234, signal.SIGTERM),
    ]


def test_signal_group_reports_permission_denied_only_after_pid_fallback(
    monkeypatch,
):
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.os.killpg",
        lambda _pid, _sig: (_ for _ in ()).throw(
            PermissionError(errno.EPERM, "group denied")
        ),
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.os.kill",
        lambda _pid, _sig: (_ for _ in ()).throw(
            PermissionError(errno.EPERM, "pid denied")
        ),
    )

    assert (
        _signal_process_group(1234, signal.SIGTERM)
        is _SignalOutcome.PERMISSION_DENIED
    )


def test_signal_group_reports_process_gone_without_inferring_scope_empty(
    monkeypatch,
):
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.os.killpg",
        lambda _pid, _sig: (_ for _ in ()).throw(ProcessLookupError()),
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.os.kill",
        lambda _pid, _sig: (_ for _ in ()).throw(ProcessLookupError()),
    )

    assert (
        _signal_process_group(1234, signal.SIGTERM)
        is _SignalOutcome.PROCESS_GONE
    )


def test_signal_group_rejects_unexpected_direct_signal_error(monkeypatch):
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.os.killpg",
        lambda _pid, _sig: (_ for _ in ()).throw(ProcessLookupError()),
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.os.kill",
        lambda _pid, _sig: (_ for _ in ()).throw(
            OSError(errno.EACCES, "unexpected")
        ),
    )

    with pytest.raises(BoundedExecutionError, match="signal supervised"):
        _signal_process_group(1234, signal.SIGTERM)


def test_runner_requires_explicit_workload_identity_policy():
    with pytest.raises(TypeError, match="workload_identity_policy"):
        run_prepared_native(
            object(),
            b"",
            _limits(),
            containment_backend=object(),
            containment_request=object(),
        )


def test_runner_propagates_exact_workload_identity_policy(monkeypatch):
    policy = _workload_policy()
    observed = {}

    def stop_spawn(
        _prepared,
        _backend,
        _request,
        *,
        workload_identity_policy,
    ):
        observed["policy"] = workload_identity_policy
        raise ChildSupervisorError("stop after propagation")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.spawn_prepared_native_contained",
        stop_spawn,
    )

    with pytest.raises(BoundedExecutionError, match="spawn supervised"):
        run_prepared_native(
            object(),
            b"",
            _limits(),
            workload_identity_policy=policy,
            containment_backend=object(),
            containment_request=object(),
        )

    assert observed["policy"] is policy


def test_runner_passes_manager_client_through_contained_spawn(
    monkeypatch,
):
    observed = {}

    class NoopTransport(ContainmentManagerTransport):
        def round_trip(self, _frame: bytes) -> bytes:
            raise AssertionError("manager protocol should not run in this test")

        def close(self) -> None:
            return

    client = ContainmentManagerClient(NoopTransport())

    def stop_spawn(
        _prepared,
        backend,
        _request,
        *,
        workload_identity_policy,
    ):
        observed["backend"] = backend
        observed["policy"] = workload_identity_policy
        raise ChildSupervisorError("stop after manager backend propagation")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.spawn_prepared_native_contained",
        stop_spawn,
    )

    policy = _workload_policy()
    try:
        with pytest.raises(BoundedExecutionError, match="spawn supervised"):
            run_prepared_native(
                object(),
                b"",
                _limits(),
                workload_identity_policy=policy,
                containment_backend=client,
                containment_request=object(),
            )
    finally:
        client.close()

    assert observed["backend"] is client
    assert observed["policy"] is policy


def test_bounded_runner_uses_authenticated_manager_client_end_to_end(
    tmp_path: Path,
):
    if not hasattr(socket, "SO_PEERCRED"):
        pytest.skip("requires Linux SO_PEERCRED")

    prepared = _prepared(tmp_path, _source("/bin/cat", "/usr/bin/cat"))
    backend, request = _containment(prepared)
    client_sock, server_sock = socket.socketpair(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )
    events_read, events_write = os.pipe()
    peer_policy = LinuxPeerCredentialPolicy(
        expected_uid=os.getuid(),
        expected_gid=os.getgid(),
    )
    dispatcher = ContainmentManagerDispatcher(
        backend,
        capability_factory=lambda: "A" * 43,
    )

    manager_pid = os.fork()
    if manager_pid == 0:
        try:
            client_sock.close()
            os.close(events_read)
            serve_containment_manager_connection(
                server_sock,
                dispatcher,
                peer_policy=peer_policy,
            )
            handle = backend.handles[0]
            events = (
                f"{len(backend.requests)}:"
                f"{int(handle.attached_pid is not None)}:"
                f"{int(handle.closed)}"
            ).encode("ascii")
            os.write(events_write, events)
        finally:
            os._exit(0)

    server_sock.close()
    os.close(events_write)
    transport = UnixContainmentManagerTransport(
        client_sock,
        peer_policy=peer_policy,
        timeout_seconds=1.0,
    )
    client = ContainmentManagerClient(transport)

    try:
        result = run_prepared_native(
            prepared,
            b"manager-backed runner\n",
            _limits(),
            workload_identity_policy=_workload_policy(),
            containment_backend=client,
            containment_request=request,
            term_grace_seconds=0.05,
            kill_cleanup_seconds=0.5,
        )

        assert result.returncode == 0
        assert result.stdout == b"manager-backed runner\n"
        assert result.stderr == b""
    finally:
        prepared.close()
        client.close()

    events = os.read(events_read, 64)
    os.close(events_read)
    _, manager_status = os.waitpid(manager_pid, 0)

    assert events == b"1:1:1"
    assert os.WIFEXITED(manager_status)
    assert os.WEXITSTATUS(manager_status) == 0


def test_reap_until_is_bounded(monkeypatch):
    class NeverReaps:
        def poll(self):
            return None

    monotonic_values = iter([0.0, 1.0])
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.time.monotonic",
        lambda: next(monotonic_values),
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.time.sleep",
        lambda _seconds: None,
    )

    assert _reap_until(NeverReaps(), 0.5) is None


def test_normal_child_exit_kills_lingering_containment(tmp_path: Path):
    prepared = _prepared(
        tmp_path,
        _source("/bin/true", "/usr/bin/true"),
    )
    backend, request = _containment(
        prepared,
        populated_until_kill=True,
    )

    try:
        result = run_prepared_native(
            prepared,
            b"",
            _limits(),
            workload_identity_policy=_workload_policy(),
            containment_backend=backend,
            containment_request=request,
            term_grace_seconds=0.05,
            kill_cleanup_seconds=0.5,
        )

        assert result.returncode == 0
        assert result.timed_out is False
        assert result.output_exceeded is False
        assert backend.handles[0].kill_count == 1
        assert backend.handles[0].closed is True
        assert result.containment_stats.populated is False
    finally:
        prepared.close()


def test_successful_containment_kill_does_not_depend_on_process_group(
    monkeypatch,
):
    handle = RunContainmentHandle()

    class Child:
        pid = 1234
        containment = handle

    def deny_process_group(_pid: int, _sig: int):
        return _SignalOutcome.PERMISSION_DENIED

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run._signal_process_group",
        deny_process_group,
    )

    _hard_kill_contained(Child())

    assert handle.kill_count == 1


def test_wall_timeout_permission_denial_skips_term_grace(
    tmp_path: Path,
    monkeypatch,
):
    prepared = _prepared(
        tmp_path,
        _source("/bin/sh", "/usr/bin/dash"),
        argv=("-c", "trap '' TERM; while :; do :; done"),
    )
    backend, request = _containment(prepared)
    original_signal = _signal_process_group

    def deny_term(pid: int, sig: int):
        if sig == signal.SIGTERM:
            return _SignalOutcome.PERMISSION_DENIED
        return original_signal(pid, sig)

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run._signal_process_group",
        deny_term,
    )

    try:
        result = run_prepared_native(
            prepared,
            b"",
            _limits(timeout=0.05),
            workload_identity_policy=_workload_policy(),
            containment_backend=backend,
            containment_request=request,
            term_grace_seconds=1.0,
            kill_cleanup_seconds=0.5,
        )

        assert result.timed_out is True
        assert result.output_exceeded is False
        assert backend.handles[0].kill_count >= 1
        assert backend.handles[0].closed is True
        assert result.duration_seconds < 0.75
    finally:
        prepared.close()


def test_output_limit_permission_denial_skips_term_grace(
    tmp_path: Path,
    monkeypatch,
):
    prepared = _prepared(
        tmp_path,
        _source("/usr/bin/yes", "/bin/yes"),
    )
    backend, request = _containment(prepared)
    original_signal = _signal_process_group

    def deny_term(pid: int, sig: int):
        if sig == signal.SIGTERM:
            return _SignalOutcome.PERMISSION_DENIED
        return original_signal(pid, sig)

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run._signal_process_group",
        deny_term,
    )

    try:
        result = run_prepared_native(
            prepared,
            b"",
            _limits(timeout=2.0, output=1024),
            workload_identity_policy=_workload_policy(),
            containment_backend=backend,
            containment_request=request,
            term_grace_seconds=1.0,
            kill_cleanup_seconds=0.5,
        )

        assert result.output_exceeded is True
        assert result.timed_out is False
        assert len(result.stdout) + len(result.stderr) == 1024
        assert backend.handles[0].kill_count >= 1
        assert backend.handles[0].closed is True
        assert result.duration_seconds < 0.75
    finally:
        prepared.close()


def test_containment_kill_failure_remains_fatal(monkeypatch):
    class FailingHandle(RunContainmentHandle):
        def kill_all(self) -> None:
            raise ContainmentError("kill failed")

    handle = FailingHandle()

    class Child:
        pid = 1234
        containment = handle

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run._signal_process_group",
        lambda _pid, _sig: _SignalOutcome.PERMISSION_DENIED,
    )

    with pytest.raises(BoundedExecutionError, match="containment scope"):
        _hard_kill_contained(Child())


def test_wall_timeout_escalates_to_containment_kill_when_term_is_ignored(
    tmp_path: Path,
):
    prepared = _prepared(
        tmp_path,
        _source("/bin/sh", "/usr/bin/dash"),
        # Use shell builtins only: RLIMIT_NPROC is enforced per real UID on Linux,
        # so spawning an external sleep can fail under a busy shared runner before
        # the timeout path is exercised.
        argv=("-c", "trap '' TERM; while :; do :; done"),
    )
    backend, request = _containment(prepared)

    try:
        result = run_prepared_native(
            prepared,
            b"",
            _limits(timeout=0.05),
            workload_identity_policy=_workload_policy(),
            containment_backend=backend,
            containment_request=request,
            term_grace_seconds=0.02,
            kill_cleanup_seconds=0.5,
        )

        assert result.timed_out is True
        assert result.output_exceeded is False
        assert result.returncode < 0
        assert backend.handles[0].kill_count >= 1
        assert backend.handles[0].closed is True
        assert result.duration_seconds < 2.0
    finally:
        prepared.close()


def test_unregister_close_still_closes_fd_when_selector_unregister_raises(
    monkeypatch,
):
    class BrokenSelector:
        def unregister(self, _fd):
            raise RuntimeError("foreign selector failure")

    child = SimpleNamespace(stdin_fd=41)
    closed: list[int] = []
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.os.close",
        lambda fd: closed.append(fd),
    )

    _unregister_close(BrokenSelector(), child, "stdin_fd")

    assert closed == [41]
    assert child.stdin_fd == -1


@pytest.mark.parametrize("failing_cleanup", ["kill", "reap", "close"])
def test_unexpected_cleanup_failure_is_normalized_and_other_cleanup_continues(
    monkeypatch,
    failing_cleanup: str,
):
    class CleanupChild:
        pid = 1234
        stdin_fd = 10
        stdout_fd = 11
        stderr_fd = 12
        containment = object()

        def close_stdin(self):
            self.stdin_fd = -1

        def close_pipes(self):
            self.stdout_fd = -1
            self.stderr_fd = -1

    child = CleanupChild()
    cleanup_calls: list[str] = []

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.spawn_prepared_native_contained",
        lambda *_args, **_kwargs: child,
    )

    def fail_primary(_fd, _blocking):
        raise RuntimeError("primary supervision failure")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.os.set_blocking",
        fail_primary,
    )

    def hard_kill(_child):
        cleanup_calls.append("kill")
        if failing_cleanup == "kill":
            raise RuntimeError("secret kill cleanup failure")

    def reap(_child, _deadline):
        cleanup_calls.append("reap")
        if failing_cleanup == "reap":
            raise RuntimeError("secret reap cleanup failure")
        return 0

    def close_containment(_child, _deadline):
        cleanup_calls.append("close")
        if failing_cleanup == "close":
            raise RuntimeError("secret containment cleanup failure")
        return ContainmentStats(populated=False)

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run._hard_kill_contained",
        hard_kill,
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run._reap_until",
        reap,
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run._close_containment_bounded",
        close_containment,
    )

    with pytest.raises(
        BoundedExecutionError,
        match="bounded contained-child cleanup failed",
    ):
        run_prepared_native(
            object(),
            b"",
            _limits(),
            workload_identity_policy=_workload_policy(),
            containment_backend=object(),
            containment_request=object(),
        )

    assert cleanup_calls == ["kill", "reap", "close"]
