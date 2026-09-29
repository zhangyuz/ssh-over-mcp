import os
import resource
import shutil
import time
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.containment import (
    ContainmentBackend,
    ContainmentError,
    ContainmentHandle,
    ContainmentLimits,
    ContainmentRequest,
    ContainmentStats,
)
from ssh_over_mcp.host_agent.containment_manager_identity import (
    LinuxProcessIdentity,
    LinuxProcessIdentityPolicy,
)
from ssh_over_mcp.host_agent.file_identity import sha256_fd
from ssh_over_mcp.host_agent.policy import HostChildLimits, HostObjectIdentity
from ssh_over_mcp.host_agent.prepare import PreparedCommand
from ssh_over_mcp.host_agent.supervisor import (
    ChildSupervisorError,
    SpawnedChild,
    _apply_child_rlimits,
    _close_unrelated_fds,
    _contained_child_entry,
    _require_standard_fds,
    _set_bounded_rlimit,
    spawn_prepared_native,
    spawn_prepared_native_contained,
)

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


def _copy_native(tmp_path: Path, source: str) -> Path:
    path = Path(source)
    if not path.exists():
        pytest.skip(f"{source} is required for supervisor tests")

    target = tmp_path / path.name
    shutil.copyfile(path.resolve(), target)
    target.chmod(0o755)
    return target


def _identity(fd: int, *, bind_content: bool = False) -> HostObjectIdentity:
    info = os.fstat(fd)
    return HostObjectIdentity(
        device=info.st_dev,
        inode=info.st_ino,
        ctime_ns=info.st_ctime_ns,
        mtime_ns=info.st_mtime_ns,
        size=info.st_size,
        content_sha256=(
            sha256_fd(fd, expected_size=info.st_size)
            if bind_content
            else None
        ),
    )


def _prepared(
    tmp_path: Path,
    source: str = "/bin/cat",
    *,
    argv: tuple[str, ...] = (),
    child_limits: HostChildLimits | None = None,
) -> PreparedCommand:
    executable = _copy_native(tmp_path, source)
    cwd = tmp_path / "work"
    cwd.mkdir(exist_ok=True)

    executable_fd = os.open(
        executable,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    cwd_fd = os.open(
        cwd,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
    )

    return PreparedCommand(
        request_id="req_12345678",
        executable_fd=executable_fd,
        cwd_fd=cwd_fd,
        executable_path=str(executable),
        executable_identity=_identity(executable_fd),
        cwd_path=str(cwd),
        cwd_identity=_identity(cwd_fd),
        executable_format="elf",
        argv=argv,
        env={},
        fd_exec_supported=True,
        child_limits=child_limits or _child_limits(),
    )


def _read_all(fd: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def test_spawn_requires_explicit_workload_identity_policy(tmp_path: Path):
    prepared = _prepared(tmp_path)
    try:
        with pytest.raises(TypeError, match="workload_identity_policy"):
            spawn_prepared_native(prepared)
    finally:
        prepared.close()


def test_spawned_child_wires_stdin_stdout_and_exit(tmp_path: Path):
    prepared = _prepared(tmp_path)
    child = spawn_prepared_native(
        prepared,
        workload_identity_policy=_workload_policy(),
    )
    prepared.close()

    try:
        os.write(child.stdin_fd, b"hello supervisor\n")
        child.close_stdin()

        stdout = _read_all(child.stdout_fd)
        stderr = _read_all(child.stderr_fd)
        returncode = child.wait()

        assert stdout == b"hello supervisor\n"
        assert stderr == b""
        assert returncode == 0
    finally:
        child.close_pipes()


def test_invalid_exec_spec_is_rejected_before_fork(tmp_path: Path):
    prepared = _prepared(tmp_path)
    prepared.executable_format = "script"

    try:
        with pytest.raises(ChildSupervisorError, match="cannot enter"):
            spawn_prepared_native(
                prepared,
                workload_identity_policy=_workload_policy(),
            )
    finally:
        prepared.close()


def test_child_exec_failure_is_generic_and_exit_125(
    tmp_path: Path,
    monkeypatch,
):
    prepared = _prepared(tmp_path)

    def fail_exec(_prepared):
        raise RuntimeError("sensitive internal failure")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor.exec_prepared_native_in_child",
        fail_exec,
    )

    child = spawn_prepared_native(
        prepared,
        workload_identity_policy=_workload_policy(),
    )
    prepared.close()

    try:
        child.close_stdin()
        stdout = _read_all(child.stdout_fd)
        stderr = _read_all(child.stderr_fd)
        returncode = child.wait()

        assert stdout == b""
        assert stderr == b"ssh-over-mcp-host-agent: child exec failed\n"
        assert returncode == 125
        assert b"sensitive" not in stderr
    finally:
        child.close_pipes()


def test_close_unrelated_fds_closes_inheritable_descriptor():
    leak_read, leak_write = os.pipe()
    result_read, result_write = os.pipe()
    os.set_inheritable(leak_read, True)

    pid = os.fork()
    if pid == 0:
        try:
            os.close(result_read)
            _close_unrelated_fds({result_write})

            try:
                os.fstat(leak_read)
            except OSError:
                os.write(result_write, b"closed")
            else:
                os.write(result_write, b"open")
        finally:
            os._exit(0)

    os.close(result_write)
    try:
        result = _read_all(result_read)
        _, status = os.waitpid(pid, 0)

        assert result == b"closed"
        assert os.WIFEXITED(status)
        assert os.WEXITSTATUS(status) == 0
    finally:
        os.close(result_read)
        os.close(leak_read)
        os.close(leak_write)


def test_spawned_child_creates_own_session(tmp_path: Path):
    prepared = _prepared(tmp_path)
    child = spawn_prepared_native(
        prepared,
        workload_identity_policy=_workload_policy(),
    )
    prepared.close()

    try:
        # cat stays alive while stdin remains open. setsid() should make the
        # child both a session leader and process-group leader.
        for _ in range(100):
            try:
                if os.getsid(child.pid) == child.pid:
                    break
            except ProcessLookupError:
                break
            time.sleep(0.001)
        else:
            pytest.fail("child did not enter its own session")

        assert os.getsid(child.pid) == child.pid
        assert os.getpgid(child.pid) == child.pid

        child.close_stdin()
        _read_all(child.stdout_fd)
        _read_all(child.stderr_fd)
        assert child.wait() == 0
    finally:
        child.close_pipes()


def test_wait_retries_interrupted_waitpid(monkeypatch):
    calls = 0

    def fake_waitpid(pid: int, options: int):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise InterruptedError()
        return pid, 7 << 8

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor.os.waitpid",
        fake_waitpid,
    )

    child = SpawnedChild(
        pid=12345,
        stdin_fd=-1,
        stdout_fd=-1,
        stderr_fd=-1,
    )

    assert child.wait() == 7
    assert child.wait() == 7
    assert calls == 2


def test_missing_standard_fd_fails_closed(monkeypatch):
    real_fstat = os.fstat

    def fake_fstat(fd: int):
        if fd == 1:
            raise OSError("closed")
        return real_fstat(fd)

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor.os.fstat",
        fake_fstat,
    )

    with pytest.raises(ChildSupervisorError, match="standard"):
        _require_standard_fds()


def test_rlimit_clamps_to_inherited_hard_limit(monkeypatch):
    calls: list[tuple[int, tuple[int, int]]] = []

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor.resource.getrlimit",
        lambda _resource_id: (50, 50),
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor.resource.setrlimit",
        lambda resource_id, value: calls.append((resource_id, value)),
    )

    _set_bounded_rlimit(resource.RLIMIT_NOFILE, 128)

    assert calls == [(resource.RLIMIT_NOFILE, (50, 50))]


def test_apply_child_rlimits_uses_host_policy_values(monkeypatch):
    calls: list[tuple[int, tuple[int, int]]] = []

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor.resource.getrlimit",
        lambda _resource_id: (
            resource.RLIM_INFINITY,
            resource.RLIM_INFINITY,
        ),
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor.resource.setrlimit",
        lambda resource_id, value: calls.append((resource_id, value)),
    )

    limits = _child_limits()
    _apply_child_rlimits(limits)

    assert set(calls) == {
        (resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds)),
        (
            resource.RLIMIT_AS,
            (limits.address_space_bytes, limits.address_space_bytes),
        ),
        (
            resource.RLIMIT_NPROC,
            (limits.max_processes, limits.max_processes),
        ),
        (
            resource.RLIMIT_FSIZE,
            (limits.file_size_bytes, limits.file_size_bytes),
        ),
        (
            resource.RLIMIT_NOFILE,
            (limits.open_files, limits.open_files),
        ),
    }


def test_child_rlimit_failure_is_generic_exit_125(
    tmp_path: Path,
    monkeypatch,
):
    prepared = _prepared(tmp_path)

    def fail_limits(_limits):
        raise ChildSupervisorError("sensitive rlimit detail")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor._apply_child_rlimits",
        fail_limits,
    )

    child = spawn_prepared_native(
        prepared,
        workload_identity_policy=_workload_policy(),
    )
    prepared.close()

    try:
        child.close_stdin()
        stdout = _read_all(child.stdout_fd)
        stderr = _read_all(child.stderr_fd)
        returncode = child.wait()

        assert stdout == b""
        assert stderr == b"ssh-over-mcp-host-agent: child exec failed\n"
        assert returncode == 125
        assert b"sensitive" not in stderr
    finally:
        child.close_pipes()


def test_file_size_rlimit_is_enforced_in_real_child(tmp_path: Path):
    source = "/usr/bin/dd" if Path("/usr/bin/dd").exists() else "/bin/dd"
    if not Path(source).exists():
        pytest.skip("dd is required for RLIMIT_FSIZE integration test")

    limits = _child_limits().model_copy(
        update={"file_size_bytes": 1024}
    )
    prepared = _prepared(
        tmp_path,
        source=source,
        argv=(
            "if=/dev/zero",
            "of=too-large.bin",
            "bs=4096",
            "count=1",
            "status=none",
        ),
        child_limits=limits,
    )
    output_path = Path(prepared.cwd_path) / "too-large.bin"
    child = spawn_prepared_native(
        prepared,
        workload_identity_policy=_workload_policy(),
    )
    prepared.close()

    try:
        child.close_stdin()
        _read_all(child.stdout_fd)
        _read_all(child.stderr_fd)
        returncode = child.wait()

        assert returncode != 0
        assert output_path.exists()
        assert output_path.stat().st_size <= limits.file_size_bytes
    finally:
        child.close_pipes()


class BarrierHandle(ContainmentHandle):
    def __init__(
        self,
        marker: Path,
        *,
        fail_attach: bool = False,
    ) -> None:
        self.marker = marker
        self.fail_attach = fail_attach
        self.attached_pid: int | None = None
        self.marker_seen_during_attach: bool | None = None
        self.killed = False
        self.closed = False

    @property
    def scope_id(self) -> str:
        return "barrier-test"

    def attach(self, pid: int) -> None:
        self.marker_seen_during_attach = self.marker.exists()
        time.sleep(0.02)
        if self.fail_attach:
            raise ContainmentError("attach failed")
        self.attached_pid = pid

    def kill_all(self) -> None:
        self.killed = True

    def stats(self) -> ContainmentStats:
        return ContainmentStats(populated=False)

    def close(self) -> None:
        self.closed = True


class BarrierBackend(ContainmentBackend):
    def __init__(
        self,
        marker: Path,
        *,
        fail_attach: bool = False,
    ) -> None:
        self.handle = BarrierHandle(
            marker,
            fail_attach=fail_attach,
        )
        self.requests: list[ContainmentRequest] = []

    @property
    def name(self) -> str:
        return "barrier-test"

    def create(self, request: ContainmentRequest) -> ContainmentHandle:
        self.requests.append(request)
        return self.handle


def _containment_request(
    request_id: str = "req_12345678",
) -> ContainmentRequest:
    return ContainmentRequest(
        request_id=request_id,
        limits=ContainmentLimits(
            memory_max_bytes=512 * 1024 * 1024,
            pids_max=64,
            cpu_quota_us=50_000,
            cpu_period_us=100_000,
        ),
    )


def test_contained_spawn_requires_explicit_workload_identity_policy(
    tmp_path: Path,
):
    prepared = _prepared(tmp_path)
    backend = BarrierBackend(tmp_path / "unused")
    try:
        with pytest.raises(TypeError, match="workload_identity_policy"):
            spawn_prepared_native_contained(
                prepared,
                backend,
                _containment_request(prepared.request_id),
            )
    finally:
        prepared.close()


def test_contained_child_orders_attach_rlimits_identity_then_exec(
    tmp_path: Path,
    monkeypatch,
):
    prepared = _prepared(tmp_path)
    policy = _workload_policy()
    marker = tmp_path / "ordering.log"
    backend = BarrierBackend(tmp_path / "unused")

    def append(event: str) -> None:
        with marker.open("a", encoding="ascii") as stream:
            stream.write(event + "\n")

    original_attach = backend.handle.attach

    def attach(pid: int) -> None:
        original_attach(pid)
        append("attach")

    backend.handle.attach = attach
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor._apply_child_rlimits",
        lambda _limits: append("rlimits"),
    )

    def transition(observed_policy):
        assert observed_policy is policy
        append("transition")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor.transition_to_workload_identity",
        transition,
    )

    def fake_exec(_prepared):
        append("exec")
        os._exit(0)

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor.exec_prepared_native_in_child",
        fake_exec,
    )

    child = spawn_prepared_native_contained(
        prepared,
        backend,
        _containment_request(prepared.request_id),
        workload_identity_policy=policy,
    )
    prepared.close()

    try:
        assert child.wait() == 0
        assert marker.read_text(encoding="ascii").splitlines() == [
            "attach",
            "rlimits",
            "transition",
            "exec",
        ]
        child.close_containment()
    finally:
        child.close_pipes()


def test_identity_transition_failure_never_reaches_exec(
    tmp_path: Path,
    monkeypatch,
):
    prepared = _prepared(tmp_path)
    marker = tmp_path / "exec-ran"
    backend = BarrierBackend(tmp_path / "unused")

    def fail_transition(_policy):
        raise RuntimeError("sensitive identity transition failure")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor.transition_to_workload_identity",
        fail_transition,
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor.exec_prepared_native_in_child",
        lambda _prepared: marker.write_text("ran", encoding="ascii"),
    )

    child = spawn_prepared_native_contained(
        prepared,
        backend,
        _containment_request(prepared.request_id),
        workload_identity_policy=_workload_policy(),
    )
    prepared.close()

    try:
        child.close_stdin()
        stderr = _read_all(child.stderr_fd)
        assert child.wait() == 125
        assert stderr == b"ssh-over-mcp-host-agent: child exec failed\n"
        assert marker.exists() is False
        child.close_containment()
    finally:
        child.close_pipes()


def test_contained_child_does_not_exec_before_attach(
    tmp_path: Path,
    monkeypatch,
):
    prepared = _prepared(tmp_path)
    marker = tmp_path / "child-started"
    backend = BarrierBackend(marker)

    def fake_child_main(*_args, **_kwargs):
        marker.write_text("started", encoding="ascii")
        os._exit(0)

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor._child_main",
        fake_child_main,
    )

    child = spawn_prepared_native_contained(
        prepared,
        backend,
        _containment_request(prepared.request_id),
        workload_identity_policy=_workload_policy(),
    )
    prepared.close()

    try:
        assert backend.handle.marker_seen_during_attach is False
        assert backend.handle.attached_pid == child.pid
        assert child.wait() == 0
        assert marker.read_text(encoding="ascii") == "started"
        child.close_containment()
        assert backend.handle.closed is True
    finally:
        child.close_pipes()


def test_containment_attach_failure_never_releases_child(
    tmp_path: Path,
    monkeypatch,
):
    prepared = _prepared(tmp_path)
    marker = tmp_path / "child-started"
    backend = BarrierBackend(marker, fail_attach=True)

    def fake_child_main(*_args, **_kwargs):
        marker.write_text("started", encoding="ascii")
        os._exit(0)

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor._child_main",
        fake_child_main,
    )

    try:
        with pytest.raises(
            ChildSupervisorError,
            match="cannot attach contained child",
        ):
            spawn_prepared_native_contained(
                prepared,
                backend,
                _containment_request(prepared.request_id),
                workload_identity_policy=_workload_policy(),
            )

        assert marker.exists() is False
        assert backend.handle.killed is True
        assert backend.handle.closed is True
    finally:
        prepared.close()


def test_containment_request_id_mismatch_is_rejected_before_create(
    tmp_path: Path,
):
    prepared = _prepared(tmp_path)
    backend = BarrierBackend(tmp_path / "unused")

    try:
        with pytest.raises(
            ChildSupervisorError,
            match="request id",
        ):
            spawn_prepared_native_contained(
                prepared,
                backend,
                _containment_request("req_different"),
                workload_identity_policy=_workload_policy(),
            )

        assert backend.requests == []
    finally:
        prepared.close()


def test_child_exec_base_exception_is_generic_and_exit_125(
    tmp_path: Path,
    monkeypatch,
):
    prepared = _prepared(tmp_path)

    def fail_exec(_prepared):
        raise KeyboardInterrupt

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor.exec_prepared_native_in_child",
        fail_exec,
    )

    child = spawn_prepared_native(
        prepared,
        workload_identity_policy=_workload_policy(),
    )
    prepared.close()

    try:
        child.close_stdin()
        stderr = _read_all(child.stderr_fd)
        returncode = child.wait()

        assert stderr == b"ssh-over-mcp-host-agent: child exec failed\n"
        assert returncode == 125
    finally:
        child.close_pipes()


def test_contained_child_barrier_base_exception_exits_125(monkeypatch):
    def interrupt_barrier(_fd):
        raise KeyboardInterrupt

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.supervisor._wait_start_barrier",
        interrupt_barrier,
    )

    barrier_read, barrier_write = os.pipe2(os.O_CLOEXEC)
    stdin_read, stdin_write = os.pipe2(os.O_CLOEXEC)
    stdout_read, stdout_write = os.pipe2(os.O_CLOEXEC)
    stderr_read, stderr_write = os.pipe2(os.O_CLOEXEC)
    fds = (
        barrier_read,
        barrier_write,
        stdin_read,
        stdin_write,
        stdout_read,
        stdout_write,
        stderr_read,
        stderr_write,
    )

    pid = os.fork()
    if pid == 0:
        _contained_child_entry(
            object(),
            workload_identity_policy=_workload_policy(),
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

    try:
        _, status = os.waitpid(pid, 0)
        assert os.WIFEXITED(status)
        assert os.WEXITSTATUS(status) == 125
    finally:
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass
