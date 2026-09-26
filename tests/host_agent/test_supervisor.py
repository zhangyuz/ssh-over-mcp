import os
import shutil
import time
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.policy import HostObjectIdentity
from ssh_over_mcp.host_agent.prepare import PreparedCommand
from ssh_over_mcp.host_agent.supervisor import (
    ChildSupervisorError,
    _close_unrelated_fds,
    spawn_prepared_native,
)

pytestmark = pytest.mark.skipif(
    os.name != "posix"
    or not hasattr(os, "fork")
    or not hasattr(os, "pipe2")
    or os.execve not in os.supports_fd,
    reason="requires Linux/POSIX fork, pipe2, and fd-based execve",
)


def _copy_native(tmp_path: Path, source: str) -> Path:
    path = Path(source)
    if not path.exists():
        pytest.skip(f"{source} is required for supervisor tests")

    target = tmp_path / path.name
    shutil.copyfile(path.resolve(), target)
    target.chmod(0o755)
    return target


def _identity(fd: int) -> HostObjectIdentity:
    info = os.fstat(fd)
    return HostObjectIdentity(
        device=info.st_dev,
        inode=info.st_ino,
        ctime_ns=info.st_ctime_ns,
    )


def _prepared(
    tmp_path: Path,
    source: str = "/bin/cat",
    *,
    argv: tuple[str, ...] = (),
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
    )


def _read_all(fd: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def test_spawned_child_wires_stdin_stdout_and_exit(tmp_path: Path):
    prepared = _prepared(tmp_path)
    child = spawn_prepared_native(prepared)
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
            spawn_prepared_native(prepared)
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

    child = spawn_prepared_native(prepared)
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
    child = spawn_prepared_native(prepared)
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
