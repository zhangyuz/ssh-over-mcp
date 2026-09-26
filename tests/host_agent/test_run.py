import os
import signal
import shutil
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.policy import HostObjectIdentity
from ssh_over_mcp.host_agent.prepare import PreparedCommand
from ssh_over_mcp.host_agent.run import (
    BoundedExecutionError,
    _read_output,
    _signal_process_group,
    run_prepared_native,
)
from ssh_over_mcp.ssh.protocol import ExecutionLimits

pytestmark = pytest.mark.skipif(
    os.name != "posix"
    or not hasattr(os, "fork")
    or not hasattr(os, "pipe2")
    or os.execve not in os.supports_fd,
    reason="requires Linux/POSIX fork, pipe2, and fd-based execve",
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
        ),
        cwd_path=str(cwd),
        cwd_identity=HostObjectIdentity(
            device=cwd_info.st_dev,
            inode=cwd_info.st_ino,
            ctime_ns=cwd_info.st_ctime_ns,
        ),
        executable_format="elf",
        argv=argv,
        env={},
        fd_exec_supported=True,
    )


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
    try:
        result = run_prepared_native(
            prepared,
            b"hello bounded runner\n",
            _limits(),
            term_grace_seconds=0.05,
            kill_cleanup_seconds=0.5,
        )

        assert result.returncode == 0
        assert result.stdout == b"hello bounded runner\n"
        assert result.stderr == b""
        assert result.timed_out is False
        assert result.output_exceeded is False
    finally:
        prepared.close()


def test_wall_timeout_terminates_process_group(tmp_path: Path):
    prepared = _prepared(
        tmp_path,
        _source("/bin/sleep", "/usr/bin/sleep"),
        argv=("5",),
    )
    try:
        result = run_prepared_native(
            prepared,
            b"",
            _limits(timeout=0.05),
            term_grace_seconds=0.02,
            kill_cleanup_seconds=0.5,
        )

        assert result.timed_out is True
        assert result.output_exceeded is False
        assert result.returncode < 0
        assert result.duration_seconds < 2.0
    finally:
        prepared.close()


def test_output_budget_is_hard_combined_ceiling(tmp_path: Path):
    prepared = _prepared(
        tmp_path,
        _source("/usr/bin/yes", "/bin/yes"),
    )
    try:
        result = run_prepared_native(
            prepared,
            b"",
            _limits(timeout=2.0, output=1024),
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
    try:
        result = run_prepared_native(
            prepared,
            b"",
            _limits(),
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


def test_oversized_stdin_is_rejected_before_spawn(
    tmp_path: Path,
    monkeypatch,
):
    prepared = _prepared(tmp_path, _source("/bin/cat", "/usr/bin/cat"))
    called = False

    def fake_spawn(_prepared):
        nonlocal called
        called = True
        raise AssertionError("must not spawn")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.run.spawn_prepared_native",
        fake_spawn,
    )

    try:
        with pytest.raises(BoundedExecutionError, match="stdin"):
            run_prepared_native(
                prepared,
                b"too large",
                _limits(stdin=1),
            )
        assert called is False
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

    _signal_process_group(1234, signal.SIGTERM)

    assert calls == [
        ("killpg", 1234, signal.SIGTERM),
        ("kill", 1234, signal.SIGTERM),
    ]
