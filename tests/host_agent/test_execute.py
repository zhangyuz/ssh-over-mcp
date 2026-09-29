import errno
import os
import shutil
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.execute import (
    NativeExecutionError,
    build_native_exec_spec,
    exec_prepared_native_in_child,
)
from ssh_over_mcp.host_agent.file_identity import sha256_fd
from ssh_over_mcp.host_agent.policy import HostChildLimits, HostObjectIdentity
from ssh_over_mcp.host_agent.prepare import PreparedCommand


def _child_limits() -> HostChildLimits:
    return HostChildLimits(
        cpu_seconds=10,
        address_space_bytes=512 * 1024 * 1024,
        max_processes=64,
        file_size_bytes=64 * 1024 * 1024,
        open_files=128,
    )


def _copy_native_elf(tmp_path: Path) -> Path:
    source = Path("/bin/true")
    if not source.exists():
        pytest.skip("/bin/true is required for Linux native-exec tests")

    target = tmp_path / "true"
    shutil.copyfile(source.resolve(), target)
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
    *,
    env: dict[str, str] | None = None,
    argv: tuple[str, ...] = (),
    fd_exec_supported: bool = True,
) -> PreparedCommand:
    executable = _copy_native_elf(tmp_path)
    cwd = tmp_path / "work"
    cwd.mkdir()

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
        env=dict(env or {}),
        fd_exec_supported=fd_exec_supported,
        child_limits=_child_limits(),
    )


def test_build_native_exec_spec_uses_fd_and_explicit_environment(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setenv("SECRET_FROM_HOST_AGENT", "must-not-leak")
    prepared = _prepared(
        tmp_path,
        env={"CI": "1"},
        argv=("--help",),
    )

    try:
        spec = build_native_exec_spec(prepared)

        assert spec.executable_fd == prepared.executable_fd
        assert spec.cwd_fd == prepared.cwd_fd
        assert spec.argv == (prepared.executable_path, "--help")
        assert spec.env == {"CI": "1"}
        assert "SECRET_FROM_HOST_AGENT" not in spec.env
    finally:
        prepared.close()


def test_non_elf_is_rejected(tmp_path: Path):
    prepared = _prepared(tmp_path)
    prepared.executable_format = "script"

    try:
        with pytest.raises(NativeExecutionError, match="native ELF"):
            build_native_exec_spec(prepared)
    finally:
        prepared.close()


def test_fd_exec_support_is_required(tmp_path: Path):
    prepared = _prepared(tmp_path, fd_exec_supported=False)

    try:
        with pytest.raises(NativeExecutionError, match="unavailable"):
            build_native_exec_spec(prepared)
    finally:
        prepared.close()


def test_pinned_cwd_is_required(tmp_path: Path):
    prepared = _prepared(tmp_path)
    os.close(prepared.cwd_fd)
    prepared.cwd_fd = None
    prepared.cwd_identity = None

    try:
        with pytest.raises(NativeExecutionError, match="pinned cwd"):
            build_native_exec_spec(prepared)
    finally:
        prepared.close()


def test_executable_mutation_after_preparation_is_denied(tmp_path: Path):
    prepared = _prepared(tmp_path)

    try:
        with open(prepared.executable_path, "ab") as stream:
            stream.write(b"x")

        with pytest.raises(NativeExecutionError, match="changed before exec"):
            build_native_exec_spec(prepared)
    finally:
        prepared.close()


def test_same_size_executable_rewrite_after_preparation_is_denied(
    tmp_path: Path,
):
    prepared = _prepared(tmp_path)

    try:
        path = Path(prepared.executable_path)
        original = path.read_bytes()
        mutated = bytearray(original)
        mutated[-1] ^= 0x01
        assert len(mutated) == len(original)
        path.write_bytes(mutated)

        current = path.stat()
        prepared.executable_identity = prepared.executable_identity.model_copy(
            update={
                "ctime_ns": current.st_ctime_ns,
                "mtime_ns": current.st_mtime_ns,
                "size": current.st_size,
            }
        )

        with pytest.raises(NativeExecutionError, match="changed before exec"):
            build_native_exec_spec(prepared)
    finally:
        prepared.close()


def test_missing_executable_content_binding_fails_closed(tmp_path: Path):
    prepared = _prepared(tmp_path)

    try:
        prepared.executable_identity = prepared.executable_identity.model_copy(
            update={"content_sha256": None}
        )
        with pytest.raises(NativeExecutionError, match="content binding"):
            build_native_exec_spec(prepared)
    finally:
        prepared.close()


def test_cwd_content_change_does_not_invalidate_identity(tmp_path: Path):
    prepared = _prepared(tmp_path)

    try:
        assert prepared.cwd_path is not None
        Path(prepared.cwd_path, "new-file").write_text("ok", encoding="utf-8")

        spec = build_native_exec_spec(prepared)
        assert spec.cwd_fd == prepared.cwd_fd
    finally:
        prepared.close()


def test_exec_primitive_calls_fchdir_then_fd_execve(tmp_path: Path):
    prepared = _prepared(
        tmp_path,
        env={"CI": "1"},
        argv=("--version",),
    )
    calls: list[tuple] = []

    def fake_fchdir(fd: int):
        calls.append(("fchdir", fd))

    def fake_execve(fd: int, argv: tuple[str, ...], env: dict[str, str]):
        calls.append(("execve", fd, argv, env))
        raise OSError(errno.EPERM, "blocked by test")

    try:
        with pytest.raises(NativeExecutionError, match="execve failed"):
            exec_prepared_native_in_child(
                prepared,
                execve=fake_execve,
                fchdir=fake_fchdir,
            )

        assert calls[0] == ("fchdir", prepared.cwd_fd)
        assert calls[1][0] == "execve"
        assert calls[1][1] == prepared.executable_fd
        assert calls[1][2] == (
            prepared.executable_path,
            "--version",
        )
        assert calls[1][3] == {"CI": "1"}
    finally:
        prepared.close()


@pytest.mark.skipif(
    os.name != "posix"
    or not hasattr(os, "fork")
    or os.execve not in os.supports_fd,
    reason="requires POSIX fork and fd-based execve",
)
def test_native_fd_execve_works_in_disposable_child(tmp_path: Path):
    prepared = _prepared(tmp_path)
    pid = os.fork()

    if pid == 0:
        try:
            exec_prepared_native_in_child(prepared)
        except BaseException:  # noqa: BLE001
            # Disposable fork child must never unwind into the pytest process.
            os._exit(125)
        os._exit(126)

    try:
        _, status = os.waitpid(pid, 0)
        assert os.WIFEXITED(status)
        assert os.WEXITSTATUS(status) == 0
    finally:
        prepared.close()
