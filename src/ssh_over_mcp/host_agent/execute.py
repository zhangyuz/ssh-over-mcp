from __future__ import annotations

import os
import stat
from collections.abc import Callable
from dataclasses import dataclass

from .policy import HostObjectIdentity
from .prepare import PreparedCommand


class NativeExecutionError(RuntimeError):
    """A pinned command cannot enter the native fd-based exec path."""


@dataclass(frozen=True, slots=True)
class NativeExecSpec:
    executable_fd: int
    cwd_fd: int
    argv: tuple[str, ...]
    env: dict[str, str]


def _same_identity(
    info: os.stat_result,
    identity: HostObjectIdentity,
    *,
    include_change_metadata: bool,
) -> bool:
    if info.st_dev != identity.device or info.st_ino != identity.inode:
        return False
    if not include_change_metadata:
        return True
    return (
        info.st_ctime_ns == identity.ctime_ns
        and info.st_mtime_ns == identity.mtime_ns
        and info.st_size == identity.size
    )


def _validate_fd_identity(
    fd: int,
    identity: HostObjectIdentity,
    *,
    require_directory: bool,
    include_change_metadata: bool,
) -> None:
    try:
        info = os.fstat(fd)
    except OSError as exc:
        raise NativeExecutionError("pinned descriptor is unavailable") from exc

    if not _same_identity(info, identity, include_change_metadata=include_change_metadata):
        raise NativeExecutionError("pinned object changed before exec")

    if require_directory:
        if not stat.S_ISDIR(info.st_mode):
            raise NativeExecutionError("pinned cwd is not a directory")
        return

    if not stat.S_ISREG(info.st_mode):
        raise NativeExecutionError("pinned executable is not a regular file")
    if identity.content_sha256 is None:
        raise NativeExecutionError("pinned executable lacks content binding")

    try:
        content_sha256 = sha256_fd(fd, expected_size=info.st_size)
        after = os.fstat(fd)
    except OSError as exc:
        raise NativeExecutionError("cannot verify pinned executable content") from exc

    if (
        not _same_identity(
            after,
            identity,
            include_change_metadata=include_change_metadata,
        )
        or content_sha256 != identity.content_sha256
    ):
        raise NativeExecutionError("pinned object changed before exec")


def _validate_argv_env(
    argv: tuple[str, ...],
    env: dict[str, str],
) -> None:
    if not argv:
        raise NativeExecutionError("exec argv must contain argv[0]")
    if any("\x00" in value for value in argv):
        raise NativeExecutionError("exec argv contains NUL")

    for name, value in env.items():
        if not name or "=" in name or "\x00" in name or "\x00" in value:
            raise NativeExecutionError("exec environment is invalid")


def build_native_exec_spec(prepared: PreparedCommand) -> NativeExecSpec:
    """Build an fd-only native execution specification.

    This does not execute, fork, reopen an executable pathname, or inherit the
    host-agent environment.
    """

    if prepared._closed:
        raise NativeExecutionError("prepared command is closed")
    if prepared.executable_format != "elf":
        raise NativeExecutionError("only native ELF execution is supported")
    if not prepared.fd_exec_supported:
        raise NativeExecutionError("fd-based os.execve is unavailable")

    _validate_fd_identity(
        prepared.executable_fd,
        prepared.executable_identity,
        require_directory=False,
        include_change_metadata=True,
    )

    if prepared.cwd_fd is None:
        raise NativeExecutionError("native execution requires a pinned cwd")
    if prepared.cwd_identity is None:
        raise NativeExecutionError("pinned cwd identity is missing")
    _validate_fd_identity(
        prepared.cwd_fd,
        prepared.cwd_identity,
        require_directory=True,
        include_change_metadata=False,
    )

    # argv[0] is descriptive only. The executable itself is selected by fd.
    argv = (prepared.executable_path, *prepared.argv)
    env = dict(prepared.env)
    _validate_argv_env(argv, env)

    return NativeExecSpec(
        executable_fd=prepared.executable_fd,
        cwd_fd=prepared.cwd_fd,
        argv=argv,
        env=env,
    )


def exec_prepared_native_in_child(
    prepared: PreparedCommand,
    *,
    execve: Callable[[int, tuple[str, ...], dict[str, str]], object] = os.execve,
    fchdir: Callable[[int], object] = os.fchdir,
) -> None:
    """Replace the current *child* process with a pinned native executable.

    This primitive MUST only be called in a disposable child process. If cwd is
    configured it changes the current process directory with fchdir() before
    execve(). No shell is involved and no ambient environment is inherited.
    """

    spec = build_native_exec_spec(prepared)

    try:
        fchdir(spec.cwd_fd)
    except OSError as exc:
        raise NativeExecutionError("cannot enter pinned cwd") from exc

    # fchdir itself doesn't consume the descriptor. Revalidate it after
    # changing cwd and immediately before exec.
    if prepared.cwd_identity is None:
        raise NativeExecutionError("pinned cwd identity is missing")
    _validate_fd_identity(
        spec.cwd_fd,
        prepared.cwd_identity,
        require_directory=True,
        include_change_metadata=False,
    )

    _validate_fd_identity(
        spec.executable_fd,
        prepared.executable_identity,
        require_directory=False,
        include_change_metadata=True,
    )

    try:
        execve(spec.executable_fd, spec.argv, spec.env)
    except OSError as exc:
        raise NativeExecutionError("fd-based execve failed") from exc

    # A real successful execve never returns.
    raise NativeExecutionError("fd-based execve returned unexpectedly")
