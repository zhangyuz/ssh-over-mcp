from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from typing import Literal, Self

from ssh_over_mcp.ssh.protocol import ExecEnvelope

from .policy import (
    HostAuthorizationResult,
    HostChildLimits,
    HostCommandRule,
    HostExecutionPolicy,
    HostObjectIdentity,
    authorize_request,
)


class CommandPreparationError(RuntimeError):
    """An authorized pathname could not be safely pinned to file descriptors."""


ExecutableFormat = Literal["elf", "script", "other"]


@dataclass(slots=True)
class PreparedCommand:
    request_id: str
    executable_fd: int
    cwd_fd: int | None
    executable_path: str
    executable_identity: HostObjectIdentity
    cwd_path: str | None
    cwd_identity: HostObjectIdentity | None
    executable_format: ExecutableFormat
    argv: tuple[str, ...]
    env: dict[str, str]
    fd_exec_supported: bool
    child_limits: HostChildLimits
    _closed: bool = False

    def close(self) -> None:
        if self._closed:
            return

        try:
            if self.cwd_fd is not None:
                try:
                    os.close(self.cwd_fd)
                except OSError:
                    pass
        finally:
            try:
                os.close(self.executable_fd)
            except OSError:
                pass
            self._closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def _require_linux_open_flags() -> int:
    required = ("O_CLOEXEC", "O_NOFOLLOW")
    missing = [name for name in required if not hasattr(os, name)]
    if missing:
        raise CommandPreparationError(
            "required secure open flags are unavailable"
        )

    return os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW


def _same_authorized_identity(
    left: HostObjectIdentity | None,
    right: HostObjectIdentity | None,
    *,
    include_change_metadata: bool,
) -> bool:
    if left is None or right is None:
        return left is right
    if left.device != right.device or left.inode != right.inode:
        return False
    if not include_change_metadata:
        return True
    return (
        left.ctime_ns == right.ctime_ns
        and left.mtime_ns == right.mtime_ns
        and left.size == right.size
    )


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


def _read_file_capability(fd: int) -> bytes:
    if not hasattr(os, "getxattr"):
        raise CommandPreparationError(
            "file-capability inspection is unavailable"
        )

    try:
        return os.getxattr(fd, "security.capability")
    except (TypeError, NotImplementedError) as exc:
        raise CommandPreparationError(
            "file-capability inspection by fd is unavailable"
        ) from exc
    except OSError as exc:
        if exc.errno in {
            errno.ENODATA,
            errno.ENOTSUP,
            errno.EOPNOTSUPP,
        }:
            return b""
        raise CommandPreparationError(
            "file-capability inspection failed"
        ) from exc


def _validate_executable_fd(
    fd: int,
    *,
    identity: HostObjectIdentity,
    rule: HostCommandRule,
) -> os.stat_result:
    try:
        info = os.fstat(fd)
    except OSError as exc:
        raise CommandPreparationError(
            "cannot inspect pinned executable"
        ) from exc

    if not _same_identity(info, identity, include_change_metadata=True):
        raise CommandPreparationError(
            "executable changed after authorization"
        )
    if not stat.S_ISREG(info.st_mode):
        raise CommandPreparationError(
            "pinned executable is not a regular file"
        )
    if rule.require_root_owned and info.st_uid != 0:
        raise CommandPreparationError(
            "pinned executable is not root-owned"
        )
    if (
        not rule.allow_group_or_world_writable
        and info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise CommandPreparationError(
            "pinned executable is group/other writable"
        )
    if (
        not rule.allow_setuid_or_setgid
        and info.st_mode & (stat.S_ISUID | stat.S_ISGID)
    ):
        raise CommandPreparationError(
            "pinned executable has setuid/setgid bits"
        )
    if not rule.allow_file_capabilities and _read_file_capability(fd):
        raise CommandPreparationError(
            "pinned executable has file capabilities"
        )

    if not (info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
        raise CommandPreparationError(
            "pinned executable has no execute bits"
        )

    return info


def _detect_executable_format(fd: int) -> ExecutableFormat:
    try:
        prefix = os.pread(fd, 4, 0)
    except (AttributeError, OSError):
        return "other"

    if prefix.startswith(b"\x7fELF"):
        return "elf"
    if prefix.startswith(b"#!"):
        return "script"
    return "other"


def _open_executable(
    decision: HostAuthorizationResult,
    rule: HostCommandRule,
) -> tuple[int, ExecutableFormat]:
    if (
        decision.resolved_executable is None
        or decision.executable_identity is None
    ):
        raise CommandPreparationError(
            "authorization result lacks executable identity"
        )

    flags = _require_linux_open_flags()
    try:
        fd = os.open(decision.resolved_executable, flags)
    except OSError as exc:
        raise CommandPreparationError(
            "cannot open authorized executable"
        ) from exc

    try:
        _validate_executable_fd(
            fd,
            identity=decision.executable_identity,
            rule=rule,
        )
        executable_format = _detect_executable_format(fd)
    except Exception:
        os.close(fd)
        raise

    return fd, executable_format


def _open_cwd(decision: HostAuthorizationResult) -> int | None:
    if decision.resolved_cwd is None:
        if decision.cwd_identity is not None:
            raise CommandPreparationError(
                "authorization result has inconsistent cwd identity"
            )
        return None

    if decision.cwd_identity is None:
        raise CommandPreparationError(
            "authorization result lacks cwd identity"
        )
    if not hasattr(os, "O_DIRECTORY"):
        raise CommandPreparationError(
            "secure directory open is unavailable"
        )

    flags = _require_linux_open_flags() | os.O_DIRECTORY
    try:
        fd = os.open(decision.resolved_cwd, flags)
    except OSError as exc:
        raise CommandPreparationError(
            "cannot open authorized working directory"
        ) from exc

    try:
        info = os.fstat(fd)
        if not _same_identity(
            info,
            decision.cwd_identity,
            include_change_metadata=False,
        ):
            raise CommandPreparationError(
                "working directory changed after authorization"
            )
        if not stat.S_ISDIR(info.st_mode):
            raise CommandPreparationError(
                "pinned working directory is not a directory"
            )
    except Exception:
        os.close(fd)
        raise

    return fd


def prepare_command(
    policy: HostExecutionPolicy,
    envelope: ExecEnvelope,
    decision: HostAuthorizationResult,
) -> PreparedCommand:
    """Pin an allowed executable/cwd to fds without executing anything."""

    if not decision.allowed:
        raise CommandPreparationError(
            "cannot prepare a denied authorization result"
        )

    fresh = authorize_request(policy, envelope)
    if not fresh.allowed:
        raise CommandPreparationError(
            "request is no longer authorized"
        )
    if (
        fresh.resolved_executable != decision.resolved_executable
        or not _same_authorized_identity(
            fresh.executable_identity,
            decision.executable_identity,
            include_change_metadata=True,
        )
        or fresh.resolved_cwd != decision.resolved_cwd
        or not _same_authorized_identity(
            fresh.cwd_identity,
            decision.cwd_identity,
            include_change_metadata=False,
        )
    ):
        raise CommandPreparationError(
            "authorized filesystem objects changed before preparation"
        )

    decision = fresh

    rule = policy.commands.get(envelope.executable)
    if rule is None:
        raise CommandPreparationError(
            "authorized command rule is unavailable"
        )

    executable_fd, executable_format = _open_executable(
        decision,
        rule,
    )

    try:
        cwd_fd = _open_cwd(decision)
    except Exception:
        os.close(executable_fd)
        raise

    return PreparedCommand(
        request_id=envelope.request_id,
        executable_fd=executable_fd,
        cwd_fd=cwd_fd,
        executable_path=decision.resolved_executable or "",
        executable_identity=decision.executable_identity,
        cwd_path=decision.resolved_cwd,
        cwd_identity=decision.cwd_identity,
        executable_format=executable_format,
        argv=envelope.argv,
        env=dict(envelope.env),
        fd_exec_supported=os.execve in os.supports_fd,
        child_limits=policy.child_limits,
    )
