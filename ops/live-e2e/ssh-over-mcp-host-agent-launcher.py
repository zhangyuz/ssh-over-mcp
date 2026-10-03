#!/usr/bin/python3
from __future__ import annotations

import ctypes
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

HOST_AGENT_UID = 2202
HOST_AGENT_GID = 3202
MANAGER_CLIENT_GID = 3299
EXPECTED_SUDO_USER = "ssh-over-mcp-e2e-host"
EXPECTED_ORIGINAL_COMMAND = "mcp-v1"

APPLICATION_SOURCE = Path(
    "/opt/ssh-over-mcp-e2e/workspace/src"
)
APPLICATION_SITE_PACKAGES = Path(
    "/opt/ssh-over-mcp-e2e/venv/lib/python3.14/site-packages"
)

CAP_SETGID = 6
CAP_SETUID = 7
EXPECTED_CAPABILITY_MASK = (1 << CAP_SETGID) | (1 << CAP_SETUID)

_PR_SET_KEEPCAPS = 8
_PR_CAP_AMBIENT = 47
_PR_CAP_AMBIENT_CLEAR_ALL = 4
_LINUX_CAPABILITY_VERSION_3 = 0x20080522


class LauncherError(RuntimeError):
    """The fixed host-agent privilege transition cannot proceed safely."""


@dataclass(frozen=True, slots=True)
class _PrivilegeSnapshot:
    real_uid: int
    effective_uid: int
    saved_uid: int
    real_gid: int
    effective_gid: int
    saved_gid: int
    supplementary_gids: tuple[int, ...]
    cap_inheritable: int
    cap_permitted: int
    cap_effective: int
    cap_ambient: int


class _PrivilegeOps(Protocol):
    def effective_uid(self) -> int: ...

    def set_keepcaps(self, enabled: bool) -> None: ...

    def set_groups(self, groups: tuple[int, ...]) -> None: ...

    def set_res_gid(self, gid: int) -> None: ...

    def set_res_uid(self, uid: int) -> None: ...

    def set_capabilities(self, mask: int) -> None: ...

    def clear_ambient_capabilities(self) -> None: ...

    def snapshot(self) -> _PrivilegeSnapshot: ...


class _CapHeader(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("pid", ctypes.c_int),
    ]


class _CapData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


def _raise_errno(label: str) -> None:
    error = ctypes.get_errno()
    raise LauncherError(f"{label} failed with errno {error}")


def _status_capabilities() -> tuple[int, int, int, int]:
    wanted = {
        "CapInh": None,
        "CapPrm": None,
        "CapEff": None,
        "CapAmb": None,
    }
    try:
        with open("/proc/self/status", encoding="ascii") as stream:
            for raw in stream:
                key, separator, value = raw.partition(":")
                if separator and key in wanted:
                    wanted[key] = int(value.strip(), 16)
    except (OSError, ValueError) as exc:
        raise LauncherError("cannot read process capability state") from exc

    if any(value is None for value in wanted.values()):
        raise LauncherError("process capability state is incomplete")

    return (
        int(wanted["CapInh"]),
        int(wanted["CapPrm"]),
        int(wanted["CapEff"]),
        int(wanted["CapAmb"]),
    )


class _LinuxPrivilegeOps:
    def __init__(self) -> None:
        self._libc = ctypes.CDLL(None, use_errno=True)
        self._libc.prctl.restype = ctypes.c_int
        self._libc.capset.restype = ctypes.c_int

    def effective_uid(self) -> int:
        return os.geteuid()

    def set_keepcaps(self, enabled: bool) -> None:
        result = self._libc.prctl(
            _PR_SET_KEEPCAPS,
            1 if enabled else 0,
            0,
            0,
            0,
        )
        if result != 0:
            _raise_errno("prctl(PR_SET_KEEPCAPS)")

    def set_groups(self, groups: tuple[int, ...]) -> None:
        try:
            os.setgroups(list(groups))
        except OSError as exc:
            raise LauncherError("cannot set host-agent supplementary groups") from exc

    def set_res_gid(self, gid: int) -> None:
        try:
            os.setresgid(gid, gid, gid)
        except OSError as exc:
            raise LauncherError("cannot drop host-agent gid") from exc

    def set_res_uid(self, uid: int) -> None:
        try:
            os.setresuid(uid, uid, uid)
        except OSError as exc:
            raise LauncherError("cannot drop host-agent uid") from exc

    def set_capabilities(self, mask: int) -> None:
        if mask < 0 or mask > 0xFFFFFFFF:
            raise LauncherError("capability mask is invalid")

        header = _CapHeader(
            version=_LINUX_CAPABILITY_VERSION_3,
            pid=0,
        )
        data = (_CapData * 2)()
        data[0].effective = mask
        data[0].permitted = mask
        data[0].inheritable = 0
        data[1].effective = 0
        data[1].permitted = 0
        data[1].inheritable = 0

        result = self._libc.capset(
            ctypes.byref(header),
            ctypes.byref(data),
        )
        if result != 0:
            _raise_errno("capset")

    def clear_ambient_capabilities(self) -> None:
        result = self._libc.prctl(
            _PR_CAP_AMBIENT,
            _PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
        if result != 0:
            _raise_errno("prctl(PR_CAP_AMBIENT_CLEAR_ALL)")

    def snapshot(self) -> _PrivilegeSnapshot:
        try:
            real_uid, effective_uid, saved_uid = os.getresuid()
            real_gid, effective_gid, saved_gid = os.getresgid()
            supplementary = tuple(sorted(set(os.getgroups())))
        except OSError as exc:
            raise LauncherError("cannot read host-agent identity state") from exc

        cap_inheritable, cap_permitted, cap_effective, cap_ambient = (
            _status_capabilities()
        )
        return _PrivilegeSnapshot(
            real_uid=real_uid,
            effective_uid=effective_uid,
            saved_uid=saved_uid,
            real_gid=real_gid,
            effective_gid=effective_gid,
            saved_gid=saved_gid,
            supplementary_gids=supplementary,
            cap_inheritable=cap_inheritable,
            cap_permitted=cap_permitted,
            cap_effective=cap_effective,
            cap_ambient=cap_ambient,
        )


_SYSTEM_OPS: _PrivilegeOps = _LinuxPrivilegeOps()


def _validated_environment(
    argv: Sequence[str],
    env: Mapping[str, str],
) -> dict[str, str]:
    if tuple(argv):
        raise LauncherError("launcher arguments are not permitted")
    if env.get("SSH_ORIGINAL_COMMAND") != EXPECTED_ORIGINAL_COMMAND:
        raise LauncherError("invalid ForceCommand request")
    if env.get("SSH_TTY", ""):
        raise LauncherError("PTY is not permitted")
    if env.get("SUDO_USER") != EXPECTED_SUDO_USER:
        raise LauncherError("invalid sudo caller")
    if env.get("SUDO_UID") != str(HOST_AGENT_UID):
        raise LauncherError("invalid sudo uid")
    if env.get("SUDO_GID") != str(HOST_AGENT_GID):
        raise LauncherError("invalid sudo gid")

    return {
        "HOME": "/home/ssh-over-mcp-e2e-host",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LOGNAME": EXPECTED_SUDO_USER,
        "PATH": "/usr/bin:/bin",
        "SSH_ORIGINAL_COMMAND": EXPECTED_ORIGINAL_COMMAND,
        "USER": EXPECTED_SUDO_USER,
    }


def _drop_and_verify(ops: _PrivilegeOps) -> None:
    if ops.effective_uid() != 0:
        raise LauncherError("launcher must begin with effective uid 0")

    ops.set_keepcaps(True)
    ops.set_groups((MANAGER_CLIENT_GID,))
    ops.set_res_gid(HOST_AGENT_GID)
    ops.set_res_uid(HOST_AGENT_UID)
    ops.set_capabilities(EXPECTED_CAPABILITY_MASK)
    ops.clear_ambient_capabilities()
    ops.set_keepcaps(False)

    snapshot = ops.snapshot()
    expected_uids = (HOST_AGENT_UID, HOST_AGENT_UID, HOST_AGENT_UID)
    expected_gids = (HOST_AGENT_GID, HOST_AGENT_GID, HOST_AGENT_GID)
    if (
        (snapshot.real_uid, snapshot.effective_uid, snapshot.saved_uid)
        != expected_uids
        or (snapshot.real_gid, snapshot.effective_gid, snapshot.saved_gid)
        != expected_gids
        or snapshot.supplementary_gids != (MANAGER_CLIENT_GID,)
        or snapshot.cap_inheritable != 0
        or snapshot.cap_permitted != EXPECTED_CAPABILITY_MASK
        or snapshot.cap_effective != EXPECTED_CAPABILITY_MASK
        or snapshot.cap_ambient != 0
    ):
        raise LauncherError("host-agent privilege transition verification failed")


def _run_application() -> int:
    for path in (APPLICATION_SITE_PACKAGES, APPLICATION_SOURCE):
        if not path.is_dir():
            raise LauncherError("host-agent application path is unavailable")

    sys.path.insert(0, str(APPLICATION_SITE_PACKAGES))
    sys.path.insert(0, str(APPLICATION_SOURCE))

    from ssh_over_mcp.host_agent.cli import main as host_agent_main

    result = host_agent_main([])
    return 0 if result is None else int(result)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    sanitized = _validated_environment(arguments, os.environ)
    os.environ.clear()
    os.environ.update(sanitized)
    _drop_and_verify(_SYSTEM_OPS)
    return _run_application()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LauncherError:
        sys.stderr.write("ssh-over-mcp host-agent launcher failed\n")
        raise SystemExit(70) from None
