from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .containment_manager_identity import (
    LinuxProcessIdentityPolicy,
    LinuxProcessIdentitySnapshot,
)

_UINT32_MAX = (1 << 32) - 1
_LINUX_CAPABILITY_VERSION_3 = 0x20080522
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39
_PR_CAP_AMBIENT = 47
_PR_CAP_AMBIENT_CLEAR_ALL = 4
_CAP_LAST_CAP_PATH = Path("/proc/sys/kernel/cap_last_cap")
_PROC_STATUS_PATH = Path("/proc/self/status")


class WorkloadIdentityTransitionError(RuntimeError):
    """The child could not enter the verified workload identity safely."""


@dataclass(frozen=True, slots=True)
class WorkloadIdentityTransitionSnapshot:
    identity: LinuxProcessIdentitySnapshot
    filesystem_uid: int
    filesystem_gid: int
    no_new_privs: bool
    effective_capabilities: int
    permitted_capabilities: int
    inheritable_capabilities: int
    ambient_capabilities_empty: bool


class _IdentitySyscalls(Protocol):
    def read_identity(self) -> LinuxProcessIdentitySnapshot: ...
    def validate_capability_abi(self) -> int: ...
    def set_no_new_privs(self) -> None: ...
    def clear_ambient_capabilities(self) -> None: ...
    def clear_supplementary_groups(self) -> None: ...
    def setresgid(self, gid: int) -> None: ...
    def setresuid(self, uid: int) -> None: ...
    def read_filesystem_ids(self) -> tuple[int, int]: ...
    def clear_capability_sets(self) -> None: ...
    def read_capability_sets(self) -> tuple[int, int, int]: ...
    def get_no_new_privs(self) -> int: ...


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


class _LinuxIdentitySyscalls:
    def __init__(self) -> None:
        if not sys.platform.startswith("linux"):
            raise WorkloadIdentityTransitionError(
                "required Linux workload identity APIs are unavailable"
            )

        for name in (
            "getresuid",
            "getresgid",
            "getgroups",
            "setgroups",
            "setresgid",
            "setresuid",
        ):
            if not hasattr(os, name):
                raise WorkloadIdentityTransitionError(
                    "required Linux workload identity APIs are unavailable"
                )

        try:
            libc = ctypes.CDLL(None, use_errno=True)
            self._prctl = libc.prctl
            self._capget = libc.capget
            self._capset = libc.capset
        except (AttributeError, OSError) as exc:
            raise WorkloadIdentityTransitionError(
                "required Linux workload identity APIs are unavailable"
            ) from exc

        self._prctl.restype = ctypes.c_int
        self._capget.argtypes = [
            ctypes.POINTER(_CapHeader),
            ctypes.POINTER(_CapData),
        ]
        self._capget.restype = ctypes.c_int
        self._capset.argtypes = [
            ctypes.POINTER(_CapHeader),
            ctypes.POINTER(_CapData),
        ]
        self._capset.restype = ctypes.c_int

    @staticmethod
    def _raise_os_error(label: str) -> None:
        error_number = ctypes.get_errno()
        if error_number:
            cause = OSError(error_number, os.strerror(error_number))
            raise WorkloadIdentityTransitionError(label) from cause
        raise WorkloadIdentityTransitionError(label)

    def _call_prctl(
        self,
        option: int,
        arg2: int = 0,
        arg3: int = 0,
        arg4: int = 0,
        arg5: int = 0,
    ) -> int:
        ctypes.set_errno(0)
        result = self._prctl(option, arg2, arg3, arg4, arg5)
        if result < 0:
            self._raise_os_error("Linux prctl operation failed")
        return int(result)

    def read_identity(self) -> LinuxProcessIdentitySnapshot:
        try:
            real_uid, effective_uid, saved_uid = os.getresuid()
            real_gid, effective_gid, saved_gid = os.getresgid()
            supplementary = tuple(os.getgroups())
        except OSError as exc:
            raise WorkloadIdentityTransitionError(
                "cannot read source Linux process identity"
            ) from exc

        return LinuxProcessIdentitySnapshot(
            real_uid=real_uid,
            effective_uid=effective_uid,
            saved_uid=saved_uid,
            real_gid=real_gid,
            effective_gid=effective_gid,
            saved_gid=saved_gid,
            supplementary_gids=supplementary,
        )

    def validate_capability_abi(self) -> int:
        try:
            raw = _CAP_LAST_CAP_PATH.read_text(encoding="ascii").strip()
            cap_last_cap = int(raw, 10)
        except (OSError, UnicodeError, ValueError) as exc:
            raise WorkloadIdentityTransitionError(
                "cannot determine kernel capability range"
            ) from exc

        if not 0 <= cap_last_cap <= 63:
            raise WorkloadIdentityTransitionError(
                "kernel capability range is unsupported"
            )

        self.read_capability_sets()
        return cap_last_cap

    def set_no_new_privs(self) -> None:
        self._call_prctl(_PR_SET_NO_NEW_PRIVS, 1)

    def get_no_new_privs(self) -> int:
        return self._call_prctl(_PR_GET_NO_NEW_PRIVS)

    def clear_ambient_capabilities(self) -> None:
        self._call_prctl(
            _PR_CAP_AMBIENT,
            _PR_CAP_AMBIENT_CLEAR_ALL,
        )

    def clear_supplementary_groups(self) -> None:
        try:
            os.setgroups([])
        except OSError as exc:
            raise WorkloadIdentityTransitionError(
                "cannot clear supplementary groups"
            ) from exc

    def setresgid(self, gid: int) -> None:
        try:
            os.setresgid(gid, gid, gid)
        except OSError as exc:
            raise WorkloadIdentityTransitionError(
                "cannot transition workload GID"
            ) from exc

    def setresuid(self, uid: int) -> None:
        try:
            os.setresuid(uid, uid, uid)
        except OSError as exc:
            raise WorkloadIdentityTransitionError(
                "cannot transition workload UID"
            ) from exc

    def read_filesystem_ids(self) -> tuple[int, int]:
        try:
            status = _PROC_STATUS_PATH.read_text(encoding="ascii")
        except (OSError, UnicodeError) as exc:
            raise WorkloadIdentityTransitionError(
                "cannot read Linux filesystem identity"
            ) from exc

        uid_values: tuple[int, int, int, int] | None = None
        gid_values: tuple[int, int, int, int] | None = None
        for line in status.splitlines():
            if line.startswith("Uid:"):
                uid_values = _parse_status_ids(line, "Uid")
            elif line.startswith("Gid:"):
                gid_values = _parse_status_ids(line, "Gid")

        if uid_values is None or gid_values is None:
            raise WorkloadIdentityTransitionError(
                "cannot read Linux filesystem identity"
            )

        return uid_values[3], gid_values[3]

    @staticmethod
    def _capability_data() -> tuple[_CapHeader, ctypes.Array[_CapData]]:
        header = _CapHeader(version=_LINUX_CAPABILITY_VERSION_3, pid=0)
        data = (_CapData * 2)()
        return header, data

    def clear_capability_sets(self) -> None:
        header, data = self._capability_data()
        ctypes.set_errno(0)
        if self._capset(ctypes.byref(header), data) != 0:
            self._raise_os_error("cannot clear Linux capability sets")

    def read_capability_sets(self) -> tuple[int, int, int]:
        header, data = self._capability_data()
        ctypes.set_errno(0)
        if self._capget(ctypes.byref(header), data) != 0:
            self._raise_os_error("cannot read Linux capability sets")

        effective = int(data[0].effective) | (int(data[1].effective) << 32)
        permitted = int(data[0].permitted) | (int(data[1].permitted) << 32)
        inheritable = int(data[0].inheritable) | (
            int(data[1].inheritable) << 32
        )
        return effective, permitted, inheritable


def _parse_status_ids(line: str, label: str) -> tuple[int, int, int, int]:
    fields = line.split()
    if len(fields) != 5 or fields[0] != f"{label}:":
        raise WorkloadIdentityTransitionError(
            "cannot read Linux filesystem identity"
        )

    try:
        values = tuple(int(value, 10) for value in fields[1:])
    except ValueError as exc:
        raise WorkloadIdentityTransitionError(
            "cannot read Linux filesystem identity"
        ) from exc

    if len(values) != 4 or any(
        value < 0 or value > _UINT32_MAX for value in values
    ):
        raise WorkloadIdentityTransitionError(
            "cannot read Linux filesystem identity"
        )

    return values[0], values[1], values[2], values[3]


def _create_linux_syscalls() -> _IdentitySyscalls:
    return _LinuxIdentitySyscalls()


_SYSCALLS: _IdentitySyscalls | None = None


def _get_syscalls() -> _IdentitySyscalls:
    if _SYSCALLS is not None:
        return _SYSCALLS
    return _create_linux_syscalls()


def _validate_source_identity(
    source: LinuxProcessIdentitySnapshot,
) -> None:
    if (
        source.real_uid == 0
        or source.real_uid != source.effective_uid
        or source.real_uid != source.saved_uid
        or source.real_gid == 0
        or source.real_gid != source.effective_gid
        or source.real_gid != source.saved_gid
    ):
        raise WorkloadIdentityTransitionError(
            "source Linux process identity is invalid"
        )


def _validate_target_policy(
    policy: LinuxProcessIdentityPolicy,
    source: LinuxProcessIdentitySnapshot,
) -> None:
    if not isinstance(policy, LinuxProcessIdentityPolicy):
        raise WorkloadIdentityTransitionError(
            "workload identity policy is invalid"
        )

    target = policy.identity
    if (
        target.uid in {0, _UINT32_MAX}
        or target.gid in {0, _UINT32_MAX}
        or target.uid == source.real_uid
        or policy.supplementary_gids
    ):
        raise WorkloadIdentityTransitionError(
            "workload identity policy is invalid"
        )


def _verify_post_drop_identity(
    observed: LinuxProcessIdentitySnapshot,
    policy: LinuxProcessIdentityPolicy,
) -> None:
    target = policy.identity
    if (
        observed.real_uid != target.uid
        or observed.effective_uid != target.uid
        or observed.saved_uid != target.uid
        or observed.real_gid != target.gid
        or observed.effective_gid != target.gid
        or observed.saved_gid != target.gid
        or observed.supplementary_gids != ()
    ):
        raise WorkloadIdentityTransitionError(
            "post-drop Linux process identity is invalid"
        )


def transition_to_workload_identity(
    policy: LinuxProcessIdentityPolicy,
) -> WorkloadIdentityTransitionSnapshot:
    """Irreversibly enter and verify the configured Linux workload identity."""

    syscalls = _get_syscalls()
    source = syscalls.read_identity()
    _validate_source_identity(source)
    _validate_target_policy(policy, source)
    syscalls.validate_capability_abi()

    syscalls.set_no_new_privs()
    syscalls.clear_ambient_capabilities()
    syscalls.clear_supplementary_groups()

    target = policy.identity
    syscalls.setresgid(target.gid)
    syscalls.setresuid(target.uid)

    filesystem_uid, filesystem_gid = syscalls.read_filesystem_ids()
    if (
        filesystem_uid != target.uid
        or filesystem_gid != target.gid
    ):
        raise WorkloadIdentityTransitionError(
            "post-drop filesystem identity is invalid"
        )

    syscalls.clear_capability_sets()

    identity = syscalls.read_identity()
    _verify_post_drop_identity(identity, policy)

    effective, permitted, inheritable = syscalls.read_capability_sets()
    if effective or permitted or inheritable:
        raise WorkloadIdentityTransitionError(
            "post-drop Linux capabilities are not empty"
        )

    no_new_privs = syscalls.get_no_new_privs()
    if no_new_privs != 1:
        raise WorkloadIdentityTransitionError(
            "post-drop no_new_privs is not enabled"
        )

    return WorkloadIdentityTransitionSnapshot(
        identity=identity,
        filesystem_uid=filesystem_uid,
        filesystem_gid=filesystem_gid,
        no_new_privs=True,
        effective_capabilities=effective,
        permitted_capabilities=permitted,
        inheritable_capabilities=inheritable,
        ambient_capabilities_empty=True,
    )
