from __future__ import annotations

import ctypes
import errno
import os
import sys
import time
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.containment_manager_identity import (
    LinuxProcessIdentity,
    LinuxProcessIdentityPolicy,
)
from ssh_over_mcp.host_agent.execute import exec_prepared_native_in_child
from ssh_over_mcp.host_agent.policy import HostChildLimits, HostObjectIdentity
from ssh_over_mcp.host_agent.prepare import PreparedCommand
from ssh_over_mcp.host_agent.workload_identity import (
    WorkloadIdentityTransitionSnapshot,
    transition_to_workload_identity,
)

_RUN_LIVE = os.environ.get("SSH_OVER_MCP_RUN_LIVE_WORKLOAD_IDENTITY") == "1"
pytestmark = pytest.mark.skipif(
    not _RUN_LIVE or not sys.platform.startswith("linux"),
    reason="dedicated Linux capability-transition probe only",
)
_HOST_UID = 2101
_HOST_GID = 3101
_WORKLOAD_UID = 2201
_WORKLOAD_GID = 2201
_MANAGER_CLIENT_GID = 4101

_CAP_SETGID = 6
_CAP_SETUID = 7
_EXPECTED_SOURCE_CAPS = (1 << _CAP_SETGID) | (1 << _CAP_SETUID)
_LINUX_CAPABILITY_VERSION_3 = 0x20080522
_PR_SET_KEEPCAPS = 8
_PROBE_ELF = Path("/usr/local/bin/ssh-over-mcp-identity-state-probe")


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
def _selected_status_text() -> str:
    prefixes = (
        "Uid:",
        "Gid:",
        "Groups:",
        "CapInh:",
        "CapPrm:",
        "CapEff:",
        "CapAmb:",
        "NoNewPrivs:",
    )
    status = Path("/proc/self/status").read_text(encoding="ascii")
    return "".join(
        f"{line}\n"
        for line in status.splitlines()
        if line.startswith(prefixes)
    )


def _parse_status(text: str) -> dict[str, object]:
    rows = {}
    for raw_line in text.splitlines():
        name, raw_value = raw_line.split(":", 1)
        rows[name] = raw_value.strip()

    return {
        "uid": tuple(int(value) for value in rows["Uid"].split()),
        "gid": tuple(int(value) for value in rows["Gid"].split()),
        "groups": tuple(int(value) for value in rows["Groups"].split()),
        "cap_inh": int(rows["CapInh"], 16),
        "cap_prm": int(rows["CapPrm"], 16),
        "cap_eff": int(rows["CapEff"], 16),
        "cap_amb": int(rows["CapAmb"], 16),
        "no_new_privs": int(rows["NoNewPrivs"]),
    }
def _read_status() -> dict[str, object]:
    return _parse_status(_selected_status_text())


def _assert_source_state(state: dict[str, object]) -> None:
    assert state["uid"] == (_HOST_UID,) * 4
    assert state["gid"] == (_HOST_GID,) * 4
    assert state["groups"] == (_MANAGER_CLIENT_GID,)
    assert state["cap_eff"] == _EXPECTED_SOURCE_CAPS
    assert state["cap_prm"] == _EXPECTED_SOURCE_CAPS
    assert state["cap_inh"] == 0
    assert state["cap_amb"] == 0
    assert state["no_new_privs"] == 0
    assert not (int(state["cap_eff"]) & (1 << 5))
    assert not (int(state["cap_prm"]) & (1 << 5))


def _assert_workload_state(state: dict[str, object]) -> None:
    assert state["uid"] == (_WORKLOAD_UID,) * 4
    assert state["gid"] == (_WORKLOAD_GID,) * 4
    assert state["groups"] == ()
    assert state["cap_eff"] == 0
    assert state["cap_prm"] == 0
    assert state["cap_inh"] == 0
    assert state["cap_amb"] == 0
    assert state["no_new_privs"] == 1
def _set_keepcaps(libc: ctypes.CDLL, enabled: bool) -> None:
    prctl = libc.prctl
    prctl.restype = ctypes.c_int
    ctypes.set_errno(0)
    if prctl(_PR_SET_KEEPCAPS, int(enabled), 0, 0, 0) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _set_source_capabilities(libc: ctypes.CDLL) -> None:
    capset = libc.capset
    capset.restype = ctypes.c_int
    header = _CapHeader(version=_LINUX_CAPABILITY_VERSION_3, pid=0)
    data = (_CapData * 2)()
    data[0].effective = _EXPECTED_SOURCE_CAPS
    data[0].permitted = _EXPECTED_SOURCE_CAPS

    ctypes.set_errno(0)
    if capset(ctypes.byref(header), data) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _bootstrap_host_agent() -> None:
    assert os.getresuid() == (0, 0, 0)
    libc = ctypes.CDLL(None, use_errno=True)
    _set_keepcaps(libc, True)
    os.setgroups([_MANAGER_CLIENT_GID])
    os.setresgid(_HOST_GID, _HOST_GID, _HOST_GID)
    os.setresuid(_HOST_UID, _HOST_UID, _HOST_UID)
    _set_source_capabilities(libc)
    _set_keepcaps(libc, False)
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


def _child_limits() -> HostChildLimits:
    return HostChildLimits(
        cpu_seconds=10,
        address_space_bytes=256 * 1024 * 1024,
        max_processes=16,
        file_size_bytes=16 * 1024 * 1024,
        open_files=64,
    )


def _prepared(report_fd: int) -> PreparedCommand:
    assert _PROBE_ELF.is_file()
    assert os.execve in os.supports_fd
    executable_fd = os.open(
        _PROBE_ELF,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    cwd_fd = os.open(
        "/tmp",
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY,
    )
    return PreparedCommand(
        request_id="req_live_identity",
        executable_fd=executable_fd,
        cwd_fd=cwd_fd,
        executable_path=str(_PROBE_ELF),
        executable_identity=_identity(executable_fd),
        cwd_path="/tmp",
        cwd_identity=_identity(cwd_fd),
        executable_format="elf",
        argv=(),
        env={"SSH_OVER_MCP_LIVE_REPORT_FD": str(report_fd)},
        fd_exec_supported=True,
        child_limits=_child_limits(),
    )


def _write_status_block(fd: int, label: str) -> None:
    payload = (
        f"{label}_BEGIN\n"
        f"{_selected_status_text()}"
        f"{label}_END\n"
    ).encode("ascii")
    os.write(fd, payload)


def _read_status_block(stream, label: str) -> dict[str, object]:
    first = stream.readline()
    assert first == f"{label}_BEGIN\n", first.rstrip()
    lines: list[str] = []
    for line in stream:
        if line == f"{label}_END\n":
            return _parse_status("".join(lines))
        lines.append(line)
    raise AssertionError(f"{label} status block ended unexpectedly")
def _expect_eperm(operation, label: str) -> None:
    try:
        operation()
    except OSError as exc:
        assert exc.errno == errno.EPERM, f"{label}: {exc!r}"
    else:
        raise AssertionError(f"{label} unexpectedly succeeded")


def _assert_snapshot(snapshot: WorkloadIdentityTransitionSnapshot) -> None:
    identity = snapshot.identity
    assert (
        identity.real_uid,
        identity.effective_uid,
        identity.saved_uid,
    ) == (_WORKLOAD_UID,) * 3
    assert (
        identity.real_gid,
        identity.effective_gid,
        identity.saved_gid,
    ) == (_WORKLOAD_GID,) * 3
    assert identity.supplementary_gids == ()
    assert snapshot.filesystem_uid == _WORKLOAD_UID
    assert snapshot.filesystem_gid == _WORKLOAD_GID
    assert snapshot.no_new_privs is True
    assert snapshot.effective_capabilities == 0
    assert snapshot.permitted_capabilities == 0
    assert snapshot.inheritable_capabilities == 0
    assert snapshot.ambient_capabilities_empty is True
def _run_child(
    prepared: PreparedCommand,
    report_fd: int,
    release_fd: int,
) -> None:
    try:
        policy = LinuxProcessIdentityPolicy(
            identity=LinuxProcessIdentity(
                uid=_WORKLOAD_UID,
                gid=_WORKLOAD_GID,
            ),
            supplementary_gids=frozenset(),
        )
        snapshot = transition_to_workload_identity(policy)
        _assert_snapshot(snapshot)
        _assert_workload_state(_read_status())

        _expect_eperm(
            lambda: os.setresuid(_HOST_UID, _HOST_UID, _HOST_UID),
            "restore host-agent uid",
        )
        _expect_eperm(
            lambda: os.setresgid(_HOST_GID, _HOST_GID, _HOST_GID),
            "restore host-agent gid",
        )
        _expect_eperm(
            lambda: os.setgroups([_MANAGER_CLIENT_GID]),
            "restore manager-client group",
        )
        _assert_workload_state(_read_status())
        _write_status_block(report_fd, "PRE")
        assert os.read(release_fd, 1) == b"1"
        os.set_inheritable(report_fd, True)
        exec_prepared_native_in_child(prepared)
    except BaseException as exc:  # noqa: BLE001
        try:
            message = f"ERROR {type(exc).__name__}: {exc}\n"
            os.write(report_fd, message.encode("utf-8", errors="replace"))
        finally:
            os._exit(125)
    os._exit(126)


def _wait_bounded(pid: int, timeout_seconds: float = 5.0) -> int:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        waited_pid, status = os.waitpid(pid, os.WNOHANG)
        if waited_pid == pid:
            return status
        time.sleep(0.01)
    raise AssertionError("live workload child did not exit within cleanup bound")


def test_live_workload_identity_transition_and_native_exec() -> None:
    _bootstrap_host_agent()
    parent_before = _read_status()
    _assert_source_state(parent_before)

    report_read, report_write = os.pipe()
    release_read, release_write = os.pipe()
    prepared = _prepared(report_write)
    pid = os.fork()
    if pid == 0:
        os.close(report_read)
        os.close(release_write)
        _run_child(prepared, report_write, release_read)

    os.close(report_write)
    os.close(release_read)
    prepared.close()
    stream = os.fdopen(report_read, "r", encoding="ascii", buffering=1)
    released = False

    try:
        pre_exec = _read_status_block(stream, "PRE")
        _assert_workload_state(pre_exec)

        parent_after_drop = _read_status()
        assert parent_after_drop == parent_before

        with pytest.raises(PermissionError) as denied:
            os.kill(pid, 0)
        assert denied.value.errno == errno.EPERM

        os.write(release_write, b"1")
        os.close(release_write)
        released = True

        post_exec = _read_status_block(stream, "POST")
        _assert_workload_state(post_exec)

        status = _wait_bounded(pid)
        assert os.WIFEXITED(status)
        assert os.WEXITSTATUS(status) == 0
        assert _read_status() == parent_before
    finally:
        if not released:
            try:
                os.close(release_write)
            except OSError:
                pass
        stream.close()
