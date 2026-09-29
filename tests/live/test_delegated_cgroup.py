from __future__ import annotations

import ctypes
import errno
import json
import os
import select
import signal
import stat
import sys
import time
import traceback
from dataclasses import dataclass
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.cgroup_v2 import CgroupV2Backend
from ssh_over_mcp.host_agent.containment import (
    REQUIRED_CGROUP_V2_CONTROLLERS,
    ContainmentLimits,
    ContainmentRequest,
)
from ssh_over_mcp.host_agent.containment_manager import (
    ContainmentManagerDispatcher,
)
from ssh_over_mcp.host_agent.containment_manager_identity import (
    ContainmentServiceIdentityPlan,
    LinuxProcessIdentity,
    require_linux_process_identity,
)
from ssh_over_mcp.host_agent.containment_manager_service import (
    ContainmentManagerService,
)
from ssh_over_mcp.host_agent.containment_manager_unix import (
    connect_authenticated_containment_manager,
)
from ssh_over_mcp.host_agent.file_identity import sha256_fd
from ssh_over_mcp.host_agent.policy import HostChildLimits, HostObjectIdentity
from ssh_over_mcp.host_agent.prepare import PreparedCommand
from ssh_over_mcp.host_agent.run import run_prepared_native
from ssh_over_mcp.ssh.protocol import ExecutionLimits

_RUN_LIVE = os.environ.get("SSH_OVER_MCP_RUN_LIVE_CGROUP") == "1"
pytestmark = pytest.mark.skipif(
    not _RUN_LIVE or not sys.platform.startswith("linux"),
    reason="dedicated Linux delegated-cgroup probe only",
)

_ROOT_ENV = "SSH_OVER_MCP_LIVE_CGROUP_ROOT"
_HOST_SOURCE_ENV = "SSH_OVER_MCP_LIVE_CGROUP_HOST_SOURCE"
_SOURCE_PID_ENV = "SSH_OVER_MCP_LIVE_CGROUP_SOURCE_PID"
_MANAGER_UID_ENV = "SSH_OVER_MCP_LIVE_CGROUP_MANAGER_UID"
_MANAGER_GID_ENV = "SSH_OVER_MCP_LIVE_CGROUP_MANAGER_GID"
_HOST_UID_ENV = "SSH_OVER_MCP_LIVE_CGROUP_HOST_UID"
_HOST_GID_ENV = "SSH_OVER_MCP_LIVE_CGROUP_HOST_GID"
_WORKLOAD_UID_ENV = "SSH_OVER_MCP_LIVE_CGROUP_WORKLOAD_UID"
_WORKLOAD_GID_ENV = "SSH_OVER_MCP_LIVE_CGROUP_WORKLOAD_GID"
_MANAGER_CLIENT_GID_ENV = "SSH_OVER_MCP_LIVE_CGROUP_MANAGER_CLIENT_GID"


@dataclass(frozen=True, slots=True)
class _Cgroup2Mount:
    root: Path
    mountpoint: Path


@dataclass(frozen=True, slots=True)
class _LiveFixture:
    root: Path
    host_source: Path
    identities: ContainmentServiceIdentityPlan


def _required_id(name: str) -> int:
    raw = os.environ.get(name)
    assert raw is not None and raw != "", f"{name} is required for the live cgroup fixture"
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise AssertionError(f"{name} must be a decimal integer") from exc
    assert 0 < value < (1 << 32) - 1, (
        f"{name} must be a non-root, non-sentinel Linux uid/gid"
    )
    return value


def _fixture() -> _LiveFixture:
    raw_root = os.environ.get(_ROOT_ENV)
    assert raw_root, f"{_ROOT_ENV} is required for the live cgroup fixture"
    root = Path(raw_root)
    assert root.is_absolute(), f"{_ROOT_ENV} must be absolute"

    raw_source = os.environ.get(_HOST_SOURCE_ENV)
    assert raw_source, f"{_HOST_SOURCE_ENV} is required for the live cgroup fixture"
    host_source = Path(raw_source)
    assert host_source.is_absolute(), f"{_HOST_SOURCE_ENV} must be absolute"

    identities = ContainmentServiceIdentityPlan(
        manager=LinuxProcessIdentity(
            uid=_required_id(_MANAGER_UID_ENV),
            gid=_required_id(_MANAGER_GID_ENV),
        ),
        host_agent=LinuxProcessIdentity(
            uid=_required_id(_HOST_UID_ENV),
            gid=_required_id(_HOST_GID_ENV),
        ),
        workload=LinuxProcessIdentity(
            uid=_required_id(_WORKLOAD_UID_ENV),
            gid=_required_id(_WORKLOAD_GID_ENV),
        ),
        manager_client_gid=_required_id(_MANAGER_CLIENT_GID_ENV),
    )
    assert identities.manager.uid != 0 and identities.manager.gid != 0
    return _LiveFixture(
        root=root,
        host_source=host_source,
        identities=identities,
    )


def _required_pid(name: str) -> int:
    raw = os.environ.get(name)
    assert raw is not None and raw != "", f"{name} is required for the live cgroup fixture"
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise AssertionError(f"{name} must be a decimal integer") from exc
    assert value > 1, f"{name} must be a positive non-init PID"
    return value


def _decode_mountinfo_path(raw: str) -> Path:
    decoded = (
        raw.replace(r"\040", " ")
        .replace(r"\011", "\t")
        .replace(r"\012", "\n")
        .replace(r"\134", "\\")
    )
    return Path(decoded)


def _cgroup2_mount_for(root: Path) -> _Cgroup2Mount:
    candidates: list[_Cgroup2Mount] = []
    raw = Path("/proc/self/mountinfo").read_text(encoding="ascii")
    for line in raw.splitlines():
        if " - cgroup2 " not in line:
            continue
        before, _separator, _after = line.partition(" - ")
        fields = before.split()
        assert len(fields) >= 5, "invalid /proc/self/mountinfo cgroup2 record"
        mount = _Cgroup2Mount(
            root=_decode_mountinfo_path(fields[3]),
            mountpoint=_decode_mountinfo_path(fields[4]).resolve(strict=True),
        )
        if root == mount.mountpoint or root.is_relative_to(mount.mountpoint):
            candidates.append(mount)

    assert candidates, "configured delegated root is not inside a cgroup-v2 mount"
    return max(candidates, key=lambda item: len(item.mountpoint.parts))


def _cgroup_path_from_proc_file(
    proc_cgroup: Path,
    mount: _Cgroup2Mount,
) -> Path:
    unified_path: Path | None = None
    raw = proc_cgroup.read_text(encoding="ascii")
    for line in raw.splitlines():
        hierarchy, controllers, value = line.split(":", 2)
        if hierarchy == "0" and controllers == "":
            unified_path = Path(value)
            break

    assert unified_path is not None, "unified cgroup-v2 membership is unavailable"
    try:
        relative = unified_path.relative_to(mount.root)
    except ValueError as exc:
        raise AssertionError(
            "current process cgroup is outside the selected cgroup-v2 mount root"
        ) from exc
    return (mount.mountpoint / relative).resolve(strict=True)


def _current_cgroup_path(mount: _Cgroup2Mount) -> Path:
    return _cgroup_path_from_proc_file(Path("/proc/self/cgroup"), mount)


def _pid_cgroup_path(pid: int, mount: _Cgroup2Mount) -> Path:
    return _cgroup_path_from_proc_file(Path(f"/proc/{pid}/cgroup"), mount)


def _read_proc_status(pid: int) -> dict[str, str]:
    rows: dict[str, str] = {}
    raw = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        rows[key] = value.strip()
    return rows


def _pid_start_time_ticks(pid: int) -> int:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    command_end = raw.rfind(")")
    assert command_end >= 0, "invalid /proc/<pid>/stat record"
    fields = raw[command_end + 2 :].split()
    assert len(fields) > 19, "truncated /proc/<pid>/stat record"
    return int(fields[19], 10)


def _pid_matches_start_time(pid: int, expected_start_time: int) -> bool:
    try:
        return _pid_start_time_ticks(pid) == expected_start_time
    except FileNotFoundError:
        return False


def _assert_same_process(pid: int, expected_start_time: int) -> None:
    assert _pid_matches_start_time(pid, expected_start_time), (
        "operator source PID exited or was reused during the live proof"
    )


def _assert_stopped_host_agent_fixture_process(
    fixture: _LiveFixture,
    pid: int,
    mount: _Cgroup2Mount,
    expected_cgroup: Path,
) -> None:
    rows = _read_proc_status(pid)
    assert rows["State"].split()[0] == "T", (
        "operator source PID must already be stopped"
    )

    host = fixture.identities.host_agent
    assert tuple(int(value) for value in rows["Uid"].split()) == (host.uid,) * 4
    assert tuple(int(value) for value in rows["Gid"].split()) == (host.gid,) * 4

    observed_groups = {int(value) for value in rows["Groups"].split()}
    observed_extra = observed_groups - {host.gid}
    expected_extra = set(
        fixture.identities.host_agent_process_policy().supplementary_gids
    )
    assert observed_extra == expected_extra, (
        "source PID supplementary groups do not match host-agent policy"
    )
    assert _pid_cgroup_path(pid, mount) == expected_cgroup, (
        "operator fixture PID is not resident in expected cgroup"
    )


def _wait_until_scope_empty(handle, *, timeout_seconds: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while True:
        if handle.stats().populated is False:
            return
        if time.monotonic() >= deadline:
            raise AssertionError("request cgroup did not become empty before deadline")
        time.sleep(0.01)


def _assert_no_runtime_capabilities() -> None:
    rows: dict[str, str] = {}
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        rows[key] = value.strip()

    for name in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
        assert int(rows[name], 16) == 0, f"manager must have zero {name}"


def _assert_no_posix_access_acl(path: Path) -> None:
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as exc:
        if exc.errno in {errno.ENOTSUP, errno.EOPNOTSUPP}:
            return
        raise
    assert "system.posix_acl_access" not in names, f"unexpected access ACL on {path}"


def _assert_manager_only_write(path: Path, *, uid: int, directory: bool) -> None:
    info = path.stat()
    assert info.st_uid == uid, f"{path} must be owned by manager UID {uid}"
    assert info.st_mode & stat.S_IWUSR, f"{path} must be owner-writable"
    assert not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH), (
        f"{path} must not be group/other writable"
    )
    if directory:
        assert info.st_mode & stat.S_IXUSR, f"{path} must be owner-searchable"
        assert os.access(path, os.W_OK | os.X_OK, effective_ids=True)
    else:
        assert os.access(path, os.W_OK, effective_ids=True)
    _assert_no_posix_access_acl(path)


def _write_control(path: Path, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        data = value.encode("ascii")
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            assert written > 0, f"short write to {path}"
            offset += written
    finally:
        os.close(fd)


def _read_tokens(path: Path) -> frozenset[str]:
    return frozenset(path.read_text(encoding="ascii").split())


def test_preflight_live_delegated_cgroup_fixture() -> None:
    fixture = _fixture()
    resolved = fixture.root.resolve(strict=True)
    assert resolved == fixture.root, "delegated root must already be canonical"
    assert resolved.is_dir(), "delegated root must be a directory"

    host_source = fixture.host_source.resolve(strict=True)
    assert host_source == fixture.host_source, (
        "host-agent source cgroup must already be canonical"
    )
    assert host_source.is_dir(), "host-agent source cgroup must be a directory"
    assert host_source.parent == resolved, (
        "host-agent source cgroup must be a direct child of delegated root"
    )

    mount = _cgroup2_mount_for(resolved)
    assert resolved != mount.mountpoint, "the cgroup-v2 mount root itself must never be delegated"

    identities = fixture.identities
    require_linux_process_identity(identities.manager_process_policy())
    _assert_no_runtime_capabilities()

    manager_cgroup = _current_cgroup_path(mount)
    assert manager_cgroup != resolved and not manager_cgroup.is_relative_to(resolved), (
        "containment manager process must remain outside the delegated root"
    )

    controllers_path = resolved / "cgroup.controllers"
    procs_path = resolved / "cgroup.procs"
    subtree_path = resolved / "cgroup.subtree_control"

    controllers = _read_tokens(controllers_path)
    assert REQUIRED_CGROUP_V2_CONTROLLERS.issubset(controllers)
    assert procs_path.read_text(encoding="ascii").strip() == "", (
        "delegated root must contain no member processes"
    )

    source_procs_path = host_source / "cgroup.procs"
    assert source_procs_path.exists(), "host-agent source cgroup.procs is unavailable"

    for path, directory in (
        (resolved, True),
        (procs_path, False),
        (subtree_path, False),
        (host_source, True),
        (source_procs_path, False),
    ):
        _assert_manager_only_write(
            path,
            uid=identities.manager.uid,
            directory=directory,
        )

    originally_enabled = _read_tokens(subtree_path)
    enabled_by_test = REQUIRED_CGROUP_V2_CONTROLLERS.difference(originally_enabled)
    scope = resolved / f"ssh-over-mcp-preflight-{os.getpid()}"
    assert not scope.exists(), "preflight cgroup already exists"

    cleanup_errors: list[BaseException] = []
    try:
        if enabled_by_test:
            request = " ".join(f"+{name}" for name in sorted(enabled_by_test))
            _write_control(subtree_path, f"{request}\n")

        enabled = _read_tokens(subtree_path)
        assert REQUIRED_CGROUP_V2_CONTROLLERS.issubset(enabled)

        scope.mkdir(mode=0o700)
        assert (scope / "cgroup.procs").exists()
        assert (scope / "cgroup.events").exists()
        os.rmdir(scope)
    finally:
        if scope.exists():
            try:
                os.rmdir(scope)
            except OSError as exc:
                cleanup_errors.append(exc)
        if enabled_by_test:
            try:
                request = " ".join(f"-{name}" for name in sorted(enabled_by_test))
                _write_control(subtree_path, f"{request}\n")
            except OSError as exc:
                cleanup_errors.append(exc)

    assert not cleanup_errors, f"preflight cleanup failed: {cleanup_errors!r}"
    assert _read_tokens(subtree_path) == originally_enabled



def test_real_cgroup_backend_create_attach_limits_and_cleanup() -> None:
    fixture = _fixture()
    root = fixture.root.resolve(strict=True)
    source = fixture.host_source.resolve(strict=True)
    source_pid = _required_pid(_SOURCE_PID_ENV)

    mount = _cgroup2_mount_for(root)
    identities = fixture.identities
    require_linux_process_identity(identities.manager_process_policy())
    _assert_no_runtime_capabilities()
    assert not _current_cgroup_path(mount).is_relative_to(root)
    assert source.parent == root

    source_start_time = _pid_start_time_ticks(source_pid)
    _assert_stopped_host_agent_fixture_process(
        fixture,
        source_pid,
        mount,
        source,
    )
    _assert_same_process(source_pid, source_start_time)

    subtree_path = root / "cgroup.subtree_control"
    originally_enabled = _read_tokens(subtree_path)
    enabled_by_backend = REQUIRED_CGROUP_V2_CONTROLLERS.difference(
        originally_enabled
    )

    limits = ContainmentLimits(
        memory_max_bytes=512 * 1024 * 1024,
        pids_max=64,
        cpu_quota_us=50_000,
        cpu_period_us=100_000,
    )
    request = ContainmentRequest(
        request_id=f"req_live_backend_{os.getpid()}_{source_pid}",
        limits=limits,
    )
    backend = CgroupV2Backend(root)
    handle = None
    scope: Path | None = None
    cleanup_errors: list[BaseException] = []

    try:
        handle = backend.create(request)
        scope = handle.path.resolve(strict=True)
        assert scope.parent == root
        assert scope.name == f"ssh-over-mcp-{request.request_id}"

        assert (scope / "memory.max").read_text(encoding="ascii").strip() == str(
            limits.memory_max_bytes
        )
        assert (scope / "pids.max").read_text(encoding="ascii").strip() == str(
            limits.pids_max
        )
        assert (scope / "cpu.max").read_text(encoding="ascii").strip() == (
            f"{limits.cpu_quota_us} {limits.cpu_period_us}"
        )

        empty_stats = handle.stats()
        assert empty_stats.populated is False
        assert empty_stats.pids_current == 0
        assert empty_stats.memory_current_bytes is not None
        assert empty_stats.cpu_usage_usec is not None

        _assert_same_process(source_pid, source_start_time)
        handle.attach(source_pid)
        _assert_same_process(source_pid, source_start_time)
        assert _pid_cgroup_path(source_pid, mount) == scope
        _assert_stopped_host_agent_fixture_process(
            fixture,
            source_pid,
            mount,
            scope,
        )

        attached_stats = handle.stats()
        assert attached_stats.populated is True
        assert attached_stats.pids_current is not None
        assert attached_stats.pids_current >= 1
        assert attached_stats.memory_current_bytes is not None
        assert attached_stats.cpu_usage_usec is not None

        _assert_same_process(source_pid, source_start_time)
        _write_control(source / "cgroup.procs", f"{source_pid}\n")
        _assert_same_process(source_pid, source_start_time)
        _assert_stopped_host_agent_fixture_process(
            fixture,
            source_pid,
            mount,
            source,
        )
        _wait_until_scope_empty(handle)

        handle.close()
        handle = None
        assert scope.exists() is False
    finally:
        active_exception = sys.exception()

        if handle is not None:
            try:
                if _pid_matches_start_time(source_pid, source_start_time):
                    _write_control(source / "cgroup.procs", f"{source_pid}\n")
            except BaseException as exc:  # noqa: BLE001
                cleanup_errors.append(exc)

            try:
                populated = handle.stats().populated
            except BaseException as exc:  # noqa: BLE001
                cleanup_errors.append(exc)
                populated = True

            if populated:
                try:
                    handle.kill_all()
                except BaseException as exc:  # noqa: BLE001
                    cleanup_errors.append(exc)

            try:
                _wait_until_scope_empty(handle)
                handle.close()
            except BaseException as exc:  # noqa: BLE001
                cleanup_errors.append(exc)

        if enabled_by_backend:
            try:
                request_value = " ".join(
                    f"-{name}" for name in sorted(enabled_by_backend)
                )
                _write_control(subtree_path, f"{request_value}\n")
            except BaseException as exc:  # noqa: BLE001
                cleanup_errors.append(exc)

        try:
            restored_controllers = _read_tokens(subtree_path)
        except BaseException as exc:  # noqa: BLE001
            cleanup_errors.append(exc)
        else:
            if restored_controllers != originally_enabled:
                cleanup_errors.append(
                    AssertionError(
                        "cgroup.subtree_control was not restored after backend proof"
                    )
                )

        if cleanup_errors:
            message = f"real backend cleanup failed: {cleanup_errors!r}"
            if active_exception is not None:
                active_exception.add_note(message)
            else:
                raise AssertionError(message)


_PROBE_ELF_ENV = "SSH_OVER_MCP_LIVE_CGROUP_PROBE_ELF"
_SIBLING_PROCS_ENV = "SSH_OVER_MCP_LIVE_CGROUP_SIBLING_PROCS"
_CAP_SETGID = 6
_CAP_SETUID = 7
_CAP_KILL = 5
_CAP_SYS_ADMIN = 21
_EXPECTED_HOST_CAPS = (1 << _CAP_SETGID) | (1 << _CAP_SETUID)
_LINUX_CAPABILITY_VERSION_3 = 0x20080522
_PR_SET_KEEPCAPS = 8


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


def _write_pipe_json(fd: int, payload: dict[str, object]) -> None:
    data = json.dumps(payload, sort_keys=True).encode("utf-8")
    assert len(data) <= 16384, "live fixture message exceeds pipe bound"
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        assert written > 0, "short live fixture pipe write"
        offset += written


def _read_pipe_json(fd: int, *, timeout_seconds: float) -> dict[str, object]:
    readable, _writable, _exceptional = select.select(
        [fd],
        [],
        [],
        timeout_seconds,
    )
    assert readable, "live fixture process did not report before deadline"
    data = os.read(fd, 16384)
    assert data, "live fixture process closed status pipe without a report"
    value = json.loads(data.decode("utf-8"))
    assert isinstance(value, dict)
    return value


def _waitpid_bounded(pid: int, *, timeout_seconds: float) -> int | None:
    deadline = time.monotonic() + timeout_seconds
    while True:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return status
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.01)


def _set_keepcaps(libc: ctypes.CDLL, enabled: bool) -> None:
    prctl = libc.prctl
    prctl.restype = ctypes.c_int
    ctypes.set_errno(0)
    if prctl(_PR_SET_KEEPCAPS, int(enabled), 0, 0, 0) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _set_host_transition_capabilities(libc: ctypes.CDLL) -> None:
    capset = libc.capset
    capset.restype = ctypes.c_int
    header = _CapHeader(version=_LINUX_CAPABILITY_VERSION_3, pid=0)
    data = (_CapData * 2)()
    data[0].effective = _EXPECTED_HOST_CAPS
    data[0].permitted = _EXPECTED_HOST_CAPS

    ctypes.set_errno(0)
    if capset(ctypes.byref(header), data) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _drop_to_manager_identity(plan: ContainmentServiceIdentityPlan) -> None:
    manager = plan.manager
    groups = (
        [plan.manager_client_gid]
        if plan.manager_client_gid != manager.gid
        else []
    )
    os.setgroups(groups)
    os.setresgid(manager.gid, manager.gid, manager.gid)
    os.setresuid(manager.uid, manager.uid, manager.uid)
    require_linux_process_identity(plan.manager_process_policy())
    _assert_no_runtime_capabilities()


def _drop_to_host_agent_identity(plan: ContainmentServiceIdentityPlan) -> None:
    host = plan.host_agent
    libc = ctypes.CDLL(None, use_errno=True)
    _set_keepcaps(libc, True)
    groups = (
        [plan.manager_client_gid]
        if plan.manager_client_gid != host.gid
        else []
    )
    os.setgroups(groups)
    os.setresgid(host.gid, host.gid, host.gid)
    os.setresuid(host.uid, host.uid, host.uid)
    _set_host_transition_capabilities(libc)
    _set_keepcaps(libc, False)
    require_linux_process_identity(plan.host_agent_process_policy())

    rows = _read_proc_status(os.getpid())
    effective = int(rows["CapEff"], 16)
    permitted = int(rows["CapPrm"], 16)
    inheritable = int(rows["CapInh"], 16)
    ambient = int(rows["CapAmb"], 16)
    assert effective == _EXPECTED_HOST_CAPS
    assert permitted == _EXPECTED_HOST_CAPS
    assert inheritable == 0
    assert ambient == 0
    assert not effective & (1 << _CAP_KILL)
    assert not effective & (1 << _CAP_SYS_ADMIN)
    assert rows["NoNewPrivs"] == "0"


def _object_identity(fd: int, *, bind_content: bool) -> HostObjectIdentity:
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


def _live_child_limits() -> HostChildLimits:
    return HostChildLimits(
        cpu_seconds=10,
        address_space_bytes=256 * 1024 * 1024,
        max_processes=32,
        file_size_bytes=16 * 1024 * 1024,
        open_files=64,
    )


def _prepared_probe(
    probe: Path,
    *,
    request_id: str,
    argv: tuple[str, ...],
    env: dict[str, str] | None = None,
) -> PreparedCommand:
    executable_fd = os.open(
        probe,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    cwd_fd = os.open(
        "/tmp",
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
    )
    try:
        return PreparedCommand(
            request_id=request_id,
            executable_fd=executable_fd,
            cwd_fd=cwd_fd,
            executable_path=str(probe),
            executable_identity=_object_identity(
                executable_fd,
                bind_content=True,
            ),
            cwd_path="/tmp",
            cwd_identity=_object_identity(cwd_fd, bind_content=False),
            executable_format="elf",
            argv=argv,
            env=dict(env or {}),
            fd_exec_supported=os.execve in os.supports_fd,
            child_limits=_live_child_limits(),
        )
    except BaseException:
        os.close(cwd_fd)
        os.close(executable_fd)
        raise


def _prepared_escape_probe(
    probe: Path,
    *,
    request_id: str,
    root: Path,
    sibling_procs: Path,
) -> PreparedCommand:
    return _prepared_probe(
        probe,
        request_id=request_id,
        argv=("escape-check",),
        env={
            _ROOT_ENV: str(root),
            _SIBLING_PROCS_ENV: str(sibling_procs),
        },
    )


def _unified_membership_for(scope: Path, mount: _Cgroup2Mount) -> str:
    relative = scope.relative_to(mount.mountpoint)
    return str(mount.root / relative)


def _cleanup_dispatcher_scopes(
    dispatcher: ContainmentManagerDispatcher,
) -> None:
    cleanup_errors: list[BaseException] = []
    for scope_id, managed in list(dispatcher._scopes.items()):
        handle = managed.handle
        try:
            if handle.stats().populated:
                handle.kill_all()
                _wait_until_scope_empty(handle)
            handle.close()
            del dispatcher._scopes[scope_id]
        except BaseException as exc:  # noqa: BLE001
            cleanup_errors.append(exc)
    if cleanup_errors:
        raise AssertionError(
            f"manager dispatcher cleanup failed: {cleanup_errors!r}"
        )


def _manager_process(
    fixture: _LiveFixture,
    endpoint: Path,
    ready_fd: int,
) -> None:
    service = None
    sentinel = None
    dispatcher = None
    sent_ready = False
    subtree_path = fixture.root / "cgroup.subtree_control"
    originally_enabled: frozenset[str] | None = None
    enabled_by_backend: frozenset[str] = frozenset()

    try:
        _drop_to_manager_identity(fixture.identities)
        mount = _cgroup2_mount_for(fixture.root)
        assert not _current_cgroup_path(mount).is_relative_to(fixture.root)

        originally_enabled = _read_tokens(subtree_path)
        enabled_by_backend = REQUIRED_CGROUP_V2_CONTROLLERS.difference(
            originally_enabled
        )
        backend = CgroupV2Backend(fixture.root)
        sentinel_request = ContainmentRequest(
            request_id=f"req_live_sentinel_{os.getpid()}",
            limits=ContainmentLimits(
                memory_max_bytes=128 * 1024 * 1024,
                pids_max=16,
                cpu_quota_us=50_000,
                cpu_period_us=100_000,
            ),
        )
        sentinel = backend.create(sentinel_request)
        sentinel_path = sentinel.path.resolve(strict=True)
        assert sentinel_path.parent == fixture.root
        os.chmod(sentinel_path, 0o711)

        dispatcher = ContainmentManagerDispatcher(backend)
        service = ContainmentManagerService.create(
            identity_policy=fixture.identities.manager_process_policy(),
            endpoint_policy=fixture.identities.endpoint_policy(endpoint),
            peer_policy=fixture.identities.manager_accept_peer_policy(),
            dispatcher=dispatcher,
        )
        _write_pipe_json(
            ready_fd,
            {
                "ok": True,
                "sentinel_path": str(sentinel_path),
            },
        )
        sent_ready = True

        service.serve_one()
        assert dispatcher._scopes == {}

        assert sentinel.stats().populated is False
        sentinel.close()
        sentinel = None
        service.close()
        service = None

        if enabled_by_backend:
            value = " ".join(
                f"-{name}" for name in sorted(enabled_by_backend)
            )
            _write_control(subtree_path, f"{value}\n")
        assert _read_tokens(subtree_path) == originally_enabled
        os._exit(0)
    except BaseException:  # noqa: BLE001
        if not sent_ready:
            try:
                _write_pipe_json(
                    ready_fd,
                    {
                        "ok": False,
                        "error": traceback.format_exc()[-8000:],
                    },
                )
            except BaseException as report_exc:  # noqa: BLE001
                print(
                    f"cannot report manager fixture failure: {report_exc!r}",
                    file=sys.stderr,
                )
        traceback.print_exc()
        cleanup_errors: list[BaseException] = []
        try:
            if service is not None:
                service.close()
        except BaseException as cleanup_exc:  # noqa: BLE001
            cleanup_errors.append(cleanup_exc)
        try:
            if dispatcher is not None:
                _cleanup_dispatcher_scopes(dispatcher)
        except BaseException as cleanup_exc:  # noqa: BLE001
            cleanup_errors.append(cleanup_exc)
        try:
            if sentinel is not None:
                if sentinel.stats().populated:
                    sentinel.kill_all()
                    _wait_until_scope_empty(sentinel)
                sentinel.close()
        except BaseException as cleanup_exc:  # noqa: BLE001
            cleanup_errors.append(cleanup_exc)
        if originally_enabled is not None and enabled_by_backend:
            try:
                value = " ".join(
                    f"-{name}" for name in sorted(enabled_by_backend)
                )
                _write_control(subtree_path, f"{value}\n")
            except BaseException as cleanup_exc:  # noqa: BLE001
                cleanup_errors.append(cleanup_exc)
        if originally_enabled is not None:
            try:
                if _read_tokens(subtree_path) != originally_enabled:
                    cleanup_errors.append(
                        AssertionError(
                            "cgroup.subtree_control was not restored"
                        )
                    )
            except BaseException as cleanup_exc:  # noqa: BLE001
                cleanup_errors.append(cleanup_exc)
        for cleanup_exc in cleanup_errors:
            print(
                f"manager fixture cleanup failed: {cleanup_exc!r}",
                file=sys.stderr,
            )
        os._exit(125)


def _host_agent_process(
    fixture: _LiveFixture,
    endpoint: Path,
    sentinel_path: Path,
    probe: Path,
    start_fd: int,
    result_fd: int,
) -> None:
    client = None
    prepared = None
    try:
        token = os.read(start_fd, 1)
        assert token == b"R", "host-agent bootstrap barrier was not released"

        _drop_to_host_agent_identity(fixture.identities)
        mount = _cgroup2_mount_for(fixture.root)
        assert _current_cgroup_path(mount) == fixture.host_source

        request_id = f"req_live_composition_{os.getpid()}"
        request_scope = fixture.root / f"ssh-over-mcp-{request_id}"
        prepared = _prepared_escape_probe(
            probe,
            request_id=request_id,
            root=fixture.root,
            sibling_procs=sentinel_path / "cgroup.procs",
        )
        assert prepared.argv == ("escape-check",)
        assert set(prepared.env) == {_ROOT_ENV, _SIBLING_PROCS_ENV}

        client = connect_authenticated_containment_manager(
            endpoint,
            identity_plan=fixture.identities,
            timeout_seconds=2.0,
        )
        request = ContainmentRequest(
            request_id=request_id,
            limits=ContainmentLimits(
                memory_max_bytes=128 * 1024 * 1024,
                pids_max=16,
                cpu_quota_us=50_000,
                cpu_period_us=100_000,
            ),
        )
        result = run_prepared_native(
            prepared,
            b"",
            ExecutionLimits(
                timeout_seconds=5.0,
                max_output_bytes=64 * 1024,
                max_stdin_bytes=0,
            ),
            workload_identity_policy=fixture.identities.workload_process_policy(),
            containment_backend=client,
            containment_request=request,
            term_grace_seconds=0.05,
            kill_cleanup_seconds=1.0,
        )

        assert result.returncode == 0
        assert result.stderr == b""
        records = [
            json.loads(line)
            for line in result.stdout.decode("utf-8").splitlines()
            if line
        ]
        assert len(records) == 3
        state, root_migration, sibling_migration = records
        assert state["event"] == "state"
        assert state["argc"] == 2
        assert state["env_count"] == 2
        assert state["cgroup"] == _unified_membership_for(
            request_scope,
            mount,
        )

        workload = fixture.identities.workload
        assert (state["ruid"], state["euid"], state["suid"]) == (
            workload.uid,
            workload.uid,
            workload.uid,
        )
        assert (state["rgid"], state["egid"], state["sgid"]) == (
            workload.gid,
            workload.gid,
            workload.gid,
        )
        assert state["groups"] == []
        for name in ("cap_inh", "cap_prm", "cap_eff", "cap_amb"):
            assert int(state[name], 16) == 0
        assert state["no_new_privs"] == "1"
        assert state["socket_inodes"] == []

        for record, target in (
            (root_migration, "root"),
            (sibling_migration, "sibling"),
        ):
            assert record["event"] == "migration"
            assert record["target"] == target
            assert record["outcome"] == "denied"
            assert record["errno"] in {errno.EACCES, errno.EPERM}

        assert _current_cgroup_path(mount) == fixture.host_source
        _write_pipe_json(result_fd, {"ok": True})
        os._exit(0)
    except BaseException:  # noqa: BLE001
        try:
            _write_pipe_json(
                result_fd,
                {
                    "ok": False,
                    "error": traceback.format_exc()[-12000:],
                },
            )
        except BaseException as report_exc:  # noqa: BLE001
            print(
                f"cannot report host-agent fixture failure: {report_exc!r}",
                file=sys.stderr,
            )
        traceback.print_exc()
        os._exit(125)
    finally:
        if client is not None:
            client.close()
        if prepared is not None:
            prepared.close()


def test_production_manager_client_barrier_and_migration_denial() -> None:
    assert os.geteuid() == 0, (
        "Task 4 composition proof requires the dedicated root bootstrap launcher"
    )
    fixture = _fixture()
    root = fixture.root.resolve(strict=True)
    source = fixture.host_source.resolve(strict=True)
    assert root == fixture.root
    assert source == fixture.host_source
    assert source.parent == root
    assert root.stat().st_mode & stat.S_IXOTH, (
        "delegated root must be searchable by the workload for denial probes"
    )
    assert (source / "cgroup.procs").read_text(encoding="ascii").strip() == ""

    raw_probe = os.environ.get(_PROBE_ELF_ENV)
    assert raw_probe, f"{_PROBE_ELF_ENV} is required"
    probe = Path(raw_probe).resolve(strict=True)
    assert probe == Path(raw_probe)
    assert probe.is_file()
    assert os.execve in os.supports_fd

    mount = _cgroup2_mount_for(root)
    assert not _current_cgroup_path(mount).is_relative_to(root)

    runtime_dir = Path(f"/tmp/ssh-over-mcp-live-manager-{os.getpid()}")
    assert not runtime_dir.exists()
    runtime_dir.mkdir(mode=0o700)
    os.chown(
        runtime_dir,
        fixture.identities.manager.uid,
        fixture.identities.manager_client_gid,
    )
    os.chmod(runtime_dir, 0o710)
    endpoint = runtime_dir / "manager.sock"

    manager_read, manager_write = os.pipe()
    manager_pid = os.fork()
    if manager_pid == 0:
        os.close(manager_read)
        _manager_process(fixture, endpoint, manager_write)
        os._exit(126)

    os.close(manager_write)
    host_pid: int | None = None
    host_start_write = -1
    host_result_read = -1
    sentinel_path: Path | None = None

    try:
        manager_ready = _read_pipe_json(
            manager_read,
            timeout_seconds=5.0,
        )
        assert manager_ready.get("ok") is True, manager_ready.get("error")
        sentinel_path = Path(str(manager_ready["sentinel_path"])).resolve(
            strict=True
        )
        assert sentinel_path.parent == root
        assert (sentinel_path / "cgroup.procs").exists()
        assert stat.S_IMODE(sentinel_path.stat().st_mode) == 0o711

        host_start_read, host_start_write = os.pipe()
        host_result_read, host_result_write = os.pipe()
        host_pid = os.fork()
        if host_pid == 0:
            os.close(host_start_write)
            os.close(host_result_read)
            _host_agent_process(
                fixture,
                endpoint,
                sentinel_path,
                probe,
                host_start_read,
                host_result_write,
            )
            os._exit(126)

        os.close(host_start_read)
        os.close(host_result_write)

        _write_control(source / "cgroup.procs", f"{host_pid}\n")
        assert _pid_cgroup_path(host_pid, mount) == source
        os.write(host_start_write, b"R")
        os.close(host_start_write)
        host_start_write = -1

        host_result = _read_pipe_json(
            host_result_read,
            timeout_seconds=12.0,
        )
        assert host_result.get("ok") is True, host_result.get("error")

        host_status = _waitpid_bounded(host_pid, timeout_seconds=2.0)
        assert host_status is not None
        assert os.WIFEXITED(host_status)
        assert os.WEXITSTATUS(host_status) == 0
        host_pid = None

        manager_status = _waitpid_bounded(manager_pid, timeout_seconds=3.0)
        assert manager_status is not None
        assert os.WIFEXITED(manager_status)
        assert os.WEXITSTATUS(manager_status) == 0
        manager_pid = -1

        assert (source / "cgroup.procs").read_text(
            encoding="ascii"
        ).strip() == ""
        assert sentinel_path.exists() is False
        assert endpoint.exists() is False
    finally:
        os.close(manager_read)
        if host_start_write >= 0:
            os.close(host_start_write)
        if host_result_read >= 0:
            os.close(host_result_read)

        if host_pid is not None:
            try:
                os.kill(host_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _waitpid_bounded(host_pid, timeout_seconds=1.0)

        if manager_pid > 0:
            try:
                os.kill(manager_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _waitpid_bounded(manager_pid, timeout_seconds=1.0)

        if endpoint.exists():
            endpoint.unlink()
        if runtime_dir.exists():
            runtime_dir.rmdir()


def _read_int_file(path: Path) -> int:
    return int(path.read_text(encoding="ascii").strip(), 10)


def _read_cpu_stat(path: Path) -> dict[str, int]:
    rows: dict[str, int] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        name, raw_value = line.split(None, 1)
        rows[name] = int(raw_value, 10)
    return rows


def _wait_for_scope(path: Path, *, timeout_seconds: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while True:
        if path.is_dir():
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"request scope did not appear: {path}")
        time.sleep(0.002)


def _wait_for_control_value(
    path: Path,
    expected: str,
    *,
    timeout_seconds: float = 2.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_value: str | None = None
    while True:
        try:
            last_value = path.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            last_value = None
        if last_value == expected:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{path} did not reach expected value {expected!r}; "
                f"last observed {last_value!r}"
            )
        time.sleep(0.002)


def _observe_pid_enforcement(
    scope: Path,
    *,
    expected_max: int,
    timeout_seconds: float = 5.0,
) -> dict[str, int]:
    _wait_for_scope(scope)
    _wait_for_control_value(scope / "pids.max", str(expected_max))

    observed: list[int] = []
    max_events: list[int] = []
    deadline = time.monotonic() + timeout_seconds
    while True:
        if not scope.exists():
            break
        try:
            current = _read_int_file(scope / "pids.current")
            events = _read_cpu_stat(scope / "pids.events")
        except OSError as exc:
            if exc.errno in {errno.ENOENT, errno.ENODEV}:
                break
            raise
        observed.append(current)
        assert "max" in events
        max_events.append(events["max"])
        assert current <= expected_max, (
            f"pids.current exceeded pids.max: {current} > {expected_max}"
        )
        if time.monotonic() >= deadline:
            raise AssertionError("PID enforcement scope exceeded observer deadline")
        time.sleep(0.002)

    assert observed, "PID enforcement observer captured no kernel samples"
    assert max(max_events) > 0, (
        "pids.events did not attribute a fork refusal to pids.max"
    )
    return {
        "min": min(observed),
        "max": max(observed),
        "max_events": max(max_events),
        "samples": len(observed),
    }


def _observe_cpu_enforcement(
    scope: Path,
    *,
    quota_us: int,
    period_us: int,
    timeout_seconds: float = 5.0,
) -> dict[str, int]:
    _wait_for_scope(scope)
    _wait_for_control_value(
        scope / "cpu.max",
        f"{quota_us} {period_us}",
    )

    samples: list[dict[str, int]] = []
    deadline = time.monotonic() + timeout_seconds
    while True:
        if not scope.exists():
            break
        try:
            sample = _read_cpu_stat(scope / "cpu.stat")
        except OSError as exc:
            if exc.errno in {errno.ENOENT, errno.ENODEV}:
                break
            raise
        assert "nr_throttled" in sample
        assert "throttled_usec" in sample
        if samples:
            assert sample["nr_throttled"] >= samples[-1]["nr_throttled"]
            assert sample["throttled_usec"] >= samples[-1]["throttled_usec"]
        samples.append(sample)
        if time.monotonic() >= deadline:
            raise AssertionError("CPU enforcement scope exceeded observer deadline")
        time.sleep(0.005)

    assert len(samples) >= 2, "CPU observer captured too few kernel samples"
    first = samples[0]
    last = samples[-1]
    assert last["nr_throttled"] > first["nr_throttled"], (
        "cpu.stat nr_throttled did not increase under CPU saturation"
    )
    assert last["throttled_usec"] >= first["throttled_usec"]
    return {
        "first_nr_throttled": first["nr_throttled"],
        "last_nr_throttled": last["nr_throttled"],
        "first_throttled_usec": first["throttled_usec"],
        "last_throttled_usec": last["throttled_usec"],
        "samples": len(samples),
    }


def _parse_probe_records(stdout: bytes) -> list[dict[str, object]]:
    records = [
        json.loads(line)
        for line in stdout.decode("utf-8").splitlines()
        if line
    ]
    assert all(isinstance(record, dict) for record in records)
    return records


def _host_agent_pid_cpu_process(
    fixture: _LiveFixture,
    endpoint: Path,
    probe: Path,
    start_fd: int,
    result_fd: int,
) -> None:
    client = None
    prepared = None
    try:
        token = os.read(start_fd, 1)
        assert token == b"R", "host-agent bootstrap barrier was not released"

        _drop_to_host_agent_identity(fixture.identities)
        mount = _cgroup2_mount_for(fixture.root)
        assert _current_cgroup_path(mount) == fixture.host_source

        client = connect_authenticated_containment_manager(
            endpoint,
            identity_plan=fixture.identities,
            timeout_seconds=2.0,
        )

        pid_request_id = f"req_live_pid_{os.getpid()}"
        pid_limit = 4
        prepared = _prepared_probe(
            probe,
            request_id=pid_request_id,
            argv=("fork", "16", "5000"),
        )
        pid_result = run_prepared_native(
            prepared,
            b"",
            ExecutionLimits(
                timeout_seconds=0.75,
                max_output_bytes=64 * 1024,
                max_stdin_bytes=0,
            ),
            workload_identity_policy=fixture.identities.workload_process_policy(),
            containment_backend=client,
            containment_request=ContainmentRequest(
                request_id=pid_request_id,
                limits=ContainmentLimits(
                    memory_max_bytes=128 * 1024 * 1024,
                    pids_max=pid_limit,
                    cpu_quota_us=50_000,
                    cpu_period_us=100_000,
                ),
            ),
            term_grace_seconds=0.02,
            kill_cleanup_seconds=1.0,
        )
        prepared.close()
        prepared = None

        assert pid_result.timed_out is True
        assert pid_result.containment_stats is not None
        assert pid_result.containment_stats.populated is False
        pid_records = _parse_probe_records(pid_result.stdout)
        pid_summary = next(
            record for record in pid_records
            if record.get("event") == "fork_summary"
        )
        assert int(pid_summary["attempts"]) == 16
        assert int(pid_summary["created"]) == pid_limit - 1
        assert int(pid_summary["errno"]) == errno.EAGAIN

        cpu_request_id = f"req_live_cpu_{os.getpid()}"
        cpu_quota_us = 10_000
        cpu_period_us = 100_000
        prepared = _prepared_probe(
            probe,
            request_id=cpu_request_id,
            argv=("cpu", "1500"),
        )
        cpu_result = run_prepared_native(
            prepared,
            b"",
            ExecutionLimits(
                timeout_seconds=4.0,
                max_output_bytes=64 * 1024,
                max_stdin_bytes=0,
            ),
            workload_identity_policy=fixture.identities.workload_process_policy(),
            containment_backend=client,
            containment_request=ContainmentRequest(
                request_id=cpu_request_id,
                limits=ContainmentLimits(
                    memory_max_bytes=128 * 1024 * 1024,
                    pids_max=16,
                    cpu_quota_us=cpu_quota_us,
                    cpu_period_us=cpu_period_us,
                ),
            ),
            term_grace_seconds=0.02,
            kill_cleanup_seconds=1.0,
        )
        prepared.close()
        prepared = None

        assert cpu_result.returncode == 0
        assert cpu_result.timed_out is False
        assert cpu_result.stderr == b""
        cpu_records = _parse_probe_records(cpu_result.stdout)
        assert any(
            record.get("event") == "cpu_done"
            for record in cpu_records
        )
        assert cpu_result.containment_stats is not None
        assert cpu_result.containment_stats.populated is False
        assert _current_cgroup_path(mount) == fixture.host_source

        _write_pipe_json(
            result_fd,
            {
                "ok": True,
                "pid_created": int(pid_summary["created"]),
                "pid_errno": int(pid_summary["errno"]),
            },
        )
        os._exit(0)
    except BaseException:  # noqa: BLE001
        try:
            _write_pipe_json(
                result_fd,
                {
                    "ok": False,
                    "error": traceback.format_exc()[-12000:],
                },
            )
        except BaseException as report_exc:  # noqa: BLE001
            print(
                f"cannot report PID/CPU host-agent failure: {report_exc!r}",
                file=sys.stderr,
            )
        traceback.print_exc()
        os._exit(125)
    finally:
        if prepared is not None:
            prepared.close()
        if client is not None:
            client.close()


def test_real_pid_and_cpu_enforcement() -> None:
    assert os.geteuid() == 0, (
        "Task 5 PID/CPU proof requires the dedicated root bootstrap launcher"
    )
    fixture = _fixture()
    root = fixture.root.resolve(strict=True)
    source = fixture.host_source.resolve(strict=True)
    assert root == fixture.root
    assert source == fixture.host_source
    assert source.parent == root
    assert (source / "cgroup.procs").read_text(encoding="ascii").strip() == ""

    raw_probe = os.environ.get(_PROBE_ELF_ENV)
    assert raw_probe, f"{_PROBE_ELF_ENV} is required"
    probe = Path(raw_probe).resolve(strict=True)
    assert probe == Path(raw_probe)
    assert probe.is_file()
    assert os.execve in os.supports_fd

    mount = _cgroup2_mount_for(root)
    assert not _current_cgroup_path(mount).is_relative_to(root)

    runtime_dir = Path(f"/tmp/ssh-over-mcp-live-manager-task5-{os.getpid()}")
    assert not runtime_dir.exists()
    runtime_dir.mkdir(mode=0o700)
    os.chown(
        runtime_dir,
        fixture.identities.manager.uid,
        fixture.identities.manager_client_gid,
    )
    os.chmod(runtime_dir, 0o710)
    endpoint = runtime_dir / "manager.sock"

    manager_read, manager_write = os.pipe()
    manager_pid = os.fork()
    if manager_pid == 0:
        os.close(manager_read)
        _manager_process(fixture, endpoint, manager_write)
        os._exit(126)

    os.close(manager_write)
    host_pid: int | None = None
    host_start_write = -1
    host_result_read = -1

    try:
        manager_ready = _read_pipe_json(
            manager_read,
            timeout_seconds=5.0,
        )
        assert manager_ready.get("ok") is True, manager_ready.get("error")
        sentinel_path = Path(str(manager_ready["sentinel_path"])).resolve(
            strict=True
        )
        assert sentinel_path.parent == root
        assert (sentinel_path / "cgroup.procs").exists()

        host_start_read, host_start_write = os.pipe()
        host_result_read, host_result_write = os.pipe()
        host_pid = os.fork()
        if host_pid == 0:
            os.close(host_start_write)
            os.close(host_result_read)
            _host_agent_pid_cpu_process(
                fixture,
                endpoint,
                probe,
                host_start_read,
                host_result_write,
            )
            os._exit(126)

        os.close(host_start_read)
        os.close(host_result_write)

        _write_control(source / "cgroup.procs", f"{host_pid}\n")
        assert _pid_cgroup_path(host_pid, mount) == source

        pid_scope = root / f"ssh-over-mcp-req_live_pid_{host_pid}"
        cpu_scope = root / f"ssh-over-mcp-req_live_cpu_{host_pid}"

        os.write(host_start_write, b"R")
        os.close(host_start_write)
        host_start_write = -1

        pid_observation = _observe_pid_enforcement(
            pid_scope,
            expected_max=4,
            timeout_seconds=4.0,
        )
        assert pid_observation["max"] == 4

        cpu_observation = _observe_cpu_enforcement(
            cpu_scope,
            quota_us=10_000,
            period_us=100_000,
            timeout_seconds=4.0,
        )
        assert cpu_observation["last_throttled_usec"] >= (
            cpu_observation["first_throttled_usec"]
        )

        host_result = _read_pipe_json(
            host_result_read,
            timeout_seconds=3.0,
        )
        assert host_result.get("ok") is True, host_result.get("error")
        assert int(host_result["pid_created"]) == 3
        assert int(host_result["pid_errno"]) == errno.EAGAIN
        assert pid_observation["max_events"] > 0

        host_status = _waitpid_bounded(host_pid, timeout_seconds=2.0)
        assert host_status is not None
        assert os.WIFEXITED(host_status)
        assert os.WEXITSTATUS(host_status) == 0
        host_pid = None

        manager_status = _waitpid_bounded(manager_pid, timeout_seconds=3.0)
        assert manager_status is not None
        assert os.WIFEXITED(manager_status)
        assert os.WEXITSTATUS(manager_status) == 0
        manager_pid = -1

        assert pid_scope.exists() is False
        assert cpu_scope.exists() is False
        assert sentinel_path.exists() is False
        assert endpoint.exists() is False
        assert (source / "cgroup.procs").read_text(
            encoding="ascii"
        ).strip() == ""
    finally:
        os.close(manager_read)
        if host_start_write >= 0:
            os.close(host_start_write)
        if host_result_read >= 0:
            os.close(host_result_read)

        if host_pid is not None:
            try:
                os.kill(host_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _waitpid_bounded(host_pid, timeout_seconds=1.0)

        if manager_pid > 0:
            try:
                os.kill(manager_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _waitpid_bounded(manager_pid, timeout_seconds=1.0)

        if endpoint.exists():
            endpoint.unlink()
        if runtime_dir.exists():
            runtime_dir.rmdir()


class _CreateObservationBackend:
    def __init__(
        self,
        backend,
        *,
        ready_fd: int,
        release_fd: int,
    ) -> None:
        self._backend = backend
        self._ready_fd = ready_fd
        self._release_fd = release_fd

    @property
    def name(self) -> str:
        return self._backend.name

    def create(self, request: ContainmentRequest):
        handle = self._backend.create(request)
        try:
            _write_pipe_json(
                self._ready_fd,
                {
                    "scope_id": handle.scope_id,
                },
            )
            token = os.read(self._release_fd, 1)
            assert token == b"R", (
                "memory observer did not release request creation barrier"
            )
            return handle
        except BaseException:
            if handle.stats().populated:
                handle.kill_all()
                _wait_until_scope_empty(handle)
            handle.close()
            raise
        finally:
            os.close(self._ready_fd)
            os.close(self._release_fd)
            self._ready_fd = -1
            self._release_fd = -1


def _memory_observation_baseline(
    scope: Path,
    *,
    sentinel_scope: Path,
    expected_max_bytes: int,
) -> tuple[dict[str, int], int, dict[str, int]]:
    _wait_for_scope(scope)
    _wait_for_control_value(
        scope / "memory.max",
        str(expected_max_bytes),
    )
    assert sentinel_scope.is_dir(), "sibling sentinel scope disappeared"

    baseline_events = _read_cpu_stat(scope / "memory.events")
    baseline_current = _read_int_file(scope / "memory.current")
    sentinel_baseline = _read_cpu_stat(sentinel_scope / "memory.events")
    for name in ("oom", "oom_kill"):
        assert name in baseline_events
        assert name in sentinel_baseline
        assert baseline_events[name] == 0, (
            "new request scope already recorded OOM before workload release"
        )
    return baseline_events, baseline_current, sentinel_baseline


def _observe_memory_enforcement(
    scope: Path,
    *,
    sentinel_scope: Path,
    baseline_events: dict[str, int],
    baseline_current: int,
    sentinel_baseline: dict[str, int],
    timeout_seconds: float = 5.0,
) -> dict[str, int]:
    peak_current = baseline_current
    observed_events = baseline_events
    deadline = time.monotonic() + timeout_seconds

    while True:
        assert sentinel_scope.is_dir(), (
            "sibling sentinel scope disappeared during memory pressure"
        )
        sentinel_events = _read_cpu_stat(sentinel_scope / "memory.events")
        assert sentinel_events["oom"] == sentinel_baseline["oom"]
        assert sentinel_events["oom_kill"] == sentinel_baseline["oom_kill"]

        try:
            current = _read_int_file(scope / "memory.current")
            events = _read_cpu_stat(scope / "memory.events")
        except OSError as exc:
            if exc.errno in {errno.ENOENT, errno.ENODEV}:
                break
            raise

        peak_current = max(peak_current, current)
        observed_events = events
        oom_delta = events["oom"] - baseline_events["oom"]
        oom_kill_delta = events["oom_kill"] - baseline_events["oom_kill"]
        if oom_delta > 0 or oom_kill_delta > 0:
            return {
                "baseline_current": baseline_current,
                "after_current": current,
                "peak_current": peak_current,
                "baseline_oom": baseline_events["oom"],
                "after_oom": events["oom"],
                "baseline_oom_kill": baseline_events["oom_kill"],
                "after_oom_kill": events["oom_kill"],
                "sentinel_oom": sentinel_events["oom"],
                "sentinel_oom_kill": sentinel_events["oom_kill"],
            }

        if time.monotonic() >= deadline:
            raise AssertionError(
                "memory.events did not attribute OOM pressure before deadline; "
                f"last events={observed_events!r}"
            )
        time.sleep(0.002)

    raise AssertionError(
        "request scope disappeared before memory.events OOM attribution "
        f"was observed; last events={observed_events!r}"
    )

def _host_agent_memory_process(
    fixture: _LiveFixture,
    endpoint: Path,
    probe: Path,
    start_fd: int,
    result_fd: int,
    create_ready_fd: int,
    create_release_fd: int,
) -> None:
    client = None
    prepared = None
    try:
        token = os.read(start_fd, 1)
        assert token == b"R", "host-agent bootstrap barrier was not released"

        _drop_to_host_agent_identity(fixture.identities)
        mount = _cgroup2_mount_for(fixture.root)
        assert _current_cgroup_path(mount) == fixture.host_source

        client = connect_authenticated_containment_manager(
            endpoint,
            identity_plan=fixture.identities,
            timeout_seconds=2.0,
        )

        request_id = f"req_live_memory_{os.getpid()}"
        memory_max_bytes = 32 * 1024 * 1024
        allocation_bytes = 64 * 1024 * 1024
        prepared = _prepared_probe(
            probe,
            request_id=request_id,
            argv=("memory", str(allocation_bytes), "100"),
        )
        observed_backend = _CreateObservationBackend(
            client,
            ready_fd=create_ready_fd,
            release_fd=create_release_fd,
        )
        result = run_prepared_native(
            prepared,
            b"",
            ExecutionLimits(
                timeout_seconds=5.0,
                max_output_bytes=64 * 1024,
                max_stdin_bytes=0,
            ),
            workload_identity_policy=fixture.identities.workload_process_policy(),
            containment_backend=observed_backend,
            containment_request=ContainmentRequest(
                request_id=request_id,
                limits=ContainmentLimits(
                    memory_max_bytes=memory_max_bytes,
                    pids_max=16,
                    cpu_quota_us=50_000,
                    cpu_period_us=100_000,
                ),
            ),
            term_grace_seconds=0.02,
            kill_cleanup_seconds=1.0,
        )
        prepared.close()
        prepared = None

        assert result.timed_out is False
        assert result.output_exceeded is False
        assert result.containment_stats is not None
        assert result.containment_stats.populated is False

        records = _parse_probe_records(result.stdout)
        state = next(
            record
            for record in records
            if record.get("event") == "state"
        )
        assert state["cgroup"] == _unified_membership_for(
            fixture.root / f"ssh-over-mcp-{request_id}",
            mount,
        )

        allocation_failures = [
            record
            for record in records
            if record.get("event") == "memory_alloc"
            and record.get("outcome") == "failed"
        ]
        completed = any(
            record.get("event") == "memory_done"
            for record in records
        )
        killed_by_sigkill = result.returncode == -signal.SIGKILL

        assert not completed, (
            "memory workload unexpectedly completed beyond memory.max"
        )
        assert killed_by_sigkill or (
            result.returncode == 71 and len(allocation_failures) == 1
        ), (
            "memory workload termination was not consistent with "
            "cgroup OOM or allocation failure"
        )
        assert _current_cgroup_path(mount) == fixture.host_source

        _write_pipe_json(
            result_fd,
            {
                "ok": True,
                "returncode": result.returncode,
                "killed_by_sigkill": killed_by_sigkill,
                "allocation_failure": len(allocation_failures) == 1,
            },
        )
        os._exit(0)
    except BaseException:  # noqa: BLE001
        try:
            _write_pipe_json(
                result_fd,
                {
                    "ok": False,
                    "error": traceback.format_exc()[-12000:],
                },
            )
        except BaseException as report_exc:  # noqa: BLE001
            print(
                f"cannot report memory host-agent failure: {report_exc!r}",
                file=sys.stderr,
            )
        traceback.print_exc()
        os._exit(125)
    finally:
        if prepared is not None:
            prepared.close()
        if client is not None:
            client.close()


def test_real_memory_enforcement_with_request_scope_oom_attribution() -> None:
    assert os.geteuid() == 0, (
        "Task 6 memory proof requires the dedicated root bootstrap launcher"
    )
    fixture = _fixture()
    root = fixture.root.resolve(strict=True)
    source = fixture.host_source.resolve(strict=True)
    assert root == fixture.root
    assert source == fixture.host_source
    assert source.parent == root
    assert (source / "cgroup.procs").read_text(encoding="ascii").strip() == ""

    raw_probe = os.environ.get(_PROBE_ELF_ENV)
    assert raw_probe, f"{_PROBE_ELF_ENV} is required"
    probe = Path(raw_probe).resolve(strict=True)
    assert probe == Path(raw_probe)
    assert probe.is_file()
    assert os.execve in os.supports_fd

    mount = _cgroup2_mount_for(root)
    assert not _current_cgroup_path(mount).is_relative_to(root)

    runtime_dir = Path(f"/tmp/ssh-over-mcp-live-manager-task6-{os.getpid()}")
    assert not runtime_dir.exists()
    runtime_dir.mkdir(mode=0o700)
    os.chown(
        runtime_dir,
        fixture.identities.manager.uid,
        fixture.identities.manager_client_gid,
    )
    os.chmod(runtime_dir, 0o710)
    endpoint = runtime_dir / "manager.sock"

    manager_read, manager_write = os.pipe()
    manager_pid = os.fork()
    if manager_pid == 0:
        os.close(manager_read)
        _manager_process(fixture, endpoint, manager_write)
        os._exit(126)

    os.close(manager_write)
    host_pid: int | None = None
    host_start_write = -1
    host_result_read = -1
    create_ready_read = -1
    create_release_write = -1

    try:
        manager_ready = _read_pipe_json(
            manager_read,
            timeout_seconds=5.0,
        )
        assert manager_ready.get("ok") is True, manager_ready.get("error")
        sentinel_path = Path(str(manager_ready["sentinel_path"])).resolve(
            strict=True
        )
        assert sentinel_path.parent == root
        assert (sentinel_path / "memory.events").exists()

        host_start_read, host_start_write = os.pipe()
        host_result_read, host_result_write = os.pipe()
        create_ready_read, create_ready_write = os.pipe()
        create_release_read, create_release_write = os.pipe()
        host_pid = os.fork()
        if host_pid == 0:
            os.close(host_start_write)
            os.close(host_result_read)
            os.close(create_ready_read)
            os.close(create_release_write)
            _host_agent_memory_process(
                fixture,
                endpoint,
                probe,
                host_start_read,
                host_result_write,
                create_ready_write,
                create_release_read,
            )
            os._exit(126)

        os.close(host_start_read)
        os.close(host_result_write)
        os.close(create_ready_write)
        os.close(create_release_read)

        _write_control(source / "cgroup.procs", f"{host_pid}\n")
        assert _pid_cgroup_path(host_pid, mount) == source

        memory_scope = root / f"ssh-over-mcp-req_live_memory_{host_pid}"
        os.write(host_start_write, b"R")
        os.close(host_start_write)
        host_start_write = -1

        created = _read_pipe_json(
            create_ready_read,
            timeout_seconds=3.0,
        )
        assert created["scope_id"] == memory_scope.name
        (
            baseline_events,
            baseline_current,
            sentinel_baseline,
        ) = _memory_observation_baseline(
            memory_scope,
            sentinel_scope=sentinel_path,
            expected_max_bytes=32 * 1024 * 1024,
        )
        os.write(create_release_write, b"R")
        os.close(create_release_write)
        create_release_write = -1

        observation = _observe_memory_enforcement(
            memory_scope,
            sentinel_scope=sentinel_path,
            baseline_events=baseline_events,
            baseline_current=baseline_current,
            sentinel_baseline=sentinel_baseline,
            timeout_seconds=4.0,
        )
        assert (
            observation["after_oom"] > observation["baseline_oom"]
            or observation["after_oom_kill"]
            > observation["baseline_oom_kill"]
        )
        assert observation["peak_current"] > observation["baseline_current"]
        assert observation["peak_current"] <= 64 * 1024 * 1024
        assert observation["sentinel_oom"] == 0
        assert observation["sentinel_oom_kill"] == 0
        assert sentinel_path.is_dir(), (
            "sibling sentinel did not survive request-scope OOM"
        )

        host_result = _read_pipe_json(
            host_result_read,
            timeout_seconds=4.0,
        )
        assert host_result.get("ok") is True, host_result.get("error")
        killed_by_sigkill = bool(host_result["killed_by_sigkill"])
        allocation_failure = bool(host_result["allocation_failure"])
        assert killed_by_sigkill or allocation_failure
        if killed_by_sigkill:
            assert observation["after_oom_kill"] > observation["baseline_oom_kill"]
        if allocation_failure:
            assert observation["after_oom"] > observation["baseline_oom"]

        host_status = _waitpid_bounded(host_pid, timeout_seconds=2.0)
        assert host_status is not None
        assert os.WIFEXITED(host_status)
        assert os.WEXITSTATUS(host_status) == 0
        host_pid = None

        manager_status = _waitpid_bounded(manager_pid, timeout_seconds=3.0)
        assert manager_status is not None
        assert os.WIFEXITED(manager_status)
        assert os.WEXITSTATUS(manager_status) == 0
        manager_pid = -1

        assert memory_scope.exists() is False
        assert sentinel_path.exists() is False
        assert endpoint.exists() is False
        assert (source / "cgroup.procs").read_text(
            encoding="ascii"
        ).strip() == ""
    finally:
        os.close(manager_read)
        if host_start_write >= 0:
            os.close(host_start_write)
        if host_result_read >= 0:
            os.close(host_result_read)
        if create_ready_read >= 0:
            os.close(create_ready_read)
        if create_release_write >= 0:
            os.close(create_release_write)

        if host_pid is not None:
            try:
                os.kill(host_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _waitpid_bounded(host_pid, timeout_seconds=1.0)

        if manager_pid > 0:
            try:
                os.kill(manager_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _waitpid_bounded(manager_pid, timeout_seconds=1.0)

        if endpoint.exists():
            endpoint.unlink()
        if runtime_dir.exists():
            runtime_dir.rmdir()
