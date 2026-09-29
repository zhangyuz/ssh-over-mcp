from __future__ import annotations

import errno
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.containment import REQUIRED_CGROUP_V2_CONTROLLERS
from ssh_over_mcp.host_agent.containment_manager_identity import (
    ContainmentServiceIdentityPlan,
    LinuxProcessIdentity,
    require_linux_process_identity,
)

_RUN_LIVE = os.environ.get("SSH_OVER_MCP_RUN_LIVE_CGROUP") == "1"
pytestmark = pytest.mark.skipif(
    not _RUN_LIVE or not sys.platform.startswith("linux"),
    reason="dedicated Linux delegated-cgroup probe only",
)

_ROOT_ENV = "SSH_OVER_MCP_LIVE_CGROUP_ROOT"
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
    return _LiveFixture(root=root, identities=identities)


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


def _current_cgroup_path(mount: _Cgroup2Mount) -> Path:
    unified_path: Path | None = None
    raw = Path("/proc/self/cgroup").read_text(encoding="ascii")
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

    for path, directory in (
        (resolved, True),
        (procs_path, False),
        (subtree_path, False),
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
