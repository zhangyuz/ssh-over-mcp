from __future__ import annotations

import importlib
import os
import socket
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from ssh_over_mcp.host_agent.containment_manager_endpoint import (
    ContainmentManagerEndpointError,
    UnixManagerEndpointPolicy,
)
from ssh_over_mcp.host_agent.containment_manager_identity import (
    LinuxProcessIdentity,
    LinuxProcessIdentityError,
    LinuxProcessIdentityPolicy,
)


def _service_module():
    try:
        return importlib.import_module(
            "ssh_over_mcp.host_agent.containment_manager_service"
        )
    except ModuleNotFoundError:
        pytest.fail("containment manager service module is missing")


@pytest.mark.parametrize(
    "failure_case",
    ["real_uid", "effective_uid", "saved_uid", "supplementary_groups"],
)
def test_identity_failure_happens_before_listener_creation(
    monkeypatch,
    failure_case: str,
):
    module = _service_module()
    events: list[str] = []

    def fail_identity(_policy):
        events.append("identity")
        raise LinuxProcessIdentityError(failure_case)

    def create_listener(_policy):
        events.append("listener")
        return SimpleNamespace(close=lambda: None)

    monkeypatch.setattr(module, "require_linux_process_identity", fail_identity)
    monkeypatch.setattr(
        module.UnixContainmentManagerListener,
        "create",
        create_listener,
    )

    with pytest.raises(LinuxProcessIdentityError):
        module.ContainmentManagerService.create(
            identity_policy=object(),
            endpoint_policy=object(),
            peer_policy=object(),
            dispatcher=object(),
        )

    assert events == ["identity"]


def test_valid_identity_creates_listener_once(monkeypatch):
    module = _service_module()
    events: list[str] = []
    listener = SimpleNamespace(close=lambda: None)

    monkeypatch.setattr(
        module,
        "require_linux_process_identity",
        lambda _policy: events.append("identity"),
    )

    def create_listener(_policy):
        events.append("listener")
        return listener

    monkeypatch.setattr(
        module.UnixContainmentManagerListener,
        "create",
        create_listener,
    )

    service = module.ContainmentManagerService.create(
        identity_policy=object(),
        endpoint_policy=object(),
        peer_policy=object(),
        dispatcher=object(),
    )

    assert events == ["identity", "listener"]
    service.close()


def test_service_close_delegates_once_and_is_idempotent(monkeypatch):
    module = _service_module()
    close_calls: list[str] = []
    listener = SimpleNamespace(
        close=lambda: close_calls.append("close")
    )

    monkeypatch.setattr(
        module,
        "require_linux_process_identity",
        lambda _policy: None,
    )
    monkeypatch.setattr(
        module.UnixContainmentManagerListener,
        "create",
        lambda _policy: listener,
    )

    service = module.ContainmentManagerService.create(
        identity_policy=object(),
        endpoint_policy=object(),
        peer_policy=object(),
        dispatcher=object(),
    )

    service.close()
    service.close()

    assert close_calls == ["close"]


def _current_identity_policy() -> LinuxProcessIdentityPolicy:
    return LinuxProcessIdentityPolicy(
        identity=LinuxProcessIdentity(uid=os.getuid(), gid=os.getgid()),
        supplementary_gids=frozenset(set(os.getgroups()) - {os.getgid()}),
    )


def _endpoint_policy(endpoint: Path) -> UnixManagerEndpointPolicy:
    return UnixManagerEndpointPolicy(
        path=endpoint,
        directory_uid=os.getuid(),
        directory_gid=os.getgid(),
        socket_uid=os.getuid(),
        socket_gid=os.getgid(),
        socket_mode=0o600,
        backlog=4,
    )


def _create_real_service(tmp_path: Path):
    module = _service_module()
    parent = tmp_path / "manager"
    parent.mkdir()
    parent.chmod(0o700)
    endpoint = parent / "manager.sock"
    service = module.ContainmentManagerService.create(
        identity_policy=_current_identity_policy(),
        endpoint_policy=_endpoint_policy(endpoint),
        peer_policy=object(),
        dispatcher=object(),
    )
    return service, endpoint


def test_service_close_removes_still_owned_socket(tmp_path: Path):
    service, endpoint = _create_real_service(tmp_path)

    assert stat.S_ISSOCK(endpoint.lstat().st_mode)

    service.close()

    assert not endpoint.exists()


def test_service_close_accepts_already_absent_endpoint(tmp_path: Path):
    service, endpoint = _create_real_service(tmp_path)
    endpoint.unlink()

    service.close()

    assert not endpoint.exists()


@pytest.mark.parametrize(
    "replacement_kind",
    ["regular_file", "symlink", "different_socket"],
)
def test_service_close_preserves_replacement_path(
    tmp_path: Path,
    replacement_kind: str,
):
    service, endpoint = _create_real_service(tmp_path)
    endpoint.unlink()
    replacement_socket = None

    if replacement_kind == "regular_file":
        endpoint.write_text("replacement", encoding="utf-8")
    elif replacement_kind == "symlink":
        target = endpoint.parent / "replacement-target"
        target.write_text("sentinel", encoding="utf-8")
        endpoint.symlink_to(target)
    else:
        replacement_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        replacement_socket.bind(os.fspath(endpoint))

    try:
        before = endpoint.lstat()
        with pytest.raises(
            ContainmentManagerEndpointError,
            match="changed before cleanup",
        ):
            service.close()
        after = endpoint.lstat()
        assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
    finally:
        if replacement_socket is not None:
            replacement_socket.close()
            endpoint.unlink(missing_ok=True)
