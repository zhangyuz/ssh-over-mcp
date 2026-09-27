from __future__ import annotations

import os
import socket
import stat
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.containment_manager_endpoint import (
    ContainmentManagerEndpointError,
    UnixContainmentManagerListener,
    UnixManagerEndpointPolicy,
)


def secure_parent(tmp_path: Path) -> Path:
    parent = tmp_path / "manager"
    parent.mkdir()
    parent.chmod(0o700)
    return parent


def policy(path: Path | str) -> UnixManagerEndpointPolicy:
    return UnixManagerEndpointPolicy(
        path=path,
        directory_uid=os.getuid(),
        directory_gid=os.getgid(),
        socket_uid=os.getuid(),
        socket_gid=os.getgid(),
        socket_mode=0o600,
        backlog=4,
    )


def test_policy_normalizes_string_path(tmp_path: Path):
    parent = secure_parent(tmp_path)
    endpoint = parent / "manager.sock"

    value = policy(str(endpoint))

    assert value.path == endpoint
    assert isinstance(value.path, Path)


def test_listener_create_accept_and_close(tmp_path: Path):
    parent = secure_parent(tmp_path)
    endpoint = parent / "manager.sock"

    listener = UnixContainmentManagerListener.create(policy(endpoint))
    try:
        info = endpoint.lstat()
        assert stat.S_ISSOCK(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == 0o600
        assert info.st_uid == os.getuid()
        assert info.st_gid == os.getgid()
        assert listener.inheritable is False

        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(os.fspath(endpoint))
            accepted = listener.accept()
            try:
                assert accepted.family == socket.AF_UNIX
                assert accepted.get_inheritable() is False

                client.sendall(b"x")
                assert accepted.recv(1) == b"x"
            finally:
                accepted.close()
        finally:
            client.close()
    finally:
        listener.close()

    assert endpoint.exists() is False


def test_listener_close_is_idempotent(tmp_path: Path):
    parent = secure_parent(tmp_path)
    endpoint = parent / "manager.sock"
    listener = UnixContainmentManagerListener.create(policy(endpoint))

    listener.close()
    listener.close()

    assert not endpoint.exists()


def test_existing_regular_file_is_rejected_and_preserved(tmp_path: Path):
    parent = secure_parent(tmp_path)
    endpoint = parent / "manager.sock"
    endpoint.write_text("sentinel", encoding="utf-8")

    with pytest.raises(
        ContainmentManagerEndpointError,
        match="already exists",
    ):
        UnixContainmentManagerListener.create(policy(endpoint))

    assert endpoint.read_text(encoding="utf-8") == "sentinel"


def test_existing_socket_is_rejected_and_preserved(tmp_path: Path):
    parent = secure_parent(tmp_path)
    endpoint = parent / "manager.sock"
    existing = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        existing.bind(os.fspath(endpoint))

        with pytest.raises(
            ContainmentManagerEndpointError,
            match="already exists",
        ):
            UnixContainmentManagerListener.create(policy(endpoint))

        assert stat.S_ISSOCK(endpoint.lstat().st_mode)
    finally:
        existing.close()
        endpoint.unlink(missing_ok=True)


def test_symlink_parent_is_rejected(tmp_path: Path):
    real_parent = secure_parent(tmp_path)
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(
        ContainmentManagerEndpointError,
        match="canonical|symlink",
    ):
        UnixContainmentManagerListener.create(
            policy(linked_parent / "manager.sock")
        )


@pytest.mark.parametrize("mode", [0o720, 0o702, 0o722])
def test_group_or_world_writable_parent_is_rejected(
    tmp_path: Path,
    mode: int,
):
    parent = secure_parent(tmp_path)
    parent.chmod(mode)

    with pytest.raises(
        ContainmentManagerEndpointError,
        match="group/world writable",
    ):
        UnixContainmentManagerListener.create(
            policy(parent / "manager.sock")
        )


def test_parent_owner_mismatch_is_rejected(tmp_path: Path):
    parent = secure_parent(tmp_path)
    endpoint = parent / "manager.sock"
    wrong_uid = 0 if os.getuid() != 0 else 1

    value = UnixManagerEndpointPolicy(
        path=endpoint,
        directory_uid=wrong_uid,
        directory_gid=os.getgid(),
        socket_uid=os.getuid(),
        socket_gid=os.getgid(),
        socket_mode=0o600,
    )

    with pytest.raises(
        ContainmentManagerEndpointError,
        match="ownership",
    ):
        UnixContainmentManagerListener.create(value)


def test_relative_endpoint_path_is_rejected():
    with pytest.raises(ValueError, match="absolute"):
        policy(Path("manager.sock"))


def test_lexically_noncanonical_endpoint_path_is_rejected(tmp_path: Path):
    parent = secure_parent(tmp_path)
    raw = os.fspath(parent / ".." / parent.name / "manager.sock")

    with pytest.raises(ValueError, match="canonical"):
        policy(raw)


def test_too_long_endpoint_path_is_rejected(tmp_path: Path):
    parent = secure_parent(tmp_path)
    long_name = "s" * 108

    with pytest.raises(ValueError, match="AF_UNIX"):
        policy(parent / long_name)


@pytest.mark.parametrize("mode", [0o000, 0o640, 0o666, 0o700])
def test_socket_mode_is_restricted(mode: int, tmp_path: Path):
    parent = secure_parent(tmp_path)

    with pytest.raises(ValueError, match="0600 or 0660"):
        UnixManagerEndpointPolicy(
            path=parent / "manager.sock",
            directory_uid=os.getuid(),
            directory_gid=os.getgid(),
            socket_uid=os.getuid(),
            socket_gid=os.getgid(),
            socket_mode=mode,
        )


def test_close_does_not_unlink_replacement_path(tmp_path: Path):
    parent = secure_parent(tmp_path)
    endpoint = parent / "manager.sock"
    listener = UnixContainmentManagerListener.create(policy(endpoint))

    endpoint.unlink()
    endpoint.write_text("replacement", encoding="utf-8")

    with pytest.raises(
        ContainmentManagerEndpointError,
        match="changed before cleanup",
    ):
        listener.close()

    assert endpoint.read_text(encoding="utf-8") == "replacement"


def test_accept_after_close_fails_closed(tmp_path: Path):
    parent = secure_parent(tmp_path)
    listener = UnixContainmentManagerListener.create(
        policy(parent / "manager.sock")
    )
    listener.close()

    with pytest.raises(
        ContainmentManagerEndpointError,
        match="closed",
    ):
        listener.accept()
