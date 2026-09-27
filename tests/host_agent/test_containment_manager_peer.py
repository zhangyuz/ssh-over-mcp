from __future__ import annotations

import os
import socket

import pytest

from ssh_over_mcp.host_agent.containment import ContainmentUnavailableError
from ssh_over_mcp.host_agent.containment_manager_peer import (
    ContainmentManagerPeerAuthError,
    LinuxPeerCredentialPolicy,
    authenticate_linux_unix_peer,
    read_linux_unix_peer_credentials,
)


def socket_pair() -> tuple[socket.socket, socket.socket]:
    if not hasattr(socket, "SO_PEERCRED"):
        pytest.skip("Linux SO_PEERCRED is required")
    return socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)


def different_kernel_id(value: int) -> int:
    return 0 if value != 0 else 1


def test_read_peer_credentials_are_kernel_supplied():
    client, server = socket_pair()
    try:
        credentials = read_linux_unix_peer_credentials(client)

        assert credentials.pid == os.getpid()
        assert credentials.uid == os.getuid()
        assert credentials.gid == os.getgid()
    finally:
        client.close()
        server.close()


def test_peer_policy_accepts_exact_uid_and_gid():
    client, server = socket_pair()
    try:
        credentials = authenticate_linux_unix_peer(
            client,
            LinuxPeerCredentialPolicy(
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            ),
        )

        assert credentials.uid == os.getuid()
        assert credentials.gid == os.getgid()
    finally:
        client.close()
        server.close()


def test_peer_policy_can_authorize_by_uid_only():
    client, server = socket_pair()
    try:
        credentials = authenticate_linux_unix_peer(
            client,
            LinuxPeerCredentialPolicy(
                expected_uid=os.getuid(),
            ),
        )

        assert credentials.uid == os.getuid()
    finally:
        client.close()
        server.close()


def test_wrong_uid_is_rejected_without_identity_detail():
    client, server = socket_pair()
    try:
        with pytest.raises(
            ContainmentManagerPeerAuthError,
            match="peer is not authorized",
        ) as excinfo:
            authenticate_linux_unix_peer(
                client,
                LinuxPeerCredentialPolicy(
                    expected_uid=different_kernel_id(os.getuid()),
                ),
            )

        assert str(os.getuid()) not in str(excinfo.value)
    finally:
        client.close()
        server.close()


def test_wrong_gid_is_rejected_without_identity_detail():
    client, server = socket_pair()
    try:
        with pytest.raises(
            ContainmentManagerPeerAuthError,
            match="peer is not authorized",
        ) as excinfo:
            authenticate_linux_unix_peer(
                client,
                LinuxPeerCredentialPolicy(
                    expected_uid=os.getuid(),
                    expected_gid=different_kernel_id(os.getgid()),
                ),
            )

        assert str(os.getgid()) not in str(excinfo.value)
    finally:
        client.close()
        server.close()


def test_missing_so_peercred_fails_closed(monkeypatch):
    if not hasattr(socket, "SO_PEERCRED"):
        pytest.skip("SO_PEERCRED already unavailable on this platform")

    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        monkeypatch.delattr(socket, "SO_PEERCRED")
        with pytest.raises(
            ContainmentUnavailableError,
            match="SO_PEERCRED",
        ):
            read_linux_unix_peer_credentials(client)
    finally:
        client.close()
        server.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("expected_uid", True),
        ("expected_uid", -1),
        ("expected_uid", 1 << 32),
        ("expected_gid", True),
        ("expected_gid", -1),
        ("expected_gid", 1 << 32),
    ],
)
def test_invalid_peer_policy_kernel_ids_are_rejected(field, value):
    values = {
        "expected_uid": 1000,
        "expected_gid": 1000,
    }
    values[field] = value

    with pytest.raises(ValueError):
        LinuxPeerCredentialPolicy(**values)
