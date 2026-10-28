"""Portable fd-ownership regression; Linux CI covers actual ancillary transport."""

from __future__ import annotations

import array
import os
import socket

import pytest

from ssh_over_mcp.host_agent import oci_pidfd_handoff
from ssh_over_mcp.host_agent.containment_manager_peer import (
    LinuxPeerCredentialPolicy,
    LinuxPeerCredentials,
)


class _TruncatedPeer:
    family = socket.AF_UNIX

    def __init__(self, received: list[int]) -> None:
        self._received = received

    def getsockopt(self, _level: int, _option: int) -> int:
        return socket.SOCK_STREAM

    def getpeername(self) -> str:
        return ""

    def settimeout(self, _timeout: float) -> None:
        return

    def recvmsg(self, _size: int, _space: int, _flags: int):
        return (
            b"P",
            [
                (
                    socket.SOL_SOCKET,
                    socket.SCM_RIGHTS,
                    array.array("i", self._received).tobytes(),
                )
            ],
            socket.MSG_CTRUNC,
            None,
        )


def test_truncated_ancillary_closes_all_delivered_fds_even_when_rejected(monkeypatch):
    # Tests descriptor ownership, not simulated Linux kernel identity.
    monkeypatch.setattr(oci_pidfd_handoff.sys, "platform", "linux")
    monkeypatch.setattr(oci_pidfd_handoff.socket, "MSG_CMSG_CLOEXEC", 0, raising=False)
    monkeypatch.setattr(
        oci_pidfd_handoff,
        "authenticate_linux_unix_peer",
        lambda *_args, **_kwargs: LinuxPeerCredentials(pid=123, uid=2204, gid=3204),
    )

    read_fd, write_fd = os.pipe()
    delivered: list[int] = []
    try:
        delivered = [os.dup(read_fd) for _ in range(8)]
        with pytest.raises(oci_pidfd_handoff.OciPidfdHandoffRefused, match="truncated"):
            oci_pidfd_handoff.receive_peer_self_pidfd(
                _TruncatedPeer(delivered),  # type: ignore[arg-type]
                peer_policy=LinuxPeerCredentialPolicy(expected_uid=2204),
            )
        for fd in delivered:
            with pytest.raises(OSError):
                os.fstat(fd)
    finally:
        # Handle the case the refusal leaked descriptors so this test never
        # leaves the test runner with permanent fd leaks.
        for fd in delivered:
            try:
                os.close(fd)
            except OSError:
                pass
        os.close(read_fd)
        os.close(write_fd)
