"""Nonprivileged Linux kernel smoke for the proposed Mode A pidfd handoff.

These checks exercise process-local Linux pidfd/SCM_RIGHTS semantics in
hosted CI; they do NOT certify cross-userns maps, cgroup migration,
Docker, sudo, or permission to execute the proposed OCI profile.
"""

from __future__ import annotations

import array
import os
import signal
import socket
import struct
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux"
    or not hasattr(os, "pidfd_open")
    or not hasattr(signal, "pidfd_send_signal")
    or not hasattr(socket, "SCM_RIGHTS"),
    reason="requires unprivileged Linux pidfd/SCM_RIGHTS kernel APIs",
)


def test_pidfd_can_cross_unix_socket_and_still_bind_to_kernel_pid():
    """No integer-PID-only attach evidence: the descriptor must survive transfer."""
    original = os.pidfd_open(os.getpid())
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    received: list[int] = []
    try:
        with sender, receiver:
            assert (
                sender.sendmsg(
                    [b"P"],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [original]))],
                )
                == 1
            )
            data, controls, flags, address = receiver.recvmsg(
                1,
                socket.CMSG_SPACE(array.array("i", [0]).itemsize),
                getattr(socket, "MSG_CMSG_CLOEXEC", 0),
            )
            assert data == b"P"
            assert flags & getattr(socket, "MSG_CTRUNC", 0) == 0
            assert flags & getattr(socket, "MSG_TRUNC", 0) == 0
            assert address is None or address == "" or address == b""
            assert len(controls) == 1
            level, kind, payload = controls[0]
            assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
            descriptors = array.array("i")
            assert len(payload) == descriptors.itemsize
            descriptors.frombytes(payload)
            received.extend(descriptors)
            assert len(received) == 1
            assert os.get_inheritable(received[0]) is False
            # A descriptor referring to a live process stays actionable after
            # the original sender's descriptor is closed.
            os.close(original)
            original = -1
            signal.pidfd_send_signal(received[0], 0)
            fields = {}
            with open(f"/proc/self/fdinfo/{received[0]}", encoding="ascii") as report:
                for line in report:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        fields[key] = value.strip()
            assert fields.get("Pid") == str(os.getpid())
            assert fields.get("NSpid") is not None
            # On this same-namespace test, SO_PEERCRED should bind to this
            # process. It does NOT establish cross-userns UID/GID mappings.
            raw = receiver.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("=iII")
            )
            peer_pid, peer_uid, peer_gid = struct.unpack("=iII", raw)
            assert (peer_pid, peer_uid, peer_gid) == (
                os.getpid(),
                os.getuid(),
                os.getgid(),
            )
    finally:
        if original >= 0:
            os.close(original)
        for fd in received:
            os.close(fd)


def test_pidfd_reports_reaped_child_gone():
    """Exit detection only, not a proof of race-free cgroup.procs attach."""
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    try:
        try:
            fd = os.pidfd_open(child.pid)
        except OSError as exc:
            pytest.fail(f"hosted Linux pidfd unavailable: {exc}")
        try:
            signal.pidfd_send_signal(fd, 0)
            child.terminate()
            child.wait(timeout=4)
            with pytest.raises(ProcessLookupError):
                signal.pidfd_send_signal(fd, 0)
            fields = {}
            with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as report:
                for line in report:
                    if ":" in line:
                        key, value = line.split(":", 1)
                        fields[key] = value.strip()
            assert fields.get("Pid") in ("-1", str(child.pid))
        finally:
            os.close(fd)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=4)
