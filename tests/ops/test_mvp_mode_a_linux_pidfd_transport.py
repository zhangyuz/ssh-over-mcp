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

# A Linux runner lacking any required interface MUST fail this gate, not
# quietly mark its real-kernel proof as skipped while ordinary CI stays green.
pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Linux-only kernel proof; never skipped for missing Linux pidfd APIs",
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


def test_oci_manager_receives_only_authenticated_peer_self_pidfd():
    from ssh_over_mcp.host_agent.containment_manager_peer import (
        LinuxPeerCredentialPolicy,
    )
    from ssh_over_mcp.host_agent.oci_pidfd_handoff import (
        receive_peer_self_pidfd,
        send_self_pidfd,
    )

    source, target = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with source, target:
        send_self_pidfd(source)
        fd = receive_peer_self_pidfd(
            target,
            peer_policy=LinuxPeerCredentialPolicy(
                expected_uid=os.getuid(), expected_gid=os.getgid()
            ),
        )
        try:
            signal.pidfd_send_signal(fd, 0)
            assert not os.get_inheritable(fd)
        finally:
            os.close(fd)


def test_oci_manager_rejects_fd_for_a_different_process():
    from ssh_over_mcp.host_agent.containment_manager_peer import (
        LinuxPeerCredentialPolicy,
    )
    from ssh_over_mcp.host_agent.oci_pidfd_handoff import (
        OciPidfdHandoffRefused,
        receive_peer_self_pidfd,
    )

    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        pinned = os.pidfd_open(child.pid)
        try:
            source, target = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            with source, target:
                source.sendmsg(
                    [b"P"],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [pinned]))],
                )
                with pytest.raises(OciPidfdHandoffRefused, match="authenticated peer"):
                    receive_peer_self_pidfd(
                        target,
                        peer_policy=LinuxPeerCredentialPolicy(
                            expected_uid=os.getuid(), expected_gid=os.getgid()
                        ),
                    )
        finally:
            os.close(pinned)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=4)


def test_oci_manager_rejects_missing_fd_and_wrong_peer_uid():
    from ssh_over_mcp.host_agent.containment_manager_peer import (
        ContainmentManagerPeerAuthError,
        LinuxPeerCredentialPolicy,
    )
    from ssh_over_mcp.host_agent.oci_pidfd_handoff import (
        OciPidfdHandoffRefused,
        receive_peer_self_pidfd,
    )

    source, target = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with source, target:
        source.sendall(b"P")
        with pytest.raises(ContainmentManagerPeerAuthError):
            receive_peer_self_pidfd(
                target,
                peer_policy=LinuxPeerCredentialPolicy(expected_uid=os.getuid() + 1),
            )
        with pytest.raises(OciPidfdHandoffRefused, match="exactly one"):
            receive_peer_self_pidfd(
                target,
                peer_policy=LinuxPeerCredentialPolicy(expected_uid=os.getuid()),
            )


def test_oci_manager_rejects_duplicated_fds_without_leaking():
    from ssh_over_mcp.host_agent.containment_manager_peer import (
        LinuxPeerCredentialPolicy,
    )
    from ssh_over_mcp.host_agent.oci_pidfd_handoff import (
        OciPidfdHandoffRefused,
        receive_peer_self_pidfd,
    )

    before = set(os.listdir("/proc/self/fd"))
    pinned = os.pidfd_open(os.getpid())
    try:
        source, target = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with source, target:
            source.sendmsg(
                [b"P"],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [pinned, pinned]))],
            )
            with pytest.raises(OciPidfdHandoffRefused, match="exactly one"):
                receive_peer_self_pidfd(
                    target,
                    peer_policy=LinuxPeerCredentialPolicy(expected_uid=os.getuid()),
                )
    finally:
        os.close(pinned)
    assert set(os.listdir("/proc/self/fd")) == before


def test_oci_manager_refuses_an_exited_peer_pidfd():
    from ssh_over_mcp.host_agent.oci_pidfd_handoff import (
        OciPidfdHandoffRefused,
        _pidfd_pid,
    )

    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        pinned = os.pidfd_open(child.pid)
        try:
            child.terminate()
            child.wait(timeout=4)
            with pytest.raises(OciPidfdHandoffRefused, match="already exited"):
                _pidfd_pid(pinned)
        finally:
            os.close(pinned)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=4)


def test_oci_manager_closes_delivered_fds_when_ancillary_is_truncated():
    from ssh_over_mcp.host_agent.containment_manager_peer import (
        LinuxPeerCredentialPolicy,
    )
    from ssh_over_mcp.host_agent.oci_pidfd_handoff import (
        OciPidfdHandoffRefused,
        receive_peer_self_pidfd,
    )

    before = set(os.listdir("/proc/self/fd"))
    descriptor = os.pidfd_open(os.getpid())
    try:
        source, target = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with source, target:
            source.sendmsg(
                [b"P"],
                [
                    (
                        socket.SOL_SOCKET,
                        socket.SCM_RIGHTS,
                        array.array("i", [descriptor] * 16),
                    )
                ],
            )
            with pytest.raises(OciPidfdHandoffRefused, match="truncated"):
                receive_peer_self_pidfd(
                    target,
                    peer_policy=LinuxPeerCredentialPolicy(expected_uid=os.getuid()),
                )
    finally:
        os.close(descriptor)
    assert set(os.listdir("/proc/self/fd")) == before


def test_oci_manager_accepts_only_direct_child_pinned_by_authenticated_parent():
    from ssh_over_mcp.host_agent.containment_manager_peer import LinuxPeerCredentialPolicy
    from ssh_over_mcp.host_agent.oci_pidfd_handoff import (
        receive_direct_child_pidfd,
        send_pinned_child_pidfd,
    )

    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(12)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    try:
        pinned = os.pidfd_open(child.pid)
        try:
            source, target = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            with source, target:
                send_pinned_child_pidfd(source, pinned)
                received = receive_direct_child_pidfd(
                    target, peer_policy=LinuxPeerCredentialPolicy(expected_uid=os.getuid())
                )
                try:
                    assert received.pid == child.pid
                    assert received.parent_pid == os.getpid()
                    received.recheck_identity()
                    assert not os.get_inheritable(received.fd)
                finally:
                    os.close(received.fd)
        finally:
            os.close(pinned)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=4)


def test_oci_manager_rejects_own_pid_as_child_and_closes_fd():
    from ssh_over_mcp.host_agent.containment_manager_peer import LinuxPeerCredentialPolicy
    from ssh_over_mcp.host_agent.oci_pidfd_handoff import (
        OciPidfdHandoffRefused,
        receive_direct_child_pidfd,
    )

    before = set(os.listdir("/proc/self/fd"))
    pinned = os.pidfd_open(os.getpid())
    try:
        source, target = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with source, target:
            source.sendmsg(
                [b"C"],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [pinned]))],
            )
            with pytest.raises(OciPidfdHandoffRefused, match="direct child"):
                receive_direct_child_pidfd(
                    target, peer_policy=LinuxPeerCredentialPolicy(expected_uid=os.getuid())
                )
    finally:
        os.close(pinned)
    assert set(os.listdir("/proc/self/fd")) == before


def test_oci_manager_rejects_child_exited_before_receipt():
    from ssh_over_mcp.host_agent.containment_manager_peer import LinuxPeerCredentialPolicy
    from ssh_over_mcp.host_agent.oci_pidfd_handoff import (
        OciPidfdHandoffRefused,
        receive_direct_child_pidfd,
        send_pinned_child_pidfd,
    )

    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(12)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        pinned = os.pidfd_open(child.pid)
        try:
            source, target = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            with source, target:
                send_pinned_child_pidfd(source, pinned)
                child.terminate()
                child.wait(timeout=4)
                with pytest.raises(OciPidfdHandoffRefused, match="already exited"):
                    receive_direct_child_pidfd(
                        target, peer_policy=LinuxPeerCredentialPolicy(expected_uid=os.getuid())
                    )
        finally:
            os.close(pinned)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=4)


def test_oci_source_manager_reads_real_linux_unified_cgroup_fail_closed():
    """Host CI may have '/', which must refuse instead of authorizing a move."""
    from ssh_over_mcp.host_agent import oci_source_migration
    from ssh_over_mcp.host_agent.oci_pidfd_handoff import OciPidfdHandoffRefused

    with open("/proc/self/cgroup", encoding="ascii") as report:
        lines = report.read(4097).splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::") or lines[0] == "0::/":
        with pytest.raises(OciPidfdHandoffRefused, match="unified"):
            oci_source_migration._current_cgroup(os.getpid())
    else:
        expected = lines[0][3:]
        try:
            observed = oci_source_migration._current_cgroup(os.getpid())
        except OciPidfdHandoffRefused:
            # A noncanonical, ambiguous kernel mount path must be refused.
            assert "//" in expected or "/.." in expected or " " in expected
        else:
            assert observed == expected
