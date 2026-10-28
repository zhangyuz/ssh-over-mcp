"""OCI-only pidfd handoff for a *fresh, authenticated* manager AF_UNIX stream.

One fd per connection, no cgroup action or target-provided PID. This is
deliberately not wired into the existing integer-PID production manager
protocol. Kernel userns/cgroup attachment still requires separate live proof.
"""

from __future__ import annotations

import array
import os
import select
import socket
import sys
from dataclasses import dataclass

from .containment_manager_peer import (
    LinuxPeerCredentialPolicy,
    authenticate_linux_unix_peer,
)

_HANDOFF_BYTE = b"P"
_MAX_FDS = 8


class OciPidfdHandoffRefused(RuntimeError):
    """The requested kernel-bound OCI identity transfer was not verified."""


def _require_connected_unix_stream(sock: socket.socket) -> None:
    if sys.platform != "linux":
        raise OciPidfdHandoffRefused("Linux-only pidfd handoff")
    if sock.family != socket.AF_UNIX:
        raise OciPidfdHandoffRefused("AF_UNIX socket required")
    try:
        if sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
            raise OciPidfdHandoffRefused("Unix stream socket required")
        sock.getpeername()
    except OSError as exc:
        raise OciPidfdHandoffRefused("connected Unix socket required") from exc


def send_self_pidfd(sock: socket.socket) -> None:
    """Send ONLY the caller's live pidfd. No arbitrary target-PID parameter."""
    _require_connected_unix_stream(sock)
    if not hasattr(os, "pidfd_open"):
        raise OciPidfdHandoffRefused("pidfd_open unavailable")

    try:
        descriptor = os.pidfd_open(os.getpid(), 0)
    except OSError as exc:
        raise OciPidfdHandoffRefused("cannot pin calling process") from exc
    try:
        try:
            written = sock.sendmsg(
                [_HANDOFF_BYTE],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]))],
            )
        except (OSError, AttributeError) as exc:
            raise OciPidfdHandoffRefused("cannot transfer pinned pidfd") from exc
        if written != 1:
            raise OciPidfdHandoffRefused("incomplete pidfd transfer")
    finally:
        os.close(descriptor)


def _pidfd_pid(fd: int) -> int:
    # poll(pidfd) detects exit without requiring CAP_KILL or permission to
    # signal a root-phase peer from the unprivileged manager UID.
    try:
        events = select.poll()
        events.register(fd, select.POLLIN | select.POLLERR | select.POLLHUP)
        if events.poll(0):
            raise OciPidfdHandoffRefused("pidfd target already exited")
        with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as detail:
            lines = detail.readlines()
    except (OSError, ValueError) as exc:
        raise OciPidfdHandoffRefused("pidfd kernel identity unavailable") from exc

    fields = [line.split(":", 1)[1].strip() for line in lines if line.startswith("Pid:")]
    if len(fields) != 1:
        raise OciPidfdHandoffRefused("ambiguous pidfd kernel identity")
    try:
        pid = int(fields[0])
    except ValueError as exc:
        raise OciPidfdHandoffRefused("invalid pidfd kernel identity") from exc
    if pid <= 0:
        raise OciPidfdHandoffRefused("pidfd is not bound to a live visible process")
    return pid


def _proc_identity(pid: int) -> tuple[int, int]:
    """Read direct-parent and birth starttime in the manager's PID namespace."""
    if pid <= 0:
        raise OciPidfdHandoffRefused("invalid target PID")
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii") as report:
            raw = report.read(4096)
        # comm may contain spaces or parentheses; the LAST ')' terminates comm.
        head, separator, tail = raw.rpartition(")")
        if not separator or not head.startswith(f"{pid} ("):
            raise ValueError("ambiguous process stat")
        fields = tail.strip().split()
        # tail starts with field 3 (state), field 4 is ppid,
        # field 22 is the kernel's monotonic process birth starttime.
        if len(fields) < 20 or fields[0] in {"Z", "X", "x"}:
            raise ValueError("child is exited or malformed")
        parent, birth = int(fields[1]), int(fields[19])
        if parent <= 0 or birth <= 0:
            raise ValueError("invalid process identity")
        return parent, birth
    except (OSError, UnicodeError, ValueError) as exc:
        raise OciPidfdHandoffRefused("direct child identity unavailable") from exc


def _send_pinned(sock: socket.socket, fd: int, tag: bytes) -> None:
    try:
        count = sock.sendmsg(
            [tag],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))],
        )
    except (OSError, AttributeError) as exc:
        raise OciPidfdHandoffRefused("cannot transfer pinned pidfd") from exc
    if count != 1:
        raise OciPidfdHandoffRefused("incomplete pidfd transfer")


def send_pinned_child_pidfd(sock: socket.socket, pinned_fd: int) -> None:
    """Send a caller-owned already pinned live *direct child* descriptor.

    The fork parent must keep the child blocked/unreaped until attach ACK.
    This function neither starts the child nor permits numeric-PID fallback.
    """
    _require_connected_unix_stream(sock)
    pid = _pidfd_pid(pinned_fd)
    parent, _birth = _proc_identity(pid)
    if pid == os.getpid() or parent != os.getpid():
        raise OciPidfdHandoffRefused("target is not a direct child of sender")
    _send_pinned(sock, pinned_fd, b"C")


def _receive_single_pidfd(
    sock: socket.socket, peer_policy: LinuxPeerCredentialPolicy, tag: bytes
) -> tuple[int, int]:
    _require_connected_unix_stream(sock)
    if not hasattr(socket, "SCM_RIGHTS") or not hasattr(socket, "MSG_CMSG_CLOEXEC"):
        raise OciPidfdHandoffRefused("Linux descriptor transport unavailable")

    credentials = authenticate_linux_unix_peer(sock, peer_policy)
    if credentials.pid <= 0:
        raise OciPidfdHandoffRefused("sender PID invisible in manager namespace")

    received: list[int] = []
    try:
        try:
            sock.settimeout(2.0)
            payload, ancillaries, flags, _ = sock.recvmsg(
                1,
                socket.CMSG_SPACE(array.array("i", [0] * _MAX_FDS).itemsize * _MAX_FDS),
                socket.MSG_CMSG_CLOEXEC,
            )
        except OSError as exc:
            raise OciPidfdHandoffRefused("cannot receive pinned pidfd") from exc

        # The kernel may already have installed SCM_RIGHTS FDs on MSG_CTRUNC.
        # Harvest all delivered FDs BEFORE checking flags, to close on reject.
        invalid_control = False
        for level, kind, data in ancillaries:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                invalid_control = True
                continue
            itemsize = array.array("i").itemsize
            fds = array.array("i")
            fds.frombytes(data[: len(data) // itemsize * itemsize])
            received.extend(fds)
            if len(data) % itemsize:
                invalid_control = True
        if flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC):
            raise OciPidfdHandoffRefused("truncated descriptor control message")
        if invalid_control:
            raise OciPidfdHandoffRefused("unexpected or malformed Unix control message")
        if payload != tag or len(received) != 1:
            raise OciPidfdHandoffRefused("expected exactly one peer pidfd")
        fd = received[0]
        os.set_inheritable(fd, False)
        _pidfd_pid(fd)
        received.clear()
        return fd, credentials.pid
    finally:
        for fd in received:
            try:
                os.close(fd)
            except OSError:
                pass


def receive_peer_self_pidfd(sock: socket.socket, *, peer_policy: LinuxPeerCredentialPolicy) -> int:
    """One authenticated root-phase self pidfd; caller owns returned FD."""
    fd, peer_pid = _receive_single_pidfd(sock, peer_policy, b"P")
    try:
        if _pidfd_pid(fd) != peer_pid:
            raise OciPidfdHandoffRefused("pidfd does not identify authenticated peer")
        return fd
    except BaseException:
        os.close(fd)
        raise


@dataclass(frozen=True, slots=True)
class PinnedOciChild:
    """Verified direct-child identity, not permission to move a cgroup."""

    fd: int
    pid: int
    parent_pid: int
    starttime: int

    def recheck_identity(self) -> None:
        # Must be rechecked around every future numeric cgroup.procs write.
        # pidfd + readback does NOT make numeric cgroup migration atomic.
        if _pidfd_pid(self.fd) != self.pid:
            raise OciPidfdHandoffRefused("pinned child PID changed")
        parent, birth = _proc_identity(self.pid)
        if parent != self.parent_pid or birth != self.starttime:
            raise OciPidfdHandoffRefused("pinned child identity changed")


def receive_direct_child_pidfd(
    sock: socket.socket, *, peer_policy: LinuxPeerCredentialPolicy
) -> PinnedOciChild:
    """Accept a live pinned direct child of the connect-time authenticated peer.

    Checks only peer/child identity. Kernel namespace maps, source cgroup,
    blocked-child barrier and PID-reuse-safe attach remain HARD runtime gates.
    """
    fd, parent_pid = _receive_single_pidfd(sock, peer_policy, b"C")
    try:
        pid = _pidfd_pid(fd)
        actual_parent, birth = _proc_identity(pid)
        if pid == parent_pid or actual_parent != parent_pid:
            raise OciPidfdHandoffRefused("target is not a direct child of authenticated peer")
        child = PinnedOciChild(fd, pid, parent_pid, birth)
        child.recheck_identity()
        return child
    except BaseException:
        os.close(fd)
        raise
