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


def receive_peer_self_pidfd(sock: socket.socket, *, peer_policy: LinuxPeerCredentialPolicy) -> int:
    """Receive a sole pidfd bound to the connect-time peer.

    The caller owns/shall close the returned fd. The socket is for a single
    handoff only; close it before a UID change and establish a new manager
    connection for post-drop commands. No integer-only attach fallback.
    """
    _require_connected_unix_stream(sock)
    if not hasattr(socket, "SCM_RIGHTS") or not hasattr(socket, "MSG_CMSG_CLOEXEC"):
        raise OciPidfdHandoffRefused("Linux descriptor transport unavailable")

    # Snapshot credentials before reading. In OCI this must be a FRESH socket,
    # never a root-phase session retained after setresuid/setresgid.
    credentials = authenticate_linux_unix_peer(sock, peer_policy)
    if credentials.pid <= 0:
        raise OciPidfdHandoffRefused("sender PID invisible in manager namespace")

    received: list[int] = []
    try:
        try:
            # Fresh one-shot handoff: never let a nonresponsive peer hold the
            # manager admission worker indefinitely.
            sock.settimeout(2.0)
            payload, ancillaries, flags, _ = sock.recvmsg(
                1,
                socket.CMSG_SPACE(array.array("i", [0] * _MAX_FDS).itemsize * _MAX_FDS),
                socket.MSG_CMSG_CLOEXEC,
            )
        except OSError as exc:
            raise OciPidfdHandoffRefused("cannot receive pinned pidfd") from exc
        # Even when MSG_CTRUNC is set, the kernel may have *already*
        # installed several received descriptors. Collect every complete
        # SCM_RIGHTS integer before rejecting, so finally closes them all.
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
        if payload != _HANDOFF_BYTE or len(received) != 1:
            raise OciPidfdHandoffRefused("expected exactly one peer pidfd")
        pinned_fd = received[0]
        os.set_inheritable(pinned_fd, False)
        if _pidfd_pid(pinned_fd) != credentials.pid:
            raise OciPidfdHandoffRefused("pidfd does not identify authenticated peer")
        received.clear()
        return pinned_fd
    finally:
        for fd in received:
            try:
                os.close(fd)
            except OSError:
                pass
