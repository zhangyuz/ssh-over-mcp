"""Fixed OCI-only SSH launcher. Source-only until runtime trust gates pass.

ForceCommand invokes this exact -I -S Python file without arguments.
No caller-configurable cgroup/node/manager path or direct cgroupfs write.
The image's STOP entrypoint remains active until independent guest proof.
"""

from __future__ import annotations

import ctypes
import os
import socket
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

NODE_ID_PATH = "/etc/ssh-over-mcp/node-id"
SOURCE_PATH = "/opt/ssh-over-mcp-e2e/workspace/src"
SITE_PACKAGES = "/opt/ssh-over-mcp-e2e/venv/lib/python3.14/site-packages"
MANAGER_SOCKET = "/run/som/manager.sock"
_CAP_VERSION = 0x20080522
_KEEP_CAPS = 8
_CAP_AMBIENT = 47
_CLEAR_ALL = 4


class OciLauncherFailure(RuntimeError):
    """Refuse the OCI admission transition without exposing internals."""


def parse_node_id(raw: bytes) -> str:
    if raw == b"node01\n":
        return "node01"
    if raw == b"node02\n":
        return "node02"
    raise OciLauncherFailure("invalid fixed node identity")


def _trusted_regular_file(path: str) -> None:
    """Validate root-owned, nonmutable code/config paths without following links."""
    current = Path("/")
    for segment in Path(path).parts[1:]:
        current = current / segment
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise OciLauncherFailure("trusted runtime file unavailable") from exc
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise OciLauncherFailure("untrusted writable or linked runtime path")
        if current == Path(path):
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OciLauncherFailure("untrusted runtime regular file")
        elif not stat.S_ISDIR(info.st_mode):
            raise OciLauncherFailure("non-directory runtime ancestor")


def _refuse_source_bytecode() -> None:
    """Prevent Python loading an unreviewed pre-drop .pyc in either package."""
    for directory in (
        SOURCE_PATH + "/ssh_over_mcp",
        SOURCE_PATH + "/ssh_over_mcp/host_agent",
    ):
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.name == "__pycache__" or entry.name.endswith((".pyc", ".pyo")):
                        raise OciLauncherFailure("unreviewed privileged import bytecode")
        except OSError as exc:
            raise OciLauncherFailure("trusted Python source directory unavailable") from exc


def _load_node_id() -> str:
    _trusted_regular_file(NODE_ID_PATH)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd = os.open(NODE_ID_PATH, flags)
    try:
        info = os.fstat(fd)
        if (
            info.st_uid != 0
            or info.st_mode & 0o022
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
        ):
            raise OciLauncherFailure("node identity file changed")
        return parse_node_id(os.read(fd, 32))
    finally:
        os.close(fd)


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


class _LinuxPrivilegeOps:
    """OCI admission uses real Linux syscalls, never managed-host cgroupfs code."""

    def __init__(self) -> None:
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.prctl.restype = ctypes.c_int
        self.libc.capset.restype = ctypes.c_int

    def effective_uid(self) -> int:
        return os.geteuid()

    def set_keepcaps(self, flag: bool) -> None:
        if self.libc.prctl(_KEEP_CAPS, int(flag), 0, 0, 0) != 0:
            raise OciLauncherFailure("keepcaps transition failed")

    def set_groups(self, groups: tuple[int, ...]) -> None:
        os.setgroups(list(groups))

    def set_res_gid(self, gid: int) -> None:
        os.setresgid(gid, gid, gid)

    def set_res_uid(self, uid: int) -> None:
        os.setresuid(uid, uid, uid)

    def set_capabilities(self, mask: int) -> None:
        from ssh_over_mcp.host_agent.oci_launcher_admission import TRUSTED_AGENT_CAP_MASK

        if mask != TRUSTED_AGENT_CAP_MASK:
            raise OciLauncherFailure("unreviewed OCI capability mask")
        header = _CapHeader(_CAP_VERSION, 0)
        data = (_CapData * 2)()
        data[0] = _CapData(mask, mask, 0)
        if self.libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
            raise OciLauncherFailure("capability drop failed")

    def clear_ambient_capabilities(self) -> None:
        if self.libc.prctl(_CAP_AMBIENT, _CLEAR_ALL, 0, 0, 0) != 0:
            raise OciLauncherFailure("cannot clear ambient capabilities")

    def snapshot(self):
        from ssh_over_mcp.host_agent.oci_launcher_admission import OciAdmissionSnapshot

        try:
            with open("/proc/self/status", encoding="ascii") as state:
                entries = {}
                for line in state:
                    key, colon, value = line.partition(":")
                    if colon and key in {"CapInh", "CapPrm", "CapEff", "CapAmb"}:
                        if key in entries:
                            raise OciLauncherFailure("duplicate kernel capability state")
                        entries[key] = int(value.strip(), 16)
            if len(entries) != 4:
                raise OciLauncherFailure("incomplete kernel capability state")
            uid = os.getresuid()
            gid = os.getresgid()
            groups = tuple(sorted(os.getgroups()))
        except (OSError, ValueError) as exc:
            raise OciLauncherFailure("cannot prove OCI privilege state") from exc
        return OciAdmissionSnapshot(
            *uid,
            *gid,
            groups,
            entries["CapInh"],
            entries["CapPrm"],
            entries["CapEff"],
            entries["CapAmb"],
        )


def _connect_manager(path: str):
    if path != MANAGER_SOCKET:
        raise OciLauncherFailure("unreviewed OCI manager socket")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | getattr(socket, "SOCK_CLOEXEC", 0))
    try:
        sock.settimeout(2.0)
        sock.connect(path)
        os.set_inheritable(sock.fileno(), False)
        return sock
    except BaseException:
        sock.close()
        raise


def _run_application() -> int:
    """Only called after verified full nonroot/capability transition."""
    from ssh_over_mcp.host_agent.cli import main

    result = main([])
    return 0 if result is None else int(result)


def run(
    *,
    argv: Sequence[str],
    env: Mapping[str, str],
    node_loader: Callable[[], str],
    ops_factory: Callable[[], object],
    connector: Callable[[str], object],
    application: Callable[[], int],
) -> int:
    from ssh_over_mcp.host_agent import oci_launcher_admission as admission

    if tuple(argv):
        raise OciLauncherFailure("OCI launcher refuses argv")
    try:
        node = node_loader()
        domain = admission.OciLauncherDomain.for_node(node)
        admission.sanitized_oci_environment(env)
        ops = ops_factory()
        clean = admission.admit_oci_source_before_application(
            argv=argv, env=env, domain=domain, ops=ops, connect_manager=connector
        )
    except (ValueError, TypeError, RuntimeError, OSError) as exc:
        raise OciLauncherFailure("OCI launcher admission refused") from exc

    os.environ.clear()
    os.environ.update(clean)
    return application()


def main() -> int:
    # -I -S excludes ambient PYTHONPATH and site hooks. Source files are
    # pinned to root-owned, nonwritable, nonlinked image content before import.
    sys.dont_write_bytecode = True
    _refuse_source_bytecode()
    if tuple(sys.argv[1:]):
        raise OciLauncherFailure("OCI launcher refuses arguments")
    for path in (
        SOURCE_PATH + "/ssh_over_mcp/__init__.py",
        SOURCE_PATH + "/ssh_over_mcp/host_agent/__init__.py",
        SOURCE_PATH + "/ssh_over_mcp/host_agent/oci_launcher_admission.py",
        SOURCE_PATH + "/ssh_over_mcp/host_agent/oci_source_migration.py",
        SOURCE_PATH + "/ssh_over_mcp/host_agent/oci_pidfd_handoff.py",
        SOURCE_PATH + "/ssh_over_mcp/host_agent/containment_manager_peer.py",
        SOURCE_PATH + "/ssh_over_mcp/host_agent/containment.py",
    ):
        _trusted_regular_file(path)
    if os.geteuid() != 0:
        raise OciLauncherFailure("OCI launcher not root")
    sys.path.insert(0, SOURCE_PATH)

    # site-packages only added after privileged admission; no untrusted
    # third-party dependency imports before successful identity transition.
    def application() -> int:
        sys.path.insert(0, SITE_PACKAGES)
        return _run_application()

    return run(
        argv=tuple(sys.argv[1:]),
        env=os.environ.copy(),
        node_loader=_load_node_id,
        ops_factory=_LinuxPrivilegeOps,
        connector=_connect_manager,
        application=application,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OciLauncherFailure, OSError, ValueError, RuntimeError):
        sys.stderr.write("ssh-over-mcp OCI launcher refused\n")
        raise SystemExit(70) from None
