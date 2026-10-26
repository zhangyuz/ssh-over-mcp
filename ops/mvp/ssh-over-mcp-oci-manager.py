"""Fixed OCI manager executable; separate guest container, never SSH image.

Invocation is python3 -I -S THIS_FILE (no args) after immutable no-NIC
guest provisions root-owned node-id and a delegated node-local cgroup2 mount.
No host/container actions occur from merely importing this module.
"""

from __future__ import annotations

import os
import signal
import stat
import sys
from pathlib import Path

NODE_ID_PATH = "/etc/ssh-over-mcp/node-id"
SOURCE_PATH = "/opt/ssh-over-mcp-e2e/workspace/src"
SITE_PACKAGES = "/opt/ssh-over-mcp-e2e/venv/lib/python3.14/site-packages"
_MANAGER_UID = 2204


class OciManagerStartRefused(RuntimeError):
    """Trusted guest manager identity or runtime not established."""


def _trusted_file(path: str) -> None:
    current = Path("/")
    for component in Path(path).parts[1:]:
        current = current / component
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise OciManagerStartRefused("trusted manager file unavailable") from exc
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise OciManagerStartRefused("untrusted mutable/linked manager file")
        if current == Path(path):
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OciManagerStartRefused("untrusted manager regular file")
        elif not stat.S_ISDIR(info.st_mode):
            raise OciManagerStartRefused("untrusted manager path")


def _refuse_source_bytecode() -> None:
    # -I -S does not disable normal .pyc resolution for importable packages.
    # Before the first trusted source import, reject any cached bytecode.
    for directory in (
        SOURCE_PATH + "/ssh_over_mcp",
        SOURCE_PATH + "/ssh_over_mcp/host_agent",
    ):
        try:
            with os.scandir(directory) as records:
                if any(
                    record.name == "__pycache__" or record.name.endswith((".pyc", ".pyo"))
                    for record in records
                ):
                    raise OciManagerStartRefused("unreviewed manager Python bytecode")
        except OSError as exc:
            raise OciManagerStartRefused("trusted manager source unavailable") from exc


def _node_id() -> str:
    _trusted_file(NODE_ID_PATH)
    fd = os.open(NODE_ID_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (
            info.st_uid != 0
            or info.st_mode & 0o022
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
        ):
            raise OciManagerStartRefused("node identity changed")
        raw = os.read(fd, 32)
    finally:
        os.close(fd)
    if raw == b"node01\n":
        return "node01"
    if raw == b"node02\n":
        return "node02"
    raise OciManagerStartRefused("manager node identity invalid")


def _kernel_unprivileged() -> None:
    if sys.platform != "linux" or os.geteuid() != _MANAGER_UID:
        raise OciManagerStartRefused("manager is not required Linux UID")
    try:
        with open("/proc/self/status", encoding="ascii") as fp:
            fields = {}
            for line in fp:
                key, sep, value = line.partition(":")
                if sep and key in {"NoNewPrivs", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}:
                    if key in fields:
                        raise OciManagerStartRefused("duplicate kernel privilege status")
                    fields[key] = value.strip()
        if fields.get("NoNewPrivs") != "1" or any(
            fields.get(key) != "0000000000000000"
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        ):
            raise OciManagerStartRefused("manager must be NNP and zero capabilities")
    except (OSError, UnicodeError) as exc:
        raise OciManagerStartRefused("manager kernel status unavailable") from exc


def main(argv: tuple[str, ...] | None = None) -> int:
    if tuple(sys.argv[1:] if argv is None else argv):
        raise OciManagerStartRefused("manager refuses argv")
    _kernel_unprivileged()
    for path in (
        SOURCE_PATH + "/ssh_over_mcp/__init__.py",
        SOURCE_PATH + "/ssh_over_mcp/host_agent/__init__.py",
        SOURCE_PATH + "/ssh_over_mcp/host_agent/oci_manager_runtime.py",
        SOURCE_PATH + "/ssh_over_mcp/host_agent/oci_source_writer.py",
        SOURCE_PATH + "/ssh_over_mcp/host_agent/oci_source_migration.py",
        SOURCE_PATH + "/ssh_over_mcp/host_agent/oci_pidfd_handoff.py",
        SOURCE_PATH + "/ssh_over_mcp/host_agent/containment_manager_peer.py",
        SOURCE_PATH + "/ssh_over_mcp/host_agent/containment_manager_identity.py",
        SOURCE_PATH + "/ssh_over_mcp/host_agent/containment_manager_endpoint.py",
        SOURCE_PATH + "/ssh_over_mcp/host_agent/containment.py",
    ):
        _trusted_file(path)
    node = _node_id()
    sys.dont_write_bytecode = True
    _refuse_source_bytecode()
    sys.path.insert(0, SOURCE_PATH)
    sys.path.insert(1, SITE_PACKAGES)
    from ssh_over_mcp.host_agent.oci_manager_runtime import serve_oci_source_manager

    terminated = False

    def shutdown(_signal: int, _frame: object) -> None:
        nonlocal terminated
        terminated = True

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    serve_oci_source_manager(trusted_node=node, stop_requested=lambda: terminated)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OciManagerStartRefused, OSError, RuntimeError, ValueError):
        sys.stderr.write("ssh-over-mcp OCI manager refused\n")
        raise SystemExit(70) from None
