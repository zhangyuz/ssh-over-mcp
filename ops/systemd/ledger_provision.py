"""Operator-only fresh reference provisioning; never an application/root RPC."""

from __future__ import annotations

import grp
import importlib.abc
import importlib.util
import os
import pwd
import resource
import stat
import sys
from contextlib import ExitStack
from pathlib import PurePosixPath
from types import ModuleType

_PREFIX = "/opt/ssh-over-mcp/venv"
_LEDGER = "ssh-over-mcp-ledger"
_EXEC = "ssh-over-mcp-exec"
_ADMIN = "ssh-over-mcp-admin"
_EXEC_GROUP = "ssh-over-mcp-ledger-exec"
_ADMIN_GROUP = "ssh-over-mcp-ledger-admin"


class ProvisionError(RuntimeError):
    """Reference provisioning failed; any created state remains uncertain."""


def _refuse() -> None:
    raise ProvisionError("Ledger provisioning failed")


def _identity(info):
    return info.st_dev, info.st_ino


class _Tree:
    """Keep canonical ancestry pinned and revalidate names before success."""

    def __init__(self, stack: ExitStack):
        self.stack = stack
        self.nodes = {}
        fd = self.open("/", os.O_RDONLY | os.O_DIRECTORY)
        self.nodes[()] = (fd, None, None, 0, 0, None, _identity(os.fstat(fd)))
        self.verify()

    def open(self, name, flags, mode=0o777, *, dir_fd=None):
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=dir_fd)
        self.stack.callback(os.close, fd)
        return fd

    def directory(self, path: str, *, create_config=False):
        parts = PurePosixPath(path).parts[1:]
        for index, name in enumerate(parts, 1):
            key = parts[:index]
            if key in self.nodes:
                continue
            parent = self.nodes[key[:-1]][0]
            try:
                fd = self.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent)
            except FileNotFoundError:
                if not create_config or key != ("etc", "ssh-over-mcp"):
                    raise
                fd = self.fresh_child(parent, name, uid=0, gid=0, mode=0o755)
            mode = 0o755 if key == ("etc", "ssh-over-mcp") else None
            self.nodes[key] = (fd, parent, name, 0, 0, mode, _identity(os.fstat(fd)))
            self.verify()
        return self.nodes[parts][0]

    def fresh_child(self, parent, name, *, uid, gid, mode):
        os.mkdir(name, 0o700, dir_fd=parent)
        fd = self.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent)
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
        info = os.fstat(fd)
        if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, gid, mode):
            _refuse()
        if _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != _identity(info):
            _refuse()
        os.fsync(fd)
        os.fsync(parent)
        return fd

    def add_leaf(self, path, *, uid, gid, mode):
        parts = PurePosixPath(path).parts[1:]
        parent = self.nodes[parts[:-1]][0]
        fd = self.fresh_child(parent, parts[-1], uid=uid, gid=gid, mode=mode)
        self.nodes[parts] = (fd, parent, parts[-1], uid, gid, mode, _identity(os.fstat(fd)))
        self.verify()
        return fd

    def verify(self):
        for fd, parent, name, uid, gid, mode, identity in self.nodes.values():
            info = os.fstat(fd)
            if (
                not stat.S_ISDIR(info.st_mode)
                or _identity(info) != identity
                or (info.st_uid, info.st_gid) != (uid, gid)
                or info.st_mode & 0o022
                or (mode is not None and stat.S_IMODE(info.st_mode) != mode)
            ):
                _refuse()
            if parent is not None:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if _identity(current) != identity or not stat.S_ISDIR(current.st_mode):
                    _refuse()


def _read_fd(fd, maximum):
    data = bytearray()
    while len(data) <= maximum:
        chunk = os.read(fd, min(4096, maximum + 1 - len(data)))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
    _refuse()


def _core_preflight(tree):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    _require_no_core(tree)


def _require_no_core(tree):
    if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
        _refuse()
    parent = tree.directory("/proc/sys/kernel")
    fd = tree.open("core_pattern", os.O_RDONLY, dir_fd=parent)
    pattern = _read_fd(fd, 4096).decode("ascii").strip()
    if not pattern or pattern.startswith("|") or "\n" in pattern:
        _refuse()


def _accounts():
    users = {name: pwd.getpwnam(name) for name in (_LEDGER, _EXEC, _ADMIN)}
    names = (_LEDGER, _EXEC, _ADMIN, _EXEC_GROUP, _ADMIN_GROUP)
    groups = {name: grp.getgrnam(name) for name in names}
    uids = {user.pw_uid for user in users.values()}
    gids = {group.gr_gid for group in groups.values()}
    if len(uids) != 3 or len(gids) != 5:
        _refuse()
    if any(not 0 < number < (1 << 32) - 1 for number in uids | gids):
        _refuse()
    for name, user in users.items():
        if user.pw_name != name or user.pw_gid != groups[name].gr_gid:
            _refuse()
        aliases = [entry.pw_name for entry in pwd.getpwall() if entry.pw_uid == user.pw_uid]
        if aliases != [name] or set(groups[name].gr_mem) - {name}:
            _refuse()
    for name, group in groups.items():
        aliases = [entry.gr_name for entry in grp.getgrall() if entry.gr_gid == group.gr_gid]
        if aliases != [name]:
            _refuse()
    endpoints = {groups[_EXEC_GROUP].gr_gid, groups[_ADMIN_GROUP].gr_gid}
    expected = {
        _LEDGER: {users[_LEDGER].pw_gid} | endpoints,
        _EXEC: {users[_EXEC].pw_gid, groups[_EXEC_GROUP].gr_gid},
        _ADMIN: {users[_ADMIN].pw_gid, groups[_ADMIN_GROUP].gr_gid},
    }
    for name, membership in expected.items():
        if set(os.getgrouplist(name, users[name].pw_gid)) != membership:
            _refuse()
    if set(groups[_EXEC_GROUP].gr_mem) != {_LEDGER, _EXEC}:
        _refuse()
    if set(groups[_ADMIN_GROUP].gr_mem) != {_LEDGER, _ADMIN}:
        _refuse()
    return (
        users[_LEDGER].pw_uid,
        users[_LEDGER].pw_gid,
        groups[_EXEC_GROUP].gr_gid,
        groups[_ADMIN_GROUP].gr_gid,
    )


def _no_ledger_process(tree, uid):
    proc = tree.directory("/proc")
    for name in os.listdir(proc):
        if not name.isascii() or not name.isdecimal():
            continue
        try:
            with ExitStack() as stack:
                pid = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=proc
                )
                stack.callback(os.close, pid)
                fd = os.open("status", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=pid)
                stack.callback(os.close, fd)
                lines = _read_fd(fd, 65536).splitlines()
        except FileNotFoundError:
            continue  # This kernel process vanished; never ignore other read errors.
        records = [line.split()[1:] for line in lines if line.startswith(b"Uid:")]
        if len(records) != 1 or len(records[0]) != 4:
            _refuse()
        identities = [int(value) for value in records[0]]
        if uid in identities:
            _refuse()


def _load_keyfile(tree) -> ModuleType:
    version = sys.version_info.major, sys.version_info.minor
    if (
        sys.executable != _PREFIX + "/bin/python"
        or not sys.flags.isolated
        or not sys.flags.no_site
        or not sys.flags.dont_write_bytecode
    ):
        _refuse()
    if version not in {(3, 13), (3, 14)}:
        _refuse()
    directory = (
        f"{_PREFIX}/lib/python{version[0]}.{version[1]}/site-packages/ssh_over_mcp/approvals"
    )
    parent = tree.directory(directory)
    fd = tree.open("keyfile.py", os.O_RDONLY, dir_fd=parent)
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or (info.st_uid, info.st_gid) != (0, 0)
        or info.st_mode & 0o022
    ):
        _refuse()
    # Load only the reviewed stdlib leaf, never approvals/__init__.py or models.
    loader = _PinnedKeyLoader(fd, directory + "/keyfile.py")
    spec = importlib.util.spec_from_loader("_operator_ledger_keyfile", loader)
    if spec is None:
        _refuse()
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class _PinnedKeyLoader(importlib.abc.SourceLoader):
    """Only the already-validated source FD; no path/cache/package hooks."""

    def __init__(self, fd: int, filename: str):
        self.fd = fd
        self.filename = filename

    def get_filename(self, fullname: str) -> str:
        if fullname != "_operator_ledger_keyfile":
            _refuse()
        return self.filename

    def get_data(self, path: str) -> bytes:
        if path != self.filename:
            _refuse()
        return _read_fd(self.fd, 65536)


def _verify_key(tree, fd, parent, uid, gid):
    info = os.fstat(fd)
    current = os.stat("hmac.key", dir_fd=parent, follow_symlinks=False)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size != 32
        or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, gid, 0o400)
        or _identity(current) != _identity(info)
        or not stat.S_ISREG(current.st_mode)
    ):
        _refuse()
    tree.verify()


def provision_reference() -> None:
    """Provision fresh fixed paths; never overwrite, unlink, repair or retry."""
    try:
        if sys.platform != "linux" or os.getuid() != 0 or os.geteuid() != 0:
            _refuse()
        with ExitStack() as stack:
            tree = _Tree(stack)
            _core_preflight(tree)
            uid, gid, execution_gid, admin_gid = _accounts()
            _no_ledger_process(tree, uid)
            keyfile = _load_keyfile(tree)
            tree.directory("/etc/ssh-over-mcp", create_config=True)
            tree.directory("/var/lib")
            tree.directory("/run")
            leaves = (
                ("/etc/ssh-over-mcp/ledger-key", gid, 0o700),
                ("/var/lib/ssh-over-mcp-ledger", gid, 0o700),
                ("/run/ssh-over-mcp-ledger-exec", execution_gid, 0o750),
                ("/run/ssh-over-mcp-ledger-admin", admin_gid, 0o750),
            )
            for path, _, _ in leaves:
                parts = PurePosixPath(path).parts[1:]
                try:
                    os.stat(parts[-1], dir_fd=tree.nodes[parts[:-1]][0], follow_symlinks=False)
                except FileNotFoundError:
                    continue
                _refuse()
            parents = [
                tree.add_leaf(path, uid=uid, gid=group, mode=mode) for path, group, mode in leaves
            ]
            _no_ledger_process(tree, uid)
            _require_no_core(tree)
            fd = tree.open(
                "hmac.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parents[0]
            )
            keyfile.write_hmac_key(fd, uid=uid, gid=gid, mode=0o400)
            _verify_key(tree, fd, parents[0], uid, gid)
            os.fsync(parents[0])
            _verify_key(tree, fd, parents[0], uid, gid)
            _no_ledger_process(tree, uid)
            _require_no_core(tree)
    except (OSError, ValueError, LookupError, RuntimeError, SyntaxError):
        raise ProvisionError("Ledger provisioning failed") from None


def run(argv=None) -> int:
    try:
        if list(sys.argv[1:] if argv is None else argv):
            _refuse()
        provision_reference()
    except ProvisionError:
        print("Ledger provisioning failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
