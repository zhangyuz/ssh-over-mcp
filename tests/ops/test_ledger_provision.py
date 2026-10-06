from __future__ import annotations

import importlib.util
import os
import secrets
import shlex
import stat
import subprocess
import sys
import sysconfig
import venv
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "ops/systemd/ledger_provision.py"
KEY = "/etc/ssh-over-mcp/ledger-key/hmac.key"
KEY_DIR = "/etc/ssh-over-mcp/ledger-key"
ACCOUNTS = {
    "ssh-over-mcp-ledger": (2210, 3210),
    "ssh-over-mcp-exec": (2211, 3211),
    "ssh-over-mcp-admin": (2212, 3212),
}


class _Kernel:
    """Real temporary files/FDs; simulate only root identities and NSS."""

    def __init__(self, root: Path):
        self.root = root
        self.owners: dict[tuple[int, int], tuple[int, int]] = {}
        self.fds: dict[int, Path] = {}
        self.events: list[tuple[str, str]] = []
        self.created: list[tuple[str, int, int]] = []
        self.fault: str | None = None
        self.injected = False
        self.file_synced = False
        self.memberships = {
            "ssh-over-mcp-ledger": [3210, 3297, 3298],
            "ssh-over-mcp-exec": [3211, 3297],
            "ssh-over-mcp-admin": [3212, 3298],
        }

    def __getattr__(self, name):
        return getattr(os, name)

    def getuid(self):
        return 0

    geteuid = getuid

    def getgrouplist(self, user, primary):
        return self.memberships[user]

    def path(self, name, dir_fd=None):
        path = Path(name)
        return self.root / str(path).lstrip("/") if path.is_absolute() else self.fds[dir_fd] / path

    def label(self, path):
        return "/" + str(path.relative_to(self.root)) if path != self.root else "/"

    def metadata(self, info):
        uid, gid = self.owners.get((info.st_dev, info.st_ino), (0, 0))
        return SimpleNamespace(
            st_dev=info.st_dev,
            st_ino=info.st_ino,
            st_mode=info.st_mode,
            st_uid=uid,
            st_gid=gid,
            st_size=info.st_size,
            st_nlink=info.st_nlink,
        )

    def open(self, name, flags, mode=0o777, *, dir_fd=None):
        path = self.path(name, dir_fd)
        label = self.label(path)
        if label == KEY and flags & os.O_CREAT:
            self.created.append((label, flags, mode))
            if self.fault in {"existing-key", "symlink-key", "fifo-key"}:
                if self.fault == "existing-key":
                    path.write_bytes(b"EXISTING_KEY_MUST_NOT_BE_REPLACED!")
                elif self.fault == "symlink-key":
                    target = self.root / "existing-key-target"
                    target.write_bytes(b"EXISTING_KEY_MUST_NOT_BE_REPLACED!")
                    path.symlink_to(target)
                else:
                    os.mkfifo(path)
        fd = os.open(path, flags, mode)
        self.fds[fd] = path
        return fd

    def close(self, fd):
        os.close(fd)
        self.fds.pop(fd)

    def stat(self, name, *, dir_fd=None, follow_symlinks=True):
        return self.metadata(os.stat(self.path(name, dir_fd), follow_symlinks=follow_symlinks))

    def fstat(self, fd):
        return self.metadata(os.fstat(fd))

    def mkdir(self, name, mode=0o777, *, dir_fd=None):
        path = self.path(name, dir_fd)
        os.mkdir(path, mode)
        self.events.append(("mkdir", self.label(path)))

    def fchmod(self, fd, mode):
        os.fchmod(fd, mode)
        self.events.append(("chmod", self.label(self.fds[fd])))

    def fchown(self, fd, uid, gid):
        info = os.fstat(fd)
        self.owners[info.st_dev, info.st_ino] = (uid, gid)
        self.events.append(("chown", self.label(self.fds[fd])))
        if (
            self.fault == "late-core-pipe"
            and self.label(self.fds[fd]) == "/run/ssh-over-mcp-ledger-admin"
        ):
            (self.root / "proc/sys/kernel/core_pattern").write_text("|/usr/bin/collector\n")

    def listdir(self, path):
        return os.listdir(self.fds[path] if isinstance(path, int) else self.path(path))

    def fsync(self, fd):
        path = self.fds[fd]
        label = self.label(path)
        if self.fault == "parent-fsync" and self.file_synced and label == KEY_DIR:
            raise OSError("SYNTHETIC_SECRET_FROM_IO")
        os.fsync(fd)
        self.events.append(("fsync", label))
        if label == KEY:
            self.file_synced = True
            if self.fault == "changed-key" and not self.injected:
                self.injected = True
                payload = path.read_bytes()
                path.rename(path.with_name("original.key"))
                path.write_bytes(payload)
                os.chmod(path, 0o400)
                info = path.stat()
                self.owners[info.st_dev, info.st_ino] = (2210, 3210)
            elif self.fault == "changed-parent" and not self.injected:
                self.injected = True
                payload = path.read_bytes()
                parent = path.parent
                parent.rename(parent.with_name("original-parent"))
                parent.mkdir(mode=0o700)
                info = parent.stat()
                self.owners[info.st_dev, info.st_ino] = (2210, 3210)
                path.write_bytes(payload)
                os.chmod(path, 0o400)
                info = path.stat()
                self.owners[info.st_dev, info.st_ino] = (2210, 3210)


def _build_provision(tmp_path, monkeypatch):
    assert SOURCE.is_file(), "fixed fresh-install provisioning must exist"
    spec = importlib.util.spec_from_file_location("ledger_provision_test", SOURCE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    root = tmp_path / "root"
    root.mkdir(mode=0o755)
    for directory in ("etc/ssh-over-mcp", "var/lib", "run", "proc/sys/kernel"):
        (root / directory).mkdir(parents=True, mode=0o755)
    pattern = root / "proc/sys/kernel/core_pattern"
    pattern.write_text("core\n")
    kernel = _Kernel(root)
    users = {
        name: SimpleNamespace(pw_name=name, pw_uid=uid, pw_gid=gid)
        for name, (uid, gid) in ACCOUNTS.items()
    }
    groups = {
        name: SimpleNamespace(gr_name=name, gr_gid=gid, gr_mem=[])
        for name, (_, gid) in ACCOUNTS.items()
    }
    for suffix, gid in (("exec", 3297), ("admin", 3298)):
        name = "ssh-over-mcp-ledger-" + suffix
        groups[name] = SimpleNamespace(
            gr_name=name,
            gr_gid=gid,
            gr_mem=["ssh-over-mcp-ledger", "ssh-over-mcp-" + suffix],
        )
    monkeypatch.setattr(module, "os", kernel)
    monkeypatch.setattr(
        module,
        "pwd",
        SimpleNamespace(
            getpwnam=users.__getitem__,
            getpwall=lambda: list(users.values()),
        ),
    )
    monkeypatch.setattr(
        module,
        "grp",
        SimpleNamespace(
            getgrnam=groups.__getitem__,
            getgrall=lambda: list(groups.values()),
        ),
    )
    limits = SimpleNamespace(value=(0, 0), requested=[])

    def setlimit(which, value):
        limits.requested.append(value)

    monkeypatch.setattr(
        module,
        "resource",
        SimpleNamespace(
            RLIMIT_CORE=0,
            setrlimit=setlimit,
            getrlimit=lambda _: limits.value,
        ),
    )
    monkeypatch.setattr(
        module,
        "sys",
        SimpleNamespace(
            platform="linux",
            prefix="/opt/ssh-over-mcp/venv",
            version_info=sys.version_info,
            executable="/opt/ssh-over-mcp/venv/bin/python",
            flags=SimpleNamespace(isolated=1, dont_write_bytecode=1, no_site=1),
            argv=["ledger_provision.py"],
            stderr=sys.stderr,
        ),
    )
    library = (
        root
        / f"opt/ssh-over-mcp/venv/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages/ssh_over_mcp/approvals"
    )
    library.mkdir(parents=True, mode=0o755)
    (library / "keyfile.py").write_bytes(
        (ROOT / "src/ssh_over_mcp/approvals/keyfile.py").read_bytes()
    )
    real_load = module._load_keyfile

    def load(*args, **kwargs):
        keyfile = real_load(*args, **kwargs)
        monkeypatch.setattr(keyfile, "os", kernel)
        return keyfile

    monkeypatch.setattr(module, "_load_keyfile", load)
    requests = []
    real_tokens = secrets.token_bytes

    def tokens(size):
        requests.append(size)
        assert limits.requested == [(0, 0)]
        assert limits.value == (0, 0) and pattern.read_text() == "core\n"
        return real_tokens(size)

    monkeypatch.setattr(secrets, "token_bytes", tokens)
    return SimpleNamespace(
        module=module,
        root=root,
        kernel=kernel,
        pattern=pattern,
        limits=limits,
        requests=requests,
        library=library,
        users=users,
        groups=groups,
    )


@pytest.fixture
def provision(tmp_path, monkeypatch):
    return lambda: _build_provision(tmp_path, monkeypatch)


def test_new_key_is_exclusive_private_and_durable(provision, capsys):
    provision = provision()
    provision.module.provision_reference()
    key = provision.root / KEY.lstrip("/")
    assert len(key.read_bytes()) == 32
    assert stat.S_IMODE(key.stat().st_mode) == 0o400
    info = key.stat()
    assert provision.kernel.owners[info.st_dev, info.st_ino] == (2210, 3210)
    assert provision.requests == [32]
    for relative, expected_mode, gid in (
        ("etc/ssh-over-mcp/ledger-key", 0o700, 3210),
        ("var/lib/ssh-over-mcp-ledger", 0o700, 3210),
        ("run/ssh-over-mcp-ledger-exec", 0o750, 3297),
        ("run/ssh-over-mcp-ledger-admin", 0o750, 3298),
    ):
        metadata = (provision.root / relative).stat()
        assert stat.S_IMODE(metadata.st_mode) == expected_mode
        assert provision.kernel.owners[metadata.st_dev, metadata.st_ino] == (2210, gid)
    _, flags, mode = provision.kernel.created[0]
    assert flags & os.O_EXCL and flags & os.O_NOFOLLOW and flags & os.O_CLOEXEC
    assert mode == 0o600
    events = provision.kernel.events
    assert events.index(("fsync", KEY)) < events.index(
        ("fsync", KEY_DIR), events.index(("fsync", KEY))
    )
    assert events.index(("chmod", KEY)) < events.index(("chown", KEY))
    assert not provision.kernel.fds
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "fault",
    [
        "existing-key",
        "symlink-key",
        "fifo-key",
        "changed-key",
        "changed-parent",
        "parent-fsync",
    ],
)
def test_unknown_or_uncertain_key_state_refuses_without_cleanup(provision, capsys, fault):
    provision = provision()
    provision.kernel.fault = fault
    with pytest.raises(provision.module.ProvisionError, match="^Ledger provisioning failed$"):
        provision.module.provision_reference()
    assert not provision.kernel.fds
    assert capsys.readouterr().out == ""
    key = provision.root / KEY.lstrip("/")
    if fault in {"existing-key", "symlink-key"}:
        assert key.read_bytes() == b"EXISTING_KEY_MUST_NOT_BE_REPLACED!"
    elif fault == "fifo-key":
        assert stat.S_ISFIFO(key.lstat().st_mode)
    elif fault == "changed-key":
        assert key.with_name("original.key").exists()
    elif fault == "changed-parent":
        assert key.parent.with_name("original-parent").joinpath("hmac.key").exists()
    else:
        assert len(key.read_bytes()) == 32


@pytest.mark.parametrize("fault", ["writable", "symlink"])
def test_unsafe_ancestor_refuses_before_key_generation(provision, fault):
    provision = provision()
    parent = provision.root / "etc/ssh-over-mcp"
    if fault == "writable":
        parent.chmod(0o777)
    else:
        parent.rename(parent.with_name("actual-parent"))
        parent.symlink_to(parent.with_name("actual-parent"), target_is_directory=True)
    with pytest.raises(provision.module.ProvisionError):
        provision.module.provision_reference()
    assert provision.requests == []
    assert not provision.kernel.created


@pytest.mark.parametrize("fault", ["pipe", "limits"])
def test_core_preflight_precedes_csprng(provision, fault):
    provision = provision()
    if fault == "pipe":
        provision.pattern.write_text("|/usr/bin/collector\n")
    else:
        provision.limits.value = (0, 1)
    with pytest.raises(provision.module.ProvisionError):
        provision.module.provision_reference()
    assert provision.requests == []
    assert not provision.kernel.created


def test_changed_core_policy_refuses_immediately_before_generation(provision):
    provision = provision()
    provision.kernel.fault = "late-core-pipe"
    with pytest.raises(provision.module.ProvisionError):
        provision.module.provision_reference()
    assert provision.requests == []
    assert not provision.kernel.created


@pytest.mark.parametrize("fault", ["cross-group", "active-process", "uid-alias", "same-gid"])
def test_unsafe_account_or_active_service_refuses(provision, fault):
    provision = provision()
    if fault == "cross-group":
        provision.kernel.memberships["ssh-over-mcp-exec"].append(3298)
    elif fault == "active-process":
        proc = provision.root / "proc/999"
        proc.mkdir()
        (proc / "status").write_text("Name:\tledger\nUid:\t2210\t2210\t2210\t2210\n")
    elif fault == "uid-alias":
        provision.users["alias"] = SimpleNamespace(pw_name="alias", pw_uid=2210, pw_gid=3210)
    else:
        provision.groups["ssh-over-mcp-ledger-admin"].gr_gid = 3297
    with pytest.raises(provision.module.ProvisionError):
        provision.module.provision_reference()
    assert provision.requests == []
    assert not provision.kernel.created


@pytest.mark.parametrize("gid", [3210, 3211, 3212, 3297, 3298])
def test_unrelated_primary_gid_cannot_join_protected_groups(provision, gid):
    provision = provision()
    # Primary membership lives in passwd, not group.gr_mem or selected users' groups.
    provision.users["unexpected"] = SimpleNamespace(
        pw_name="unexpected", pw_uid=2400, pw_gid=gid
    )
    with pytest.raises(provision.module.ProvisionError, match="^Ledger provisioning failed$"):
        provision.module.provision_reference()
    assert provision.requests == []
    assert not provision.kernel.created
    assert not provision.kernel.fds


def test_unrelated_process_name_does_not_change_uid_quiescence_check(provision):
    provision = provision()
    proc = provision.root / "proc/1000"
    proc.mkdir()
    (proc / "status").write_bytes("Name:\tworker-雪\nUid:\t1000\t1000\t1000\t1000\n".encode())
    provision.module.provision_reference()
    assert provision.requests == [32]


@pytest.mark.parametrize(
    "fault", ["args", "unisolated", "site-hooks", "foreign-prefix", "writable-loader"]
)
def test_cli_and_loader_cannot_select_foreign_authority(provision, capsys, fault):
    provision = provision()
    args = []
    if fault == "args":
        args = ["--key", "/tmp/other", "--uid", "0"]
    elif fault == "unisolated":
        provision.module.sys.flags.isolated = 0
    elif fault == "site-hooks":
        provision.module.sys.flags.no_site = 0
    elif fault == "foreign-prefix":
        provision.module.sys.prefix = "/tmp/other"
        provision.module.sys.executable = "/tmp/other/bin/python"
    else:
        (provision.library / "keyfile.py").chmod(0o666)
    assert provision.module.run(args) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "Ledger provisioning failed\n"
    assert provision.requests == []


def test_python313_site_free_prefix_does_not_require_site_initialization(provision):
    provision = provision()
    provision.module.sys.version_info = SimpleNamespace(major=3, minor=13)
    provision.module.sys.prefix = "/usr"  # Python 3.13 -S leaves prefix at base_prefix.
    library = (
        provision.root / "opt/ssh-over-mcp/venv/lib/python3.13/site-packages/ssh_over_mcp/approvals"
    )
    library.mkdir(parents=True, exist_ok=True)
    (library / "keyfile.py").write_bytes(
        (ROOT / "src/ssh_over_mcp/approvals/keyfile.py").read_bytes()
    )
    provision.module.provision_reference()
    assert provision.requests == [32]


def test_launcher_has_fixed_isolated_entrypoint():
    launcher = ROOT / "ops/systemd/ssh-over-mcp-ledger-provision"
    assert launcher.is_file(), "fixed operator launcher must exist"
    source = launcher.read_text()
    assert "/opt/ssh-over-mcp/venv/bin/python -I -S -B" in source
    assert "/opt/ssh-over-mcp/ops/systemd/ledger_provision.py" in source
    assert '"$@"' not in source
    assert "PYTHONPATH" not in source


def test_launcher_flags_block_real_site_and_environment_hooks(tmp_path):
    launcher = ROOT / "ops/systemd/ssh-over-mcp-ledger-provision"
    command = next(line for line in launcher.read_text().splitlines() if line.startswith("exec "))
    flags = shlex.split(command)[2:-1]
    runtime = tmp_path / "venv"
    venv.EnvBuilder(with_pip=False).create(runtime)
    library = runtime / f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
    site_marker = tmp_path / "site-hook"
    env_marker = tmp_path / "environment-hook"
    (library / "provision-hook.pth").write_text(
        f"import pathlib; pathlib.Path({str(site_marker)!r}).touch()\n"
    )
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "sitecustomize.py").write_text(
        f"from pathlib import Path; Path({str(env_marker)!r}).touch()\n"
    )
    env = {"PATH": os.defpath, "PYTHONPATH": str(foreign), "PYTHONHOME": str(foreign)}
    # CI toolcache Python is dynamically linked. Use its own trusted library directory,
    # not inherited loader paths, so the child reaches Python/site initialization.
    if sys.platform == "linux":
        env["LD_LIBRARY_PATH"] = sysconfig.get_config_var("LIBDIR")
    interpreter = runtime / "bin/python"
    subprocess.run([str(interpreter), "-I", "-B", "-c", "pass"], check=True, env=env)
    assert site_marker.exists(), "differential control must actually execute the installed hook"
    site_marker.unlink()
    subprocess.run([str(interpreter), *flags, "-c", "pass"], check=True, env=env)
    assert not site_marker.exists()
    assert not env_marker.exists()
