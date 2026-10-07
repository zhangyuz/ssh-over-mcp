from __future__ import annotations

import errno
import fcntl
import hashlib
import importlib.util
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "ops/live-e2e/staging_diagnostics.py"
AUTHORITY = "1ddebe541ee80c0febc4cd35072f3a5046fac5cb"
BINDING = (
    ("docs/decisions/0011-incident-bound-e2e-staging-recovery.md", 11227,
     "c98f99d29f8e02bae4c90f56565241818f23e10a229afcecafbebd2a91b43e3b"),
    ("docs/decisions/0012-owned-diagnostic-child-lifecycle.md", 11238,
     "980801f685dba9eee8a8e76c0e39641fd7aa61d5c3453ecd6e10d9ba5f4a51a3"),
    ("docs/superpowers/specs/2026-10-06-incident-staging-inspection-design.md", 22821,
     "650d65243e023f647e4c7424357ad1e2b19d6317eb603cfa1bebde388e358882"),
)


def _load_module() -> ModuleType:
    assert MODULE.is_file(), "dormant fixed diagnostic module is not implemented"
    name = "ssh_over_mcp_staging_diagnostics"
    spec = importlib.util.spec_from_file_location(name, MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


@pytest.fixture
def diagnostics():
    return _load_module()


@pytest.fixture
def authority_tree(diagnostics, monkeypatch):
    # The production chain refuses shared writable /tmp ancestors.
    scratch = ROOT / ".superpowers"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="diagnostic-authority-", dir=scratch) as name:
        root = Path(name)
        for path, _, _ in BINDING:
            destination = root / path
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(ROOT / path, destination)
            destination.chmod(0o644)
        monkeypatch.setattr(diagnostics, "__file__", str(root / "ops/live-e2e/module.py"))
        yield root


def test_binding_matches_exact_main_blobs(diagnostics):
    assert diagnostics.AUTHORITY_COMMIT == AUTHORITY
    assert diagnostics.AUTHORITY_FILES == BINDING
    for path, size, digest in BINDING:
        blob = subprocess.run(
            ["git", "show", f"{AUTHORITY}:{path}"], cwd=ROOT, check=True, capture_output=True
        ).stdout
        assert len(blob) == size and hashlib.sha256(blob).hexdigest() == digest
    diagnostics._verify_authority()


def test_fixed_constants(diagnostics):
    # Literal constraints are also exercised through the capture consumers in
    # Task 2; these vectors pin the approved authority values independently.
    assert diagnostics.GETCONF_ARGV == ("/usr/bin/getconf", "DARWIN_USER_TEMP_DIR")
    assert diagnostics.PS_ARGV == ("/bin/ps", "-ww", "-U", "502", "-o", "pid=,comm=")
    assert diagnostics.GETCONF_SECONDS == 5
    assert diagnostics.PS_SECONDS == 10
    assert diagnostics.CLEANUP_SECONDS == 2
    assert diagnostics.GETCONF_STREAM_BYTES == 1024
    assert diagnostics.GETCONF_COMBINED_BYTES == 2048
    assert diagnostics.PS_COMBINED_BYTES == 65536
    assert diagnostics.MAX_FD_NAMES == 1024


@pytest.mark.parametrize("change", ["changed", "missing", "symlink", "fifo", "hardlink", "mode"])
def test_binding_refuses_changed_symlink_special_or_unstable_documents(
    diagnostics, authority_tree, monkeypatch, change
):
    path = authority_tree / BINDING[0][0]
    secret = authority_tree / "unrelated-file"
    secret.write_bytes(b"must-not-read-this-canary")
    if change == "changed":
        raw = path.read_bytes()
        path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
    elif change == "mode":
        path.chmod(0o666)
    elif change == "hardlink":
        os.link(path, authority_tree / "alias")
    else:
        path.unlink()
        if change == "symlink":
            path.symlink_to(secret)
        elif change == "fifo":
            os.mkfifo(path, 0o600)
    real_read = os.read
    secret_identity = (secret.stat().st_dev, secret.stat().st_ino)

    def read(fd, size):
        info = os.fstat(fd)
        assert (info.st_dev, info.st_ino) != secret_identity
        assert stat.S_ISREG(info.st_mode), "non-regular authority object read"
        return real_read(fd, size)

    monkeypatch.setattr(diagnostics.os, "read", read)
    with pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"):
        diagnostics._verify_authority()


def test_binding_rejects_namespace_replacement_during_read(
    diagnostics, authority_tree, monkeypatch
):
    path = authority_tree / BINDING[0][0]
    before = path.stat()
    real_read = os.read
    replaced = False

    def read(fd, size):
        nonlocal replaced
        info = os.fstat(fd)
        result = real_read(fd, size)
        if info.st_ino == before.st_ino and not replaced:
            replacement = path.with_suffix(".replacement")
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o644)
            replacement.replace(path)
            replaced = True
        return result

    monkeypatch.setattr(diagnostics.os, "read", read)
    with pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"):
        diagnostics._verify_authority()
    assert replaced


def test_binding_accepts_complete_short_reads(diagnostics, authority_tree, monkeypatch):
    real_read = os.read
    monkeypatch.setattr(diagnostics.os, "read", lambda fd, size: real_read(fd, min(size, 17)))
    diagnostics._verify_authority()


@pytest.mark.parametrize("change", ["directory_mode", "directory_symlink", "owner", "file_size"])
def test_binding_rejects_unsafe_chain_or_file_metadata(
    diagnostics, authority_tree, monkeypatch, change
):
    parent = authority_tree / "docs/decisions"
    path = authority_tree / BINDING[0][0]
    if change == "directory_mode":
        parent.chmod(0o777)
    elif change == "directory_symlink":
        target = parent.with_name("other")
        parent.rename(target)
        parent.symlink_to(target, target_is_directory=True)
    elif change == "file_size":
        path.write_bytes(path.read_bytes()[:-1])
    else:
        real_fstat = os.fstat

        def fstat(fd):
            info = real_fstat(fd)
            if stat.S_ISREG(info.st_mode):
                values = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
                values["st_uid"] = 900001
                return SimpleNamespace(**values)
            return info

        monkeypatch.setattr(diagnostics.os, "fstat", fstat)
    with pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"):
        diagnostics._verify_authority()


def _identity(monkeypatch, diagnostics):
    monkeypatch.setattr(diagnostics.os, "geteuid", lambda: 502)
    monkeypatch.setattr(diagnostics.os, "getegid", lambda: 20)
    monkeypatch.setattr(diagnostics.os, "getgroups", lambda: [20, 12])
    monkeypatch.setattr(diagnostics.pwd, "getpwuid", lambda uid: SimpleNamespace(
        pw_uid=502, pw_gid=20, pw_name="gha-e2e-orchestrator",
        pw_dir="/Users/gha-e2e-orchestrator"
    ))
    monkeypatch.setattr(diagnostics.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=80))


@pytest.mark.parametrize("change", ["uid", "name", "home", "primary_admin", "extra_admin", "lookup"])
def test_context_refuses_wrong_platform_identity_admin_or_reaper_state(
    diagnostics, monkeypatch, change
):
    _identity(monkeypatch, diagnostics)
    diagnostics._require_identity()
    if change == "uid":
        monkeypatch.setattr(diagnostics.os, "geteuid", lambda: 501)
    elif change == "name" or change == "home":
        monkeypatch.setattr(diagnostics.pwd, "getpwuid", lambda uid: SimpleNamespace(
            pw_uid=502, pw_gid=20,
            pw_name="other" if change == "name" else "gha-e2e-orchestrator",
            pw_dir="/tmp/other" if change == "home" else "/Users/gha-e2e-orchestrator"
        ))
    elif change == "primary_admin":
        monkeypatch.setattr(diagnostics.os, "getegid", lambda: 80)
    elif change == "extra_admin":
        monkeypatch.setattr(diagnostics.os, "getgroups", lambda: [20, 80])
    else:
        monkeypatch.setattr(diagnostics.grp, "getgrnam", lambda _: (_ for _ in ()).throw(KeyError()))
    with pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"):
        diagnostics._require_identity()


@pytest.mark.parametrize("change", ["platform", "machine", "root", "threads", "sigchld"])
def test_wait_context_refuses_unsupported_ownership_state(diagnostics, monkeypatch, change):
    monkeypatch.setattr(diagnostics.sys, "platform", "darwin")
    monkeypatch.setattr(diagnostics.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(diagnostics.os, "geteuid", lambda: 501)
    monkeypatch.setattr(diagnostics.threading, "active_count", lambda: 1)
    monkeypatch.setattr(diagnostics.signal, "getsignal", lambda _: signal.SIG_DFL)
    diagnostics._require_wait_context()
    if change == "platform":
        monkeypatch.setattr(diagnostics.sys, "platform", "linux")
    elif change == "machine":
        monkeypatch.setattr(diagnostics.platform, "machine", lambda: "arm64")
    elif change == "root":
        monkeypatch.setattr(diagnostics.os, "geteuid", lambda: 0)
    elif change == "threads":
        monkeypatch.setattr(diagnostics.threading, "active_count", lambda: 2)
    else:
        monkeypatch.setattr(diagnostics.signal, "getsignal", lambda _: signal.SIG_IGN)
    with pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"):
        diagnostics._require_wait_context()


def test_launch_excludes_inheritable_parent_fds_without_mutation(diagnostics, tmp_path):
    fd = os.open(tmp_path / "borrowed", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, b"canary")
        os.set_inheritable(fd, True)
        flags = fcntl.fcntl(fd, fcntl.F_GETFD), fcntl.fcntl(fd, fcntl.F_GETFL)
        before = os.fstat(fd)
        with diagnostics._prepare_launch(deadline=diagnostics.monotonic() + 5) as launch:
            assert (os.POSIX_SPAWN_CLOSE, fd) in launch.file_actions
            assert launch.file_actions[:3] == (
                (os.POSIX_SPAWN_DUP2, launch.stdin_fd, 0),
                (os.POSIX_SPAWN_DUP2, launch.stdout_write, 1),
                (os.POSIX_SPAWN_DUP2, launch.stderr_write, 2),
            )
            for own in (launch.stdin_fd, launch.stdout_read, launch.stdout_write,
                        launch.stderr_read, launch.stderr_write):
                assert own >= 3 and (os.POSIX_SPAWN_CLOSE, own) in launch.file_actions
            launch.close_child_ends()
            assert os.fstat(fd).st_ino == before.st_ino
        assert flags == (fcntl.fcntl(fd, fcntl.F_GETFD), fcntl.fcntl(fd, fcntl.F_GETFL))
        assert os.lseek(fd, 0, os.SEEK_CUR) == 6
        assert os.fstat(fd).st_ino == before.st_ino
    finally:
        os.close(fd)


class _Names:
    def __init__(self, names):
        self.names = names

    def __enter__(self):
        return (SimpleNamespace(name=name) for name in self.names)

    def __exit__(self, *args):
        pass


@pytest.mark.parametrize("count", [1024, 1025])
def test_fd_enumeration_overflow_refuses_before_spawn(diagnostics, monkeypatch, count):
    monkeypatch.setattr(diagnostics.os, "scandir", lambda path: _Names(map(str, range(count))))
    if count == 1024:
        with diagnostics._prepare_launch(deadline=diagnostics.monotonic() + 5) as launch:
            assert (os.POSIX_SPAWN_CLOSE, launch.stdout_read) in launch.file_actions
    else:
        with (
            pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"),
            diagnostics._prepare_launch(deadline=diagnostics.monotonic() + 5),
        ):
            pytest.fail("FD count overflow accepted")


@pytest.mark.parametrize("names", [["03"], ["-1"], ["x"], ["1", "1"], ["2147483648"]])
def test_fd_enumeration_refuses_ambiguous_names(diagnostics, monkeypatch, names):
    monkeypatch.setattr(diagnostics.os, "scandir", lambda path: _Names(names))
    with (
        pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"),
        diagnostics._prepare_launch(deadline=diagnostics.monotonic() + 5),
    ):
        pytest.fail("ambiguous FD accepted")


def test_resource_deadline_equality_refuses_without_mutating_borrowed_fd(diagnostics, tmp_path):
    fd = os.open(tmp_path / "borrowed", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with (
            pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"),
            diagnostics._prepare_launch(deadline=diagnostics.monotonic()),
        ):
            pytest.fail("expired launch accepted")
        assert stat.S_ISREG(os.fstat(fd).st_mode)
    finally:
        os.close(fd)


def test_import_produces_no_host_action_or_output(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("import performed a host action")

    monkeypatch.setattr(os, "posix_spawn", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    _load_module()
    assert capsys.readouterr() == ("", "")


def test_launch_omits_only_proven_closed_scanner_slot(diagnostics):
    with diagnostics._prepare_launch(deadline=diagnostics.monotonic() + 5) as launch:
        for action in launch.file_actions[3:]:
            assert action[0] == os.POSIX_SPAWN_CLOSE
            # EBADF for a scanner-owned transient slot must not make Darwin's
            # spawn fail. Every *open* descriptor still gets a CLOSE action.
            os.fstat(action[1])


def test_fd_verification_other_error_refuses_preserving_borrowed_fd(
    diagnostics, tmp_path, monkeypatch
):
    fd = os.open(tmp_path / "borrowed", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    real_fstat = os.fstat

    def fstat(value):
        if value == fd:
            raise OSError(errno.EIO, "private canary error must not escape")
        return real_fstat(value)

    try:
        monkeypatch.setattr(diagnostics.os, "fstat", fstat)
        with (
            pytest.raises(diagnostics.DiagnosticError, match="^staging diagnostic rejected$"),
            diagnostics._prepare_launch(deadline=diagnostics.monotonic() + 5),
        ):
            pytest.fail("unknown descriptor state accepted")
        assert stat.S_ISREG(real_fstat(fd).st_mode)
    finally:
        os.close(fd)
