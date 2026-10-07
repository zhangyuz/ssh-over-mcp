from __future__ import annotations

import errno
import importlib.util
import json
import os
import platform
import select
import signal
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "ops/live-e2e/staging_diagnostics.py"
pytestmark = pytest.mark.skipif(
    sys.platform != "darwin" or platform.machine() != "x86_64" or os.geteuid() == 0,
    reason="requires disposable non-root native Darwin x86_64 evidence",
)


def _load_module():
    assert MODULE.is_file(), "dormant fixed diagnostic module is not implemented"
    name = "ssh_over_mcp_staging_diagnostics_native"
    spec = importlib.util.spec_from_file_location(name, MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


def _fixture_exec(module, launch, script):
    # Fixture owner only; production receives neither this command nor this PID.
    try:
        pid = os.posix_spawn(
            sys.executable, (sys.executable, "-I", "-B", "-c", script), {"LC_ALL": "C"},
            file_actions=launch.file_actions, setsigdef=(signal.SIGPIPE, signal.SIGCHLD),
        )
    except OSError as error:
        raise AssertionError(f"disposable fixture spawn errno={error.errno}") from None
    launch.close_child_ends()
    os.set_blocking(launch.stdout_read, False)
    chunks = bytearray()
    deadline = module.monotonic() + 5
    reaped = False
    try:
        while module.monotonic() < deadline:
            if select.select([launch.stdout_read], [], [], max(0, deadline-module.monotonic()))[0]:
                raw = os.read(launch.stdout_read, 8192)
                if not raw:
                    break
                chunks.extend(raw)
        else:
            pytest.fail("disposable FD probe did not complete")
        own, status = os.waitpid(pid, 0)
        reaped = True
        assert own == pid and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
        return bytes(chunks)
    finally:
        if not reaped:
            own, _ = os.waitpid(pid, os.WNOHANG)
            if own == 0:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)


def test_parent_fds_preserved_and_absent_after_exec(tmp_path):
    module = _load_module()
    fd = os.open(tmp_path / "borrowed", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, b"fixture-canary")
        os.set_inheritable(fd, True)
        before = os.fstat(fd)
        import fcntl

        flags = (fcntl.fcntl(fd, fcntl.F_GETFD), fcntl.fcntl(fd, fcntl.F_GETFL))
        script = (
            "import os,json; "
            f"canary=({before.st_dev},{before.st_ino}); "
            "found=[]; "
            "\nfor item in os.scandir('/dev/fd'):\n"
            " try:\n  s=os.fstat(int(item.name)); "
            "found.append(int(item.name)) if (s.st_dev,s.st_ino)==canary else None\n"
            " except OSError: pass\n"
            "print(json.dumps(found))"
        )
        with module._prepare_launch(deadline=module.monotonic() + 5) as launch:
            assert _fixture_exec(module, launch, script) == b"[]\n"
        assert flags == (fcntl.fcntl(fd, fcntl.F_GETFD), fcntl.fcntl(fd, fcntl.F_GETFL))
        assert os.fstat(fd).st_ino == before.st_ino
        assert os.lseek(fd, 0, os.SEEK_CUR) == len(b"fixture-canary")
    finally:
        os.close(fd)


@pytest.mark.parametrize("lower_limit", [False, True])
def test_closed_stdio_sparse_high_fds_and_lowered_limit_are_safe(tmp_path, lower_limit):
    _load_module()  # RED must show missing module before launching a fixture.
    report = tmp_path / "report.json"
    script = r'''
import os, sys, fcntl, resource, importlib.util, json, time
spec=importlib.util.spec_from_file_location('fixture_diagnostics', sys.argv[1])
m=importlib.util.module_from_spec(spec); sys.modules[spec.name]=m; spec.loader.exec_module(m)
base=os.open(sys.argv[2],os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
high=fcntl.fcntl(base,fcntl.F_DUPFD,160); os.close(base); os.set_inheritable(high,True)
identity=(os.fstat(high).st_dev,os.fstat(high).st_ino)
soft,hard=resource.getrlimit(resource.RLIMIT_NOFILE)
if sys.argv[4]=='1': resource.setrlimit(resource.RLIMIT_NOFILE,(128,hard))
for fd in (0,1,2):
 try: os.close(fd)
 except OSError: pass
accepted=False
try:
 with m._prepare_launch(deadline=time.monotonic()+5) as launch:
  probe="import os; " + "\ntry: os.fstat(160)\nexcept OSError: os._exit(0)\nelse: os._exit(1)"
  try:
   pid=os.posix_spawn(sys.executable,(sys.executable,'-I','-B','-c',probe),{'LC_ALL':'C'},file_actions=launch.file_actions)
  except OSError:
   pass  # Native incompatibility must refuse; no inherited fallback.
  else:
   launch.close_child_ends(); own,status=os.waitpid(pid,0)
   assert own==pid and os.WIFEXITED(status) and os.WEXITSTATUS(status)==0
   accepted=True
except m.DiagnosticError:
 pass
assert identity==(os.fstat(high).st_dev,os.fstat(high).st_ino)
assert os.get_inheritable(high)
for fd in (0,1,2):
 try: os.fstat(fd)
 except OSError: pass
 else: raise AssertionError('originally closed parent stdio modified')
os.close(high)
with open(sys.argv[3],'x') as f: json.dump({'safe':True,'accepted':accepted},f)
'''
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script, str(MODULE),
         str(tmp_path / "high-canary"), str(report), "1" if lower_limit else "0"],
        capture_output=True, timeout=15, check=False,
    )
    assert result.returncode == 0, result.stderr
    result = json.loads(report.read_text())
    assert result["safe"] is True
    if not lower_limit:
        assert result["accepted"] is True


def test_darwin_closed_close_action_refuses_before_owned_pid(tmp_path):
    fd = os.open(tmp_path / "closed-slot", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    with pytest.raises(OSError) as error:
        os.posix_spawn(sys.executable, (sys.executable, "-I", "-B", "-c", "pass"),
                       {"LC_ALL": "C"}, file_actions=((os.POSIX_SPAWN_CLOSE, fd),))
    assert error.value.errno == errno.EBADF


@contextmanager
def _substitute_owned_fixture(module, monkeypatch, script, *, retain_pipe=False, kind="getconf"):
    """Only the test OS boundary selects a fixture executable, never production."""
    real_spawn, real_wait, real_kill = os.posix_spawn, os.waitpid, os.kill
    spawned, signals, holders = [], [], []

    def spawn(executable, argv, env, **kwargs):
        expected = (("/usr/bin/getconf", "DARWIN_USER_TEMP_DIR") if kind == "getconf" else
                    ("/bin/ps", "-ww", "-U", "502", "-o", "pid=,comm="))
        assert executable == expected[0] and tuple(argv) == expected
        assert env == {"LC_ALL": "C"}
        if retain_pipe:
            holders.append(real_spawn(
                sys.executable, (sys.executable, "-I", "-B", "-c",
                                 "import signal; signal.pause()"), env, **kwargs
            ))
        pid = real_spawn(sys.executable, (sys.executable, "-I", "-B", "-c", script),
                         env, **kwargs)
        spawned.append(pid)
        return pid

    def kill(pid, number):
        assert pid in spawned and pid not in holders and number == signal.SIGKILL
        signals.append((pid, number))
        assert len(signals) == 1
        return real_kill(pid, number)

    monkeypatch.setattr(module, "_require_identity", lambda: None)
    monkeypatch.setattr(module.os, "posix_spawn", spawn)
    monkeypatch.setattr(module.os, "kill", kill)
    try:
        yield spawned, signals, holders
    finally:
        # This is fixture-owner teardown, never the component's authority.
        for pid in spawned + holders:
            try:
                own, _ = real_wait(pid, os.WNOHANG)
            except ChildProcessError:
                continue
            if own == 0:
                real_kill(pid, signal.SIGKILL)
                assert real_wait(pid, 0)[0] == pid


@pytest.mark.parametrize("kind", ["getconf", "ps"])
def test_native_fixed_diagnostic_positive_control(monkeypatch, kind):
    module = _load_module()
    monkeypatch.setattr(module, "_require_identity", lambda: None)
    call = module.capture_getconf if kind == "getconf" else module.capture_ps
    result = call()
    assert result.kind == kind and result.child_pid > 0
    assert len(result.stdout) <= (1024 if kind == "getconf" else 65536)
    with pytest.raises(ChildProcessError):
        os.waitpid(result.child_pid, os.WNOHANG)


def test_native_stdout_and_exclusive_reap(monkeypatch):
    module = _load_module()
    with _substitute_owned_fixture(
        module, monkeypatch, "import os; os.write(1,b'bounded\\n')"
    ) as (spawned, signals, _):
        result = module.capture_getconf()
        assert result.stdout == b"bounded\n" and result.child_pid == spawned[0]
        assert signals == []
        with pytest.raises(ChildProcessError):
            os.waitpid(result.child_pid, os.WNOHANG)


@pytest.mark.parametrize("script", [
    "import os; os.write(2,b'private-canary')",
    "import os; os._exit(1)",
    "import os,signal; os.kill(os.getpid(),signal.SIGKILL)",
])
def test_native_nonzero_stderr_or_signal_returns_safe_failure(monkeypatch, script, capsys):
    module = _load_module()
    with _substitute_owned_fixture(module, monkeypatch, script) as (_, signals, _):
        with pytest.raises(module.DiagnosticError) as error:
            module.capture_getconf()
        assert str(error.value) == "staging diagnostic rejected"
        assert error.value.cleanup_uncertain is False
        assert len(signals) <= 1
        assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("script", [
    "import os,signal; os.write(1,b'x'*1025); signal.pause()",
    "import signal; signal.pause()",
    "import os,signal; os.close(1); os.close(2); signal.pause()",
])
def test_native_overflow_stall_or_early_eof_kills_only_owned_child(monkeypatch, script, tmp_path):
    module = _load_module()
    fd = os.open(tmp_path / "borrowed", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, b"borrowed-canary")
        os.set_inheritable(fd, True)
        before = os.fstat(fd)
        with _substitute_owned_fixture(module, monkeypatch, script) as (spawned, signals, _):
            with pytest.raises(module.DiagnosticError) as error:
                module.capture_getconf()
            assert error.value.cleanup_uncertain is False
            assert signals == [(spawned[0], signal.SIGKILL)]
            with pytest.raises(ChildProcessError):
                os.waitpid(spawned[0], os.WNOHANG)
        assert os.fstat(fd).st_ino == before.st_ino and os.get_inheritable(fd)
        assert os.lseek(fd, 0, os.SEEK_CUR) == len(b"borrowed-canary")
    finally:
        os.close(fd)


def test_native_exit_with_retained_pipe_never_signals_other_process(monkeypatch):
    module = _load_module()
    with _substitute_owned_fixture(module, monkeypatch, "pass", retain_pipe=True) as (
        spawned, signals, holders
    ):
        with pytest.raises(module.DiagnosticError) as error:
            module.capture_getconf()
        assert error.value.cleanup_uncertain is False
        assert signals == []
        with pytest.raises(ChildProcessError):
            os.waitpid(spawned[0], os.WNOHANG)
        assert os.waitpid(holders[0], os.WNOHANG) == (0, 0)


@pytest.mark.parametrize("size,accepted", [(65536, True), (65537, False)])
def test_native_ps_combined_output_boundary(monkeypatch, size, accepted):
    module = _load_module()
    script = f"import os; data=b'x'*{size}; " + (
        "\nwhile data:\n n=os.write(1,data); data=data[n:]"
    )
    with _substitute_owned_fixture(module, monkeypatch, script, kind="ps") as (_, signals, _):
        if accepted:
            assert module.capture_ps().stdout == b"x" * 65536
            assert signals == []
        else:
            with pytest.raises(module.DiagnosticError) as error:
                module.capture_ps()
            assert error.value.cleanup_uncertain is False
            assert len(signals) <= 1
