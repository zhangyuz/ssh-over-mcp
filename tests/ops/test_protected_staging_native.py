from __future__ import annotations

import importlib.util
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "ops/live-e2e/staging_namespace_native.py"


def load_module():
    assert MODULE.is_file(), "fixed native namespace module is missing"
    name = "_som_native_test"
    spec = importlib.util.spec_from_file_location(name, MODULE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


@pytest.fixture
def native(monkeypatch):
    module = load_module()
    # Portable fixtures keep real wait/signal ownership and replace only the
    # Darwin executable/platform boundary; no provider command is executed.
    monkeypatch.setattr(module, "_require_platform", lambda: None, raising=False)
    return module


@pytest.fixture
def child_factory(native, monkeypatch):
    children = []

    def install(script):
        def spawn():
            child = subprocess.Popen(
                [sys.executable, "-I", "-c", script], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
            )
            children.append(child)
            return child

        monkeypatch.setattr(native, "_spawn_getconf", spawn, raising=False)
        return children

    yield install
    for child in children:
        # Fixture owns these exact Popen objects; teardown never looks up PIDs.
        if child.poll() is None:
            child.kill()
        child.wait(timeout=3)
        for stream in (child.stdout, child.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def test_native_capture_is_canonical(native, child_factory):
    children = child_factory("import os; os.write(1, b'/var/folders/ab/runner_123/T/\\n')")
    parent = native.discover_native_temp()
    assert parent.source == "/var/folders/ab/runner_123/T/"
    assert parent.canonical == "/private/var/folders/ab/runner_123/T/"
    assert children[0].returncode == 0
    assert children[0].stdout.closed and children[0].stderr.closed


@pytest.mark.parametrize(
    "raw",
    [b"", b"/var/folders/ab/token/T/", b"/var/folders/ab/token/T/\n\n",
     b"/var/folders/a/token/T/\n", b"/var/folders/ab/UPPER/T/\n",
     b"/var/folders/ab/../T/\n", b"/var/folders/ab/" + b"a" * 256 + b"/T/\n",
     b"/private/var/folders/ab/token/T/\n", b"/var/folders/ab/token/T/\x00\n"],
)
def test_malformed_native_capture_refuses(native, child_factory, raw):
    children = child_factory(f"import os; os.write(1, {raw!r})")
    with pytest.raises(native.NamespaceError) as error:
        native.discover_native_temp()
    assert error.value.reason == "native-discovery"
    assert children[0].returncode == 0


def test_nonzero_exit_refuses(native, child_factory):
    children = child_factory("import sys; print('/var/folders/ab/token/T/'); sys.exit(3)")
    with pytest.raises(native.NamespaceError):
        native.discover_native_temp()
    assert children[0].returncode == 3


@pytest.mark.parametrize("size,accepted", [(1024, True), (1025, False)])
def test_stderr_bound_is_independent(native, child_factory, size, accepted):
    children = child_factory(
        f"import os; os.write(2, b'e' * {size}); "
        "os.write(1, b'/var/folders/ab/token/T/\\n')"
    )
    if accepted:
        assert native.discover_native_temp().canonical == "/private/var/folders/ab/token/T/"
    else:
        with pytest.raises(native.NamespaceError):
            native.discover_native_temp()
    assert children[0].returncode is not None


@pytest.mark.parametrize("size", [4096, 4097, 1_000_000])
def test_stdout_bound_rejects_malformed_or_flooded_output(native, child_factory, size):
    children = child_factory(f"import os; os.write(1, b'x' * {size})")
    started = time.monotonic()
    with pytest.raises(native.NamespaceError):
        native.discover_native_temp()
    assert time.monotonic() - started < 8
    assert children[0].returncode is not None


def test_deadline_terminates_and_reaps_only_owned_child(native, child_factory):
    children = child_factory("import time; time.sleep(30)")
    started = time.monotonic()
    with pytest.raises(native.NamespaceError) as error:
        native.discover_native_temp()
    elapsed = time.monotonic() - started
    assert 4.8 <= elapsed < 8
    assert error.value.cleanup_uncertain is False
    assert children[0].returncode is not None


def test_term_ignoring_child_is_killed_within_owned_cleanup_budget(native, child_factory):
    children = child_factory(
        "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)"
    )
    started = time.monotonic()
    with pytest.raises(native.NamespaceError) as error:
        native.discover_native_temp()
    assert time.monotonic() - started < 8
    assert error.value.cleanup_uncertain is False
    assert children[0].returncode == -signal.SIGKILL


@pytest.mark.parametrize("bad", ["sigchld", "threads", "non-main"])
def test_unsafe_reaper_context_refuses_before_spawn(native, monkeypatch, bad):
    def forbidden():
        pytest.fail("unsafe wait context reached spawn")

    monkeypatch.setattr(native, "_spawn_getconf", forbidden)
    if bad == "sigchld":
        monkeypatch.setattr(native.signal, "getsignal", lambda _sig: signal.SIG_IGN)
    elif bad == "threads":
        monkeypatch.setattr(native.threading, "active_count", lambda: 2)
    else:
        monkeypatch.setattr(native.threading, "current_thread", lambda: object())
    with pytest.raises(native.NamespaceError):
        native.discover_native_temp()


def test_externally_reaped_child_never_reaches_pid_reuse_signal(
    native, child_factory, monkeypatch
):
    child_factory("import time; time.sleep(30)")
    real_waitpid = os.waitpid
    signals = []

    def lost_status(_pid, _flags):
        raise ChildProcessError("simulated competing reaper")

    with monkeypatch.context() as patch:
        patch.setattr(native.os, "waitpid", lost_status)
        patch.setattr(native.os, "kill", lambda pid, sig: signals.append((pid, sig)))
        with pytest.raises(native.NamespaceError) as error:
            native.discover_native_temp()
    assert error.value.cleanup_uncertain is True
    assert signals == []
    assert os.waitpid is real_waitpid


def test_fixed_spawn_has_no_environment_or_descriptor_inheritance(native, monkeypatch):
    observed = []

    def record(argv, **kwargs):
        observed.append((argv, kwargs))
        raise OSError("pre-spawn fixture refusal")

    monkeypatch.setattr(native.subprocess, "Popen", record)
    with pytest.raises(native.NamespaceError):
        native.discover_native_temp()
    assert observed[0][0] == ("/usr/bin/getconf", "DARWIN_USER_TEMP_DIR")
    opts = observed[0][1]
    assert opts["env"] == {"LC_ALL": "C", "LANG": "C"}
    assert opts["shell"] is False and opts["close_fds"] is True
    assert opts["stdin"] == subprocess.DEVNULL


def test_late_reaper_context_drift_prevents_signalling(native, child_factory, monkeypatch):
    child_factory("import time; time.sleep(30)")
    original = native._spawn_getconf
    signals = []

    def spawn_then_drift():
        child = original()
        monkeypatch.setattr(native.signal, "getsignal", lambda _sig: signal.SIG_IGN)
        return child

    with monkeypatch.context() as patch:
        patch.setattr(native, "_spawn_getconf", spawn_then_drift)
        patch.setattr(native.os, "kill", lambda pid, sig: signals.append((pid, sig)))
        with pytest.raises(native.NamespaceError) as error:
            native.discover_native_temp()
    assert error.value.cleanup_uncertain is True
    assert signals == []


def test_interruption_reaps_owned_child(native, child_factory, monkeypatch):
    children = child_factory("import time; time.sleep(30)")
    original = native.selectors.DefaultSelector

    class InterruptedSelector:
        def __init__(self):
            self.inner = original()

        def register(self, *args):
            return self.inner.register(*args)

        def unregister(self, *args):
            return self.inner.unregister(*args)

        def select(self, *_args):
            raise KeyboardInterrupt()

        def close(self):
            self.inner.close()

    monkeypatch.setattr(native.selectors, "DefaultSelector", InterruptedSelector)
    with pytest.raises(native.NamespaceError) as error:
        native.discover_native_temp()
    assert error.value.cleanup_uncertain is False
    assert children[0].returncode is not None


def test_committed_stream_close_error_is_not_retried(native, child_factory, monkeypatch):
    children = child_factory("import os; os.write(1, b'/var/folders/ab/token/T/\\n')")
    spawn = native._spawn_getconf
    closed = []

    class AmbiguousStream:
        def __init__(self, stream):
            self.stream = stream

        @property
        def closed(self):
            return self.stream.closed

        def fileno(self):
            return self.stream.fileno()

        def close(self):
            closed.append(True)
            self.stream.close()
            raise OSError("fixture close committed but reported error")

    def ambiguous_spawn():
        child = spawn()
        child.stdout = AmbiguousStream(child.stdout)
        return child

    monkeypatch.setattr(native, "_spawn_getconf", ambiguous_spawn)
    with pytest.raises(native.NamespaceError) as error:
        native.discover_native_temp()
    assert error.value.cleanup_uncertain is True
    assert children[0].returncode is not None
    assert closed == [True]
