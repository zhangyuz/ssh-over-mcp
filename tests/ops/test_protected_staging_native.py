from __future__ import annotations

import ctypes
import errno
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
            child = native._POPEN_TYPE(
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

    monkeypatch.setattr(native, "_DiscoveryChild", record)
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


class AclApi:
    def __init__(self, tags=()):
        self.tags = tags
        self.wire = (0x012cc16d).to_bytes(4, 'big') + bytes(32) + len(tags).to_bytes(4, 'big') + bytes(4)
        self.wire += b''.join(bytes(16) + tag.to_bytes(4, 'big') + bytes(4) for tag in tags)
        self.cursor = 0
        self.freed = []
        self.null_errno = None
        self.size_override = None
        self.free_result = 0
        self.iter_result = None

    def acl_get_fd_np(self, fd, kind):
        assert kind == 0x100
        if self.null_errno is not None:
            ctypes.set_errno(self.null_errno)
            return None
        return 123

    def acl_size(self, acl):
        assert acl == 123
        return self.size_override if self.size_override is not None else len(self.wire)

    def acl_copy_ext(self, buffer, acl, size):
        assert acl == 123 and size >= len(self.wire)
        ctypes.memmove(buffer, self.wire, len(self.wire))
        return len(self.wire)

    def acl_get_entry(self, acl, selector, out):
        assert acl == 123 and selector == (0 if self.cursor == 0 else -1)
        if self.iter_result is not None:
            ctypes.set_errno(errno.EINVAL)
            return self.iter_result
        if self.cursor == len(self.tags):
            ctypes.set_errno(errno.EINVAL)
            return -1
        ctypes.cast(out, ctypes.POINTER(ctypes.c_void_p))[0] = self.cursor + 1
        self.cursor += 1
        return 0

    def acl_get_tag_type(self, entry, out):
        ctypes.cast(out, ctypes.POINTER(ctypes.c_uint32))[0] = self.tags[entry.value - 1]
        return 0

    def acl_free(self, acl):
        self.freed.append(acl)
        return self.free_result


@pytest.fixture
def acl_fixture(native, tmp_path, monkeypatch):
    directory = tmp_path / 'acl-dir'
    directory.mkdir(mode=0o700)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    monkeypatch.setattr(native, '_require_apfs_fd', lambda fd, lib: None, raising=False)
    api = AclApi()
    monkeypatch.setattr(native, '_load_acl_library', lambda: api, raising=False)
    yield native, fd, api
    os.close(fd)


@pytest.mark.parametrize('tags', [(), (1,), (2,), (2, 1), (2,) * 128])
def test_acl_export_and_darwin_iteration_preserve_order(acl_fixture, tags):
    n, fd, api = acl_fixture
    api.__init__(tags)
    snapshot = n.read_acl(fd)
    assert snapshot.tags == tags and snapshot.serialized == api.wire
    assert api.freed == [123]
    assert os.fstat(fd)  # The caller still owns its descriptor.


@pytest.mark.parametrize('code,accepted', [(errno.ENOENT, True), (0, False), (errno.EACCES, False), (errno.EINVAL, False), (errno.ENOTSUP, False)])
def test_null_acl_errno_is_not_guessed(acl_fixture, code, accepted):
    n, fd, api = acl_fixture
    api.null_errno = code
    if accepted:
        assert n.read_acl(fd) == n.AclSnapshot(b'', ())
    else:
        with pytest.raises(n.NamespaceError):
            n.read_acl(fd)
    assert api.freed == []


@pytest.mark.parametrize('size', [-1, 0, 43, 16385])
def test_acl_export_bound_refuses_before_copy(acl_fixture, size):
    n, fd, api = acl_fixture
    api.size_override = size
    with pytest.raises(n.NamespaceError):
        n.read_acl(fd)
    assert api.freed == [123]


@pytest.mark.parametrize('tags', [(3,), (0,), (2,) * 129])
def test_unknown_tag_or_entry_bound_refuses(acl_fixture, tags):
    n, fd, api = acl_fixture
    api.__init__(tags)
    with pytest.raises(n.NamespaceError):
        n.read_acl(fd)
    assert api.freed == [123]


@pytest.mark.parametrize('result', [1, -1])
def test_linux_iteration_or_premature_end_refuses(acl_fixture, result):
    n, fd, api = acl_fixture
    api.__init__((2,))
    api.iter_result = result
    with pytest.raises(n.NamespaceError):
        n.read_acl(fd)
    assert api.freed == [123]


def test_acl_free_failure_is_uncertain_not_retried(acl_fixture):
    n, fd, api = acl_fixture
    api.free_result = -1
    with pytest.raises(n.NamespaceError) as error:
        n.read_acl(fd)
    assert error.value.cleanup_uncertain is True
    assert api.freed == [123]


@pytest.mark.parametrize('fault', ['magic', 'count', 'wire-tag', 'copy-result', 'apfs', 'tag-result'])
def test_ambiguous_acl_evidence_refuses_and_frees_once(acl_fixture, monkeypatch, fault):
    n, fd, api = acl_fixture
    api.__init__((2,))
    if fault == 'magic':
        api.wire = bytes(4) + api.wire[4:]
    elif fault == 'count':
        api.wire = api.wire[:36] + bytes(4) + api.wire[40:]
    elif fault == 'wire-tag':
        api.wire = api.wire[:60] + (1).to_bytes(4, 'big') + api.wire[64:]
    elif fault == 'copy-result':
        monkeypatch.setattr(api, 'acl_copy_ext', lambda *a: -1)
    elif fault == 'tag-result':
        monkeypatch.setattr(api, 'acl_get_tag_type', lambda *a: -1)
    else:
        def non_apfs(fd, lib):
            raise n.NamespaceError('namespace')
        monkeypatch.setattr(n, '_require_apfs_fd', non_apfs)
    with pytest.raises(n.NamespaceError):
        n.read_acl(fd)
    assert api.freed == ([] if fault == 'apfs' else [123])


def test_acl_identity_changes_during_retrieval_refuse(acl_fixture, monkeypatch):
    n, fd, api = acl_fixture
    original = api.acl_get_fd_np

    def change(fd, kind):
        os.fchmod(fd, 0o755)
        return original(fd, kind)
    monkeypatch.setattr(api, 'acl_get_fd_np', change)
    with pytest.raises(n.NamespaceError):
        n.read_acl(fd)


@pytest.mark.parametrize('exception', [OSError, KeyboardInterrupt])
def test_uncaptured_acl_acquisition_is_cleanup_uncertain(acl_fixture, monkeypatch, exception):
    n, fd, api = acl_fixture

    def interrupted(*_):
        raise exception()
    monkeypatch.setattr(api, 'acl_get_fd_np', interrupted)
    with pytest.raises(n.NamespaceError) as error:
        n.read_acl(fd)
    assert error.value.cleanup_uncertain is True
    assert api.freed == []  # No captured pointer may be guessed or freed.


def test_fixed_library_missing_symbol_refuses(native, monkeypatch):
    monkeypatch.setattr(ctypes, 'CDLL', lambda *a, **k: object())
    with pytest.raises(native.NamespaceError):
        native._load_acl_library()


@pytest.mark.skipif(sys.platform != 'darwin', reason='actual Mac ACL evidence required separately')
@pytest.mark.parametrize('entry,tags', [(None, ()), ('everyone deny delete', (2,)), ('everyone allow write', (1,)), ('everyone allow write,file_inherit,directory_inherit', (1,))])
def test_real_mac_fd_acl_and_renamed_directory(tmp_path, entry, tags):
    n = load_module()
    directory = tmp_path / 'real-acl'
    directory.mkdir(mode=0o700)
    subprocess.run(['/bin/chmod', '-N', str(directory)], check=True, capture_output=True)
    if entry:
        subprocess.run(['/bin/chmod', '+a', entry, str(directory)], check=True, capture_output=True)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    current = directory
    try:
        first = n.read_acl(fd)
        assert first.tags == tags
        if tags == (2,):
            with pytest.raises(PermissionError):
                directory.rename(tmp_path / 'renamed')
            subprocess.run(['/bin/chmod', '-N', str(directory)], check=True, capture_output=True)
        directory.rename(tmp_path / 'renamed')
        current = tmp_path / 'renamed'
        directory.mkdir(mode=0o700)
        if tags == (2,):
            subprocess.run(['/bin/chmod', '+a', entry, str(current)], check=True, capture_output=True)
        assert n.read_acl(fd).tags == tags
        assert directory.stat().st_ino != os.fstat(fd).st_ino
        subprocess.run(['/bin/chmod', '-N', str(tmp_path / 'renamed')], check=True, capture_output=True)
        assert n.read_acl(fd).tags == ()
        assert os.fstat(fd)
    finally:
        subprocess.run(['/bin/chmod', '-N', str(current)], check=True, capture_output=True)
        os.close(fd)


@pytest.mark.skipif(sys.platform != 'darwin', reason='actual Mac empty ACL evidence')
def test_real_mac_explicit_empty_acl(tmp_path):
    n = load_module()
    directory = tmp_path / 'explicit-empty-acl'
    directory.mkdir(mode=0o700)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    lib.acl_init.argtypes, lib.acl_init.restype = [ctypes.c_int], ctypes.c_void_p
    lib.acl_set_fd_np.argtypes, lib.acl_set_fd_np.restype = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int], ctypes.c_int
    lib.acl_free.argtypes, lib.acl_free.restype = [ctypes.c_void_p], ctypes.c_int
    acl = lib.acl_init(0)
    try:
        assert acl and lib.acl_set_fd_np(fd, acl, 0x100) == 0
        assert n.read_acl(fd).tags == ()
    finally:
        assert lib.acl_free(acl) == 0
        os.close(fd)


@pytest.mark.parametrize('cause', ['echild', 'context', 'cleanup-timeout'])
def test_uncertain_managed_child_has_no_implicit_wait_or_active_retry(native, monkeypatch, cause):
    import gc
    import weakref

    canary = 999999991
    child = native._POPEN_TYPE.__new__(native._POPEN_TYPE)
    child.pid, child.returncode, child._child_created = canary, None, True
    child.stdout = child.stderr = child.stdin = None
    child._waitpid_lock = native.threading.Lock()
    owner = native._OwnedChild(child, canary)
    explicit, implicit, signals = [], [], []
    active = []
    monkeypatch.setattr(native.subprocess, '_active', active)

    def wait(pid, flags):
        assert pid == canary and flags == os.WNOHANG
        explicit.append(pid)
        if cause == 'echild':
            raise ChildProcessError(errno.ECHILD, 'fixture external reap')
        return 0, 0

    def hidden_wait(pid, flags):
        assert pid == canary and flags == os.WNOHANG
        implicit.append(pid)
        return 0, 0

    monkeypatch.setattr(native.os, 'waitpid', wait)
    monkeypatch.setattr(native.subprocess._del_safe, 'waitpid', hidden_wait)
    monkeypatch.setattr(native.os, 'kill', lambda pid, sig: signals.append((pid, sig)))
    if cause == 'context':
        def lost_context():
            raise native.NamespaceError('native-discovery')
        monkeypatch.setattr(native, '_require_owned_child_context', lost_context)
    elif cause == 'cleanup-timeout':
        clock = iter((0.0, 3.0))
        monkeypatch.setattr(native.time, 'monotonic', lambda: next(clock))
    with pytest.raises(native.NamespaceError) as error:
        if cause == 'cleanup-timeout':
            native._cleanup_child(owner)
        else:
            native._wait_owned(owner)
    assert error.value.cleanup_uncertain and owner.lost and child.returncode is None
    before = list(explicit), list(signals)
    del error  # ExceptionInfo traceback otherwise retains owner and child.
    witness = weakref.ref(child)
    del owner, child
    gc.collect()
    native.subprocess._cleanup()  # Later stdlib housekeeping must not retry it.
    try:
        assert implicit == [] and explicit == before[0] and signals == before[1]
        assert active == [] and witness() is None
    finally:
        active.clear()  # Only artificial in-memory records, never a real child.


def test_pending_stdlib_reaper_refuses_before_new_child(native, monkeypatch):
    calls = []
    active = [object()]
    monkeypatch.setattr(native.subprocess, '_active', active)

    def spawn():
        calls.append(True)
        raise OSError('fixture should never spawn')
    monkeypatch.setattr(native, '_spawn_getconf', spawn)
    with pytest.raises(native.NamespaceError):
        native.discover_native_temp()
    assert calls == [] and len(active) == 1


def test_final_successful_iteration_must_still_meet_execution_deadline(native, monkeypatch):
    from types import SimpleNamespace

    clock = [0.0]
    canary = 999999992

    class Stream:
        def __init__(self, fd):
            self.fd = fd
            self.closed = False

        def fileno(self):
            return self.fd

        def close(self):
            self.closed = True
            if self.fd == 50101:
                clock[0] = 5.0  # Last EOF lands exactly on the fixed deadline.

    class Selector:
        def __init__(self):
            self.keys = {}

        def register(self, fd, events, data):
            self.keys[fd] = SimpleNamespace(fd=fd, data=data)

        def unregister(self, fd):
            self.keys.pop(fd)

        def select(self, timeout):
            return [(key, 1) for key in self.keys.values()]

        def close(self):
            pass

    child = native._POPEN_TYPE.__new__(native._POPEN_TYPE)
    child.pid, child.returncode, child._child_created = canary, None, True
    child.stdout, child.stderr, child.stdin = Stream(50101), Stream(50102), None
    child._waitpid_lock = native.threading.Lock()
    chunks = {50101: [b'/var/folders/ab/token/T/\n', b''], 50102: [b'']}
    monkeypatch.setattr(native, '_spawn_getconf', lambda: child)
    monkeypatch.setattr(native.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(native.selectors, 'DefaultSelector', Selector)
    monkeypatch.setattr(native.os, 'set_blocking', lambda *a: None)
    monkeypatch.setattr(native.os, 'read', lambda fd, count: chunks[fd].pop(0))

    def reap(pid, flags):
        assert pid == canary and flags == os.WNOHANG
        return canary, 0
    monkeypatch.setattr(native.os, 'waitpid', reap)
    with pytest.raises(native.NamespaceError) as error:
        native.discover_native_temp()
    assert error.value.reason == 'native-discovery'
    assert child.returncode == 0 and child.stdout.closed and child.stderr.closed
