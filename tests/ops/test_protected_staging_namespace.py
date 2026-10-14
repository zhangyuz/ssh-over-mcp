from __future__ import annotations

import importlib.util
import inspect
import os
import socket
import sys
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
PROTECTED = ('Users', 'gha-e2e-orchestrator', 'Library', 'Application Support',
             'ssh-over-mcp-e2e', 'staging-v1')
NATIVE = ('private', 'var', 'folders', 'ab', 'runner_123', 'T')
ALL_EDGES = ((), *(PROTECTED[:i] for i in range(1, 7)),
             *(NATIVE[:i] for i in range(1, 7)), ('private', 'tmp'))


def load_module():
    name = '_som_namespace_test'
    spec = importlib.util.spec_from_file_location(name, ROOT / 'ops/live-e2e/protected_staging.py')
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


@pytest.fixture
def namespace(tmp_path, monkeypatch):
    p = load_module()
    root = tmp_path / 'root'
    root.mkdir(mode=0o700)
    for parts in (PROTECTED, NATIVE, ('private', 'tmp')):
        for i in range(1, len(parts) + 1):
            root.joinpath(*parts[:i]).mkdir(mode=0o700, exist_ok=True)
    root.joinpath('private', 'tmp').chmod(0o1777)
    monkeypatch.setattr(p, '_SYSTEM_UID', os.getuid(), raising=False)
    monkeypatch.setattr(p, '_ACCOUNT_UID', os.getuid(), raising=False)
    monkeypatch.setattr(p, '_open_literal_root', lambda: os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC), raising=False)
    monkeypatch.setattr(p, '_stat_literal_root', lambda: os.stat(root, follow_symlinks=False), raising=False)
    monkeypatch.setattr(p, '_native_module', lambda: SimpleNamespace(read_acl=lambda fd: p.AclSnapshot(b'', ())), raising=False)
    native = p.NativeTempParent('/var/folders/ab/runner_123/T/', '/private/var/folders/ab/runner_123/T/')
    return p, root, native


def test_all_fixed_parents_pin_without_mutation(namespace, monkeypatch):
    p, root, native = namespace
    mutations = []
    for name in ('mkdir', 'chmod', 'chown', 'unlink', 'rmdir'):
        monkeypatch.setattr(os, name, lambda *a, _name=name, **k: mutations.append(_name))
    with p._pin_namespaces(native) as pinned:
        assert pinned.protected_missing == ()
        assert pinned.protected_fd is not None
        assert len(pinned.legacy_fds) == 2
        assert tuple(x.label for x in pinned.snapshot()) == ('protected', 'private-tmp', 'native-temp')
        pinned.revalidate()
    assert mutations == []
    assert root.joinpath(*PROTECTED).is_dir()


@pytest.mark.parametrize('missing', [3, 4, 5])
def test_missing_support_suffix_is_stable_and_uncreated(namespace, missing, monkeypatch):
    p, root, native = namespace
    for i in range(6, missing, -1):
        root.joinpath(*PROTECTED[:i]).rmdir()
    fixture_mutations = []
    monkeypatch.setattr(os, 'mkdir', lambda *a, **k: fixture_mutations.append(a))
    with p._pin_namespaces(native) as pinned:
        assert pinned.protected_missing == PROTECTED[missing:]
        assert pinned.protected_fd is None
        pinned.revalidate()
    assert fixture_mutations == []


def test_missing_library_refuses(namespace):
    p, root, native = namespace
    for i in range(6, 2, -1):
        root.joinpath(*PROTECTED[:i]).rmdir()
    with pytest.raises(p.NamespaceError) as error, p._pin_namespaces(native):
        pytest.fail('missing required Library accepted')
    assert error.value.reason == 'namespace'


@pytest.mark.parametrize('parts', ALL_EDGES)
@pytest.mark.parametrize('change', ['replacement', 'mode', 'owner', 'device', 'lost-fd'])
def test_every_late_edge_identity_change_refuses(namespace, monkeypatch, parts, change):
    p, root, native = namespace
    original_fstat = os.fstat
    with pytest.raises(p.NamespaceError), p._pin_namespaces(native) as pinned:
        edge = root.joinpath(*parts)
        inode = edge.stat().st_ino
        if change == 'replacement':
            edge.rename(edge.with_name(edge.name + '-old'))
            edge.mkdir(mode=0o700)
        elif change == 'mode':
            edge.chmod(0o777)
        else:
            def changed(fd):
                value = original_fstat(fd)
                if value.st_ino != inode:
                    return value
                if change == 'lost-fd':
                    raise OSError('lost descriptor')
                values = {name: getattr(value, name) for name in dir(value) if name.startswith('st_')}
                values['st_uid' if change == 'owner' else 'st_dev'] += 1
                return SimpleNamespace(**values)
            monkeypatch.setattr(os, 'fstat', changed)
        pinned.revalidate()


@pytest.mark.parametrize('parts', ALL_EDGES[1:])
@pytest.mark.parametrize('kind', ['symlink', 'file', 'mode', 'owner'])
def test_preopen_substitution_refuses(namespace, monkeypatch, parts, kind):
    p, root, native = namespace
    target = root.joinpath(*parts)
    original_open = os.open
    original_fstat = os.fstat
    changed = False
    bad_inode = None

    def swap(path, flags, *args, **kwargs):
        nonlocal changed, bad_inode
        parent_fd = kwargs.get('dir_fd')
        if not changed and path == parts[-1] and parent_fd is not None and original_fstat(parent_fd).st_ino == target.parent.stat().st_ino:
            changed = True
            if kind in ('file', 'symlink'):
                target.rename(target.with_name(target.name + '-old'))
                if kind == 'file':
                    target.write_bytes(b'canary')
                else:
                    target.symlink_to(target.with_name(target.name + '-old'), target_is_directory=True)
            elif kind == 'mode':
                target.chmod(0o777)
            else:
                bad_inode = target.stat().st_ino
        return original_open(path, flags, *args, **kwargs)

    def owner(fd):
        value = original_fstat(fd)
        if value.st_ino != bad_inode:
            return value
        values = {name: getattr(value, name) for name in dir(value) if name.startswith('st_')}
        values['st_uid'] += 1
        return SimpleNamespace(**values)

    monkeypatch.setattr(os, 'open', swap)
    monkeypatch.setattr(os, 'fstat', owner)
    with pytest.raises(p.NamespaceError), p._pin_namespaces(native):
        pytest.fail('substituted edge accepted')
    assert changed


def test_initial_device_transition_is_permitted(namespace, monkeypatch):
    p, root, native = namespace
    original_stat, original_fstat = os.stat, os.fstat
    inode = root.joinpath('Users').stat().st_ino

    def transition(value):
        if value.st_ino != inode:
            return value
        values = {name: getattr(value, name) for name in dir(value) if name.startswith('st_')}
        values['st_dev'] += 123
        return SimpleNamespace(**values)
    monkeypatch.setattr(os, 'stat', lambda *a, **k: transition(original_stat(*a, **k)))
    monkeypatch.setattr(os, 'fstat', lambda fd: transition(original_fstat(fd)))
    with p._pin_namespaces(native) as pinned:
        pinned.revalidate()


@pytest.mark.parametrize('parts,tag', [(PROTECTED[:2], 1), (PROTECTED[:5], 2), (PROTECTED, 2), (NATIVE, 1)])
def test_acl_grant_refuses_even_with_mode_0700(namespace, monkeypatch, parts, tag):
    p, root, native = namespace
    inode = root.joinpath(*parts).stat().st_ino
    monkeypatch.setattr(p, '_native_module', lambda: SimpleNamespace(read_acl=lambda fd: p.AclSnapshot(b'ace', (tag,)) if os.fstat(fd).st_ino == inode else p.AclSnapshot(b'', ())))
    with pytest.raises(p.NamespaceError) as error, p._pin_namespaces(native):
        pytest.fail('unsupported ACL accepted')
    assert error.value.reason == 'namespace'


def test_ancestor_deny_does_not_grant_authority(namespace, monkeypatch):
    p, root, native = namespace
    inode = root.joinpath(*PROTECTED[:3]).stat().st_ino
    raw = [b'deny-a']
    monkeypatch.setattr(p, '_native_module', lambda: SimpleNamespace(read_acl=lambda fd: p.AclSnapshot(raw[0], (2,)) if os.fstat(fd).st_ino == inode else p.AclSnapshot(b'', ())))
    with pytest.raises(p.NamespaceError) as error, p._pin_namespaces(native) as pinned:
        pinned.revalidate()
        raw[0] = b'deny-b'
        pinned.revalidate()
    assert error.value.reason == 'drift'


def test_missing_suffix_appearing_refuses(namespace):
    p, root, native = namespace
    root.joinpath(*PROTECTED).rmdir()
    with pytest.raises(p.NamespaceError), p._pin_namespaces(native) as pinned:
        root.joinpath(*PROTECTED).mkdir(mode=0o700)
        pinned.revalidate()


def test_ambiguous_close_is_not_retried(namespace, monkeypatch):
    p, _, native = namespace
    close = os.close
    counts = {}
    failed = []

    def ambiguous(fd):
        counts[fd] = counts.get(fd, 0) + 1
        close(fd)
        if not failed:
            failed.append(fd)
            raise OSError('committed close uncertainty')
    monkeypatch.setattr(os, 'close', ambiguous)
    with pytest.raises(p.NamespaceError) as error, p._pin_namespaces(native):
        pass
    assert error.value.cleanup_uncertain is True
    assert counts[failed[0]] == 1


def test_postclose_replacement_refuses(namespace, monkeypatch):
    p, root, native = namespace
    inode = root.joinpath(*PROTECTED).stat().st_ino
    close = os.close
    changed = []

    def replace_after_close(fd):
        match = os.fstat(fd).st_ino == inode
        close(fd)
        if match:
            edge = root.joinpath(*PROTECTED)
            edge.rename(edge.with_name(edge.name + '-old'))
            edge.mkdir(mode=0o700)
            changed.append(True)
    monkeypatch.setattr(os, 'close', replace_after_close)
    with pytest.raises(p.NamespaceError), p._pin_namespaces(native):
        pass
    assert changed


@pytest.mark.parametrize('fault', ['identity', 'registration', 'ambiguous-close'])
def test_pre_registration_fd_fault_closes_once(namespace, monkeypatch, fault):
    p, _, native = namespace
    original_open = p._open_literal_root
    original_close = os.close
    held, closes = [], []

    def opened():
        fd = original_open()
        held.append(fd)
        return fd

    def fail_identity(_):
        raise TypeError('unavailable identity')

    def close(fd):
        closes.append(fd)
        original_close(fd)
        if fault == 'ambiguous-close':
            raise OSError('close committed')

    if fault == 'registration':
        class BrokenRegistry(dict):
            def __setitem__(self, key, value):
                raise MemoryError()
        init = p._PinnedNamespaces.__init__

        def broken_init(self, native):
            init(self, native)
            self._edges = BrokenRegistry()
        monkeypatch.setattr(p._PinnedNamespaces, '__init__', broken_init)
    else:
        monkeypatch.setattr(p, '_identity', fail_identity)
    monkeypatch.setattr(p, '_open_literal_root', opened)
    monkeypatch.setattr(os, 'close', close)
    try:
        with pytest.raises(p.NamespaceError) as error, p._pin_namespaces(native):
            pass
        assert closes == held
        assert error.value.cleanup_uncertain is (fault == 'ambiguous-close')
        with pytest.raises(OSError):
            os.fstat(held[0])
    finally:
        for fd in held:
            try:
                os.fstat(fd)
            except OSError:
                pass
            else:
                original_close(fd)  # Fixture settles only its exact leaked FD.


def test_postclose_ancestor_link_is_never_traversed(namespace, monkeypatch, tmp_path):
    p, root, native = namespace
    ancestor = root.joinpath(*PROTECTED[:4])
    outside = tmp_path / 'unrelated-tree'
    outside.mkdir()
    close, original_stat = os.close, os.stat
    inode = root.joinpath(*PROTECTED).stat().st_ino
    changed, traversals = [], []

    def swap_on_close(fd):
        match = os.fstat(fd).st_ino == inode
        close(fd)
        if match:
            ancestor.rename(ancestor.with_name('old-support'))
            ancestor.symlink_to(outside, target_is_directory=True)
            changed.append(True)

    def reject_traversal(path, *a, **k):
        if changed and k.get('dir_fd') is not None and isinstance(path, str) and '/' in path:
            traversals.append(path)
        return original_stat(path, *a, **k)
    monkeypatch.setattr(os, 'close', swap_on_close)
    monkeypatch.setattr(os, 'stat', reject_traversal)
    with pytest.raises(p.NamespaceError), p._pin_namespaces(native):
        pass
    assert changed and traversals == []


def test_cleanup_does_not_abandon_fds_on_collection_allocation_failure(namespace):
    p, _, native = namespace
    held = []

    class FaultyCollection(dict):
        def values(self):
            raise MemoryError('cleanup list allocation boundary')

    try:
        with p._pin_namespaces(native) as pinned:
            held.extend(edge.fd for edge in pinned._edges.values())
            pinned._edges = FaultyCollection(pinned._edges)
    except p.NamespaceError as error:
        assert error.cleanup_uncertain is True
    finally:
        leaked = []
        for fd in held:
            try:
                os.fstat(fd)
            except OSError:
                pass
            else:
                os.close(fd)
                leaked.append(fd)
        assert leaked == [], 'cleanup abandoned owned FDs'


@pytest.mark.parametrize('root_open', [True, False])
def test_interrupted_open_without_captured_fd_is_uncertain(namespace, monkeypatch, root_open):
    p, _, native = namespace

    def interrupted(*a, **k):
        raise KeyboardInterrupt()
    if root_open:
        monkeypatch.setattr(p, '_open_literal_root', interrupted)
    else:
        original = os.open
        monkeypatch.setattr(os, 'open', lambda path, *a, **k: original(path, *a, **k) if path != 'Users' else interrupted())
    with pytest.raises(p.NamespaceError) as error, p._pin_namespaces(native):
        pass
    assert error.value.cleanup_uncertain is True


@pytest.fixture
def health(namespace, monkeypatch):
    p, root, native = namespace
    for key in ('TMPDIR', 'TEMP', 'TMP'):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(tempfile, 'tempdir', None)
    context = p.ProviderContext(os.getuid(), os.getuid(), os.getgid(), os.getgid(), tuple(sorted(os.getgroups())))
    monkeypatch.setattr(p, '_validate_context', lambda: context, raising=False)
    monkeypatch.setattr(p, '_native_module', lambda: SimpleNamespace(read_acl=lambda fd: p.AclSnapshot(b'', ()), discover_native_temp=lambda: native))
    return p, root, native, context


def test_clean_inspection_requires_two_real_observations(health, monkeypatch):
    p, root, native, context = health
    calls = []
    original = getattr(p, '_scan_observation', lambda *_a: None)

    def observe(pinned):
        calls.append(True)
        return original(pinned)
    monkeypatch.setattr(p, '_scan_observation', observe, raising=False)
    result = p.inspect_namespace()
    assert calls == [True, True]
    assert result.native == native and result.context == context
    assert tuple(x.label for x in result.parents) == ('protected', 'private-tmp', 'native-temp')
    assert root.joinpath(*PROTECTED).is_dir()


@pytest.mark.parametrize('count', [1, 64, 65])
def test_marker_free_protected_entry_blocks(health, count):
    p, root, *_ = health
    for i in range(count):
        root.joinpath(*PROTECTED, f'unrelated-{i}').write_bytes(b'private-canary')
    with pytest.raises(p.NamespaceError) as error:
        p.inspect_namespace()
    assert error.value.reason == 'residual'


@pytest.mark.parametrize('parts', [('private', 'tmp'), NATIVE])
@pytest.mark.parametrize('kind', ['directory', 'file', 'link', 'fifo', 'socket'])
def test_legacy_owned_entry_blocks_without_read(health, monkeypatch, parts, kind):
    p, root, *_ = health
    parent = root.joinpath(*parts)
    entry = parent / 'ssh-over-mcp-e2e-canary'
    held_socket = None
    if kind == 'directory':
        entry.mkdir(mode=0o700)
    elif kind == 'file':
        entry.write_bytes(b'preserve-me')
    elif kind == 'link':
        entry.symlink_to('/nonexistent/unrelated-canary')
    elif kind == 'fifo':
        os.mkfifo(entry)
    else:
        # Short basename avoids Darwin sun_path limits; fixture cwd only.
        monkeypatch.chdir(parent)
        held_socket = socket.socket(socket.AF_UNIX)
        held_socket.bind(entry.name)
    reads = []
    original = os.open

    def directories_only(path, flags, *a, **k):
        if not flags & os.O_DIRECTORY:
            reads.append(path)
            pytest.fail('payload open')
        return original(path, flags, *a, **k)
    monkeypatch.setattr(os, 'open', directories_only)
    try:
        with pytest.raises(p.NamespaceError) as error:
            p.inspect_namespace()
        assert error.value.reason == 'residual'
        assert reads == []
        assert os.path.lexists(entry)
    finally:
        if held_socket:
            held_socket.close()


def foreign_stat(monkeypatch, inodes):
    original = os.stat

    def foreign(*a, **k):
        value = original(*a, **k)
        if value.st_ino not in inodes:
            return value
        values = {name: getattr(value, name) for name in dir(value) if name.startswith('st_')}
        values['st_uid'] += 10000
        return SimpleNamespace(**values)
    monkeypatch.setattr(os, 'stat', foreign)


@pytest.mark.parametrize('count,accepted', [(64, True), (65, False)])
def test_foreign_prefix_bound_and_second_cursor_pass(health, monkeypatch, count, accepted):
    p, root, *_ = health
    entries = [root.joinpath('private', 'tmp', f'ssh-over-mcp-e2e-foreign-{i}') for i in range(count)]
    for entry in entries:
        entry.write_bytes(b'preserve-me')
    foreign_stat(monkeypatch, {x.stat().st_ino for x in entries})
    seen = []
    original = os.stat

    def record(path, *a, **k):
        if isinstance(path, str) and path.startswith('ssh-over-mcp-e2e-foreign-'):
            assert k.get('follow_symlinks') is False and type(k.get('dir_fd')) is int
            seen.append(path)
        return original(path, *a, **k)
    monkeypatch.setattr(os, 'stat', record)
    if accepted:
        p.inspect_namespace()
        assert len(seen) == 128 and len(set(seen)) == 64
    else:
        with pytest.raises(p.NamespaceError) as error:
            p.inspect_namespace()
        assert error.value.reason == 'budget'
        assert len(seen) <= 64
    assert all(x.read_bytes() == b'preserve-me' for x in entries)


@pytest.mark.parametrize('count,accepted', [(4096, True), (4097, False)])
def test_legacy_direct_entry_bound(health, count, accepted):
    p, root, *_ = health
    for i in range(count):
        root.joinpath('private', 'tmp', f'unrelated-{i}').touch()
    if accepted:
        p.inspect_namespace()
    else:
        with pytest.raises(p.NamespaceError) as error:
            p.inspect_namespace()
        assert error.value.reason == 'budget'


@pytest.mark.parametrize('count', [16, 17])
def test_owned_inventory_refuses_early(health, monkeypatch, count):
    p, root, *_ = health
    for i in range(count):
        root.joinpath('private', 'tmp', f'ssh-over-mcp-e2e-{i}').touch()
    seen = []
    original = os.stat

    def record(path, *a, **k):
        if isinstance(path, str) and path.startswith('ssh-over-mcp-e2e-'):
            seen.append(path)
        return original(path, *a, **k)
    monkeypatch.setattr(os, 'stat', record)
    with pytest.raises(p.NamespaceError) as error:
        p.inspect_namespace()
    assert error.value.reason == 'residual' and len(seen) == 1


@pytest.mark.parametrize('owned,remove', [(False, False), (False, True), (True, True), (True, False)])
def test_between_pass_churn_refuses_and_preserves_canaries(health, monkeypatch, owned, remove):
    p, root, *_ = health
    original = getattr(p, '_scan_observation', lambda *_: None)
    parent = root.joinpath('private', 'tmp')
    entry = parent / ('ssh-over-mcp-e2e-transient' if owned else 'foreign-unrelated')
    calls = []
    changed = []

    def observe(pinned):
        original(pinned)
        calls.append(True)
        if len(calls) == 1:
            before = parent.stat()
            entry.write_bytes(b'preserve-me')
            if remove:
                entry.unlink()  # Test owns this exact injected entry.
            after = parent.stat()
            assert (before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns)
            changed.append(True)
    monkeypatch.setattr(p, '_scan_observation', observe, raising=False)
    with pytest.raises(p.NamespaceError) as error:
        p.inspect_namespace()
    assert error.value.reason == 'drift' and changed == [True]
    if not remove:
        assert entry.read_bytes() == b'preserve-me'


def test_concurrent_foreign_churn_uses_barriers(health, monkeypatch):
    p, root, *_ = health
    original = getattr(p, '_scan_observation', lambda *_: None)
    ready, complete = threading.Event(), threading.Event()
    parent = root.joinpath('private', 'tmp')
    canary = parent / 'foreign-live-canary'
    before = parent.stat()

    def writer():
        assert ready.wait(3)
        canary.write_bytes(b'preserve-me')
        complete.set()
    thread = threading.Thread(target=writer)
    thread.start()

    def observe(pinned):
        original(pinned)
        ready.set()
        assert complete.wait(3)
        after = parent.stat()
        assert before.st_ctime_ns != after.st_ctime_ns or before.st_mtime_ns != after.st_mtime_ns
    monkeypatch.setattr(p, '_scan_observation', observe, raising=False)
    try:
        with pytest.raises(p.NamespaceError) as error:
            p.inspect_namespace()
        assert error.value.reason == 'drift'
        assert canary.read_bytes() == b'preserve-me'
    finally:
        ready.set()
        thread.join(timeout=3)
        assert not thread.is_alive()


@pytest.mark.parametrize('fault', ['selector', 'context', 'groups', 'budget'])
def test_interpass_context_selector_and_budget_drift_refuse(health, monkeypatch, fault):
    p, _, _, context = health
    original = getattr(p, '_scan_observation', lambda *_: None)

    def observe(pinned):
        original(pinned)
        if fault == 'selector':
            monkeypatch.setenv('TMP', '/tmp')  # Supported value, changed snapshot.
        elif fault == 'budget':
            monkeypatch.setattr(p.time, 'monotonic', lambda: pinned._deadline)
        else:
            changed = p.ProviderContext(context.uid + int(fault == 'context'), context.euid, context.gid, context.egid, context.groups + (99999,))
            monkeypatch.setattr(p, '_validate_context', lambda: changed)
    monkeypatch.setattr(p, '_scan_observation', observe, raising=False)
    with pytest.raises(p.NamespaceError) as error:
        p.inspect_namespace()
    assert error.value.reason == ('budget' if fault == 'budget' else 'drift')


def test_public_inspection_has_no_path_override(health):
    p, *_ = health
    assert inspect.signature(p.inspect_namespace).parameters == {}
    with pytest.raises(TypeError):
        p.inspect_namespace('/untrusted')


def test_inspection_never_mutates_or_probes_tempfile(health, monkeypatch):
    p, *_ = health
    operations = []

    def forbidden(*a, **k):
        operations.append(True)
        pytest.fail('unauthorized mutation/payload/probe')
    for name in ('mkdir', 'unlink', 'rmdir', 'chmod', 'chown', 'read', 'kill'):
        monkeypatch.setattr(os, name, forbidden)
    for name in ('gettempdir', 'gettempdirb', '_get_default_tempdir'):
        monkeypatch.setattr(tempfile, name, forbidden)
    p.inspect_namespace()
    assert operations == []


def test_final_supported_workflow_sha_drift_refuses(health, monkeypatch):
    p, *_ = health
    monkeypatch.setenv('GITHUB_SHA', 'a' * 40)
    original = getattr(p, '_scan_observation', lambda *_: None)

    def observe(pinned):
        original(pinned)
        monkeypatch.setenv('GITHUB_SHA', 'b' * 40)
    monkeypatch.setattr(p, '_scan_observation', observe, raising=False)
    with pytest.raises(p.NamespaceError) as error:
        p.inspect_namespace()
    assert error.value.reason == 'drift'


def test_foreign_native_prefix_evidence_refuses(health, monkeypatch):
    p, root, *_ = health
    canary = root.joinpath(*NATIVE, 'ssh-over-mcp-e2e-foreign')
    canary.write_bytes(b'preserve-me')
    foreign_stat(monkeypatch, {canary.stat().st_ino})
    with pytest.raises(p.NamespaceError) as error:
        p.inspect_namespace()
    assert error.value.reason == 'residual'
    assert canary.read_bytes() == b'preserve-me'


def test_observed_owned_match_removed_cannot_become_success(health, monkeypatch):
    p, root, *_ = health
    canary = root.joinpath('private', 'tmp', 'ssh-over-mcp-e2e-disappearing')
    canary.touch()
    original = os.stat
    removed = []

    def remove_after_stat(path, *a, **k):
        value = original(path, *a, **k)
        if path == canary.name and k.get('dir_fd') is not None:
            canary.unlink()  # This fixture owns only this injected entry.
            removed.append(True)
        return value
    monkeypatch.setattr(os, 'stat', remove_after_stat)
    with pytest.raises(p.NamespaceError) as error:
        p.inspect_namespace()
    assert error.value.reason == 'residual' and removed == [True]


def test_scandir_close_uncertainty_is_not_retried(health, monkeypatch):
    p, *_ = health
    original = os.scandir
    closes = []

    class AmbiguousIterator:
        def __init__(self, fd):
            self.inner = original(fd)

        def __iter__(self):
            return self

        def __next__(self):
            return next(self.inner)

        def close(self):
            closes.append(True)
            self.inner.close()
            raise OSError('close committed')
    monkeypatch.setattr(os, 'scandir', AmbiguousIterator)
    with pytest.raises(p.NamespaceError) as error:
        p.inspect_namespace()
    assert error.value.cleanup_uncertain is True and closes == [True]


@pytest.mark.parametrize('fault', ['acl', 'ancestor-link', 'cache', 'missing-suffix'])
def test_health_integration_revalidates_interpass_boundaries(health, monkeypatch, fault, tmp_path):
    p, root, *_ = health
    original = p._scan_observation
    changed = []
    raw = [b'']
    if fault == 'acl':
        backend = p._native_module()
        backend.read_acl = lambda fd: p.AclSnapshot(raw[0], ())
        monkeypatch.setattr(p, '_native_module', lambda: backend)
    if fault == 'missing-suffix':
        root.joinpath(*PROTECTED).rmdir()

    def observe(pinned):
        original(pinned)
        if changed:
            return
        if fault == 'acl':
            raw[0] = b'changed-acl'
        elif fault == 'cache':
            monkeypatch.setattr(tempfile, 'tempdir', '/tmp')
        elif fault == 'missing-suffix':
            root.joinpath(*PROTECTED).mkdir(mode=0o700)
        else:
            outside = tmp_path / 'unrelated'
            outside.mkdir()
            edge = root.joinpath(*PROTECTED[:4])
            edge.rename(edge.with_name('old-support'))
            edge.symlink_to(outside, target_is_directory=True)
        changed.append(True)
    monkeypatch.setattr(p, '_scan_observation', observe)
    with pytest.raises(p.NamespaceError) as error:
        p.inspect_namespace()
    assert changed == [True] and error.value.reason == 'drift'


def test_health_missing_suffix_is_evidence_only(health, monkeypatch):
    p, root, *_ = health
    for i in range(6, 3, -1):
        root.joinpath(*PROTECTED[:i]).rmdir()
    mutations = []
    monkeypatch.setattr(os, 'mkdir', lambda *a, **k: mutations.append(True))
    result = p.inspect_namespace()
    assert result.protected_missing == PROTECTED[3:]
    assert mutations == []


def test_health_last_close_swap_refuses(health, monkeypatch):
    p, root, *_ = health
    original = os.close
    inode = root.joinpath(*PROTECTED).stat().st_ino
    changed = []

    def swap(fd):
        match = os.fstat(fd).st_ino == inode
        original(fd)
        if match and not changed:
            edge = root.joinpath(*PROTECTED)
            edge.rename(edge.with_name('former-staging'))
            edge.mkdir(mode=0o700)
            changed.append(True)
    monkeypatch.setattr(os, 'close', swap)
    with pytest.raises(p.NamespaceError) as error:
        p.inspect_namespace()
    assert changed == [True] and error.value.reason == 'drift'
