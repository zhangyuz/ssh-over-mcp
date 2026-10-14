from __future__ import annotations

import importlib.util
import os
import sys
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

