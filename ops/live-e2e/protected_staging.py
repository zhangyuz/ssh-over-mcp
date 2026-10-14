"""Dormant fixed namespace inspection; importing this module admits nothing."""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import os
import re
import stat
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from staging_namespace_types import (
        DirectoryIdentity,
        NativeTempParent,
        ParentSnapshot,
        SelectorSnapshot,
    )

_SYSTEM_UID = 0
_ACCOUNT_UID = 502
_PROTECTED_PARTS = ('Users', 'gha-e2e-orchestrator', 'Library', 'Application Support',
                    'ssh-over-mcp-e2e', 'staging-v1')
_OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_METADATA_SECONDS = 10.0
_HOST_ERRORS = (OSError, RuntimeError, TypeError, ValueError, AttributeError,
                LookupError, OverflowError, MemoryError,
                KeyboardInterrupt, SystemExit, GeneratorExit)

_TYPE_NAMES = {
    "NamespaceError", "NativeTempParent", "SelectorSnapshot", "DirectoryIdentity",
    "AclSnapshot", "ParentSnapshot", "ProviderContext", "NamespaceSnapshot",
}


def _types():
    # Lazy fixed sibling import: no provider access or tempfile import at import.
    path = Path(__file__).parent / "staging_namespace_types.py"
    key = "_som_namespace_types_" + hashlib.sha256(os.fsencode(path)).hexdigest()
    cached = sys.modules.get(key)
    if cached is not None:
        if type(cached) is not ModuleType or cached.__file__ != str(path):
            raise RuntimeError("namespace types unavailable")
        return cached
    spec = importlib.util.spec_from_file_location(key, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("namespace types unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[key] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(key, None)
        raise
    return module


def __getattr__(name: str):
    if name in _TYPE_NAMES:
        return getattr(_types(), name)
    raise AttributeError(name)


def _selector_scalar(value: object) -> str | None:
    if value is None:
        return None
    if (
        type(value) is not str or not value.isascii() or len(value) > 4096
        or "\x00" in value or any(char.isspace() for char in value)
    ):
        raise _types().NamespaceError("selector") from None
    return value


def _capture_selectors() -> SelectorSnapshot:
    types = _types()
    values = tuple(_selector_scalar(os.environ.get(k)) for k in ("TMPDIR", "TEMP", "TMP"))
    loaded = "tempfile" in sys.modules
    cache = None
    if loaded:
        module = sys.modules["tempfile"]
        if type(module) is not ModuleType or "tempdir" not in module.__dict__:
            raise types.NamespaceError("selector") from None
        cache = _selector_scalar(module.__dict__["tempdir"])
    return types.SelectorSnapshot(values, loaded, cache)


def _validate_selectors(snapshot: SelectorSnapshot, native: NativeTempParent) -> None:
    types = _types()
    if type(snapshot) is not types.SelectorSnapshot or type(native) is not types.NativeTempParent:
        raise types.NamespaceError("selector") from None
    source = native.source
    if (
        type(source) is not str
        or re.fullmatch(r"/var/folders/[a-z0-9]{2}/[a-z0-9_]{1,255}/T/", source) is None
        or native.canonical != "/private" + source
    ):
        raise types.NamespaceError("selector") from None
    allowed = {
        "/tmp", "/tmp/", "/private/tmp", "/private/tmp/",
        source, source[:-1], native.canonical, native.canonical[:-1],
    }
    for value in (*snapshot.overrides, snapshot.cached):
        value = _selector_scalar(value)
        if value not in (None, "") and value not in allowed:
            raise types.NamespaceError("selector") from None


def _native_module():
    path = Path(__file__).parent / 'staging_namespace_native.py'
    key = '_som_namespace_native_' + hashlib.sha256(os.fsencode(path)).hexdigest()
    cached = sys.modules.get(key)
    if cached is not None:
        if type(cached) is not ModuleType or cached.__file__ != str(path):
            raise _types().NamespaceError('namespace') from None
        return cached
    spec = importlib.util.spec_from_file_location(key, path)
    if spec is None or spec.loader is None:
        raise _types().NamespaceError('namespace') from None
    module = importlib.util.module_from_spec(spec)
    sys.modules[key] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(key, None)
        raise
    return module


def _identity(value) -> DirectoryIdentity:
    return _types().DirectoryIdentity(value.st_dev, value.st_ino, value.st_uid,
                                      value.st_gid, value.st_mode,
                                      value.st_mtime_ns, value.st_ctime_ns)


def _open_literal_root() -> int:
    return os.open('/', _OPEN_FLAGS)


def _stat_literal_root():
    return os.stat('/', follow_symlinks=False)


def _open_error(error) -> None:
    # A normal POSIX error is settled; an interrupted/untyped acquisition may
    # have opened a descriptor that Python never delivered. Never guess it.
    uncertain = not isinstance(error, OSError) or error.errno in (None, errno.EINTR)
    raise _types().NamespaceError('namespace', cleanup_uncertain=uncertain) from None


def _open_directory(name: str, parent_fd: int) -> int:
    try:
        return os.open(name, _OPEN_FLAGS, dir_fd=parent_fd)
    except _HOST_ERRORS as error:
        _open_error(error)


def _policy(parts: tuple[str, ...], identity: DirectoryIdentity, acl) -> None:
    types = _types()
    if not stat.S_ISDIR(identity.mode) or type(acl) is not types.AclSnapshot:
        raise types.NamespaceError('namespace') from None
    mode = stat.S_IMODE(identity.mode)
    if parts == ('private', 'tmp'):
        if identity.uid != _SYSTEM_UID or mode != 0o1777:
            raise types.NamespaceError('namespace') from None
        return  # Shared inspection parent: no private authority from its ACL.
    account = (parts[:2] == _PROTECTED_PARTS[:2] or len(parts) >= 5 and parts[:3] == ('private', 'var', 'folders'))
    if identity.uid != (_ACCOUNT_UID if account else _SYSTEM_UID) or mode & 0o7022:
        raise types.NamespaceError('namespace') from None
    if (parts == _PROTECTED_PARTS[:4] or len(parts) == 5 and parts[:3] == ('private', 'var', 'folders')) and mode not in (0o700, 0o755):
        raise types.NamespaceError('namespace') from None
    private = parts in (_PROTECTED_PARTS[:5], _PROTECTED_PARTS)
    if (private or len(parts) == 6 and parts[:3] == ('private', 'var', 'folders')) and mode != 0o700:
        raise types.NamespaceError('namespace') from None
    if (private and acl.tags) or any(tag != 2 for tag in acl.tags):
        raise types.NamespaceError('namespace') from None


@dataclass(slots=True)
class _Edge:
    parts: tuple[str, ...]
    fd: int
    identity: DirectoryIdentity
    acl: object


class _PinnedNamespaces:
    def __init__(self, native: NativeTempParent):
        self._deadline = time.monotonic() + _METADATA_SECONDS
        self._edges: dict[tuple[str, ...], _Edge] = {}
        self._chains: list[tuple[str, tuple[str, ...]]] = []
        self._closed = False
        self.protected_missing: tuple[str, ...] = ()
        self.protected_fd: int | None = None
        self.legacy_fds: tuple[int, ...] = ()
        self._native = native

    def _check_budget(self) -> None:
        if self._closed:
            raise _types().NamespaceError('namespace') from None
        if time.monotonic() >= self._deadline:
            raise _types().NamespaceError('budget') from None

    def _capture(self, parts: tuple[str, ...], fd: int, before) -> None:
        # Until registration succeeds, the stack owns this exact descriptor.
        try:
            edge = _Edge(parts, fd, _identity(before), None)
            self._edges[parts] = edge
        except _HOST_ERRORS:
            self._edges.pop(parts, None)
            try:
                os.close(fd)
            except _HOST_ERRORS:
                raise _types().NamespaceError('namespace', cleanup_uncertain=True) from None
            raise
        self._check_budget()
        actual = _identity(os.fstat(fd))
        if actual != edge.identity:
            raise _types().NamespaceError('drift') from None
        acl = _native_module().read_acl(fd)
        self._check_budget()
        if _identity(os.fstat(fd)) != actual:
            raise _types().NamespaceError('drift') from None
        _policy(parts, actual, acl)
        edge.acl = acl

    def _chain(self, label: str, parts: tuple[str, ...], optional: bool = False) -> int | None:
        for index in range(1, len(parts) + 1):
            prefix = parts[:index]
            if prefix in self._edges:
                continue
            self._check_budget()
            parent = self._edges[prefix[:-1]]
            try:
                before = os.stat(prefix[-1], dir_fd=parent.fd, follow_symlinks=False)
            except FileNotFoundError:
                if not optional or index < 4:
                    raise _types().NamespaceError('namespace') from None
                self.protected_missing = parts[index - 1:]
                self._chains.append((label, prefix[:-1]))
                return None
            if not stat.S_ISDIR(before.st_mode):
                raise _types().NamespaceError('namespace') from None
            fd = _open_directory(prefix[-1], parent.fd)
            self._capture(prefix, fd, before)
            self._revalidate_edge(prefix)
        self._chains.append((label, parts))
        return self._edges[parts].fd

    def _acquire(self) -> None:
        # Validate discovery lexically before the literal root is opened.
        _validate_selectors(_types().SelectorSnapshot((None, None, None), False, None), self._native)
        before = _stat_literal_root()
        try:
            fd = _open_literal_root()
        except _HOST_ERRORS as error:
            _open_error(error)
        self._capture((), fd, before)
        self.protected_fd = self._chain('protected', _PROTECTED_PARTS, optional=True)
        shared = self._chain('private-tmp', ('private', 'tmp'))
        native_parts = tuple(self._native.canonical.strip('/').split('/'))
        native = self._chain('native-temp', native_parts)
        self.legacy_fds = (shared, native)
        self.revalidate()

    def _revalidate_edge(self, parts: tuple[str, ...]) -> None:
        self._check_budget()
        edge = self._edges[parts]
        before = (_stat_literal_root() if not parts else os.stat(parts[-1], dir_fd=self._edges[parts[:-1]].fd, follow_symlinks=False))
        if _identity(before) != edge.identity or _identity(os.fstat(edge.fd)) != edge.identity:
            raise _types().NamespaceError('drift') from None
        if _native_module().read_acl(edge.fd) != edge.acl:
            raise _types().NamespaceError('drift') from None
        self._check_budget()
        if _identity(os.fstat(edge.fd)) != edge.identity:
            raise _types().NamespaceError('drift') from None

    def revalidate(self) -> None:
        for parts in self._edges:
            self._revalidate_edge(parts)
        if self.protected_missing:
            prefix = _PROTECTED_PARTS[:len(_PROTECTED_PARTS) - len(self.protected_missing)]
            try:
                os.stat(self.protected_missing[0], dir_fd=self._edges[prefix].fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise _types().NamespaceError('drift') from None
        self._check_budget()

    def snapshot(self) -> tuple[ParentSnapshot, ...]:
        self._check_budget()
        types = _types()
        result = []
        for label, parts in self._chains:
            edges = [self._edges[parts[:i]] for i in range(len(parts) + 1)]
            result.append(types.ParentSnapshot(label, tuple(x.identity for x in edges), tuple(x.acl for x in edges)))
        return tuple(result)

    def _finish(self, check: bool) -> None:
        failure = None
        uncertain = False
        root = self._edges.get(())
        # Pop in reverse insertion order without allocating a cleanup inventory.
        # Every child's original parent remains held until that edge is checked.
        while len(self._edges) > 1:
            try:
                _, edge = self._edges.popitem()
            except _HOST_ERRORS:
                uncertain = True
                break  # Unknown ownership is never guessed or retried.
            parent = self._edges.get(edge.parts[:-1])
            if check and self.protected_missing and edge.parts == _PROTECTED_PARTS[:len(_PROTECTED_PARTS) - len(self.protected_missing)]:
                try:
                    self._check_budget()
                    try:
                        os.stat(self.protected_missing[0], dir_fd=edge.fd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        raise _types().NamespaceError('drift')
                except _HOST_ERRORS as error:
                    failure = failure or error
            # Drop ownership before the one close attempt, even if it commits
            # and raises. Metadata failures do not abandon remaining FDs.
            try:
                os.close(edge.fd)
            except _HOST_ERRORS:
                uncertain = True
            if check and not uncertain and parent is not None:
                try:
                    self._check_budget()
                    value = os.stat(edge.parts[-1], dir_fd=parent.fd, follow_symlinks=False)
                    if _identity(value) != edge.identity:
                        raise _types().NamespaceError('drift')
                    if _identity(os.fstat(parent.fd)) != parent.identity:
                        raise _types().NamespaceError('drift')
                except _HOST_ERRORS as error:
                    failure = failure or error
        if root is not None:
            self._edges.pop(())
            try:
                os.close(root.fd)
            except _HOST_ERRORS:
                uncertain = True
            if check and not uncertain:
                try:
                    if _identity(_stat_literal_root()) != root.identity:
                        raise _types().NamespaceError('drift')
                except _HOST_ERRORS as error:
                    failure = error
        self._closed = True
        if uncertain or failure is not None:
            reason = getattr(failure, 'reason', 'namespace')
            raise _types().NamespaceError(reason, cleanup_uncertain=uncertain) from None


@contextmanager
def _pin_namespaces(native: NativeTempParent):
    pinned = _PinnedNamespaces(native)
    failure = None
    try:
        pinned._acquire()
        yield pinned
        pinned.revalidate()
    except _HOST_ERRORS as error:
        failure = error
    finally:
        try:
            pinned._finish(failure is None)
        except _HOST_ERRORS as error:
            if getattr(error, 'cleanup_uncertain', False) or failure is None:
                failure = error
    if failure is not None:
        raise _types().NamespaceError(getattr(failure, 'reason', 'namespace'), cleanup_uncertain=getattr(failure, 'cleanup_uncertain', False)) from None
