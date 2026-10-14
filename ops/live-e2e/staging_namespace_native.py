"""Fixed native discovery and metadata primitives; no CLI or import-time I/O."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import platform
import re
import selectors
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from staging_namespace_types import NativeTempParent

_EXECUTE_SECONDS = 5.0
_CLEANUP_SECONDS = 2.0
_POPEN_TYPE = subprocess.Popen
_TYPE_NAMES = {"NamespaceError", "NativeTempParent", "AclSnapshot", "DirectoryIdentity"}
_LIFECYCLE_ERRORS = (
    OSError, RuntimeError, TypeError, ValueError, AttributeError, LookupError,
    OverflowError, MemoryError, subprocess.SubprocessError,
    KeyboardInterrupt, SystemExit, GeneratorExit,
)


def _types():
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


def _require_platform() -> None:
    if (
        platform.system() != "Darwin" or platform.machine() != "x86_64"
        or os.getuid() != os.geteuid() or os.geteuid() == 0
    ):
        raise _types().NamespaceError("native-discovery") from None


def _require_owned_child_context() -> None:
    # A trusted standalone caller also excludes native competing reapers and
    # FD/PID-mutating handlers. Python thread/handler checks cannot prove that.
    if (
        threading.current_thread() is not threading.main_thread()
        or threading.active_count() != 1
        or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
    ):
        raise _types().NamespaceError("native-discovery") from None


def _spawn_getconf() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        ("/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"),
        env={"LC_ALL": "C", "LANG": "C"}, shell=False, close_fds=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


@dataclass(slots=True)
class _OwnedChild:
    child: subprocess.Popen[bytes]
    pid: int
    reaped: bool = False
    lost: bool = False


def _wait_owned(owner: _OwnedChild) -> int | None:
    if owner.lost:
        raise _types().NamespaceError("native-discovery", cleanup_uncertain=True)
    if owner.reaped:
        return owner.child.returncode
    try:
        _require_owned_child_context()
        if owner.child.pid != owner.pid or owner.child.returncode is not None:
            raise RuntimeError()
        pid, status = os.waitpid(owner.pid, os.WNOHANG)
        if type(pid) is not int or type(status) is not int:
            raise RuntimeError()
        if pid == 0 and status == 0:
            return None
        if pid != owner.pid:
            raise RuntimeError()
        result = os.waitstatus_to_exitcode(status)
        owner.child.returncode = result
        owner.reaped = True
        return result
    except _LIFECYCLE_ERRORS:
        owner.lost = True
        raise _types().NamespaceError("native-discovery", cleanup_uncertain=True) from None


def _signal_owned(owner: _OwnedChild, sig: int) -> None:
    if _wait_owned(owner) is not None:
        return
    try:
        _require_owned_child_context()
        os.kill(owner.pid, sig)
    except _LIFECYCLE_ERRORS:
        owner.lost = True
        raise _types().NamespaceError("native-discovery", cleanup_uncertain=True) from None


def _cleanup_child(owner: _OwnedChild) -> None:
    if owner.reaped:
        return
    if owner.lost:
        raise _types().NamespaceError("native-discovery", cleanup_uncertain=True)
    until = time.monotonic() + _CLEANUP_SECONDS
    _signal_owned(owner, signal.SIGTERM)
    killed = False
    while not owner.reaped:
        if _wait_owned(owner) is not None:
            break
        remaining = until - time.monotonic()
        if remaining <= 0:
            owner.lost = True
            raise _types().NamespaceError("native-discovery", cleanup_uncertain=True)
        if not killed and remaining <= _CLEANUP_SECONDS / 2:
            _signal_owned(owner, signal.SIGKILL)
            killed = True
        time.sleep(min(0.01, remaining))


def discover_native_temp() -> NativeTempParent:
    types = _types()
    owner = None
    selector = None
    streams = []
    closed = set()
    failure = None
    uncertain = False
    attempted = False
    stdout = bytearray()
    stderr = bytearray()
    try:
        _require_platform()
        _require_owned_child_context()
        until = time.monotonic() + _EXECUTE_SECONDS
        attempted = True
        child = _spawn_getconf()
        if (
            type(child) is not _POPEN_TYPE or type(child.pid) is not int
            or child.pid <= 1 or child.returncode is not None
        ):
            raise types.NamespaceError("native-discovery", cleanup_uncertain=True)
        owner = _OwnedChild(child, child.pid)
        streams = [child.stdout, child.stderr]
        if any(stream is None for stream in streams):
            raise types.NamespaceError("native-discovery")
        selector = selectors.DefaultSelector()
        pending = set()
        for stream, buffer, limit in zip(streams, (stdout, stderr), (4096, 1024), strict=True):
            fd = stream.fileno()
            os.set_blocking(fd, False)
            selector.register(fd, selectors.EVENT_READ, (stream, buffer, limit))
            pending.add(fd)
        while pending or not owner.reaped:
            remaining = until - time.monotonic()
            if remaining <= 0:
                raise types.NamespaceError("native-discovery")
            _wait_owned(owner)
            for key, _events in selector.select(min(remaining, 0.05)):
                stream, buffer, limit = key.data
                try:
                    chunk = os.read(key.fd, min(8192, limit - len(buffer) + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    pending.remove(key.fd)
                    closed.add(id(stream))  # one close attempt, including ambiguity
                    try:
                        stream.close()
                    except _LIFECYCLE_ERRORS:
                        uncertain = True
                        raise types.NamespaceError("native-discovery", cleanup_uncertain=True)
                elif len(buffer) + len(chunk) > limit:
                    raise types.NamespaceError("native-discovery")
                else:
                    buffer.extend(chunk)
        if owner.child.returncode != 0:
            raise types.NamespaceError("native-discovery")
        raw = bytes(stdout)
        if re.fullmatch(rb"/var/folders/[a-z0-9]{2}/[a-z0-9_]{1,255}/T/\n", raw) is None:
            raise types.NamespaceError("native-discovery")
    except _LIFECYCLE_ERRORS as error:
        failure = error
        uncertain |= isinstance(error, types.NamespaceError) and error.cleanup_uncertain
        if attempted and owner is None:
            uncertain = True
    finally:
        if owner is not None:
            try:
                _cleanup_child(owner)
            except _LIFECYCLE_ERRORS:
                uncertain = True
                failure = failure or types.NamespaceError("native-discovery")
        for stream in streams:
            if stream is not None and id(stream) not in closed:
                closed.add(id(stream))
                try:
                    stream.close()
                except _LIFECYCLE_ERRORS:
                    uncertain = True
                    failure = failure or types.NamespaceError("native-discovery")
        if selector is not None:
            try:
                selector.close()
            except _LIFECYCLE_ERRORS:
                uncertain = True
                failure = failure or types.NamespaceError("native-discovery")
    if failure is not None:
        raise types.NamespaceError("native-discovery", cleanup_uncertain=uncertain) from None
    source = bytes(stdout[:-1]).decode("ascii")
    return types.NativeTempParent(source, "/private" + source)
