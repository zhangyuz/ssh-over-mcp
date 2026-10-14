"""Dormant fixed namespace inspection; importing this module admits nothing."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from staging_namespace_types import NativeTempParent, SelectorSnapshot

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
