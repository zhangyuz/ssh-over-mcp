from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "ops/live-e2e/protected_staging.py"


def load_module() -> ModuleType:
    assert MODULE.is_file(), "shared namespace module is missing"
    name = "_som_selector_test"
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
def module(monkeypatch):
    for name in ("TMPDIR", "TEMP", "TMP"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(tempfile, "tempdir", None)
    return load_module()


@pytest.mark.parametrize(
    "value",
    ["", "/tmp", "/tmp/", "/private/tmp", "/private/tmp/",
     "/var/folders/ab/runner_123/T", "/var/folders/ab/runner_123/T/",
     "/private/var/folders/ab/runner_123/T", "/private/var/folders/ab/runner_123/T/"],
)
@pytest.mark.parametrize("name", ["TMPDIR", "TEMP", "TMP"])
def test_supported_aliases_are_lexical_only(module, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    native = module.NativeTempParent(
        "/var/folders/ab/runner_123/T/", "/private/var/folders/ab/runner_123/T/"
    )
    snapshot = module._capture_selectors()
    module._validate_selectors(snapshot, native)
    assert snapshot.overrides[("TMPDIR", "TEMP", "TMP").index(name)] == value


@pytest.mark.parametrize(
    "value",
    ["relative", "/var/tmp", "/usr/tmp", "/tmp//", "/private/./tmp",
     "/private/../tmp", "/var/folders/ab/other_token/T/", "/arbitrary"],
)
def test_selectors_never_probe_paths(module, monkeypatch, value):
    monkeypatch.setenv("TMPDIR", value)
    snapshot = module._capture_selectors()
    native = module.NativeTempParent(
        "/var/folders/ab/runner_123/T/", "/private/var/folders/ab/runner_123/T/"
    )

    def forbidden(*_args, **_kwargs):
        pytest.fail("lexical selector reached filesystem or tempfile probe")

    with monkeypatch.context() as patch:
        for name in ("gettempdir", "gettempdirb", "_get_default_tempdir"):
            patch.setattr(tempfile, name, forbidden)
        for name in ("stat", "access", "open"):
            patch.setattr(os, name, forbidden)
        patch.setattr(os.path, "realpath", forbidden)
        with pytest.raises(module.NamespaceError) as error:
            module._validate_selectors(snapshot, native)
    assert error.value.reason == "selector"


@pytest.mark.parametrize("value", [b"/tmp", 3, False, [], "é", "/tmp\x00", "/tmp ", "x" * 4097])
def test_invalid_cached_selector_refuses(module, monkeypatch, value):
    monkeypatch.setattr(tempfile, "tempdir", value)
    with pytest.raises(module.NamespaceError) as error:
        module._capture_selectors()
    assert error.value.reason == "selector"


def test_capture_preserves_empty_unset_and_detects_loaded_cache(module, monkeypatch):
    initial = module._capture_selectors()
    assert initial.overrides == (None, None, None)
    assert initial.module_loaded is True and initial.cached is None
    monkeypatch.setenv("TEMP", "")
    assert module._capture_selectors() != initial
    monkeypatch.delenv("TEMP")
    monkeypatch.setattr(tempfile, "tempdir", "/tmp")
    assert module._capture_selectors() != initial
    monkeypatch.delitem(sys.modules, "tempfile")
    absent = module._capture_selectors()
    assert absent.module_loaded is False and absent.cached is None
    assert absent != initial
    assert "tempfile" not in sys.modules


def test_cached_path_cannot_bypass_environment_validation(module, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", "/elsewhere")
    native = module.NativeTempParent(
        "/var/folders/ab/runner_123/T/", "/private/var/folders/ab/runner_123/T/"
    )
    with pytest.raises(module.NamespaceError):
        module._validate_selectors(module._capture_selectors(), native)


@pytest.mark.parametrize("value", ["/tmp\n", "é", "x" * 4097])
def test_invalid_environment_scalar_refuses(module, monkeypatch, value):
    monkeypatch.setenv("TMPDIR", value)
    with pytest.raises(module.NamespaceError):
        module._capture_selectors()


def test_cached_str_subclass_is_not_a_selector(module, monkeypatch):
    class ForeignString(str):
        pass

    monkeypatch.setattr(tempfile, "tempdir", ForeignString("/tmp"))
    with pytest.raises(module.NamespaceError):
        module._capture_selectors()
