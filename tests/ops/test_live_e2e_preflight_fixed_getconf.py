"""Disposable RED/GREEN tests for fixed preflight getconf-to-temp-parent adapter."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = ROOT / "ops/live-e2e/staging_preflight.py"
DIAGNOSTICS = ROOT / "ops/live-e2e/staging_diagnostics.py"
METADATA = ROOT / "ops/live-e2e/staging_process_metadata.py"
NATIVE = b"/var/folders/ab/runner_123/T/\n"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    try:
        spec.loader.exec_module(result)
    finally:
        sys.modules.pop(name, None)
    return result


@pytest.fixture
def modules(monkeypatch):
    p = _load(PREFLIGHT, "_som_fixture_getconf_preflight")
    d = _load(DIAGNOSTICS, "_som_fixture_getconf_diagnostics")
    m = _load(METADATA, "_som_fixture_getconf_metadata")
    monkeypatch.setattr(p, "_fixed_diagnostics_module", lambda: d)
    monkeypatch.setattr(p, "_fixed_process_metadata_module", lambda: m)
    return p, d, m


def _setup(modules, monkeypatch, *, capture=None, authority_error=None):
    _, diagnostics, _ = modules
    events = []

    def identity():
        events.append("identity")

    def context():
        events.append("context")

    def authority():
        events.append("authority")
        if authority_error is not None:
            raise authority_error

    def getconf():
        events.append("getconf")
        if isinstance(capture, BaseException):
            raise capture
        return (
            diagnostics.DiagnosticCapture("getconf", NATIVE, 34567) if capture is None else capture
        )

    monkeypatch.setattr(diagnostics, "_require_identity", identity)
    monkeypatch.setattr(diagnostics, "_require_wait_context", context)
    monkeypatch.setattr(diagnostics, "_verify_authority", authority)
    monkeypatch.setattr(diagnostics, "capture_getconf", getconf)
    return events


def test_exact_fresh_capture_and_provenance_order(modules, monkeypatch):
    preflight, _, metadata = modules
    events = _setup(modules, monkeypatch)
    value = preflight._observe_fixed_temp_parent()
    assert type(value) is metadata.TempParent
    assert (value.native_path, value.canonical_path) == (
        "/var/folders/ab/runner_123/T/",
        "/private/var/folders/ab/runner_123/T/",
    )
    assert events == ["identity", "context", "authority", "getconf"]
    assert not hasattr(value, "stdout") and not hasattr(value, "child_pid")


@pytest.mark.parametrize("authority_error", [ValueError("bad authority"), OSError("bad authority")])
def test_authority_failure_refuses_before_any_child_capture(modules, monkeypatch, authority_error):
    preflight, _, _ = modules
    events = _setup(modules, monkeypatch, authority_error=authority_error)
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
        preflight._observe_fixed_temp_parent()
    assert events == ["identity", "context", "authority"]
    assert err.value.cleanup_uncertain is False
    assert err.value.__cause__ is None


@pytest.mark.parametrize(
    "capture",
    [
        lambda d: SimpleNamespace(kind="getconf", stdout=NATIVE, child_pid=34567),
        lambda d: d.DiagnosticCapture("ps", NATIVE, 34567),
        lambda d: d.DiagnosticCapture("getconf", NATIVE.decode(), 34567),
        lambda d: d.DiagnosticCapture("getconf", NATIVE, True),
        lambda d: d.DiagnosticCapture("getconf", NATIVE, 0),
        lambda d: d.DiagnosticCapture("getconf", NATIVE, -1),
        lambda d: d.DiagnosticCapture("getconf", NATIVE, 2147483648),
    ],
)
def test_malformed_capture_return_is_uncertain(modules, monkeypatch, capture):
    preflight, d, _ = modules
    events = _setup(modules, monkeypatch, capture=capture(d))
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
        preflight._observe_fixed_temp_parent()
    assert events == ["identity", "context", "authority", "getconf"]
    assert err.value.cleanup_uncertain is True
    assert err.value.__cause__ is None


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"/var/folders/ab/runner_123/T/",
        b"/var/folders/ab/runner_123/T/\n\n",
        b"/private/var/folders/ab/runner_123/T/\n",
        b"/tmp/unauthorized/T/\n",
        b"/var/folders/ab/../T/\n",
        b"/var/folders/ab/token/T/\x00\n",
        b"/var/folders/ab/token/T/\r\n",
    ],
)
def test_invalid_native_temp_bytes_fail_after_valid_capture(modules, monkeypatch, raw):
    preflight, d, _ = modules
    _setup(modules, monkeypatch, capture=d.DiagnosticCapture("getconf", raw, 34567))
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
        preflight._observe_fixed_temp_parent()
    assert err.value.cleanup_uncertain is False
    assert err.value.__cause__ is None


@pytest.mark.parametrize("uncertain", [False, True])
def test_typed_diagnostic_error_retains_cleanup_status(modules, monkeypatch, uncertain):
    preflight, d, _ = modules
    _setup(modules, monkeypatch, capture=d.DiagnosticError(cleanup_uncertain=uncertain))
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
        preflight._observe_fixed_temp_parent()
    assert err.value.cleanup_uncertain is uncertain


@pytest.mark.parametrize(
    "exc",
    [
        RuntimeError("secret"),
        OSError("secret"),
        KeyboardInterrupt("secret"),
        SystemExit("secret"),
        GeneratorExit("secret"),
    ],
)
def test_non_contract_capture_failure_fails_conservatively(modules, monkeypatch, exc):
    preflight, _, _ = modules
    _setup(modules, monkeypatch, capture=exc)
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
        preflight._observe_fixed_temp_parent()
    assert err.value.cleanup_uncertain is True
    assert err.value.__cause__ is None
    assert "secret" not in str(err.value)


@pytest.mark.parametrize("value", [None, "False", 0])
def test_unreliable_diagnostic_cleanup_flag_is_uncertain(modules, monkeypatch, value):
    preflight, d, _ = modules

    class Unreliable(d.DiagnosticError):
        @property
        def cleanup_uncertain(self):
            return value

    _setup(modules, monkeypatch, capture=Unreliable())
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
        preflight._observe_fixed_temp_parent()
    assert err.value.cleanup_uncertain is True


def test_throwing_cleanup_accessor_is_uncertain(modules, monkeypatch):
    preflight, d, _ = modules

    class Unreadable(d.DiagnosticError):
        @property
        def cleanup_uncertain(self):
            raise KeyboardInterrupt("secret")

    _setup(modules, monkeypatch, capture=Unreadable())
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
        preflight._observe_fixed_temp_parent()
    assert err.value.cleanup_uncertain is True


def test_no_mutation_or_generic_selector(modules, monkeypatch):
    import inspect

    preflight, _, _ = modules
    events = _setup(modules, monkeypatch)

    def forbidden(*args, **kwargs):
        pytest.fail("unexpected mutation or process action")

    for name in ("kill", "unlink", "rmdir", "rename", "write"):
        monkeypatch.setattr(preflight.os, name, forbidden)
    assert len(inspect.signature(preflight._observe_fixed_temp_parent).parameters) == 0
    preflight._observe_fixed_temp_parent()
    assert events == ["identity", "context", "authority", "getconf"]


@pytest.mark.parametrize("index", [0, 1, 2])
def test_real_pinned_authority_byte_tamper_blocks_getconf_before_capture(
    modules, monkeypatch, index
):
    """Real verified hash/size binding; only disposable trusted-doc copies."""
    import shutil
    import tempfile

    preflight, diagnostics, _ = modules
    real_verify = diagnostics._verify_authority
    events = _setup(modules, monkeypatch)
    root = ROOT / ".superpowers"
    root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="getconf-authority-", dir=root) as temp:
        checkout = Path(temp)
        for path, _, _ in diagnostics.AUTHORITY_FILES:
            dst = checkout / path
            dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(ROOT / path, dst)
            dst.chmod(0o644)
        monkeypatch.setattr(
            diagnostics, "__file__", str(checkout / "ops/live-e2e/staging_diagnostics.py")
        )
        # Before mutation, authentic pinned files have the approved content.
        real_verify()
        mutated = checkout / diagnostics.AUTHORITY_FILES[index][0]
        data = mutated.read_bytes()
        mutated.write_bytes(bytes((data[0] ^ 1,)) + data[1:])
        mutated.chmod(0o644)

        def authority():
            events.append("authority")
            real_verify()

        monkeypatch.setattr(diagnostics, "_verify_authority", authority)
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
            preflight._observe_fixed_temp_parent()
        assert events == ["identity", "context", "authority"]
        assert err.value.cleanup_uncertain is False
        assert err.value.__cause__ is None


def test_parser_contract_return_is_not_trusted(modules, monkeypatch):
    preflight, _, metadata = modules
    _setup(modules, monkeypatch)
    monkeypatch.setattr(
        metadata,
        "_parse_temp_parent",
        lambda _: SimpleNamespace(
            native_path="/var/folders/ab/runner_123/T/",
            canonical_path="/private/var/folders/ab/runner_123/T/",
        ),
    )
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
        preflight._observe_fixed_temp_parent()
    assert err.value.cleanup_uncertain is False
