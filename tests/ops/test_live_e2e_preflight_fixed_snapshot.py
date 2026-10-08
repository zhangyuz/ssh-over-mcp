"""Disposable RED/GREEN for one fixed UID-502 process snapshot, without activation."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = ROOT / "ops/live-e2e/staging_preflight.py"
DIAGNOSTICS = ROOT / "ops/live-e2e/staging_diagnostics.py"
METADATA = ROOT / "ops/live-e2e/staging_process_metadata.py"


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
    preflight = _load(PREFLIGHT, "_som_fixture_preflight_snapshot")
    diagnostics = _load(DIAGNOSTICS, "_som_fixture_diagnostics_snapshot")
    metadata = _load(METADATA, "_som_fixture_metadata_snapshot")
    monkeypatch.setattr(preflight, "_fixed_diagnostics_module", lambda: diagnostics, raising=False)
    monkeypatch.setattr(
        preflight, "_fixed_process_metadata_module", lambda: metadata, raising=False
    )
    return preflight, diagnostics, metadata


def _ps(inspection_pid: int, ps_pid: int, *, extra: bytes = b"") -> bytes:
    return f"{inspection_pid} python3.13\n{ps_pid} ps\n".encode("ascii") + extra


def _configure(modules, monkeypatch, *, captures=None, owner=None):
    preflight, diagnostics, _ = modules
    calls = []
    inspection_pid = os.getpid()
    if captures is None:
        captures = [diagnostics.DiagnosticCapture("ps", _ps(inspection_pid, 34567), 34567)]
    values = iter(captures)

    def capture():
        calls.append("capture_ps")
        return next(values)

    def check_owner(pid, signal_number):
        calls.append(("kill", pid, signal_number))
        assert pid == 38013
        assert signal_number == 0
        if owner is None:
            raise ProcessLookupError()
        if isinstance(owner, Exception):
            raise owner
        return owner

    monkeypatch.setattr(diagnostics, "capture_ps", capture)
    monkeypatch.setattr(preflight.os, "kill", check_owner)
    return calls


def test_one_snapshot_is_validated_and_returns_no_process_evidence(modules, monkeypatch):
    calls = _configure(modules, monkeypatch)
    assert modules[0]._observe_fixed_process_snapshot() is None
    assert calls == ["capture_ps", ("kill", 38013, 0)]


def test_distinct_invocations_can_reuse_pid_and_identical_stdout(modules, monkeypatch):
    preflight, diagnostics, _ = modules
    pid = 34567
    raw = _ps(os.getpid(), pid)
    capture = diagnostics.DiagnosticCapture("ps", raw, pid)
    calls = _configure(modules, monkeypatch, captures=[capture, capture])
    preflight._observe_fixed_process_snapshot()
    preflight._observe_fixed_process_snapshot()
    assert calls == ["capture_ps", ("kill", 38013, 0), "capture_ps", ("kill", 38013, 0)]


@pytest.mark.parametrize(
    "capture",
    [
        lambda diag: diag.DiagnosticCapture("getconf", _ps(os.getpid(), 34567), 34567),
        lambda diag: diag.DiagnosticCapture("ps", "not bytes", 34567),
        lambda diag: diag.DiagnosticCapture("ps", _ps(os.getpid(), 34567), True),
        lambda diag: diag.DiagnosticCapture("ps", _ps(os.getpid(), 34567), 123456),
        lambda diag: diag.DiagnosticCapture(
            "ps", _ps(os.getpid(), 34567, extra=b"38013 idle\n"), 34567
        ),
        lambda diag: diag.DiagnosticCapture("ps", b"38013 ps\n", 38013),
        lambda diag: diag.DiagnosticCapture("ps", b"0 bad\n", 34567),
        lambda diag: SimpleNamespace(kind="ps", stdout=_ps(os.getpid(), 34567), child_pid=34567),
    ],
)
def test_invalid_capture_and_owner_row_refuse(modules, monkeypatch, capture):
    preflight, diag, _ = modules
    calls = _configure(modules, monkeypatch, captures=[capture(diag)])
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
        preflight._observe_fixed_process_snapshot()
    assert err.value.cleanup_uncertain is False
    assert err.value.__cause__ is None
    assert "capture_ps" in calls


@pytest.mark.parametrize(
    "owner", [0, PermissionError(), OSError(5, "unexpected"), RuntimeError("bad")]
)
def test_owner_must_be_proven_absent(modules, monkeypatch, owner):
    preflight = modules[0]
    calls = _configure(modules, monkeypatch, owner=owner)
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
        preflight._observe_fixed_process_snapshot()
    assert err.value.cleanup_uncertain is False
    assert calls == ["capture_ps", ("kill", 38013, 0)]


@pytest.mark.parametrize("uncertain", [False, True])
def test_diagnostic_uncertainty_is_preserved(modules, monkeypatch, uncertain):
    preflight, diagnostics, _ = modules

    def failure():
        raise diagnostics.DiagnosticError(cleanup_uncertain=uncertain)

    monkeypatch.setattr(diagnostics, "capture_ps", failure)
    monkeypatch.setattr(
        preflight.os, "kill", lambda *_: pytest.fail("must not probe after failure")
    )
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
        preflight._observe_fixed_process_snapshot()
    assert err.value.cleanup_uncertain is uncertain
    assert err.value.__cause__ is None


@pytest.mark.parametrize("value", [None, 0, "false"])
def test_unreliable_cleanup_status_defaults_to_uncertain(modules, monkeypatch, value):
    preflight, diagnostics, _ = modules

    class Unreliable(diagnostics.DiagnosticError):
        @property
        def cleanup_uncertain(self):
            return value

    def failure():
        raise Unreliable()

    monkeypatch.setattr(diagnostics, "capture_ps", failure)
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
        preflight._observe_fixed_process_snapshot()
    assert err.value.cleanup_uncertain is True


def test_throwing_cleanup_status_defaults_to_uncertain(modules, monkeypatch):
    preflight, diagnostics, _ = modules

    class Unreadable(diagnostics.DiagnosticError):
        @property
        def cleanup_uncertain(self):
            raise RuntimeError("sensitive internal state")

    def failure():
        raise Unreadable()

    monkeypatch.setattr(diagnostics, "capture_ps", failure)
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
        preflight._observe_fixed_process_snapshot()
    assert err.value.cleanup_uncertain is True
    assert "sensitive" not in str(err.value)


def test_metadata_parse_errors_are_sanitized(modules, monkeypatch):
    preflight, _, metadata = modules
    _configure(modules, monkeypatch)

    def failure(_stdout):
        raise metadata.ProcessMetadataError()

    monkeypatch.setattr(metadata, "_parse_process_rows", failure)
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
        preflight._observe_fixed_process_snapshot()
    assert err.value.cleanup_uncertain is False


@pytest.mark.parametrize(
    "failure", [RuntimeError("unknown capture outcome"), OSError(5, "unknown")]
)
def test_unknown_post_capture_failure_preserves_uncertainty(modules, monkeypatch, failure):
    preflight, diagnostics, _ = modules

    def capture():
        raise failure

    monkeypatch.setattr(diagnostics, "capture_ps", capture)
    monkeypatch.setattr(preflight.os, "kill", lambda *_: pytest.fail("no owner probe"))
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
        preflight._observe_fixed_process_snapshot()
    assert err.value.cleanup_uncertain is True
    assert err.value.__cause__ is None


def test_owner_probe_has_fixed_literal_pid_and_no_generic_parameters(modules):
    from inspect import signature

    preflight, _diagnostics, _metadata = modules
    assert str(signature(preflight._observe_fixed_process_snapshot)) == "() -> 'None'"
    assert str(signature(preflight._require_fixed_marker_owner_absent)) == "() -> 'None'"
    probe = preflight._fixed_owner_probe_module()
    assert str(signature(probe.require_owner_absent)) == "() -> 'None'"
    assert "os.kill" not in PREFLIGHT.read_text()
