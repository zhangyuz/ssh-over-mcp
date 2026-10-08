"""Disposable RED/GREEN for independent fixed ps observations around staging inventory."""

from __future__ import annotations

import importlib.util
import os
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "ops/live-e2e/staging_preflight.py"
DIAGNOSTICS = ROOT / "ops/live-e2e/staging_diagnostics.py"
METADATA = ROOT / "ops/live-e2e/staging_process_metadata.py"
SHA = "47531dadb58d365f74089dd5f52ce1b61bb0fdd1"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


@pytest.fixture
def stage(tmp_path, monkeypatch):
    preflight = _load(SOURCE, "_som_pair_ps_preflight")
    diagnostics = _load(DIAGNOSTICS, "_som_pair_ps_diagnostics")
    metadata = _load(METADATA, "_som_pair_ps_metadata")
    monkeypatch.setattr(preflight, "_fixed_diagnostics_module", lambda: diagnostics)
    monkeypatch.setattr(preflight, "_fixed_process_metadata_module", lambda: metadata)

    fixed = preflight._select_incident("stale-target")
    base = tmp_path / "disposable"
    base.mkdir(mode=0o700)
    root = base / fixed.basename
    root.mkdir(mode=0o700)
    payload = root / "payload-content"
    payload.mkdir(mode=0o700)
    commit = payload / "expected_commit"
    commit.write_bytes((SHA + "\n").encode())
    commit.chmod(0o600)
    for name in ("bootstrap-wheels", "payload-iso", "seed", "target.git", "wheels"):
        (root / name).mkdir(mode=0o700)
    for name in ("git-askpass", "overlay.qcow2", "payload.iso", "seed.iso", "target.bundle"):
        (root / name).write_bytes(b"metadata only")
        (root / name).chmod(0o600)

    info = root.stat()
    fake = replace(fixed, uid=os.geteuid(), device=info.st_dev, inode=info.st_ino)
    real_selector = preflight._select_incident

    def selector(value):
        incident = real_selector(value)
        return fake if value == "stale-target" else incident

    monkeypatch.setattr(preflight, "_select_incident", selector)
    events = []
    child = 34567
    raw = f"{os.getpid()} python3.13\n{child} ps\n".encode()
    diagnostic_capture = diagnostics.DiagnosticCapture("ps", raw, child)
    calls = []

    def capture():
        events.append("ps")
        calls.append(1)
        return diagnostic_capture

    def owner(pid, sig):
        events.append("owner")
        assert (pid, sig) == (38013, 0)
        raise ProcessLookupError()

    monkeypatch.setattr(diagnostics, "capture_ps", capture)
    monkeypatch.setattr(preflight.os, "kill", owner)
    actual_inventory = preflight._collect_and_bind

    def inventory(*args, **kwargs):
        events.append("inventory")
        return actual_inventory(*args, **kwargs)

    monkeypatch.setattr(preflight, "_collect_and_bind", inventory)

    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with preflight._pin_fixed_incident_root(fd, "stale-target") as chain:
            yield preflight, diagnostics, root, commit, chain, events, calls
    finally:
        os.close(fd)


def test_two_real_capture_invocations_bracket_inventory(stage):
    p, _diagnostics, root, commit, chain, events, calls = stage
    result = p._observe_paired_process_inventory(chain, "stale-target")
    assert events == ["ps", "owner", "inventory", "ps", "owner"]
    assert len(calls) == 2
    assert type(result) is p._SelectedInventoryEvidence
    assert result.expected_metadata.inode == commit.stat().st_ino
    assert result.inode == root.stat().st_ino
    assert len(result.inventory) > 0
    assert not hasattr(result, "stdout") and not hasattr(result, "ps_pid")
    with pytest.raises(FrozenInstanceError):
        result.inode = 1


@pytest.mark.parametrize("stop", ["first", "second"])
def test_failed_ps_refuses_without_partial_inventory_evidence(stage, monkeypatch, stop):
    p, d, *_unused, events, calls = stage
    original = d.capture_ps

    def failure():
        if (stop == "first" and not calls) or (stop == "second" and len(calls) == 1):
            events.append("ps")
            raise d.DiagnosticError(cleanup_uncertain=True)
        return original()

    monkeypatch.setattr(d, "capture_ps", failure)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as err:
        p._observe_paired_process_inventory(_unused[2], "stale-target")
    assert err.value.cleanup_uncertain is True
    assert err.value.__cause__ is None
    assert events == (["ps"] if stop == "first" else ["ps", "owner", "inventory", "ps"])


def test_final_staging_edge_revalidated_after_second_snapshot(stage, monkeypatch):
    p, d, root, _commit, chain, events, _calls = stage
    base = root.parent
    actual = d.capture_ps

    def swap():
        returned = actual()
        if events.count("ps") == 2:
            root.rename(base / "formerly-selected")
            root.mkdir(mode=0o700)
        return returned

    monkeypatch.setattr(d, "capture_ps", swap)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
        p._observe_paired_process_inventory(chain, "stale-target")
    assert events == ["ps", "owner", "inventory", "ps", "owner"]


def test_wrong_selector_and_untrusted_chain_refuse_without_process_spawn(stage):
    p, _, _, _, chain, events, _ = stage
    with pytest.raises(p.PreflightError):
        p._observe_paired_process_inventory(chain, "untrusted")
    with pytest.raises(p.PreflightError):
        p._observe_paired_process_inventory(object(), "stale-target")
    assert events == []


def test_no_caller_supplied_process_identity(stage):
    from inspect import signature

    p, _, _, _, chain, events, _ = stage
    parameters = tuple(signature(p._observe_paired_process_inventory).parameters)
    assert parameters == ("selected_chain", "selector")
    with pytest.raises(TypeError):
        p._observe_paired_process_inventory(chain, "stale-target", 38013)
    assert events == []


def test_owned_capture_error_is_never_downgraded(stage, monkeypatch):
    p, d, _, _, chain, events, _ = stage

    def interrupted():
        events.append("ps")
        raise KeyboardInterrupt("private details")

    monkeypatch.setattr(d, "capture_ps", interrupted)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as err:
        p._observe_paired_process_inventory(chain, "stale-target")
    assert err.value.cleanup_uncertain is True
    assert "private" not in str(err.value)
    assert events == ["ps"]


def test_commit_bytes_changed_during_second_snapshot_refuses(stage, monkeypatch):
    p, d, _root, commit, chain, events, _calls = stage
    real_capture = d.capture_ps

    def mutate():
        result = real_capture()
        if events.count("ps") == 2:
            old = commit.read_bytes()
            commit.write_bytes(bytes((old[0] ^ 1,)) + old[1:])
        return result

    monkeypatch.setattr(d, "capture_ps", mutate)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as err:
        p._observe_paired_process_inventory(chain, "stale-target")
    assert events == ["ps", "owner", "inventory", "ps", "owner"]
    assert err.value.cleanup_uncertain is False


def test_second_capture_wrong_kind_refuses_without_result(stage, monkeypatch):
    p, d, _, _, chain, events, calls = stage
    real_capture = d.capture_ps

    def malformed():
        if len(calls) == 1:
            events.append("ps")
            return d.DiagnosticCapture("getconf", b"not process metadata", 34567)
        return real_capture()

    monkeypatch.setattr(d, "capture_ps", malformed)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as err:
        p._observe_paired_process_inventory(chain, "stale-target")
    assert err.value.cleanup_uncertain is True
    assert events == ["ps", "owner", "inventory", "ps"]


def test_inventory_failure_does_not_invoke_second_ps(stage, monkeypatch):
    p, _, _, _, chain, events, calls = stage

    def fail(*_args, **_kwargs):
        events.append("inventory")
        raise p.PreflightError(cleanup_uncertain=True)

    monkeypatch.setattr(p, "_collect_and_bind", fail)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as err:
        p._observe_paired_process_inventory(chain, "stale-target")
    assert err.value.cleanup_uncertain is True
    assert events == ["ps", "owner", "inventory"]
    assert len(calls) == 1


def test_validated_selected_root_rechecked_before_ps(stage, monkeypatch):
    p, _, root, _commit, chain, events, _calls = stage
    real = root.parent
    root.rename(real / "renamed-selected")
    root.mkdir(mode=0o700)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
        p._observe_paired_process_inventory(chain, "stale-target")
    assert events == []
