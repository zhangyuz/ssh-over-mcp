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


@pytest.mark.parametrize(
    "drift,ambiguous",
    [
        ("rewrite", False),
        ("replace_payload", False),
        ("rewrite", True),
        ("replace_payload", True),
    ],
)
def test_final_payload_close_drift_never_returns_evidence(stage, monkeypatch, drift, ambiguous):
    """Inject a real successful close then mutate only disposable staged bytes."""
    p, _d, root, commit, chain, events, _calls = stage
    actual_open, actual_close = os.open, os.close
    final_payload_fds = []
    injected = []

    def tracked_open(name, flags, *args, **kwargs):
        fd = actual_open(name, flags, *args, **kwargs)
        if name == "payload-content" and events.count("ps") == 2:
            final_payload_fds.append(fd)
        return fd

    def close_and_drift(fd):
        if fd in final_payload_fds and not injected:
            actual_close(fd)
            injected.append(True)
            if drift == "rewrite":
                commit.write_bytes(b"0" * 40 + b"\n")
            else:
                payload = root / "payload-content"
                payload.rename(root / "former-payload")
                payload.mkdir(mode=0o700)
                new_commit = payload / "expected_commit"
                new_commit.write_bytes((SHA + "\n").encode())
                new_commit.chmod(0o600)
            if ambiguous:
                raise OSError("private ambiguous close")
            return
        return actual_close(fd)

    with monkeypatch.context() as patch:
        patch.setattr(p.os, "open", tracked_open)
        patch.setattr(p.os, "close", close_and_drift)
        with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as err:
            p._observe_paired_process_inventory(chain, "stale-target")
    assert injected == [True]
    assert err.value.cleanup_uncertain is ambiguous
    assert err.value.__cause__ is None
    assert "private" not in str(err.value)
    assert events == ["ps", "owner", "inventory", "ps", "owner"]


def test_final_payload_close_normal_settled_path_keeps_success(stage, monkeypatch):
    p, _, _, _, chain, _, _ = stage
    close = os.close
    seen = []

    def record(fd):
        seen.append(fd)
        return close(fd)

    with monkeypatch.context() as patch:
        patch.setattr(p.os, "close", record)
        result = p._observe_paired_process_inventory(chain, "stale-target")
    assert type(result) is p._SelectedInventoryEvidence
    assert seen


@pytest.mark.parametrize("which", [1, 2])
@pytest.mark.parametrize("error", [OSError, RuntimeError, ValueError, KeyboardInterrupt])
def test_untyped_ps_boundary_failure_is_cleanup_uncertain(stage, monkeypatch, which, error):
    p, _diagnostics, _root, _commit, chain, events, _calls = stage

    def fail():
        events.append("ps")
        if events.count("ps") == which:
            raise error("unconfirmed child ownership")

    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", fail)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as caught:
        p._observe_paired_process_inventory(chain, "stale-target")
    assert caught.value.cleanup_uncertain is True
    assert caught.value.__cause__ is None
    assert events.count("ps") == which


@pytest.mark.parametrize("which", [1, 2])
@pytest.mark.parametrize("uncertain", [False, True])
def test_typed_ps_failure_is_not_reclassified(stage, monkeypatch, which, uncertain):
    p, _d, _root, _commit, chain, events, _calls = stage

    def fail():
        events.append("ps")
        if events.count("ps") == which:
            raise p.PreflightError(cleanup_uncertain=uncertain)

    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", fail)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as caught:
        p._observe_paired_process_inventory(chain, "stale-target")
    assert caught.value.cleanup_uncertain is uncertain


@pytest.mark.parametrize("error_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("secondary", [False, True])
def test_paired_inventory_owned_root_close_cancellation_is_uncertain(
    stage, monkeypatch, error_type, secondary
):
    p, _d, _root, _commit, chain, events, _calls = stage
    actual_dup, actual_close, actual_stat = os.dup, os.close, os.stat
    inventory_root = None
    triggered = False

    def dup(fd):
        nonlocal inventory_root
        result = actual_dup(fd)
        if fd == chain._fds[-1] and events.count("ps") == 1 and "inventory" in events:
            inventory_root = result
        return result

    def close(fd):
        nonlocal triggered
        actual_close(fd)
        if fd == inventory_root and not triggered:
            triggered = True
            raise error_type("unknown collector FD close")

    def stat(path, *args, **kwargs):
        if secondary and path == "target.bundle" and kwargs.get("dir_fd") is not None:
            raise OSError("traversal failure before secondary close")
        return actual_stat(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "dup", dup)
        patch.setattr(os, "close", close)
        patch.setattr(os, "stat", stat)
        with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure:
            p._observe_paired_process_inventory(chain, "stale-target")
    assert triggered
    assert failure.value.cleanup_uncertain is True
    assert events.count("ps") == 1
    assert events.count("inventory") == 1
    chain.revalidate()


@pytest.mark.parametrize("boundary", ["dup", "scandir"])
def test_paired_uncertain_owned_acquire_blocks_ps_b(stage, monkeypatch, boundary):
    p, _diagnostics, _root, _commit, chain, events, _calls = stage
    real_dup, real_scandir, real_close = os.dup, os.scandir, os.close
    triggered = []

    def dup(fd):
        if (
            boundary == "dup"
            and fd == chain._fds[-1]
            and events.count("ps") == 1
            and "inventory" in events
            and sys._getframe(1).f_code.co_name == "collect_staging_inventory"
        ):
            acquired = real_dup(fd)
            real_close(acquired)
            triggered.append("dup")
            raise OSError("unknown collector root clone")
        return real_dup(fd)

    def scandir(fd):
        if boundary == "scandir" and events.count("ps") == 1 and "inventory" in events:
            acquired = real_scandir(fd)
            acquired.close()
            triggered.append("scandir")
            raise OSError("unknown scandir clone")
        return real_scandir(fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "dup", dup)
        patch.setattr(os, "scandir", scandir)
        with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure:
            p._observe_paired_process_inventory(chain, "stale-target")
    assert triggered == [boundary]
    assert failure.value.cleanup_uncertain is True
    assert events.count("ps") == 1
    assert events.count("inventory") == 1
    chain.revalidate()


@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt])
def test_paired_child_directory_open_ambiguity_blocks_ps_b(stage, monkeypatch, error_type):
    p, _d, _root, _commit, chain, events, _calls = stage
    original_open, original_close = os.open, os.close
    injected = []

    def ambiguous_open(name, flags, *args, **kwargs):
        if (
            name == "payload-content"
            and kwargs.get("dir_fd") is not None
            and sys._getframe(1).f_code.co_name == "walk"
            and not injected
        ):
            owned = original_open(name, flags, *args, **kwargs)
            original_close(owned)
            injected.append("child")
            raise error_type("unknown owned child acquisition")
        return original_open(name, flags, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", ambiguous_open)
        with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure:
            p._observe_paired_process_inventory(chain, "stale-target")
    assert injected == ["child"]
    assert failure.value.cleanup_uncertain is True
    assert events.count("ps") == 1
    assert events.count("inventory") == 1
    chain.revalidate()
