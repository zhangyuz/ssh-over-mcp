"""Private selected staging inventory evidence: disposable Slice A fixtures."""

from __future__ import annotations

import importlib.util
import os
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[2] / "ops/live-e2e/staging_preflight.py"
FIXED_SHA = "47531dadb58d365f74089dd5f52ce1b61bb0fdd1"


@pytest.fixture
def preflight():
    name = "ssh_over_mcp_selected_inventory_fixture"
    spec = importlib.util.spec_from_file_location(name, MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


@pytest.fixture
def staging(tmp_path, preflight, monkeypatch):
    original = preflight._select_incident("stale-target")
    assert original.uid == 502
    assert original.expected_commit == FIXED_SHA
    parent = tmp_path / "T"
    parent.mkdir(mode=0o700)
    root = parent / original.basename
    root.mkdir(mode=0o700)
    payload = root / "payload-content"
    payload.mkdir(mode=0o700)
    commit = payload / "expected_commit"
    commit.write_bytes((FIXED_SHA + "\n").encode("ascii"))
    commit.chmod(0o600)
    for dirname in ("bootstrap-wheels", "payload-iso", "seed", "target.git", "wheels"):
        (root / dirname).mkdir(mode=0o700)
    for filename in ("git-askpass", "overlay.qcow2", "payload.iso", "seed.iso", "target.bundle"):
        leaf = root / filename
        leaf.write_bytes(b"never opened as regular content")
        leaf.chmod(0o600)
    snapshot = root.stat()
    fixture_incident = replace(
        original, device=snapshot.st_dev, inode=snapshot.st_ino, uid=os.geteuid()
    )
    production_select = preflight._select_incident

    def fixture_select(selector):
        production_select(selector)
        return fixture_incident

    monkeypatch.setattr(preflight, "_select_incident", fixture_select)
    borrowed = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield parent, root, commit, borrowed
    finally:
        os.close(borrowed)


def _observe(preflight, borrowed):
    with preflight._pin_fixed_incident_root(borrowed, "stale-target") as chain:
        return preflight._observe_selected_inventory(chain, "stale-target")


def test_detached_evidence_is_immutable_and_exact(preflight, staging):
    parent, root, commit, borrowed = staging
    evidence = _observe(preflight, borrowed)
    assert evidence.selector == "stale-target"
    assert evidence.basename == root.name
    assert evidence.device == root.stat().st_dev
    assert evidence.inode == root.stat().st_ino
    assert evidence.uid == os.geteuid()
    assert evidence.mode == 0o700
    assert evidence.expected_commit == FIXED_SHA
    assert type(evidence.inventory) is tuple
    assert any(x.path == "payload-content/expected_commit" for x in evidence.inventory)
    assert len(evidence.inventory) >= 12
    assert evidence.expected_metadata.inode == commit.stat().st_ino
    assert not hasattr(evidence, "fd")
    with pytest.raises(FrozenInstanceError):
        evidence.selector = "older-target"
    assert os.fstat(borrowed).st_ino == parent.stat().st_ino


def test_modified_expected_commit_is_rejected(preflight, staging, monkeypatch):
    _, _, commit, borrowed = staging
    real_collect = preflight._collect_and_bind

    def tamper(*args, **kwargs):
        evidence = real_collect(*args, **kwargs)
        commit.write_bytes(b"0" * 40 + b"\n")
        return evidence

    monkeypatch.setattr(preflight, "_collect_and_bind", tamper)
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
        _observe(preflight, borrowed)


def test_replaced_root_edge_during_inventory_is_rejected(preflight, staging, monkeypatch):
    _, root, _, borrowed = staging
    real_collect = preflight._collect_and_bind

    def swap(*args, **kwargs):
        inventory = real_collect(*args, **kwargs)
        root.rename(root.with_name("former"))
        root.mkdir(mode=0o700)
        return inventory

    monkeypatch.setattr(preflight, "_collect_and_bind", swap)
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
        _observe(preflight, borrowed)


def test_rejects_wrong_chain_selector_and_bad_object(preflight, staging):
    _, _, _, borrowed = staging
    with preflight._pin_fixed_incident_root(borrowed, "stale-target") as chain:
        for bad in ("older-target", None, True, 12):
            with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
                preflight._observe_selected_inventory(chain, bad)
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
            preflight._observe_selected_inventory(object(), "stale-target")


def test_original_chain_borrowed_fd_remains_open(preflight, staging):
    _, _, _, borrowed = staging
    with preflight._pin_fixed_incident_root(borrowed, "stale-target") as chain:
        evidence = preflight._observe_selected_inventory(chain, "stale-target")
        chain.revalidate()
        assert evidence.selector == "stale-target"
    assert os.fstat(borrowed).st_ino > 0


def test_presanitized_cleanup_uncertainty_preserved(preflight, staging, monkeypatch):
    _, _, _, borrowed = staging

    def unsafe(*_args, **_kwargs):
        raise preflight.PreflightError(cleanup_uncertain=True)

    monkeypatch.setattr(preflight, "_collect_and_bind", unsafe)
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as error:
        _observe(preflight, borrowed)
    assert error.value.cleanup_uncertain is True


def test_no_process_or_marker_authority(preflight, staging, monkeypatch):
    _, _, _, borrowed = staging

    def forbidden(*_args, **_kwargs):
        pytest.fail("unexpected marker/process authority")

    monkeypatch.setattr(preflight, "_read_marker", forbidden)
    monkeypatch.setattr(preflight.os, "kill", forbidden)
    assert _observe(preflight, borrowed).selector == "stale-target"
    assert not hasattr(preflight, "preflight_incident")


def test_root_edge_swap_during_nested_descriptor_cleanup_refuses(preflight, staging, monkeypatch):
    """Evidence must not become valid between final read and context return."""
    from contextlib import contextmanager

    _, root, _, borrowed = staging
    actual_context = preflight._pin_expected_commit
    changed = False

    @contextmanager
    def swapped_after_cleanup(*args, **kwargs):
        nonlocal changed
        with actual_context(*args, **kwargs) as expected:
            yield expected
        root.rename(root.with_name("moved-during-cleanup"))
        root.mkdir(mode=0o700)
        changed = True

    with preflight._pin_fixed_incident_root(borrowed, "stale-target") as chain:
        monkeypatch.setattr(preflight, "_pin_expected_commit", swapped_after_cleanup)
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
            preflight._observe_selected_inventory(chain, "stale-target")
        assert changed
