"""Disposable RED/GREEN for private fixed marker + selected-staging observations."""

from __future__ import annotations

import importlib.util
import os
import sys
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[2] / "ops/live-e2e/staging_preflight.py"
FIXED_SHA = "47531dadb58d365f74089dd5f52ce1b61bb0fdd1"
MARKER = b'{"target":"47531dadb58d365f74089dd5f52ce1b61bb0fdd1","owner_pid":38013}'


@pytest.fixture
def preflight():
    name = "ssh_over_mcp_marker_staging_pair_fixture"
    spec = importlib.util.spec_from_file_location(name, MODULE)
    assert spec is not None and spec.loader is not None
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    try:
        spec.loader.exec_module(result)
    finally:
        sys.modules.pop(name, None)
    return result


@pytest.fixture
def staging_pair(tmp_path, preflight, monkeypatch):
    production = preflight._select_incident("stale-target")
    assert (production.uid, production.expected_commit) == (502, FIXED_SHA)
    assert (preflight._CACHE_SYSTEM_UID, preflight._CACHE_ACCOUNT_UID) == (0, 502)
    assert (preflight._TEMP_SYSTEM_UID, preflight._TEMP_ACCOUNT_UID) == (0, 502)

    # All filesystem objects are disposable. No real system/UID-502 pathname is opened.
    host = tmp_path / "disposable-root"
    host.mkdir(mode=0o700)
    cache = host
    for component in preflight._CACHE_PARTS:
        cache = cache / component
        cache.mkdir(mode=0o700)
    leaf = cache / "active-run.json"
    leaf.write_bytes(MARKER)
    leaf.chmod(0o600)

    shard, token = "ab", "runner_abc"
    temp = host
    for component in ("private", "var", "folders", shard, token, "T"):
        temp = temp / component
        temp.mkdir(mode=0o700)
    selected = temp / production.basename
    selected.mkdir(mode=0o700)
    payload = selected / "payload-content"
    payload.mkdir(mode=0o700)
    commit = payload / "expected_commit"
    commit.write_bytes((FIXED_SHA + "\n").encode())
    commit.chmod(0o600)
    for component in ("bootstrap-wheels", "payload-iso", "seed", "target.git", "wheels"):
        (selected / component).mkdir(mode=0o700)
    for component in ("git-askpass", "overlay.qcow2", "payload.iso", "seed.iso", "target.bundle"):
        f = selected / component
        f.write_bytes(b"metadata only")
        f.chmod(0o600)

    monkeypatch.setattr(preflight, "_CACHE_SYSTEM_UID", os.geteuid())
    monkeypatch.setattr(preflight, "_CACHE_ACCOUNT_UID", os.geteuid())
    monkeypatch.setattr(preflight, "_TEMP_SYSTEM_UID", os.geteuid())
    monkeypatch.setattr(preflight, "_TEMP_ACCOUNT_UID", os.geteuid())
    real_select = preflight._select_incident
    selected_info = selected.stat()
    fixture_incident = replace(
        production, uid=os.geteuid(), device=selected_info.st_dev, inode=selected_info.st_ino
    )

    def fixture_select(selector):
        real_select(selector)
        if selector != "stale-target":
            return real_select(selector)
        return fixture_incident

    monkeypatch.setattr(preflight, "_select_incident", fixture_select)
    host_fd = os.open(host, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield host_fd, host, cache, leaf, temp, selected, commit, (shard, token)
    finally:
        os.close(host_fd)


def _observe(preflight, staging_pair, *, hook=None):
    host_fd, _, _, _, _, _, _, parts = staging_pair
    with ExitStack() as stack:
        cache_chain = stack.enter_context(preflight._pin_fixed_cache_chain(host_fd))
        temp_chain = stack.enter_context(preflight._pin_fixed_temp_chain(host_fd, parts))
        selected_chain = stack.enter_context(
            preflight._pin_fixed_incident_root(temp_chain._fds[-1], "stale-target")
        )
        if hook:
            hook(cache_chain, temp_chain, selected_chain)
        return preflight._observe_marker_staging(cache_chain, selected_chain, "stale-target")


def test_detached_marker_and_inventory_evidence(preflight, staging_pair):
    borrowed, _, _, marker, _, selected, commit, _ = staging_pair
    observed = _observe(preflight, staging_pair)
    assert observed.marker_target == FIXED_SHA
    assert observed.marker_owner_pid == 38013
    assert observed.marker_metadata.inode == marker.stat().st_ino
    assert observed.selected.selector == "stale-target"
    assert observed.selected.inode == selected.stat().st_ino
    assert observed.selected.expected_metadata.inode == commit.stat().st_ino
    assert type(observed.selected.inventory) is tuple
    assert not hasattr(observed, "fd")
    with pytest.raises(FrozenInstanceError):
        observed.marker_owner_pid = 123
    assert os.fstat(borrowed).st_ino > 0


def test_marker_bytes_drift_during_inventory_refuses(preflight, staging_pair, monkeypatch):
    _, _, _, marker, _, _, _, _ = staging_pair
    actual = preflight._observe_selected_inventory

    def rewrite(*args, **kwargs):
        result = actual(*args, **kwargs)
        marker.write_bytes(
            b'{"target":"47531dadb58d365f74089dd5f52ce1b61bb0fdd1", "owner_pid":38013}'
        )
        return result

    monkeypatch.setattr(preflight, "_observe_selected_inventory", rewrite)
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
        _observe(preflight, staging_pair)


def test_marker_replacement_same_content_refuses(preflight, staging_pair, monkeypatch):
    _, _, _, marker, _, _, _, _ = staging_pair
    actual = preflight._observe_selected_inventory

    def replace_marker(*args, **kwargs):
        result = actual(*args, **kwargs)
        marker.rename(marker.with_name("old-marker"))
        marker.write_bytes(MARKER)
        marker.chmod(0o600)
        return result

    monkeypatch.setattr(preflight, "_observe_selected_inventory", replace_marker)
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
        _observe(preflight, staging_pair)


def test_cache_edge_swap_during_inventory_refuses(preflight, staging_pair, monkeypatch):
    _, host, cache, _, _, _, _, _ = staging_pair
    actual = preflight._observe_selected_inventory

    def swap(*args, **kwargs):
        result = actual(*args, **kwargs)
        cache.rename(host / "moved-cache")
        cache.mkdir(mode=0o700)
        return result

    monkeypatch.setattr(preflight, "_observe_selected_inventory", swap)
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
        _observe(preflight, staging_pair)


def test_selected_edge_swap_during_final_marker_read_refuses(preflight, staging_pair, monkeypatch):
    _, _, _, _, _, selected, _, _ = staging_pair
    actual = preflight._revalidate_marker

    def after_marker(*args, **kwargs):
        actual(*args, **kwargs)
        selected.rename(selected.with_name("moved-staging"))
        selected.mkdir(mode=0o700)

    monkeypatch.setattr(preflight, "_revalidate_marker", after_marker)
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
        _observe(preflight, staging_pair)


def test_preserves_cleanup_uncertain(preflight, staging_pair, monkeypatch):
    def uncertain(*_args, **_kwargs):
        raise preflight.PreflightError(cleanup_uncertain=True)

    monkeypatch.setattr(preflight, "_observe_selected_inventory", uncertain)
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$") as err:
        _observe(preflight, staging_pair)
    assert err.value.cleanup_uncertain is True


def test_wrong_selector_or_foreign_chains_refuse(preflight, staging_pair):
    def reject(cache_chain, temp_chain, selected_chain):
        for selector in ("older-target", None, True, "foreign"):
            with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
                preflight._observe_marker_staging(cache_chain, selected_chain, selector)
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
            preflight._observe_marker_staging(selected_chain, selected_chain, "stale-target")
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
            preflight._observe_marker_staging(cache_chain, object(), "stale-target")

    assert _observe(preflight, staging_pair, hook=reject).marker_target == FIXED_SHA


def test_no_signals_or_receipt_or_mutation(preflight, staging_pair, monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("unexpected process or write authority")

    for method in ("kill", "write", "unlink", "rmdir"):
        monkeypatch.setattr(preflight.os, method, forbidden)
    assert _observe(preflight, staging_pair).selected.expected_commit == FIXED_SHA
    assert not hasattr(preflight, "preflight_incident")


def test_cache_edge_swap_after_final_marker_reread_refuses(preflight, staging_pair, monkeypatch):
    _, host, cache, _, _, _, _, _ = staging_pair
    original = preflight._revalidate_marker

    def late_swap(*args, **kwargs):
        original(*args, **kwargs)
        cache.rename(host / "cache-moved-after-reread")
        cache.mkdir(mode=0o700)

    monkeypatch.setattr(preflight, "_revalidate_marker", late_swap)
    with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
        _observe(preflight, staging_pair)


def test_malformed_private_chain_state_is_sanitized(preflight, staging_pair):
    """Damaged private records must never leak raw implementation failures."""

    def reject(cache_chain, _temp_chain, selected_chain):
        corrupted_cache = preflight._PinnedDirectoryChain(
            cache_chain._fds, cache_chain._parts, None
        )
        corrupted_selected = preflight._PinnedDirectoryChain(
            None, selected_chain._parts, selected_chain._initial
        )
        for cache, selected in (
            (corrupted_cache, selected_chain),
            (cache_chain, corrupted_selected),
        ):
            with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
                preflight._observe_marker_staging(cache, selected, "stale-target")

    assert _observe(preflight, staging_pair, hook=reject).marker_target == FIXED_SHA
