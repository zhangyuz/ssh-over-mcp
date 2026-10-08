"""RED/GREEN disposable fixtures for fixed runner marker-cache ancestry."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[2] / "ops/live-e2e/staging_preflight.py"
PARTS = ("Users", "gha-e2e-orchestrator", "Library", "Caches", "ssh-over-mcp-e2e")


@pytest.fixture
def preflight():
    name = "ssh_over_mcp_cache_chain_fixture"
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
def cache_fixture(tmp_path, preflight, monkeypatch):
    # A disposable fake of the literal hierarchy. Production constants remain
    # pinned to 0/502; this fixture substitutes only filesystem ownership.
    assert preflight._CACHE_SYSTEM_UID == 0
    assert preflight._CACHE_ACCOUNT_UID == 502
    assert preflight._CACHE_PARTS == PARTS
    monkeypatch.setattr(preflight, "_CACHE_SYSTEM_UID", os.geteuid())
    monkeypatch.setattr(preflight, "_CACHE_ACCOUNT_UID", os.geteuid())
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    cursor = root
    for part in PARTS:
        cursor = cursor / part
        cursor.mkdir(mode=0o700)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield root, cursor, fd
    finally:
        os.close(fd)


def test_fixed_cache_pins_all_edges_with_safe_modes(preflight, cache_fixture):
    root, cache, borrowed = cache_fixture
    # Safe owner-writable ordinary parent directories are accepted.
    (root / "Users").chmod(0o755)
    (root / "Users" / "gha-e2e-orchestrator").chmod(0o750)
    with preflight._pin_fixed_cache_chain(borrowed) as chain:
        assert len(chain.metadata) == 5
        assert chain.metadata[-1].inode == cache.stat().st_ino
        assert chain.metadata[-1].mode == 0o700
        chain.revalidate()
    assert os.fstat(borrowed).st_ino == root.stat().st_ino


@pytest.mark.parametrize("component", PARTS)
def test_fixed_cache_rejects_unsafe_ancestor_modes(preflight, cache_fixture, component):
    root, _, borrowed = cache_fixture
    path = root.joinpath(*PARTS[: PARTS.index(component) + 1])
    path.chmod(0o777)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        preflight._pin_fixed_cache_chain(borrowed),
    ):
        pytest.fail("accepted unsafe cache ancestor")


def test_fixed_cache_requires_final_0700(preflight, cache_fixture):
    _, cache, borrowed = cache_fixture
    cache.chmod(0o755)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        preflight._pin_fixed_cache_chain(borrowed),
    ):
        pytest.fail("accepted cache without exact 0700")


def test_fixed_cache_rejects_wrong_account_owner(preflight, cache_fixture, monkeypatch):
    _, _, borrowed = cache_fixture
    monkeypatch.setattr(preflight, "_CACHE_ACCOUNT_UID", os.geteuid() + 1234)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        preflight._pin_fixed_cache_chain(borrowed),
    ):
        pytest.fail("accepted wrong owner")


def test_fixed_cache_rejects_unsafe_start_dir(preflight, cache_fixture):
    root, _, borrowed = cache_fixture
    root.chmod(0o777)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        preflight._pin_fixed_cache_chain(borrowed),
    ):
        pytest.fail("accepted unsafe parent root")


def test_fixed_cache_detects_replaced_edge_after_pin(preflight, cache_fixture):
    root, _, borrowed = cache_fixture
    with preflight._pin_fixed_cache_chain(borrowed) as chain:
        (root / "Users").rename(root / "Users-old")
        (root / "Users").mkdir(mode=0o700)
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
            chain.revalidate()


def test_fixed_cache_refuses_symlink_on_ancestor(preflight, cache_fixture):
    root, _, borrowed = cache_fixture
    old = root / "Users" / "gha-e2e-orchestrator"
    old.rename(root / "Users" / "actual")
    old.symlink_to("actual", target_is_directory=True)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        preflight._pin_fixed_cache_chain(borrowed),
    ):
        pytest.fail("accepted symlink")


def test_fixed_cache_rejects_bool_fd(preflight, cache_fixture):
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        preflight._pin_fixed_cache_chain(True),
    ):
        pytest.fail("accepted bool FD")


def test_no_production_marker_or_host_action(preflight):
    assert not hasattr(preflight, "preflight_incident")
    assert not hasattr(preflight, "main")
    assert preflight._CACHE_SYSTEM_UID == 0
    assert preflight._CACHE_ACCOUNT_UID == 502
    assert preflight._CACHE_PARTS == PARTS


def test_fixed_cache_rejects_root_mode_change_during_dup(preflight, cache_fixture, monkeypatch):
    """Initial borrowed FD check must not authorize an unsafe pinned baseline."""
    root, _, borrowed = cache_fixture
    real_dup = os.dup
    changed = False

    def change_root_before_dup(fd):
        nonlocal changed
        result = real_dup(fd)
        if fd == borrowed and not changed:
            changed = True
            root.chmod(0o777)
        return result

    monkeypatch.setattr(preflight.os, "dup", change_root_before_dup)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        preflight._pin_fixed_cache_chain(borrowed),
    ):
        pytest.fail("unsafe mode on pinned root was accepted")
    assert changed
    assert os.fstat(borrowed).st_ino == root.stat().st_ino


def test_fixed_cache_rejects_root_owner_change_during_dup(preflight, cache_fixture, monkeypatch):
    """Simulate a UID drift without chown or touching any real account."""
    from dataclasses import replace

    root, _, borrowed = cache_fixture
    real_dup = os.dup
    real_metadata = preflight._metadata
    duplicated = False
    mutated = False

    def mark_dup(fd):
        nonlocal duplicated
        result = real_dup(fd)
        if fd == borrowed:
            duplicated = True
        return result

    def changed_uid(info):
        nonlocal mutated
        result = real_metadata(info)
        if duplicated and result.inode == root.stat().st_ino:
            mutated = True
            return replace(result, uid=os.geteuid() + 77)
        return result

    monkeypatch.setattr(preflight.os, "dup", mark_dup)
    monkeypatch.setattr(preflight, "_metadata", changed_uid)
    with (
        pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"),
        preflight._pin_fixed_cache_chain(borrowed),
    ):
        pytest.fail("unsafe UID on pinned root was accepted")
    assert duplicated and mutated
    assert os.fstat(borrowed).st_ino == root.stat().st_ino


def test_fixed_cache_root_mode_drift_detected_on_late_revalidate(preflight, cache_fixture):
    root, _, borrowed = cache_fixture
    with preflight._pin_fixed_cache_chain(borrowed) as chain:
        root.chmod(0o777)
        with pytest.raises(preflight.PreflightError, match="^staging preflight rejected$"):
            chain.revalidate()
