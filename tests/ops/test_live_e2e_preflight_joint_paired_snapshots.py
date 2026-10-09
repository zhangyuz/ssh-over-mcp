"""Disposable fixed A/inventory/B under simultaneous pinned native ancestry."""

from __future__ import annotations

import importlib.util
import inspect
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "ops/live-e2e/staging_preflight.py"
PROCESS = ROOT / "ops/live-e2e/staging_process_metadata.py"
PARTS = ("private", "var", "folders", "ab", "runner_123", "T")
SHA = "47531dadb58d365f74089dd5f52ce1b61bb0fdd1"


def _load(source, name):
    spec = importlib.util.spec_from_file_location(name, source)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


@pytest.fixture
def env(tmp_path, monkeypatch):
    p = _load(SOURCE, "_som_joint_paired_native")
    process = _load(PROCESS, "_som_joint_paired_process")
    root = tmp_path / "disposable"
    root.mkdir(mode=0o700)
    cache = root.joinpath(*p._CACHE_PARTS)
    cache.mkdir(parents=True, mode=0o700)
    temp = root.joinpath(*PARTS)
    temp.mkdir(parents=True, mode=0o700)
    fixed = p._select_incident("stale-target")
    selected = temp / fixed.basename
    selected.mkdir(mode=0o700)
    payload = selected / "payload-content"
    payload.mkdir(mode=0o700)
    expected = payload / "expected_commit"
    expected.write_bytes((SHA + "\n").encode())
    expected.chmod(0o600)
    for name in ("bootstrap-wheels", "payload-iso", "seed", "target.git", "wheels"):
        (selected / name).mkdir(mode=0o700)
    for name in ("git-askpass", "overlay.qcow2", "payload.iso", "seed.iso", "target.bundle"):
        (selected / name).write_bytes(b"metadata only")
        (selected / name).chmod(0o600)

    stat = selected.stat()
    selected_incident = replace(fixed, uid=os.geteuid(), device=stat.st_dev, inode=stat.st_ino)
    original_selector = p._select_incident
    monkeypatch.setattr(
        p,
        "_select_incident",
        lambda key: selected_incident if key == "stale-target" else original_selector(key),
    )
    for uid in ("_CACHE_SYSTEM_UID", "_CACHE_ACCOUNT_UID", "_TEMP_SYSTEM_UID", "_TEMP_ACCOUNT_UID"):
        monkeypatch.setattr(p, uid, os.geteuid())
    monkeypatch.setattr(p, "_fixed_process_metadata_module", lambda: process)
    events = []

    def getconf():
        events.append("getconf")
        return process.TempParent(
            "/var/folders/ab/runner_123/T/",
            "/private/var/folders/ab/runner_123/T/",
        )

    def literal_root():
        events.append("root")
        return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    monkeypatch.setattr(p, "_observe_fixed_temp_parent", getconf)
    monkeypatch.setattr(p, "_open_fixed_native_root", literal_root)
    monkeypatch.setattr(p, "_stat_fixed_native_root", lambda: p._metadata(os.stat(root)))

    def fixed_ps():
        events.append("ps")

    original_inventory = p._observe_selected_inventory

    def selected_inventory(*args, **kwargs):
        events.append("inventory")
        return original_inventory(*args, **kwargs)

    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", fixed_ps)
    monkeypatch.setattr(p, "_observe_selected_inventory", selected_inventory)
    return p, root, cache, temp, selected, expected, events


def test_joint_ancestry_brackets_existing_two_ps_invocations(env):
    p, _root, _cache, _temp, selected, expected, events = env
    observation = p._observe_joint_paired_inventory("stale-target")
    assert type(observation) is p._SelectedInventoryEvidence
    assert observation.inode == selected.stat().st_ino
    assert observation.expected_metadata.inode == expected.stat().st_ino
    assert events == ["getconf", "root", "root", "ps", "inventory", "ps"]
    assert not hasattr(observation, "stdout")
    assert not hasattr(observation, "marker_metadata")


def test_strict_catalog_selector_and_no_arbitrary_input(env):
    p, *_rest, events = env
    assert tuple(inspect.signature(p._observe_joint_paired_inventory).parameters) == ("selector",)
    with pytest.raises(TypeError):
        p._observe_joint_paired_inventory("stale-target", "/untrusted")
    with pytest.raises(p.PreflightError):
        p._observe_joint_paired_inventory("untrusted")
    assert events == []


@pytest.mark.parametrize("which", ["cache", "temp", "selected"])
def test_late_ancestry_swap_during_second_ps_refuses(env, monkeypatch, which):
    p, _root, cache, temp, selected, _commit, events = env

    def second_ps():
        events.append("ps")
        if events.count("ps") == 2:
            target = {"cache": cache, "temp": temp, "selected": selected}[which]
            target.rename(target.with_name("former-" + target.name))
            target.mkdir(mode=0o700)

    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", second_ps)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
        p._observe_joint_paired_inventory("stale-target")
    assert events == ["getconf", "root", "root", "ps", "inventory", "ps"]


def test_expected_commit_rewrite_during_second_ps_refuses(env, monkeypatch):
    p, _root, _cache, _temp, _selected, expected, events = env

    def second_ps():
        events.append("ps")
        if events.count("ps") == 2:
            expected.write_bytes(b"0" * 40 + b"\n")

    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", second_ps)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
        p._observe_joint_paired_inventory("stale-target")
    assert events[-3:] == ["ps", "inventory", "ps"]


@pytest.mark.parametrize("position", [1, 2])
def test_process_failure_prevents_return_and_preserves_uncertainty(env, monkeypatch, position):
    p, *_rest, events = env

    def failed_ps():
        events.append("ps")
        if events.count("ps") == position:
            raise p.PreflightError(cleanup_uncertain=True)

    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", failed_ps)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as err:
        p._observe_joint_paired_inventory("stale-target")
    assert err.value.cleanup_uncertain is True
    assert events[-1] == "ps"
    assert events.count("inventory") == position - 1


def test_marker_and_provider_access_remain_out_of_scope(env, monkeypatch):
    p, *_ = env

    def denied(*_a, **_kw):
        raise AssertionError("marker, host receipt, and provider access not in scope")

    monkeypatch.setattr(p, "_read_marker", denied)
    monkeypatch.setattr(p, "_observe_marker_staging", denied)
    monkeypatch.setattr(p, "_observe_joint_marker_staging", denied)
    result = p._observe_joint_paired_inventory("stale-target")
    assert type(result) is p._SelectedInventoryEvidence


def test_unsafe_cache_prevents_any_ps(env, monkeypatch):
    p, _root, cache, *_rest, events = env
    cache.chmod(0o777)
    with pytest.raises(p.PreflightError):
        p._observe_joint_paired_inventory("stale-target")
    assert "ps" not in events


def test_selected_chain_provenance_cannot_be_cross_root(env, monkeypatch):
    p, root, _cache, *_ = env
    other = root.parent / "another-root"
    other.mkdir(mode=0o700)
    other.joinpath(*p._CACHE_PARTS).mkdir(parents=True, mode=0o700)
    opened = []
    native_open = os.open

    def split_root():
        candidate = root if not opened else other
        opened.append(candidate)
        return native_open(candidate, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    monkeypatch.setattr(p, "_open_fixed_native_root", split_root)
    monkeypatch.setattr(p, "_stat_fixed_native_root", lambda: p._metadata(os.stat(opened[-1])))
    with pytest.raises(p.PreflightError):
        p._observe_joint_paired_inventory("stale-target")
    assert opened == [root, other]


@pytest.mark.parametrize("which", [1, 2])
@pytest.mark.parametrize("error", [OSError, RuntimeError, ValueError])
def test_joint_wrapper_untyped_ps_boundary_cannot_downgrade_cleanup(env, monkeypatch, which, error):
    p, *_rest, events = env

    def ps():
        events.append("ps")
        if events.count("ps") == which:
            raise error("unknown capture/reap outcome")

    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", ps)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as caught:
        p._observe_joint_paired_inventory("stale-target")
    assert caught.value.cleanup_uncertain is True
    assert events.count("ps") == which
    assert events.count("inventory") == which - 1


@pytest.mark.parametrize("which", [1, 2])
def test_joint_wrapper_typed_settled_ps_refusal_stays_false(env, monkeypatch, which):
    p, *_rest, events = env

    def ps():
        events.append("ps")
        if events.count("ps") == which:
            raise p.PreflightError(cleanup_uncertain=False)

    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", ps)
    with pytest.raises(p.PreflightError) as caught:
        p._observe_joint_paired_inventory("stale-target")
    assert caught.value.cleanup_uncertain is False


@pytest.mark.parametrize("error_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("secondary", [False, True])
def test_joint_inventory_owned_root_close_cancellation_is_uncertain(
    env, monkeypatch, error_type, secondary
):
    p, _root, _cache, _temp, selected, _commit, events = env
    actual_dup, actual_close, actual_stat = os.dup, os.close, os.stat
    inventory_root = None
    triggered = False

    def dup(fd):
        nonlocal inventory_root
        result = actual_dup(fd)
        if (
            os.fstat(fd).st_ino == selected.stat().st_ino
            and events.count("ps") == 1
            and "inventory" in events
        ):
            inventory_root = result
        return result

    def close(fd):
        nonlocal triggered
        actual_close(fd)
        if fd == inventory_root and not triggered:
            triggered = True
            raise error_type("unknown inventory-owned close")

    def stat(path, *args, **kwargs):
        if secondary and path == "target.bundle" and kwargs.get("dir_fd") is not None:
            raise OSError("initial traversal failure")
        return actual_stat(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "dup", dup)
        patch.setattr(os, "close", close)
        patch.setattr(os, "stat", stat)
        with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure:
            p._observe_joint_paired_inventory("stale-target")
    assert triggered
    assert failure.value.cleanup_uncertain is True
    assert events.count("ps") == 1
    assert events.count("inventory") == 1


@pytest.mark.parametrize("boundary", ["dup", "scandir"])
def test_joint_uncertain_owned_acquire_blocks_ps_b(env, monkeypatch, boundary):
    p, _root, _cache, _temp, selected, _commit, events = env
    real_dup, real_scandir, real_close = os.dup, os.scandir, os.close
    triggered = []

    def dup(fd):
        if (
            boundary == "dup"
            and events.count("ps") == 1
            and "inventory" in events
            and os.fstat(fd).st_ino == selected.stat().st_ino
            and sys._getframe(1).f_code.co_name == "collect_staging_inventory"
        ):
            acquired = real_dup(fd)
            real_close(acquired)
            triggered.append("dup")
            raise OSError("unknown collector clone")
        return real_dup(fd)

    def scandir(fd):
        if boundary == "scandir" and events.count("ps") == 1 and "inventory" in events:
            acquired = real_scandir(fd)
            acquired.close()
            triggered.append("scandir")
            raise OSError("unknown iterator allocation")
        return real_scandir(fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "dup", dup)
        patch.setattr(os, "scandir", scandir)
        with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure:
            p._observe_joint_paired_inventory("stale-target")
    assert triggered == [boundary]
    assert failure.value.cleanup_uncertain is True
    assert events.count("ps") == 1
    assert events.count("inventory") == 1
