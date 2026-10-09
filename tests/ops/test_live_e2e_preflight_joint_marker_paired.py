"""Disposable joint marker and two fixed process snapshots under one held ancestry."""

from __future__ import annotations

import importlib.util
import os
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "ops/live-e2e/staging_preflight.py"
PROCESS = ROOT / "ops/live-e2e/staging_process_metadata.py"
PARTS = ("private", "var", "folders", "ab", "runner_123", "T")
SHA = "47531dadb58d365f74089dd5f52ce1b61bb0fdd1"
MARKER = b'{"target":"47531dadb58d365f74089dd5f52ce1b61bb0fdd1","owner_pid":38013}'


def _load(path, name):
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
def env(tmp_path, monkeypatch):
    p = _load(SOURCE, "_som_joint_marker_staging")
    process = _load(PROCESS, "_som_joint_marker_process")
    root = tmp_path / "disposable"
    root.mkdir(mode=0o700)
    cache = root.joinpath(*p._CACHE_PARTS)
    cache.mkdir(parents=True, mode=0o700)
    marker = cache / "active-run.json"
    marker.write_bytes(MARKER)
    marker.chmod(0o600)
    temp = root.joinpath(*PARTS)
    temp.mkdir(parents=True, mode=0o700)
    catalog = p._select_incident("stale-target")
    selected = temp / catalog.basename
    selected.mkdir(mode=0o700)
    payload = selected / "payload-content"
    payload.mkdir(mode=0o700)
    expected = payload / "expected_commit"
    expected.write_bytes((SHA + "\n").encode())
    expected.chmod(0o600)
    for item in ("bootstrap-wheels", "payload-iso", "seed", "target.git", "wheels"):
        (selected / item).mkdir(mode=0o700)
    for item in ("git-askpass", "overlay.qcow2", "payload.iso", "seed.iso", "target.bundle"):
        item_file = selected / item
        item_file.write_bytes(b"metadata only")
        item_file.chmod(0o600)
    selected_stat = selected.stat()
    adjusted = replace(
        catalog,
        uid=os.geteuid(),
        device=selected_stat.st_dev,
        inode=selected_stat.st_ino,
    )
    selector = p._select_incident

    def fixed_selector(name):
        original = selector(name)
        return adjusted if name == "stale-target" else original

    monkeypatch.setattr(p, "_select_incident", fixed_selector)
    for item in (
        "_CACHE_SYSTEM_UID",
        "_CACHE_ACCOUNT_UID",
        "_TEMP_SYSTEM_UID",
        "_TEMP_ACCOUNT_UID",
    ):
        monkeypatch.setattr(p, item, os.geteuid())
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
    return p, root, cache, marker, temp, selected, expected, events


def _spy(env, monkeypatch):
    p, _root, _cache, _marker, _temp, _selected, _expected, events = env
    real_marker = p._read_marker
    real_inventory = p._observe_selected_inventory

    def read_marker(*args, **kwargs):
        events.append("marker")
        return real_marker(*args, **kwargs)

    def inventory(*args, **kwargs):
        events.append("inventory")
        return real_inventory(*args, **kwargs)

    monkeypatch.setattr(p, "_read_marker", read_marker)
    monkeypatch.setattr(p, "_observe_selected_inventory", inventory)
    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", lambda: events.append("ps"))
    return events


def test_one_held_ancestry_marker_ps_a_inventory_ps_b_final_marker(env, monkeypatch):
    p, _root, _cache, marker, _temp, selected, expected, events = env
    _spy(env, monkeypatch)
    result = p._observe_joint_marker_paired_inventory("stale-target")
    assert type(result) is p._MarkerStagingEvidence
    assert result.marker_target == SHA
    assert result.marker_owner_pid == 38013
    assert result.marker_metadata.inode == marker.stat().st_ino
    assert result.selected.inode == selected.stat().st_ino
    assert result.selected.expected_metadata.inode == expected.stat().st_ino
    assert events[:3] == ["getconf", "root", "root"]
    assert events.count("ps") == 2
    assert events.count("inventory") == 1
    first, second = (i for i, value in enumerate(events) if value == "ps")
    inventory = events.index("inventory")
    assert events.index("marker") < first < inventory < second
    assert any(value == "marker" for value in events[second + 1 :])
    assert not hasattr(result, "stdout")
    assert not hasattr(result, "child_pid")
    assert not hasattr(result, "fds")
    with pytest.raises(FrozenInstanceError):
        result.marker_owner_pid = 3


def test_fixed_selector_rejects_before_any_host_access(env):
    import inspect

    p, *_others, events = env
    assert tuple(inspect.signature(p._observe_joint_marker_paired_inventory).parameters) == (
        "selector",
    )
    with pytest.raises(TypeError):
        p._observe_joint_marker_paired_inventory("stale-target", "/anywhere")
    for value in ("bad", "", None, True):
        with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
            p._observe_joint_marker_paired_inventory(value)
    assert events == []


@pytest.mark.parametrize("stage", ["ps-a", "inventory", "ps-b"])
def test_marker_rewrite_at_any_middle_stage_refuses(env, monkeypatch, stage):
    p, _root, _cache, marker, _temp, _selected, _expected, events = env
    _spy(env, monkeypatch)
    real_inventory = p._observe_selected_inventory

    def ps():
        events.append("ps")
        if (stage == "ps-a" and events.count("ps") == 1) or (
            stage == "ps-b" and events.count("ps") == 2
        ):
            marker.write_bytes(MARKER + b" ")

    def inventory(*args, **kwargs):
        observed = real_inventory(*args, **kwargs)
        if stage == "inventory":
            marker.write_bytes(MARKER + b" ")
        return observed

    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", ps)
    monkeypatch.setattr(p, "_observe_selected_inventory", inventory)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
        p._observe_joint_marker_paired_inventory("stale-target")


@pytest.mark.parametrize("item", ["cache", "temp", "selected", "expected"])
def test_late_ps_b_ancestry_or_expected_drift_refuses(env, monkeypatch, item):
    p, _root, cache, _marker, temp, selected, expected, events = env
    _spy(env, monkeypatch)

    def ps():
        events.append("ps")
        if events.count("ps") != 2:
            return
        if item == "expected":
            expected.write_bytes(b"0" * 40 + b"\n")
        else:
            obj = {"cache": cache, "temp": temp, "selected": selected}[item]
            obj.rename(obj.with_name("moved-" + obj.name))
            obj.mkdir(mode=0o700)

    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", ps)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
        p._observe_joint_marker_paired_inventory("stale-target")
    assert events.count("ps") == 2


def test_marker_replaced_by_symlink_during_final_marker_close_refuses(env, monkeypatch):
    p, _root, _cache, marker, _temp, _selected, _expected, _events = env
    _spy(env, monkeypatch)
    real_close = os.close
    real_reader = p._read_marker
    marker_reads = 0
    closing_last = False
    injected = False

    def read_marker(*args, **kwargs):
        nonlocal marker_reads, closing_last
        marker_reads += 1
        closing_last = marker_reads >= 4
        try:
            return real_reader(*args, **kwargs)
        finally:
            closing_last = False

    def close(fd):
        nonlocal injected
        info = os.fstat(fd)
        is_marker = info.st_ino == marker.stat().st_ino if not injected else False
        real_close(fd)
        if closing_last and is_marker and not injected:
            injected = True
            marker.rename(marker.with_name("old-marker"))
            marker.symlink_to("old-marker")

    monkeypatch.setattr(p, "_read_marker", read_marker)
    monkeypatch.setattr(os, "close", close)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
        p._observe_joint_marker_paired_inventory("stale-target")
    assert injected
    assert marker.is_symlink()


def test_expected_commit_rewrite_on_initial_file_close_refuses(env, monkeypatch):
    p, _root, _cache, _marker, _temp, _selected, expected, _events = env
    _spy(env, monkeypatch)
    real_close = os.close
    orig_inode = expected.stat().st_ino
    fired = False

    def close(fd):
        nonlocal fired
        match = os.fstat(fd).st_ino == orig_inode
        real_close(fd)
        if match and not fired:
            fired = True
            expected.write_bytes(b"0" * 40 + b"\n")

    monkeypatch.setattr(os, "close", close)
    with pytest.raises(p.PreflightError):
        p._observe_joint_marker_paired_inventory("stale-target")
    assert fired
    # This injection fires on the first regular-file read close,
    # BEFORE ps A, not on the later payload-directory close.
    assert _events.count("ps") == 0


@pytest.mark.parametrize("which", [1, 2])
def test_both_snapshot_failure_preserves_cleanup_uncertainty(env, monkeypatch, which):
    p, *_rest, events = env
    _spy(env, monkeypatch)

    def ps():
        events.append("ps")
        if events.count("ps") == which:
            raise p.PreflightError(cleanup_uncertain=True)

    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", ps)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure:
        p._observe_joint_marker_paired_inventory("stale-target")
    assert failure.value.cleanup_uncertain is True
    assert events.count("ps") == which


def test_ps_a_error_prevents_inventory_and_ps_b(env, monkeypatch):
    p, *_rest, events = env
    _spy(env, monkeypatch)
    monkeypatch.setattr(
        p, "_observe_fixed_process_snapshot", lambda: (_ for _ in ()).throw(p.PreflightError())
    )
    with pytest.raises(p.PreflightError):
        p._observe_joint_marker_paired_inventory("stale-target")
    assert events.count("inventory") == 0


def test_symlink_marker_refused_before_ps_a(env, monkeypatch):
    p, _root, _cache, marker, *_other, events = env
    _spy(env, monkeypatch)
    marker.rename(marker.with_name("original"))
    marker.symlink_to("original")
    with pytest.raises(p.PreflightError):
        p._observe_joint_marker_paired_inventory("stale-target")
    assert "ps" not in events


def test_no_activation_or_legacy_detached_composition(env, monkeypatch):
    p, *_ = env
    _spy(env, monkeypatch)

    def forbidden(*_a, **_kw):
        raise AssertionError("detached marker or paired wrappers must not be reused")

    monkeypatch.setattr(p, "_observe_joint_marker_staging", forbidden)
    monkeypatch.setattr(p, "_observe_joint_paired_inventory", forbidden)
    observation = p._observe_joint_marker_paired_inventory("stale-target")
    assert type(observation) is p._MarkerStagingEvidence


@pytest.mark.parametrize("position", [1, 2])
@pytest.mark.parametrize("exception_type", [KeyboardInterrupt, SystemExit, MemoryError])
def test_unexpected_capture_cancellation_never_claims_settled_cleanup(
    env, monkeypatch, position, exception_type
):
    p, *_rest, events = env
    _spy(env, monkeypatch)

    def interrupted():
        events.append("ps")
        if events.count("ps") == position:
            raise exception_type("unconfirmed capture lifecycle")

    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", interrupted)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure:
        p._observe_joint_marker_paired_inventory("stale-target")
    assert failure.value.cleanup_uncertain is True
    assert events.count("ps") == position


@pytest.mark.parametrize("position", [1, 2])
@pytest.mark.parametrize("error", [RuntimeError, OSError, ValueError, AssertionError])
def test_untyped_snapshot_failure_must_preserve_unknown_cleanup(env, monkeypatch, position, error):
    p, *_rest, events = env
    _spy(env, monkeypatch)

    def snapshot():
        events.append("ps")
        if events.count("ps") == position:
            raise error("unconfirmed owned diagnostic cleanup")

    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", snapshot)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure:
        p._observe_joint_marker_paired_inventory("stale-target")
    assert failure.value.cleanup_uncertain is True
    assert events.count("ps") == position


@pytest.mark.parametrize("position", [1, 2])
def test_typed_settled_snapshot_rejection_remains_false(env, monkeypatch, position):
    p, *_rest, events = env
    _spy(env, monkeypatch)

    def snapshot():
        events.append("ps")
        if events.count("ps") == position:
            raise p.PreflightError(cleanup_uncertain=False)

    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", snapshot)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure:
        p._observe_joint_marker_paired_inventory("stale-target")
    assert failure.value.cleanup_uncertain is False


def test_post_ps_b_payload_directory_close_rewrite_refuses(env, monkeypatch):
    p, _root, _cache, _marker, _temp, selected, expected, events = env
    _spy(env, monkeypatch)
    actual_payload_inode = (selected / "payload-content").stat().st_ino
    real_close = os.close
    observed = []

    def close(fd):
        is_payload_directory = os.fstat(fd).st_ino == actual_payload_inode and __import__(
            "stat"
        ).S_ISDIR(os.fstat(fd).st_mode)
        real_close(fd)
        if is_payload_directory and events.count("ps") == 2 and not observed:
            observed.append(tuple(events))
            expected.write_bytes(b"0" * 40 + b"\n")

    monkeypatch.setattr(os, "close", close)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
        p._observe_joint_marker_paired_inventory("stale-target")
    assert len(observed) == 1
    assert observed[0].count("ps") == 2
    assert observed[0].count("inventory") == 1


@pytest.mark.parametrize("acquire", ["dup", "scandir", "child-open"])
@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt])
def test_full_joint_observer_uncertain_inventory_acquisition_blocks_ps_b(
    env, monkeypatch, acquire, error_type
):
    p, _root, _cache, marker, _temp, selected, expected, events = env
    _spy(env, monkeypatch)
    actual_dup, actual_scan, actual_open, actual_close = (os.dup, os.scandir, os.open, os.close)
    triggered = []

    def dup(fd):
        if (
            acquire == "dup"
            and not triggered
            and sys._getframe(1).f_code.co_name == "collect_staging_inventory"
            and os.fstat(fd).st_ino == selected.stat().st_ino
        ):
            owned = actual_dup(fd)
            actual_close(owned)
            triggered.append("dup")
            raise error_type("private acquisition ambiguity")
        return actual_dup(fd)

    def scandir(fd):
        if acquire == "scandir" and not triggered and sys._getframe(1).f_code.co_name == "names_at":
            owned = actual_scan(fd)
            owned.close()
            triggered.append("scandir")
            raise error_type("private iterator acquisition ambiguity")
        return actual_scan(fd)

    def open_child(name, flags, *args, **kwargs):
        if (
            acquire == "child-open"
            and not triggered
            and name == "payload-content"
            and kwargs.get("dir_fd") is not None
            and sys._getframe(1).f_code.co_name == "walk"
        ):
            owned = actual_open(name, flags, *args, **kwargs)
            actual_close(owned)
            triggered.append("child-open")
            raise error_type("private child-directory acquisition ambiguity")
        return actual_open(name, flags, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "dup", dup)
        patch.setattr(os, "scandir", scandir)
        patch.setattr(os, "open", open_child)
        with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure:
            p._observe_joint_marker_paired_inventory("stale-target")
    assert triggered == [acquire]
    assert failure.value.cleanup_uncertain is True
    assert failure.value.__cause__ is None
    assert events.count("ps") == 1
    assert events.count("inventory") == 1
    assert marker.read_bytes() == MARKER
    assert expected.read_bytes() == (SHA + "\n").encode()


def test_full_joint_observer_settled_inventory_mismatch_is_not_uncertain(env, monkeypatch):
    p, _root, _cache, _marker, _temp, selected, _expected, events = env
    _spy(env, monkeypatch)
    (selected / "target.bundle").chmod(0o622)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure:
        p._observe_joint_marker_paired_inventory("stale-target")
    assert failure.value.cleanup_uncertain is False
    assert events.count("ps") == 1
    assert events.count("inventory") == 1
