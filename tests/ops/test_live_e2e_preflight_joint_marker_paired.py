"""Disposable joint marker and two fixed process snapshots under one held ancestry."""

from __future__ import annotations

import importlib.util
import os
import stat
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


@pytest.mark.parametrize("release", ["dup-root", "child-open", "scandir-iterator"])
@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt])
def test_full_joint_owned_inventory_release_uncertainty_blocks_ps_b(
    env, monkeypatch, release, error_type
):
    p, _root, _cache, marker, _temp, selected, expected, events = env
    _spy(env, monkeypatch)
    real_dup, real_open, real_close, real_scandir = os.dup, os.open, os.close, os.scandir
    target_owned_fd = None
    fired = []

    def dup(fd):
        nonlocal target_owned_fd
        owned = real_dup(fd)
        if (
            release == "dup-root"
            and sys._getframe(1).f_code.co_name == "collect_staging_inventory"
            and os.fstat(fd).st_ino == selected.stat().st_ino
        ):
            target_owned_fd = owned
        return owned

    def open_child(name, flags, *args, **kwargs):
        nonlocal target_owned_fd
        owned = real_open(name, flags, *args, **kwargs)
        if (
            release == "child-open"
            and name == "payload-content"
            and kwargs.get("dir_fd") is not None
            and sys._getframe(1).f_code.co_name == "walk"
        ):
            target_owned_fd = owned
        return owned

    def close(fd):
        should_inject = (
            release != "scandir-iterator"
            and fd == target_owned_fd
            and not fired
            and sys._getframe(1).f_code.co_name == "close_owned"
        )
        real_close(fd)
        if should_inject:
            fired.append(release)
            raise error_type("uncertain owned FD release after close")

    class OwnedIterator:
        def __init__(self, actual):
            self.actual = actual

        def __iter__(self):
            return iter(self.actual)

        def close(self):
            self.actual.close()
            if not fired:
                fired.append(release)
                raise error_type("uncertain scandir iterator release")

    def scandir(fd):
        actual = real_scandir(fd)
        if (
            release == "scandir-iterator"
            and not fired
            and sys._getframe(1).f_code.co_name == "names_at"
        ):
            return OwnedIterator(actual)
        return actual

    with monkeypatch.context() as patch:
        patch.setattr(os, "dup", dup)
        patch.setattr(os, "open", open_child)
        patch.setattr(os, "close", close)
        patch.setattr(os, "scandir", scandir)
        with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure:
            p._observe_joint_marker_paired_inventory("stale-target")
    assert fired == [release]
    assert failure.value.cleanup_uncertain is True
    assert failure.value.__cause__ is None
    assert events.count("ps") == 1
    assert events.count("inventory") == 1
    assert marker.read_bytes() == MARKER
    assert expected.read_bytes() == (SHA + "\n").encode()


@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt])
def test_full_joint_secondary_traversal_failure_then_owned_close_uncertain(
    env, monkeypatch, error_type
):
    p, _root, _cache, marker, _temp, selected, expected, events = env
    _spy(env, monkeypatch)
    real_dup, real_close, real_stat = os.dup, os.close, os.stat
    owned_root = None
    fired = []

    def dup(fd):
        nonlocal owned_root
        result = real_dup(fd)
        if (
            sys._getframe(1).f_code.co_name == "collect_staging_inventory"
            and os.fstat(fd).st_ino == selected.stat().st_ino
        ):
            owned_root = result
        return result

    def stat(path, *args, **kwargs):
        if (
            path == "target.bundle"
            and kwargs.get("dir_fd") is not None
            and sys._getframe(1).f_code.co_name == "walk"
        ):
            fired.append("traversal")
            raise OSError("primary traversal failure")
        return real_stat(path, *args, **kwargs)

    def close(fd):
        inject = (
            fd == owned_root
            and not any(event == "close" for event in fired)
            and sys._getframe(1).f_code.co_name == "close_owned"
        )
        real_close(fd)
        if inject:
            fired.append("close")
            raise error_type("secondary ambiguous owned close")

    with monkeypatch.context() as patch:
        patch.setattr(os, "dup", dup)
        patch.setattr(os, "stat", stat)
        patch.setattr(os, "close", close)
        with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure:
            p._observe_joint_marker_paired_inventory("stale-target")
    assert fired == ["traversal", "close"]
    assert failure.value.cleanup_uncertain is True
    assert failure.value.__cause__ is None
    assert events.count("ps") == 1
    assert events.count("inventory") == 1
    assert marker.read_bytes() == MARKER
    assert expected.read_bytes() == (SHA + "\n").encode()


def test_detached_joint_observation_is_complete_single_pass_and_immutable(env, monkeypatch):
    p, _root, _cache, marker, _temp, selected, expected, events = env
    _spy(env, monkeypatch)
    report = p._observe_detached_joint_preflight("stale-target")
    assert type(report) is p._DetachedJointPreflightObservation
    assert type(report.parent) is p._TempAncestryEvidence
    assert report.parent.path == "/private/var/folders/ab/runner_123/T"
    assert tuple(item.path for item in report.parent.ancestors) == (
        "/",
        "/private",
        "/private/var",
        "/private/var/folders",
        "/private/var/folders/ab",
        "/private/var/folders/ab/runner_123",
        "/private/var/folders/ab/runner_123/T",
    )
    assert all(type(item) is p._DirectoryAncestor for item in report.parent.ancestors)
    assert all(type(item.metadata) is p.DirectoryMetadata for item in report.parent.ancestors)
    assert report.parent.ancestors[-1].metadata.inode == (selected.parent).stat().st_ino
    assert report.marker_target == SHA
    assert report.marker_owner_pid == 38013
    assert report.marker_metadata.inode == marker.stat().st_ino
    assert report.selected.selector == "stale-target"
    assert report.selected.inode == selected.stat().st_ino
    assert report.selected.expected_metadata.inode == expected.stat().st_ino
    assert type(report.selected.inventory) is tuple
    assert events.count("getconf") == 1
    assert events.count("ps") == 2
    assert events.count("inventory") == 1
    assert not any(
        hasattr(report, field) for field in ("stdout", "child_pid", "fds", "receipt", "workflow")
    )
    with pytest.raises(FrozenInstanceError):
        report.parent.path = "changed"
    with pytest.raises(FrozenInstanceError):
        report.parent.ancestors[0].metadata = None
    with pytest.raises(FrozenInstanceError):
        report.marker_owner_pid = 7


def test_detached_joint_observation_cannot_take_arbitrary_authority_inputs(env, monkeypatch):
    import inspect

    p, *_other, events = env
    assert tuple(inspect.signature(p._observe_detached_joint_preflight).parameters) == ("selector",)
    with pytest.raises(TypeError):
        p._observe_detached_joint_preflight("stale-target", "/tmp/untrusted")
    for value in ("arbitrary", None, True, ""):
        with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
            p._observe_detached_joint_preflight(value)
    assert events == []


@pytest.mark.parametrize("phase", ["ps-a", "ps-b", "inventory"])
def test_detached_joint_observation_cannot_escape_from_drift(env, monkeypatch, phase):
    p, _root, _cache, marker, _temp, _selected, _expected, events = env
    _spy(env, monkeypatch)
    real_inventory = p._observe_selected_inventory

    def ps():
        events.append("ps")
        if (phase == "ps-a" and events.count("ps") == 1) or (
            phase == "ps-b" and events.count("ps") == 2
        ):
            marker.write_bytes(MARKER + b" ")

    def inventory(*args, **kwargs):
        result = real_inventory(*args, **kwargs)
        if phase == "inventory":
            marker.write_bytes(MARKER + b" ")
        return result

    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", ps)
    monkeypatch.setattr(p, "_observe_selected_inventory", inventory)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
        p._observe_detached_joint_preflight("stale-target")
    assert events.count("ps") in (1, 2)


@pytest.mark.parametrize("stage", [1, 2])
@pytest.mark.parametrize("uncertain", [False, True])
def test_detached_joint_preserves_typed_snapshot_cleanup_status(env, monkeypatch, stage, uncertain):
    p, *_rest, events = env
    _spy(env, monkeypatch)

    def ps():
        events.append("ps")
        if events.count("ps") == stage:
            raise p.PreflightError(cleanup_uncertain=uncertain)

    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", ps)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure:
        p._observe_detached_joint_preflight("stale-target")
    assert failure.value.cleanup_uncertain is uncertain
    assert events.count("ps") == stage


def test_legacy_marker_pair_cannot_claim_temp_parent(env, monkeypatch):
    p, *_ = env
    _spy(env, monkeypatch)
    jointly_observed = p._observe_joint_marker_paired_inventory("stale-target")
    marker_only = p._MarkerStagingEvidence(
        marker_target=jointly_observed.marker_target,
        marker_owner_pid=jointly_observed.marker_owner_pid,
        marker_metadata=jointly_observed.marker_metadata,
        selected=jointly_observed.selected,
    )
    assert marker_only.temp_parent is None


@pytest.mark.parametrize(
    "parts",
    [
        ("private", "var", "folders", "ab", "runner_123", "wrong"),
        ("private", "var", "folders", "ab", "..", "T"),
        ("private", "var", "folders", "ab", "runner_123"),
    ],
)
def test_detached_temp_snapshot_rejects_non_native_chain_shape(env, parts):
    p, *_ = env
    original = p._PinnedDirectoryChain(
        _fds=(),
        _parts=parts,
        _initial=(p.DirectoryMetadata(1, 2, 0, 0, 0o755),) * (len(parts) + 1),
    )
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
        p._snapshot_pinned_temp_ancestry(original)


def test_detached_joint_preserves_post_ps_b_owned_cleanup_uncertainty(env, monkeypatch):
    p, _root, _cache, _marker, _temp, selected, _expected, events = env
    _spy(env, monkeypatch)
    original_close = os.close
    original_inode = (selected / "payload-content").stat().st_ino
    triggered = []

    def close(fd):
        info = os.fstat(fd)
        is_payload = info.st_ino == original_inode and stat.S_ISDIR(info.st_mode)
        original_close(fd)
        if is_payload and events.count("ps") == 2 and not triggered:
            triggered.append("payload")
            raise OSError("uncertain owned payload close")

    with monkeypatch.context() as patch:
        patch.setattr(os, "close", close)
        with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as failure:
            p._observe_detached_joint_preflight("stale-target")
    assert triggered == ["payload"]
    assert failure.value.cleanup_uncertain is True
    assert events.count("ps") == 2
