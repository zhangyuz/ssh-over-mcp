"""Disposable read-only marker + staging under jointly pinned native ancestry."""

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


def test_fixed_paired_content_bound_under_joint_native_ancestry(env, monkeypatch):
    p, _root, _cache, marker, _temp, selected, expected, events = env

    def forbidden(*args, **kwargs):
        raise AssertionError("process capture not authorized")

    monkeypatch.setattr(p, "_observe_fixed_process_snapshot", forbidden)
    monkeypatch.setattr(p, "_observe_paired_process_inventory", forbidden)
    result = p._observe_joint_marker_staging("stale-target")
    assert type(result) is p._MarkerStagingEvidence
    assert result.marker_target == SHA and result.marker_owner_pid == 38013
    assert result.marker_metadata.inode == marker.stat().st_ino
    assert result.selected.inode == selected.stat().st_ino
    assert result.selected.expected_metadata.inode == expected.stat().st_ino
    assert events == ["getconf", "root", "root"]
    with pytest.raises(FrozenInstanceError):
        result.marker_target = "other"


def test_strict_interface_and_selector_refuses_before_getconf(env):
    import inspect

    p, *_other, events = env
    assert tuple(inspect.signature(p._observe_joint_marker_staging).parameters) == ("selector",)
    with pytest.raises(TypeError):
        p._observe_joint_marker_staging("stale-target", "/tmp")
    with pytest.raises(p.PreflightError):
        p._observe_joint_marker_staging("not-catalogued")
    assert events == []


def test_marker_inplace_rewrite_during_inventory_refuses(env, monkeypatch):
    p, _root, _cache, marker, *_ = env
    original = p._observe_selected_inventory

    def mutate(*args, **kwargs):
        result = original(*args, **kwargs)
        marker.write_bytes(MARKER + b" ")
        return result

    monkeypatch.setattr(p, "_observe_selected_inventory", mutate)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
        p._observe_joint_marker_staging("stale-target")


def test_selected_root_replacement_during_inventory_refuses(env, monkeypatch):
    p, _root, _cache, _marker, _temp, selected, _expected, _events = env
    original = p._observe_selected_inventory

    def swap(*args, **kwargs):
        result = original(*args, **kwargs)
        selected.rename(selected.with_name("former-selected"))
        selected.mkdir(mode=0o700)
        return result

    monkeypatch.setattr(p, "_observe_selected_inventory", swap)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
        p._observe_joint_marker_staging("stale-target")


def test_expected_commit_metadata_or_content_drift_refuses(env, monkeypatch):
    p, _root, _cache, _marker, _temp, _selected, expected, _events = env
    original = p._observe_selected_inventory

    def mutate(*args, **kwargs):
        result = original(*args, **kwargs)
        expected.write_bytes(b"0" * 40 + b"\n")
        return result

    monkeypatch.setattr(p, "_observe_selected_inventory", mutate)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
        p._observe_joint_marker_staging("stale-target")


def test_ancestry_mismatch_prevents_marker_read(env, monkeypatch):
    p, root, _cache, _marker, _temp, _selected, _expected, _events = env
    alternate = root.parent / "alternate-root"
    alternate.mkdir(mode=0o700)
    alternate.joinpath(*p._CACHE_PARTS).mkdir(parents=True, mode=0o700)
    roots = []
    original_open = os.open
    marker_reads = []

    def split_roots():
        choice = root if not roots else alternate
        roots.append(choice)
        return original_open(choice, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    def individual_root_stat():
        return p._metadata(os.stat(roots[-1]))

    def spy_marker(*args, **kwargs):
        marker_reads.append(True)
        raise AssertionError("marker must not be read")

    monkeypatch.setattr(p, "_open_fixed_native_root", split_roots)
    monkeypatch.setattr(p, "_stat_fixed_native_root", individual_root_stat)
    monkeypatch.setattr(p, "_read_marker", spy_marker)
    with pytest.raises(p.PreflightError):
        p._observe_joint_marker_staging("stale-target")
    assert roots == [root, alternate]
    assert marker_reads == []


@pytest.mark.parametrize(
    "bad_marker",
    [
        b'{"target":"47531dadb58d365f74089dd5f52ce1b61bb0fdd1","owner_pid":38013,"owner_pid":38013}',
        b'{"target":"47531dadb58d365f74089dd5f52ce1b61bb0fdd1","owner_pid":true}',
    ],
)
def test_marker_schema_refuses_duplicate_or_boolean_pid(env, bad_marker):
    p, _root, _cache, marker, *_ = env
    marker.write_bytes(bad_marker)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
        p._observe_joint_marker_staging("stale-target")


def test_marker_symlink_is_never_followed(env):
    p, _root, _cache, marker, *_ = env
    marker.rename(marker.with_name("former-marker"))
    marker.symlink_to("former-marker")
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
        p._observe_joint_marker_staging("stale-target")


def test_marker_replaced_with_same_bytes_during_inventory_refuses(env, monkeypatch):
    p, _root, _cache, marker, *_ = env
    original = p._observe_selected_inventory

    def replace_marker(*args, **kwargs):
        result = original(*args, **kwargs)
        marker.rename(marker.with_name("former-marker"))
        marker.write_bytes(MARKER)
        marker.chmod(0o600)
        return result

    monkeypatch.setattr(p, "_observe_selected_inventory", replace_marker)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
        p._observe_joint_marker_staging("stale-target")


def test_late_marker_mutation_during_final_expected_commit_read_refuses(env, monkeypatch):
    from contextlib import contextmanager

    p, _root, _cache, marker, *_ = env
    original = p._pin_expected_commit
    n = []

    @contextmanager
    def pin_and_mutate(*args, **kwargs):
        with original(*args, **kwargs) as pinned:
            n.append(True)
            yield pinned
            if len(n) == 2:
                marker.write_bytes(MARKER + b" ")

    monkeypatch.setattr(p, "_pin_expected_commit", pin_and_mutate)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$"):
        p._observe_joint_marker_staging("stale-target")
    assert len(n) == 2


def test_uncertain_marker_read_preserves_cleanup_flag(env, monkeypatch):
    p, *_ = env

    def uncertain(*args, **kwargs):
        raise p.PreflightError(cleanup_uncertain=True)

    monkeypatch.setattr(p, "_read_marker", uncertain)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as err:
        p._observe_joint_marker_staging("stale-target")
    assert err.value.cleanup_uncertain is True
    assert err.value.__cause__ is None


def test_expected_commit_rewrite_during_last_marker_read_refuses(env, monkeypatch):
    """Independent P2: later marker read must not leave a stale commit leaf."""
    p, _root, _cache, _marker, _temp, _selected, expected, _events = env
    original = p._read_marker
    calls = []

    def rewrite(*args, **kwargs):
        result = original(*args, **kwargs)
        calls.append(True)
        if len(calls) == 3:
            expected.write_bytes(b"0" * 40 + b"\n")
        return result

    monkeypatch.setattr(p, "_read_marker", rewrite)
    with pytest.raises(p.PreflightError, match="^staging preflight rejected$") as err:
        p._observe_joint_marker_staging("stale-target")
    assert calls == [True] * 3
    assert err.value.cleanup_uncertain is False
    assert err.value.__cause__ is None
