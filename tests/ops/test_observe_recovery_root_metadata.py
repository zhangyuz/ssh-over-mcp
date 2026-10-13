"""Disposed-only fixtures for exact UID-502 recovery root evidence observer."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load():
    source = ROOT / "ops/live-e2e/observe_recovery_root_metadata.py"
    spec = importlib.util.spec_from_file_location("special_observer_test", source)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def case(tmp_path, monkeypatch):
    mod = load()
    temp = tmp_path / "temp"
    temp.mkdir(mode=0o700)
    root = temp / "recovery"
    root.mkdir(mode=0o700)
    nested = root / "clean"
    nested.mkdir(mode=0o755)
    uid = os.geteuid()
    mod._UID = uid
    mod._CATALOG = (root.name, root.stat().st_dev, root.stat().st_ino)
    monkeypatch.setattr(mod, "_validate_context", lambda: {
        "authority_sha": "a" * 40, "run_id": "1", "run_attempt": "1",
    })
    events = []

    @contextmanager
    def parent():
        fd = os.open(temp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        meta = mod.preflight._metadata(os.fstat(fd))
        obj = SimpleNamespace(_fds=(fd,), metadata=(meta,), revalidate=lambda: events.append("parent"))
        try:
            yield obj
        finally:
            os.close(fd)

    @contextmanager
    def cache():
        fd = os.open(temp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        obj = SimpleNamespace(_fds=(fd,), revalidate=lambda: events.append("cache"))
        try:
            yield obj
        finally:
            os.close(fd)

    monkeypatch.setattr(mod.private_tmp, "_pin_private_tmp", parent)
    monkeypatch.setattr(mod.preflight, "_pin_observed_fixed_cache_chain", cache)
    marker = SimpleNamespace(metadata=mod.preflight._metadata(os.stat(root)))
    monkeypatch.setattr(mod.preflight, "_read_marker", lambda *a, **kw: marker)
    monkeypatch.setattr(mod.preflight, "_revalidate_marker", lambda *a, **kw: events.append("marker"))
    monkeypatch.setattr(mod.preflight, "_observe_fixed_process_snapshot_checked", lambda: events.append("process"))
    return mod, root, nested, events


def test_symlink_and_fifo_are_metadata_only_non_authorizing(case):
    mod, root, nested, events = case
    link_target = "/private/sensitive-data-never-read-or-logged"
    (nested / "link").symlink_to(link_target)
    os.mkfifo(nested / "pipe")
    payload = nested / "regular"
    payload.write_bytes(b"private-content-canary-never-read")
    payload.chmod(0o600)
    evidence = mod.observe_recovery_root()
    parsed = json.loads(evidence)
    assert parsed["recovery_eligible"] is False
    assert parsed["snapshot_scope"] == "metadata-only; no link target or file contents"
    assert {record["kind"] for record in parsed["entries"]} == {
        "directory", "symlink", "fifo", "regular"
    }
    assert b"private-content-canary-never-read" not in evidence
    assert link_target.encode() not in evidence
    assert events.count("process") == 2 and "marker" in events
    assert (nested / "link").is_symlink()
    assert payload.read_bytes() == b"private-content-canary-never-read"
    assert root.is_dir()


def test_missing_exact_catalog_identity_refuses(case):
    mod, root, _, _ = case
    root.rename(root.parent / "old")
    root.mkdir(mode=0o700)
    with pytest.raises(mod.preflight.PreflightError):
        mod.observe_recovery_root()


def test_second_pass_drift_refuses_without_partial_output(case, monkeypatch, capsys):
    mod, _, nested, _ = case
    original = mod._collect_special_metadata
    count = 0
    def collect(*a, **kw):
        nonlocal count
        count += 1
        if count == 2:
            (nested / "new").symlink_to("/private/unrelated")
        return original(*a, **kw)
    monkeypatch.setattr(mod, "_collect_special_metadata", collect)
    with pytest.raises(mod.preflight.PreflightError):
        mod.main([])
    assert capsys.readouterr().out == ""


def test_absent_or_unsafe_context_refuses_before_state(monkeypatch):
    mod = load()
    monkeypatch.setattr(mod.recovery, "_validate_context", lambda _: None)
    monkeypatch.setattr(mod, "_UID", os.geteuid())
    for key, value in {
        "GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "a" * 40,
        "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_WORKFLOW_REF": (
            "zhangyuz/ssh-over-mcp/.github/workflows/"
            "live-local-e2e-private-tmp-forensic.yml@refs/heads/main"
        ),
    }.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(mod.preflight.PreflightError):
        mod._validate_context()


def test_caller_selected_paths_refuse_before_incident_access(monkeypatch):
    mod = load()
    monkeypatch.setattr(mod, "observe_recovery_root", lambda: pytest.fail("touched incident"))
    with pytest.raises(mod.preflight.PreflightError):
        mod.main(["/tmp/arbitrary"])


def test_workflow_is_manual_readonly_trusted_main_and_private():
    path = ROOT / ".github/workflows/live-local-e2e-recovery-root-observe.yml"
    text = path.read_text()
    assert "workflow_dispatch:" in text
    assert "pull_request:" not in text and "push:" not in text
    assert "contents: read" in text
    assert "group: live-local-e2e" in text and "cancel-in-progress: false" in text
    assert "if: github.ref == 'refs/heads/main'" in text
    assert "persist-credentials: false" in text
    assert "python3 -I ops/live-e2e/observe_recovery_root_metadata.py" in text
    assert "retention-days: 7" in text
    assert "sudo " not in text and "rm " not in text


def test_unsafe_nested_directory_never_becomes_successful_observation(case):
    mod, _, nested, _ = case
    nested.chmod(0o777)
    with pytest.raises(mod.preflight.PreflightError):
        mod.observe_recovery_root()


def test_observation_entry_bound_refuses(case, monkeypatch, capsys):
    mod, _, nested, _ = case
    (nested / "extra").symlink_to("/private/never-follow")
    monkeypatch.setattr(mod, "MAX_ENTRIES", 2)
    with pytest.raises(mod.preflight.PreflightError):
        mod.main([])
    assert capsys.readouterr().out == ""


def test_link_contents_are_never_resolved(case, monkeypatch):
    mod, _, nested, _ = case
    (nested / "private-link").symlink_to("/private/never-follow")
    def fail_readlink(*args, **kwargs):
        raise AssertionError("must never read link contents")
    monkeypatch.setattr(mod.os, "readlink", fail_readlink)
    assert json.loads(mod.observe_recovery_root())["recovery_eligible"] is False


def test_budget_applies_during_enumeration_not_after_all_child_stats(case, monkeypatch):
    mod, root, nested, _ = case
    for index in range(10):
        leaf = nested / f"file-{index}"
        leaf.write_bytes(b"x")
        leaf.chmod(0o600)
    monkeypatch.setattr(mod, "MAX_ENTRIES", 3)
    real_stat = mod.os.stat
    observed = []
    def counted_stat(path, *args, **kwargs):
        if kwargs.get("dir_fd") is not None:
            observed.append(path)
        return real_stat(path, *args, **kwargs)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        monkeypatch.setattr(mod.os, "stat", counted_stat)
        with pytest.raises(mod.preflight.PreflightError):
            mod._collect_special_metadata(fd, uid=os.geteuid())
    finally:
        os.close(fd)
    assert len(observed) <= 2, "must refuse before probing unbounded child names"
