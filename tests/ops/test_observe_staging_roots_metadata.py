"""Disposable-root fixtures for remaining exact UID-502 historical root observer."""
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
    source = ROOT / "ops/live-e2e/observe_staging_roots_metadata.py"
    spec = importlib.util.spec_from_file_location("remaining_staging_test", source)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def case(tmp_path, monkeypatch):
    mod = load()
    parent_dir = tmp_path / "fixed-parent"
    parent_dir.mkdir(mode=0o700)
    roots = [parent_dir / "first", parent_dir / "third"]
    for root in roots:
        root.mkdir(mode=0o700)
        (root / "safe").mkdir(mode=0o755)
    uid = os.geteuid()
    mod._UID = uid
    mod._CATALOG = tuple((root.name, root.stat().st_dev, root.stat().st_ino) for root in roots)
    monkeypatch.setattr(mod, "_validate_context", lambda: {"run_id": "1", "run_attempt": "1", "authority_sha": "a" * 40})
    events = []

    @contextmanager
    def parent():
        fd = os.open(parent_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        meta = mod.preflight._metadata(os.fstat(fd))
        wrapper = SimpleNamespace(_fds=(fd,), metadata=(meta,), revalidate=lambda: events.append("parent"))
        try:
            yield wrapper
        finally:
            os.close(fd)

    @contextmanager
    def cache():
        fd = os.open(parent_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        wrapper = SimpleNamespace(_fds=(fd,), revalidate=lambda: events.append("cache"))
        try:
            yield wrapper
        finally:
            os.close(fd)

    monkeypatch.setattr(mod.observer.private_tmp, "_pin_private_tmp", parent)
    monkeypatch.setattr(mod.preflight, "_pin_observed_fixed_cache_chain", cache)
    marker = SimpleNamespace(metadata=mod.preflight._metadata(os.stat(roots[0])))
    monkeypatch.setattr(mod.preflight, "_read_marker", lambda *a, **kw: marker)
    monkeypatch.setattr(mod.preflight, "_revalidate_marker", lambda *a, **kw: events.append("marker"))
    monkeypatch.setattr(mod.preflight, "_observe_fixed_process_snapshot_checked", lambda: events.append("process"))
    return mod, roots, events


def test_both_exact_roots_complete_metadata_without_link_target_or_payload(case):
    mod, roots, events = case
    secret = "/private/do-not-read-this-link-target"
    (roots[0] / "safe" / "pointer").symlink_to(secret)
    path = roots[1] / "safe" / "payload"
    path.write_bytes(b"private-file-canary")
    path.chmod(0o600)
    evidence = mod.observe_staging_roots()
    result = json.loads(evidence)
    assert result["recovery_eligible"] is False
    assert len(result["roots"]) == 2
    assert {item["kind"] for item in result["roots"][0]["entries"]} == {"directory", "symlink"}
    assert {item["kind"] for item in result["roots"][1]["entries"]} == {"directory", "regular"}
    assert secret.encode() not in evidence and b"private-file-canary" not in evidence
    assert events.count("process") == 2 and "marker" in events
    assert (roots[0] / "safe" / "pointer").is_symlink()


def test_exact_identity_replacement_refuses_even_same_basename(case):
    mod, roots, _ = case
    roots[0].rename(roots[0].parent / "old")
    roots[0].mkdir(mode=0o700)
    with pytest.raises(mod.preflight.PreflightError):
        mod.observe_staging_roots()


def test_second_pass_drift_refuses_no_stdout(case, monkeypatch, capsys):
    mod, roots, _ = case
    original = mod.observer._collect_special_metadata
    count = 0

    def drift(*a, **kw):
        nonlocal count
        count += 1
        if count == 4:
            (roots[1] / "safe" / "new").symlink_to("/private/unrelated")
        return original(*a, **kw)

    monkeypatch.setattr(mod.observer, "_collect_special_metadata", drift)
    with pytest.raises(mod.preflight.PreflightError):
        mod.main([])
    assert capsys.readouterr().out == ""
    assert mod._REFUSAL_PHASE.startswith("inventory-b-")


def test_global_entry_budget_rejects_without_partial_stdout(case, monkeypatch, capsys):
    mod, roots, _ = case
    monkeypatch.setattr(mod, "MAX_TOTAL_ENTRIES", 3)
    with pytest.raises(mod.preflight.PreflightError):
        mod.main([])
    assert capsys.readouterr().out == ""
    assert all(root.is_dir() for root in roots)


def test_workflow_is_manual_exact_main_readonly():
    source = (ROOT / ".github/workflows/live-local-e2e-staging-roots-observe.yml").read_text()
    assert "workflow_dispatch:" in source
    assert "if: github.ref == 'refs/heads/main'" in source
    assert "group: live-local-e2e" in source
    assert "contents: read" in source and "persist-credentials: false" in source
    assert "python3 -I ops/live-e2e/observe_staging_roots_metadata.py" in source
    assert "retention-days: 7" in source
    assert "sudo " not in source and "rm " not in source


def test_third_exact_identity_replacement_refuses(case):
    mod, roots, _ = case
    roots[1].rename(roots[1].parent / "replaced")
    roots[1].mkdir(mode=0o700)
    with pytest.raises(mod.preflight.PreflightError):
        mod.observe_staging_roots()


def test_unsafe_nested_directory_refuses_with_no_partial_output(case, capsys):
    mod, roots, _ = case
    (roots[1] / "safe").chmod(0o777)
    with pytest.raises(mod.preflight.PreflightError):
        mod.main([])
    assert capsys.readouterr().out == ""
    assert mod._REFUSAL_PHASE.startswith("inventory-a-3")


def test_requires_exact_main_workflow_context(monkeypatch):
    mod = load()
    monkeypatch.setattr(mod.recovery, "_validate_context", lambda _: None)
    monkeypatch.setattr(mod, "_UID", os.geteuid())
    env = {
        "GITHUB_SHA": "a" * 40,
        "GITHUB_WORKFLOW_SHA": "a" * 40,
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_WORKFLOW_REF": (
            "zhangyuz/ssh-over-mcp/.github/workflows/"
            "live-local-e2e-recovery-root-observe.yml@refs/heads/main"
        ),
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(mod.preflight.PreflightError):
        mod._validate_context()


def test_cli_rejects_caller_selected_paths_before_any_observation(monkeypatch):
    mod = load()
    monkeypatch.setattr(
        mod, "observe_staging_roots",
        lambda: pytest.fail("must not observe caller-selected state"),
    )
    with pytest.raises(mod.preflight.PreflightError):
        mod.main(["/private/tmp/any"])
