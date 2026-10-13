"""Disposable tests for the separate private-tmp incident forensic authority."""
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
    source = ROOT / "ops/live-e2e/inspect_private_tmp_residuals.py"
    spec = importlib.util.spec_from_file_location("tmp_residual_test", source)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def case(tmp_path, monkeypatch):
    mod = load()
    root = tmp_path / "root"
    parent = root / "private"
    tmp = parent / "tmp"
    tmp.mkdir(parents=True)
    root.chmod(0o755)
    parent.chmod(0o755)
    tmp.chmod(0o1777)
    uid = os.geteuid()
    mod._SYSTEM_UID = uid
    mod._UID = uid
    mod._CATALOG = tuple(
        (name, (tmp / name).stat().st_dev, (tmp / name).stat().st_ino)
        for name in ()
    )
    entries = []
    for name in ("first", "recover", "third"):
        path = tmp / name
        path.mkdir(mode=0o700)
        (path / "empty").mkdir(mode=0o700)
        entries.append((name, path.stat().st_dev, path.stat().st_ino))
    mod._CATALOG = tuple(entries)
    monkeypatch.setattr(mod, "_open_root", lambda: os.open(root, mod._DIR_FLAGS))
    monkeypatch.setattr(mod, "_stat_root", lambda: os.stat(root, follow_symlinks=False))
    monkeypatch.setattr(mod, "_validate_context", lambda: {
        "authority_sha": "a" * 40, "run_id": "1", "run_attempt": "1",
    })
    events = []

    @contextmanager
    def cache():
        fd = os.open(root, mod._DIR_FLAGS)
        thing = SimpleNamespace(_fds=(fd,), revalidate=lambda: events.append("cache"))
        try:
            yield thing
        finally:
            os.close(fd)

    monkeypatch.setattr(mod.preflight, "_pin_observed_fixed_cache_chain", cache)
    monkeypatch.setattr(mod.preflight, "_read_marker", lambda *a, **k: SimpleNamespace(metadata=mod.preflight.DirectoryMetadata(2, 3, uid, 20, 0o600)))
    monkeypatch.setattr(mod.preflight, "_revalidate_marker", lambda *a, **k: events.append("marker"))
    monkeypatch.setattr(mod.preflight, "_observe_fixed_process_snapshot_checked", lambda: events.append("process"))
    return mod, tmp, events


def test_directory_only_evidence_never_authorizes_cleanup(case):
    mod, tmp, events = case
    result = json.loads(mod.inspect_residuals())
    assert result["recovery_eligible"] is False
    assert result["parent"] == "fixed-private-tmp"
    assert result["marker"]["owner_pid"] == 38013
    assert len(result["roots"]) == 3
    assert all(r["classification"] == "directory-only-residual" for r in result["roots"])
    assert events.count("process") == 2 and "marker" in events
    assert all((tmp / name).is_dir() for name, _, _ in mod._CATALOG)


def test_regular_content_is_never_read(case):
    mod, tmp, _ = case
    leaf = tmp / "first/empty/secret"
    leaf.write_bytes(b"secret-payload-should-not-appear")
    leaf.chmod(0o600)
    result = mod.inspect_residuals()
    assert b"secret-payload-should-not-appear" not in result
    assert json.loads(result)["roots"][0]["classification"] == "nonempty-or-unknown"


def test_private_tmp_must_remain_sticky_root_owned_exact_mode(case):
    mod, tmp, _ = case
    tmp.chmod(0o777)
    with pytest.raises(mod.preflight.PreflightError):
        mod.inspect_residuals()


def test_private_tmp_must_not_be_symlink(case):
    mod, tmp, _ = case
    tmp.rename(tmp.parent / "saved")
    tmp.symlink_to(tmp.parent / "saved", target_is_directory=True)
    with pytest.raises(mod.preflight.PreflightError):
        mod.inspect_residuals()


def test_parent_identity_swap_refuses(case, monkeypatch):
    mod, tmp, _ = case
    original = mod.preflight._observe_fixed_process_snapshot_checked
    count = 0
    def swap():
        nonlocal count
        count += 1
        original()
        if count == 2:
            tmp.rename(tmp.parent / "saved")
            tmp.mkdir(mode=0o700)
            tmp.chmod(0o1777)
    monkeypatch.setattr(mod.preflight, "_observe_fixed_process_snapshot_checked", swap)
    with pytest.raises(mod.preflight.PreflightError):
        mod.inspect_residuals()


def test_catalog_identity_exchange_refuses(case):
    mod, tmp, _ = case
    (tmp / "first").rename(tmp / "saved")
    (tmp / "first").mkdir(mode=0o700)
    with pytest.raises(mod.preflight.PreflightError):
        mod.inspect_residuals()


def test_nested_symlink_refuses(case):
    mod, tmp, _ = case
    (tmp / "first/empty/link").symlink_to(tmp)
    with pytest.raises(mod.inventory.InventoryError):
        mod.inspect_residuals()


def test_failed_process_snapshot_outputs_no_partial_evidence(case, monkeypatch, capsys):
    mod, _, _ = case
    calls = 0
    def process():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise mod.preflight.PreflightError()
    monkeypatch.setattr(mod.preflight, "_observe_fixed_process_snapshot_checked", process)
    with pytest.raises(mod.preflight.PreflightError):
        mod.main([])
    assert capsys.readouterr().out == ""


def test_empty_argv_only(case, monkeypatch):
    mod, _, _ = case
    monkeypatch.setattr(mod, "inspect_residuals", lambda: pytest.fail("touched incident"))
    with pytest.raises(mod.preflight.PreflightError):
        mod.main(["arbitrary"])


def test_documented_workflow_is_manual_trusted_main_only():
    text = (ROOT / ".github/workflows/live-local-e2e-private-tmp-forensic.yml").read_text()
    assert "workflow_dispatch:" in text
    assert "pull_request:" not in text and "push:" not in text
    assert "contents: read" in text
    assert "group: live-local-e2e" in text and "cancel-in-progress: false" in text
    assert "if: github.ref == 'refs/heads/main'" in text
    assert "persist-credentials: false" in text
    assert "python3 -I ops/live-e2e/inspect_private_tmp_residuals.py" in text
    assert "retention-days: 7" in text
    assert "rm " not in text and "sudo " not in text


@pytest.mark.parametrize("idx,name", [(1, "first"), (2, "recover"), (3, "third")])
def test_all_fixed_catalog_identities_are_required(case, idx, name):
    mod, tmp, _ = case
    (tmp / name).rename(tmp / (name + "-saved"))
    (tmp / name).mkdir(mode=0o700)
    with pytest.raises(mod.preflight.PreflightError):
        mod.inspect_residuals()
    assert mod._REFUSAL_PHASE == f"catalog-identity-{idx}"


def test_marker_recheck_refusal_never_serializes_success(case, monkeypatch, capsys):
    mod, _, _ = case
    def refuse(*a, **kw):
        raise mod.preflight.PreflightError()
    monkeypatch.setattr(mod.preflight, "_revalidate_marker", refuse)
    with pytest.raises(mod.preflight.PreflightError):
        mod.main([])
    assert capsys.readouterr().out == ""


def test_second_pass_drift_refuses(case, monkeypatch):
    mod, tmp, _ = case
    original = mod.inventory.collect_residual_inventory
    count = 0
    def changed(*a, **kw):
        nonlocal count
        count += 1
        if count == 4:
            (tmp / "first/changed").mkdir(mode=0o700)
        return original(*a, **kw)
    monkeypatch.setattr(mod.inventory, "collect_residual_inventory", changed)
    with pytest.raises(mod.preflight.PreflightError):
        mod.inspect_residuals()


def test_output_ceiling_refuses(case, monkeypatch):
    mod, _, _ = case
    monkeypatch.setattr(mod, "MAX_EVIDENCE_BYTES", 64)
    with pytest.raises(mod.preflight.PreflightError):
        mod.inspect_residuals()


def test_refusal_context_not_valid_under_other_workflow(monkeypatch):
    mod = load()
    monkeypatch.setattr(mod.recovery, "_validate_context", lambda _: None)
    monkeypatch.setattr(mod, "_UID", os.geteuid())
    for key, value in {
        "GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "a" * 40,
        "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_WORKFLOW_REF": (
            "zhangyuz/ssh-over-mcp/.github/workflows/live-local-e2e-forensic.yml@refs/heads/main"
        ),
    }.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(mod.preflight.PreflightError):
        mod._validate_context()


def test_policy_never_reuses_native_getconf_parent(case, monkeypatch):
    mod, _, _ = case
    def forbidden():
        pytest.fail("native getconf parent unexpectedly used")
    monkeypatch.setattr(mod.preflight, "_pin_observed_native_temp_chain", forbidden)
    assert json.loads(mod.inspect_residuals())["recovery_eligible"] is False

@pytest.mark.parametrize("index", [1, 2, 3])
def test_inventory_first_pass_refusal_label_is_exact_index_only(case, monkeypatch, index, capsys):
    mod, _, _ = case
    collect = mod.inventory.collect_residual_inventory
    count = 0
    def refuse(*args, **kw):
        nonlocal count
        count += 1
        if count == index:
            raise mod.inventory.InventoryError()
        return collect(*args, **kw)
    monkeypatch.setattr(mod.inventory, "collect_residual_inventory", refuse)
    with pytest.raises(mod.inventory.InventoryError):
        mod.main([])
    assert mod._REFUSAL_PHASE == f"inventory-a-{index}-probe-unresolved"
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("index", [1, 2, 3])
def test_inventory_second_pass_refusal_label_is_exact_index_only(case, monkeypatch, index, capsys):
    mod, _, _ = case
    collect = mod.inventory.collect_residual_inventory
    count = 0
    def refuse(*args, **kw):
        nonlocal count
        count += 1
        if count == 3 + index:
            raise mod.inventory.InventoryError()
        return collect(*args, **kw)
    monkeypatch.setattr(mod.inventory, "collect_residual_inventory", refuse)
    with pytest.raises(mod.inventory.InventoryError):
        mod.main([])
    assert mod._REFUSAL_PHASE == f"inventory-b-{index}"
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    ("fault", "reason"),
    [
        ("mode", "unsafe-mode"),
        ("symlink", "symlink"),
        ("hardlink", "hardlink"),
        ("fifo", "fifo"),
    ],
)
def test_catalog_two_first_pass_reports_fixed_nested_metadata_reason_only(
    case, fault, reason, capsys
):
    mod, tmp, _ = case
    nested = tmp / "recover/empty"
    if fault == "mode":
        nested.chmod(0o777)
    elif fault == "symlink":
        (nested / "canary").symlink_to(tmp / "first")
    elif fault == "hardlink":
        first = nested / "canary"
        first.write_bytes(b"private-canary")
        first.chmod(0o600)
        os.link(first, nested / "canary2")
    elif fault == "fifo":
        os.mkfifo(nested / "canary")
    with pytest.raises(mod.inventory.InventoryError):
        mod.main([])
    assert mod._REFUSAL_PHASE == f"inventory-a-2-probe-{reason}"
    assert capsys.readouterr().out == ""
    assert (tmp / "recover").is_dir()


def test_failed_inventory_diagnostic_never_turns_refusal_into_success(case, monkeypatch):
    mod, _, _ = case
    original = mod.inventory.collect_residual_inventory
    calls = 0
    def refuse(*a, **kw):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise mod.inventory.InventoryError()
        return original(*a, **kw)
    monkeypatch.setattr(mod.inventory, "collect_residual_inventory", refuse)
    with pytest.raises(mod.inventory.InventoryError):
        mod.inspect_residuals()
    assert mod._REFUSAL_PHASE == "inventory-a-2-probe-unresolved"
