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
    spec = importlib.util.spec_from_file_location("residual_test", ROOT / "ops/live-e2e/inspect_provider_residuals.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    module = load()
    uid = os.geteuid()
    temp = tmp_path / "temp"
    cache = tmp_path / "cache"
    temp.mkdir(mode=0o700)
    cache.mkdir(mode=0o700)
    catalog = []
    for name in ("first", "recovery", "older"):
        root = temp / name
        root.mkdir(mode=0o700)
        (root / "empty").mkdir(mode=0o700)
        catalog.append((name, root.stat().st_dev, root.stat().st_ino))
    monkeypatch.setattr(module, "_CATALOG", tuple(catalog))
    monkeypatch.setattr(module, "_UID", uid)
    monkeypatch.setattr(module, "_validate_context", lambda: {"authority_sha": "a" * 40, "run_id": "1", "run_attempt": "1"})
    events = []

    @contextmanager
    def chain(path, label):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        obj = SimpleNamespace(_fds=(fd,), revalidate=lambda: events.append(label))
        try:
            yield obj
        finally:
            os.close(fd)
    monkeypatch.setattr(module.preflight, "_pin_observed_native_temp_chain", lambda: chain(temp, "temp"))
    monkeypatch.setattr(module.preflight, "_pin_observed_fixed_cache_chain", lambda: chain(cache, "cache"))
    marker = SimpleNamespace(metadata=SimpleNamespace(device=1, inode=2))
    monkeypatch.setattr(module.preflight, "_read_marker", lambda *a, **k: marker)
    monkeypatch.setattr(module, "_marker_metadata", lambda obj: {"device": 1, "inode": 2})
    monkeypatch.setattr(module.preflight, "_revalidate_marker", lambda *a, **k: events.append("marker"))
    monkeypatch.setattr(module.preflight, "_observe_fixed_process_snapshot_checked", lambda: events.append("ps"))
    return module, temp, events


def test_complete_directory_only_evidence_is_non_authorizing(fixture):
    module, temp, events = fixture
    encoded = module.inspect_residuals()
    record = json.loads(encoded)
    assert record["recovery_eligible"] is False
    assert [root["classification"] for root in record["roots"]] == ["directory-only-residual"] * 3
    assert events.count("ps") == 2
    assert events.index("ps") < events.index("marker") < len(events) - 1
    assert all((temp / name).is_dir() for name, _, _ in module._CATALOG)


def test_regular_file_content_never_enters_evidence(fixture):
    module, temp, _ = fixture
    leaf = temp / "recovery/empty/private"
    leaf.write_bytes(b"secret-canary-do-not-read")
    leaf.chmod(0o600)
    encoded = module.inspect_residuals()
    assert b"secret-canary-do-not-read" not in encoded
    assert json.loads(encoded)["roots"][1]["classification"] == "nonempty-or-unknown"
    assert leaf.read_bytes() == b"secret-canary-do-not-read"


def test_replaced_catalog_root_refuses(fixture):
    module, temp, _ = fixture
    (temp / "first").rename(temp / "preserved")
    (temp / "first").mkdir(mode=0o700)
    with pytest.raises(module.preflight.PreflightError):
        module.inspect_residuals()


@pytest.mark.parametrize("index,name", [(1, "first"), (2, "recovery"), (3, "older")])
def test_catalog_phase_identifies_replaced_root_without_exposing_name(
    fixture, index, name
):
    module, temp, _ = fixture
    (temp / name).rename(temp / f"preserved-{index}")
    (temp / name).mkdir(mode=0o700)
    with pytest.raises(module.preflight.PreflightError):
        module.inspect_residuals()
    assert module._REFUSAL_PHASE == f"catalog-identity-{index}"


@pytest.mark.parametrize("index,name", [(1, "first"), (2, "recovery"), (3, "older")])
def test_catalog_phase_identifies_missing_root_without_exposing_name(
    fixture, index, name
):
    module, temp, _ = fixture
    (temp / name).rename(temp / f"preserved-{index}")
    with pytest.raises(module.preflight.PreflightError):
        module.inspect_residuals()
    assert module._REFUSAL_PHASE == f"catalog-open-{index}"


def test_nested_symlink_refuses(fixture):
    module, temp, _ = fixture
    (temp / "first/empty/link").symlink_to(temp)
    with pytest.raises(module.inventory.InventoryError):
        module.inspect_residuals()


def test_second_process_failure_emits_nothing(fixture, monkeypatch, capsys):
    module, _, _ = fixture
    calls = 0
    def process():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise module.preflight.PreflightError(cleanup_uncertain=True)
    monkeypatch.setattr(module.preflight, "_observe_fixed_process_snapshot_checked", process)
    with pytest.raises(module.preflight.PreflightError) as result:
        module.main([])
    assert result.value.cleanup_uncertain is True
    assert capsys.readouterr().out == ""


def test_inventory_drift_refuses(fixture, monkeypatch):
    module, temp, _ = fixture
    original = module.inventory.collect_residual_inventory
    calls = 0
    def collect(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 4:
            (temp / "first/changed").mkdir(mode=0o700)
        return original(*args, **kwargs)
    monkeypatch.setattr(module.inventory, "collect_residual_inventory", collect)
    with pytest.raises(module.preflight.PreflightError):
        module.inspect_residuals()


def test_output_bound_refuses(fixture, monkeypatch):
    module, _, _ = fixture
    monkeypatch.setattr(module, "MAX_EVIDENCE_BYTES", 100)
    with pytest.raises(module.preflight.PreflightError):
        module.inspect_residuals()


def test_arguments_refuse_before_state_access(monkeypatch):
    module = load()
    monkeypatch.setattr(module, "inspect_residuals", lambda: pytest.fail("state accessed"))
    with pytest.raises(module.preflight.PreflightError):
        module.main(["arbitrary-path"])


def test_marker_drift_refuses(fixture, monkeypatch):
    module, _, _ = fixture
    def refuse(*args, **kwargs):
        raise module.preflight.PreflightError()
    monkeypatch.setattr(module.preflight, "_revalidate_marker", refuse)
    with pytest.raises(module.preflight.PreflightError):
        module.inspect_residuals()


def test_final_namespace_exchange_refuses(fixture, monkeypatch):
    module, temp, _ = fixture
    calls = 0
    def process():
        nonlocal calls
        calls += 1
        if calls == 2:
            (temp / "first").rename(temp / "preserved")
            (temp / "first").mkdir(mode=0o700)
    monkeypatch.setattr(module.preflight, "_observe_fixed_process_snapshot_checked", process)
    with pytest.raises(module.preflight.PreflightError):
        module.inspect_residuals()


def test_total_entry_limit_refuses(fixture, monkeypatch):
    module, _, _ = fixture
    monkeypatch.setattr(module, "MAX_TOTAL_ENTRIES", 2)
    with pytest.raises(module.preflight.PreflightError):
        module.inspect_residuals()


def test_total_deadline_refuses(fixture, monkeypatch):
    module, _, _ = fixture
    ticks = iter([0, 421])
    monkeypatch.setattr(module, "monotonic", lambda: next(ticks))
    with pytest.raises(module.preflight.PreflightError):
        module.inspect_residuals()


@pytest.mark.parametrize("key,value", [("GITHUB_SHA", "main"), ("GITHUB_RUN_ID", "01"), ("GITHUB_RUN_ATTEMPT", "0")])
def test_context_rejects_unbound_provenance(monkeypatch, key, value):
    module = load()
    monkeypatch.setattr(module.recovery, "_validate_context", lambda env: None)
    monkeypatch.setattr(module, "_UID", os.geteuid())
    for name, supplied in {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"}.items():
        monkeypatch.setenv(name, supplied)
    monkeypatch.setenv(key, value)
    with pytest.raises(module.preflight.PreflightError):
        module._validate_context()


def test_manual_workflow_has_trusted_readonly_shared_authority():
    path = ROOT / ".github/workflows/live-local-e2e-forensic.yml"
    assert path.is_file(), "trusted forensic workflow is not implemented"
    text = path.read_text()
    assert "workflow_dispatch:" in text
    assert "pull_request:" not in text and "push:" not in text
    assert "contents: read" in text
    assert "group: live-local-e2e" in text and "cancel-in-progress: false" in text
    assert "if: github.ref == 'refs/heads/main'" in text
    assert "persist-credentials: false" in text
    assert 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' in text
    assert "python3 -I ops/live-e2e/inspect_provider_residuals.py" in text
    assert "expected_owner_pid" not in text and "inputs:" not in text
    assert "retention-days: 7" in text and "if-no-files-found: error" in text
    import re
    assert len(re.findall(r"uses: actions/[a-z-]+@[0-9a-f]{40}", text)) == 2


def test_root_exchange_during_close_emits_no_evidence(fixture, monkeypatch, capsys):
    module, temp, events = fixture
    original_close = os.close
    selected_inode = module._CATALOG[0][2]
    exchanged = False
    def close(fd):
        nonlocal exchanged
        if "marker" in events and not exchanged and os.fstat(fd).st_ino == selected_inode:
            exchanged = True
            (temp / "first").rename(temp / "preserved")
            (temp / "first").mkdir(mode=0o700)
        original_close(fd)
    monkeypatch.setattr(os, "close", close)
    with pytest.raises(module.preflight.PreflightError):
        module.main([])
    assert exchanged
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("key,value", [("GITHUB_WORKFLOW_REF", "zhangyuz/ssh-over-mcp/.github/workflows/other.yml@refs/heads/main"), ("GITHUB_WORKFLOW_SHA", "b" * 40)])
def test_context_rejects_other_workflow_authority(monkeypatch, key, value):
    module = load()
    monkeypatch.setattr(module.recovery, "_validate_context", lambda env: None)
    monkeypatch.setattr(module, "_UID", os.geteuid())
    for name, supplied in {
        "GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_WORKFLOW_REF": "zhangyuz/ssh-over-mcp/.github/workflows/live-local-e2e-forensic.yml@refs/heads/main",
        "GITHUB_WORKFLOW_SHA": "a" * 40,
    }.items():
        monkeypatch.setenv(name, supplied)
    monkeypatch.setenv(key, value)
    with pytest.raises(module.preflight.PreflightError):
        module._validate_context()



def test_refusal_phase_is_fixed_and_does_not_expose_private_details(tmp_path):
    import subprocess

    source = ROOT / "ops/live-e2e/inspect_provider_residuals.py"
    result = subprocess.run(
        [sys.executable, "-I", str(source)],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", "")},
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 70
    assert result.stdout == b""
    assert result.stderr == (
        b"provider residual inspection refused at context; no recovery authorized\n"
    )
