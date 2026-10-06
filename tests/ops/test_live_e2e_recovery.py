from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "ops/live-e2e/recover_provider.py"
WORKFLOW = ROOT / ".github/workflows/live-local-e2e-recovery.yml"
TARGET = "a" * 40


def _load_module() -> ModuleType:
    name = "ssh_over_mcp_recover_provider"
    spec = importlib.util.spec_from_file_location(name, MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


def _state(path: Path, *, target: str = TARGET, owner_pid: int = 4242) -> None:
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps({"target": target, "owner_pid": owner_pid}) + "\n")
    path.chmod(0o600)


def test_inspect_requires_exact_owned_fixed_state_and_never_mutates(tmp_path: Path) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    _state(state)

    inspection = module.inspect_recovery(TARGET, state_path=state, uid=os.geteuid())

    assert inspection.state == module.ProviderState(target=TARGET, owner_pid=4242)
    assert state.is_file()


@pytest.mark.parametrize("target", ["", "a" * 39, "g" * 40, "A" * 40])
def test_inspect_rejects_non_exact_or_noncanonical_target(tmp_path: Path, target: str) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    _state(state)
    with pytest.raises(module.RecoveryError):
        module.inspect_recovery(target, state_path=state, uid=os.geteuid())


def test_inspect_rejects_target_schema_mode_and_symlink(tmp_path: Path) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    _state(state, target="b" * 40)
    with pytest.raises(module.RecoveryError, match="target"):
        module.inspect_recovery(TARGET, state_path=state, uid=os.geteuid())

    _state(state)
    state.chmod(0o644)
    with pytest.raises(module.RecoveryError, match="mode"):
        module.inspect_recovery(TARGET, state_path=state, uid=os.geteuid())

    state.chmod(0o600)
    state.write_text(json.dumps({"target": TARGET, "owner_pid": 4242, "extra": True}))
    with pytest.raises(module.RecoveryError, match="schema"):
        module.inspect_recovery(TARGET, state_path=state, uid=os.geteuid())

    state.unlink()
    real = tmp_path / "real-state.json"
    _state(real)
    state.symlink_to(real)
    with pytest.raises(module.RecoveryError, match="ownership/type"):
        module.inspect_recovery(TARGET, state_path=state, uid=os.geteuid())


def test_recover_requires_exact_dead_owner_and_no_qemu(tmp_path: Path, monkeypatch) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    _state(state, owner_pid=4242)

    monkeypatch.setattr(module, "_process_exists", lambda pid: True)
    monkeypatch.setattr(module, "_qemu_pids", lambda uid: ())
    with pytest.raises(module.RecoveryError, match="still alive"):
        module.recover(TARGET, 4242, state_path=state, uid=os.geteuid())
    assert state.exists()

    monkeypatch.setattr(module, "_process_exists", lambda pid: False)
    monkeypatch.setattr(module, "_qemu_pids", lambda uid: (99,))
    with pytest.raises(module.RecoveryError, match="QEMU"):
        module.recover(TARGET, 4242, state_path=state, uid=os.geteuid())
    assert state.exists()

    monkeypatch.setattr(module, "_qemu_pids", lambda uid: ())
    with pytest.raises(module.RecoveryError, match="owner PID"):
        module.recover(TARGET, 4243, state_path=state, uid=os.geteuid())
    assert state.exists()


def test_recover_unlinks_only_fixed_verified_marker(tmp_path: Path, monkeypatch) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    unrelated = tmp_path / "ssh-over-mcp-e2e-unknown"
    unrelated.mkdir()
    (unrelated / "payload").write_bytes(b"must remain")
    _state(state, owner_pid=4242)

    monkeypatch.setattr(module, "_process_exists", lambda pid: False)
    monkeypatch.setattr(module, "_qemu_pids", lambda uid: ())

    recovered = module.recover(TARGET, 4242, state_path=state, uid=os.geteuid())

    assert recovered.state.owner_pid == 4242
    assert not state.exists()
    assert (unrelated / "payload").read_bytes() == b"must remain"


def test_expected_pid_zero_is_inspect_only_sentinel() -> None:
    module = _load_module()
    assert module._parse_expected_pid("0") == 0
    for value in ("", "-1", "+1", "01", "1.0"):
        with pytest.raises(module.RecoveryError):
            module._parse_expected_pid(value)


def test_workflow_is_manual_main_only_and_serialized_with_live_e2e() -> None:
    workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"workflow_dispatch"}
    inputs = workflow["on"]["workflow_dispatch"]["inputs"]
    assert set(inputs) == {"expected_target", "expected_owner_pid"}
    assert inputs["expected_target"]["required"] == "true"
    assert inputs["expected_owner_pid"]["required"] == "true"
    assert inputs["expected_owner_pid"]["default"] == "0"
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == {
        "group": "live-local-e2e",
        "cancel-in-progress": "false",
    }
    job = workflow["jobs"]["recover"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert job["runs-on"] == [
        "self-hosted",
        "macOS",
        "X64",
        "ssh-over-mcp-e2e-orchestrator",
    ]
    rendered = WORKFLOW.read_text()
    assert "persist-credentials: false" in rendered
    assert "sudo " not in rendered
    assert "rm " not in rendered
    assert "recover_provider.py" in rendered
