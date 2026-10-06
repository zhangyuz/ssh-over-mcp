from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"target": target, "owner_pid": owner_pid}) + "\n")
    path.chmod(0o600)


def _temp_root(tmp_path: Path) -> Path:
    root = tmp_path / "temp"
    root.mkdir()
    return root


def test_inspect_reports_zero_temp_state_without_mutation(tmp_path: Path) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    temp_root = _temp_root(tmp_path)
    _state(state)

    inspection = module.inspect_recovery(
        TARGET,
        state_path=state,
        temp_root=temp_root,
        uid=os.geteuid(),
    )

    assert inspection.state == module.ProviderState(target=TARGET, owner_pid=4242)
    assert inspection.temp_dirs == ()
    assert state.is_file()


def test_inspect_reports_matching_temp_state_without_deleting_it(tmp_path: Path) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    temp_root = _temp_root(tmp_path)
    orphan = temp_root / "ssh-over-mcp-e2e-one"
    orphan.mkdir()
    _state(state)

    inspection = module.inspect_recovery(
        TARGET,
        state_path=state,
        temp_root=temp_root,
        uid=os.geteuid(),
    )

    assert inspection.temp_dirs == (orphan,)
    assert state.exists() and orphan.exists()


@pytest.mark.parametrize("target", ["", "a" * 39, "g" * 40, "A" * 40])
def test_inspect_rejects_noncanonical_target(tmp_path: Path, target: str) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    temp_root = _temp_root(tmp_path)
    _state(state)
    with pytest.raises(module.RecoveryError):
        module.inspect_recovery(
            target,
            state_path=state,
            temp_root=temp_root,
            uid=os.geteuid(),
        )


def test_inspect_rejects_bad_state_symlink_and_non_directory_temp(tmp_path: Path) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    temp_root = _temp_root(tmp_path)
    _state(state, target="b" * 40)
    with pytest.raises(module.RecoveryError, match="target"):
        module.inspect_recovery(
            TARGET,
            state_path=state,
            temp_root=temp_root,
            uid=os.geteuid(),
        )

    _state(state)
    state.chmod(0o644)
    with pytest.raises(module.RecoveryError, match="mode"):
        module.inspect_recovery(
            TARGET,
            state_path=state,
            temp_root=temp_root,
            uid=os.geteuid(),
        )

    state.chmod(0o600)
    state.write_text(json.dumps({"target": TARGET, "owner_pid": 4242, "extra": True}))
    with pytest.raises(module.RecoveryError, match="schema"):
        module.inspect_recovery(
            TARGET,
            state_path=state,
            temp_root=temp_root,
            uid=os.geteuid(),
        )

    state.unlink()
    real = tmp_path / "real-state.json"
    _state(real)
    state.symlink_to(real)
    with pytest.raises(module.RecoveryError):
        module.inspect_recovery(
            TARGET,
            state_path=state,
            temp_root=temp_root,
            uid=os.geteuid(),
        )

    state.unlink()
    _state(state)
    bad = temp_root / "ssh-over-mcp-e2e-file"
    bad.write_bytes(b"not a directory")
    with pytest.raises(module.RecoveryError, match="ownership/type"):
        module.inspect_recovery(
            TARGET,
            state_path=state,
            temp_root=temp_root,
            uid=os.geteuid(),
        )


def test_process_inventory_fails_closed_on_empty_or_malformed_output(monkeypatch) -> None:
    module = _load_module()

    for output in ("", "not-a-process-line\n", "badpid python3\n", "0 python3\n"):
        monkeypatch.setattr(
            module.subprocess,
            "run",
            lambda *args, _output=output, **kwargs: SimpleNamespace(stdout=_output),
        )
        with pytest.raises(module.RecoveryError):
            module._qemu_pids(os.geteuid())

    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout="10 launchd\n11 python3\n"),
    )
    assert module._qemu_pids(os.geteuid()) == ()


def test_recover_refuses_live_owner_qemu_pid_mismatch_or_temp_state(
    tmp_path: Path, monkeypatch
) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    temp_root = _temp_root(tmp_path)
    _state(state, owner_pid=4242)

    monkeypatch.setattr(module, "_process_exists", lambda pid: True)
    monkeypatch.setattr(module, "_qemu_pids", lambda uid: ())
    with pytest.raises(module.RecoveryError, match="still alive"):
        module.recover(
            TARGET,
            4242,
            state_path=state,
            temp_root=temp_root,
            uid=os.geteuid(),
        )

    monkeypatch.setattr(module, "_process_exists", lambda pid: False)
    monkeypatch.setattr(module, "_qemu_pids", lambda uid: (99,))
    with pytest.raises(module.RecoveryError, match="QEMU"):
        module.recover(
            TARGET,
            4242,
            state_path=state,
            temp_root=temp_root,
            uid=os.geteuid(),
        )

    monkeypatch.setattr(module, "_qemu_pids", lambda uid: ())
    with pytest.raises(module.RecoveryError, match="owner PID"):
        module.recover(
            TARGET,
            4243,
            state_path=state,
            temp_root=temp_root,
            uid=os.geteuid(),
        )

    orphan = temp_root / "ssh-over-mcp-e2e-one"
    orphan.mkdir()
    with pytest.raises(module.RecoveryError, match="temp state remains"):
        module.recover(
            TARGET,
            4242,
            state_path=state,
            temp_root=temp_root,
            uid=os.geteuid(),
        )
    assert state.exists() and orphan.exists()


def test_recover_unlinks_only_fixed_marker_when_no_temp_state(
    tmp_path: Path, monkeypatch
) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    temp_root = _temp_root(tmp_path)
    unrelated = temp_root / "unrelated"
    unrelated.mkdir()
    (unrelated / "payload").write_bytes(b"must remain")
    _state(state, owner_pid=4242)

    monkeypatch.setattr(module, "_process_exists", lambda pid: False)
    monkeypatch.setattr(module, "_qemu_pids", lambda uid: ())

    recovered = module.recover(
        TARGET,
        4242,
        state_path=state,
        temp_root=temp_root,
        uid=os.geteuid(),
    )

    assert recovered.state.owner_pid == 4242
    assert not state.exists()
    assert (unrelated / "payload").read_bytes() == b"must remain"


def test_recover_rejects_marker_identity_change(tmp_path: Path, monkeypatch) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    temp_root = _temp_root(tmp_path)
    _state(state, owner_pid=4242)
    first = module.inspect_recovery(
        TARGET,
        state_path=state,
        temp_root=temp_root,
        uid=os.geteuid(),
    )
    changed = module.RecoveryInspection(
        state=first.state,
        device=first.device,
        inode=first.inode + 1,
        temp_dirs=first.temp_dirs,
    )
    inspections = iter((first, changed))
    monkeypatch.setattr(module, "inspect_recovery", lambda *args, **kwargs: next(inspections))
    monkeypatch.setattr(module, "_process_exists", lambda pid: False)
    monkeypatch.setattr(module, "_qemu_pids", lambda uid: ())

    with pytest.raises(module.RecoveryError, match="changed"):
        module.recover(
            TARGET,
            4242,
            state_path=state,
            temp_root=temp_root,
            uid=os.geteuid(),
        )
    assert state.exists()


def test_expected_pid_zero_is_inspect_only_sentinel() -> None:
    module = _load_module()
    assert module._parse_expected_pid("0") == 0
    for value in ("", "-1", "+1", "01", "1.0"):
        with pytest.raises(module.RecoveryError):
            module._parse_expected_pid(value)


def test_context_is_manual_trusted_main_non_admin_orchestrator(monkeypatch) -> None:
    module = _load_module()
    uid = 502
    monkeypatch.setattr(module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(module.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(module.os, "geteuid", lambda: uid)
    monkeypatch.setattr(module.os, "getgroups", lambda: [20])
    monkeypatch.setattr(
        module.pwd,
        "getpwuid",
        lambda value: SimpleNamespace(
            pw_name=module.ORCHESTRATOR_USER,
            pw_dir=str(module.ORCHESTRATOR_HOME),
        ),
    )
    monkeypatch.setattr(module.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=80))
    valid = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": module.EXPECTED_REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
    }
    module._validate_context(valid)

    for case in (
        {**valid, "GITHUB_ACTIONS": "false"},
        {**valid, "GITHUB_EVENT_NAME": "push"},
        {**valid, "GITHUB_REPOSITORY": "someone/else"},
        {**valid, "GITHUB_REF": "refs/heads/feature"},
    ):
        with pytest.raises(module.RecoveryError):
            module._validate_context(case)


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
