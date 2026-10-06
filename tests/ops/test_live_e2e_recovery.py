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


def test_inspect_reports_temp_state_without_mutation(tmp_path: Path) -> None:
    module = _load_module()
    state = tmp_path / "cache" / "active-run.json"
    temp_root = tmp_path / "temp"
    temp_root.mkdir()
    orphan = temp_root / "ssh-over-mcp-e2e-one"
    orphan.mkdir()
    _state(state)

    inspection = module.inspect_recovery(
        TARGET,
        state_path=state,
        temp_root=temp_root,
        uid=os.geteuid(),
    )

    assert inspection.state == module.ProviderState(target=TARGET, owner_pid=4242)
    assert inspection.temp_dirs == (orphan,)
    assert state.is_file() and orphan.is_dir()


@pytest.mark.parametrize("target", ["", "a" * 39, "g" * 40, "A" * 40])
def test_inspect_rejects_noncanonical_target(tmp_path: Path, target: str) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    _state(state)
    with pytest.raises(module.RecoveryError):
        module.inspect_recovery(target, state_path=state, temp_root=tmp_path, uid=os.geteuid())


def test_inspect_rejects_bad_state_and_non_directory_temp(tmp_path: Path) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    _state(state, target="b" * 40)
    with pytest.raises(module.RecoveryError, match="target"):
        module.inspect_recovery(TARGET, state_path=state, temp_root=tmp_path, uid=os.geteuid())

    _state(state)
    state.chmod(0o644)
    with pytest.raises(module.RecoveryError, match="mode"):
        module.inspect_recovery(TARGET, state_path=state, temp_root=tmp_path, uid=os.geteuid())

    state.chmod(0o600)
    state.write_text(json.dumps({"target": TARGET, "owner_pid": 4242, "extra": True}))
    with pytest.raises(module.RecoveryError, match="schema"):
        module.inspect_recovery(TARGET, state_path=state, temp_root=tmp_path, uid=os.geteuid())

    _state(state)
    bad = tmp_path / "ssh-over-mcp-e2e-file"
    bad.write_bytes(b"not a directory")
    bad.chmod(0o600)
    with pytest.raises(
        module.RecoveryError,
        match=(
            rf"ownership/type name={bad.name!r} kind=regular "
            rf"uid={os.geteuid()} mode=0600"
        ),
    ):
        module.inspect_recovery(TARGET, state_path=state, temp_root=tmp_path, uid=os.geteuid())


def test_temp_diagnostic_escapes_control_characters(tmp_path: Path) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    bad = tmp_path / "ssh-over-mcp-e2e-bad\n::error::fake"
    bad.write_bytes(b"x")
    _state(state)

    with pytest.raises(module.RecoveryError) as error:
        module.inspect_recovery(TARGET, state_path=state, temp_root=tmp_path, uid=os.geteuid())

    message = str(error.value)
    assert "\\n" in message
    assert "\n" not in message
    assert "::error::fake" in message


def test_inspect_ignores_foreign_owned_matching_temp_paths_without_mutation(
    tmp_path: Path, monkeypatch
) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    foreign_file = tmp_path / "ssh-over-mcp-e2e-smoke5-serial.log"
    foreign_dir = tmp_path / "ssh-over-mcp-e2e-foreign"
    foreign_file.write_bytes(b"foreign")
    foreign_dir.mkdir()
    _state(state)

    original_lstat = Path.lstat
    foreign_paths = {foreign_file, foreign_dir}

    def fake_lstat(path: Path):
        info = original_lstat(path)
        if path in foreign_paths:
            return SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid() + 1)
        return info

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    inspection = module.inspect_recovery(
        TARGET,
        state_path=state,
        temp_root=tmp_path,
        uid=os.geteuid(),
    )

    assert inspection.temp_dirs == ()
    assert foreign_file.read_bytes() == b"foreign"
    assert foreign_dir.is_dir()


def test_temp_scan_bounds_foreign_owned_prefix_matches(
    tmp_path: Path, monkeypatch
) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    _state(state)
    matches = [
        tmp_path / f"ssh-over-mcp-e2e-foreign-{index:03d}"
        for index in range(module.MAX_TEMP_MATCHES + 1)
    ]
    for path in matches:
        path.mkdir()

    original_lstat = Path.lstat
    match_set = set(matches)

    def fake_lstat(path: Path):
        info = original_lstat(path)
        if path in match_set:
            return SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid() + 1)
        return info

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    with pytest.raises(module.RecoveryError, match="too many matching E2E temp paths"):
        module.inspect_recovery(
            TARGET,
            state_path=state,
            temp_root=tmp_path,
            uid=os.geteuid(),
        )


def test_temp_diagnostics_are_bounded_nonrecursive_and_json_safe(tmp_path: Path) -> None:
    module = _load_module()
    temp_dir = tmp_path / "ssh-over-mcp-e2e-one"
    temp_dir.mkdir(mode=0o700)
    regular = temp_dir / "target\\nbundle"
    regular.write_bytes(b"abc")
    child_dir = temp_dir / "target.git"
    child_dir.mkdir()
    link = temp_dir / "overlay-link"
    link.symlink_to(regular)

    lines = module._temp_diagnostics((temp_dir,), os.geteuid())

    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["name"] == temp_dir.name
    assert record["uid"] == os.geteuid()
    entries = {entry["name"]: entry for entry in record["entries"]}
    assert entries["target\\nbundle"]["kind"] == "regular"
    assert entries["target\\nbundle"]["size"] == 3
    assert entries["target.git"]["kind"] == "directory"
    assert entries["overlay-link"]["kind"] == "symlink"
    assert "\\n" in lines[0]
    assert "\n" not in lines[0]


def test_temp_diagnostics_bind_fixed_expected_commit_without_other_content_reads(
    tmp_path: Path,
) -> None:
    module = _load_module()
    temp_dir = tmp_path / "ssh-over-mcp-e2e-one"
    payload = temp_dir / "payload-content"
    payload.mkdir(parents=True, mode=0o700)
    expected = payload / "expected_commit"
    expected.write_text(TARGET + "\n", encoding="ascii")
    unrelated = payload / "secret"
    unrelated.write_bytes(b"must-not-be-read")

    record = json.loads(module._temp_diagnostics((temp_dir,), os.geteuid())[0])

    assert record["expected_commit"] == TARGET
    assert unrelated.read_bytes() == b"must-not-be-read"


def test_temp_diagnostics_report_absent_binding_and_reject_malformed_binding(
    tmp_path: Path,
) -> None:
    module = _load_module()
    unknown = tmp_path / "ssh-over-mcp-e2e-unknown"
    unknown.mkdir(mode=0o700)
    record = json.loads(module._temp_diagnostics((unknown,), os.geteuid())[0])
    assert record["expected_commit"] is None

    payload = unknown / "payload-content"
    payload.mkdir(mode=0o700)
    expected = payload / "expected_commit"
    expected.write_text("bad\n", encoding="ascii")
    with pytest.raises(module.RecoveryError, match="expected commit"):
        module._temp_diagnostics((unknown,), os.geteuid())


def test_temp_diagnostics_refuse_root_symlink_and_too_many_children(tmp_path: Path) -> None:
    module = _load_module()
    real = tmp_path / "ssh-over-mcp-e2e-real"
    real.mkdir(mode=0o700)
    link = tmp_path / "ssh-over-mcp-e2e-link"
    link.symlink_to(real)
    with pytest.raises(module.RecoveryError):
        module._temp_diagnostics((link,), os.geteuid())

    for index in range(module.MAX_TEMP_CHILDREN + 1):
        (real / f"entry-{index:03d}").write_bytes(b"x")
    with pytest.raises(module.RecoveryError, match="too many direct entries"):
        module._temp_diagnostics((real,), os.geteuid())


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
    temp_root = tmp_path / "temp"
    temp_root.mkdir()
    _state(state, owner_pid=4242)

    monkeypatch.setattr(module, "_process_exists", lambda pid: True)
    monkeypatch.setattr(module, "_qemu_pids", lambda uid: ())
    with pytest.raises(module.RecoveryError, match="still alive"):
        module.recover(TARGET, 4242, state_path=state, temp_root=temp_root, uid=os.geteuid())

    monkeypatch.setattr(module, "_process_exists", lambda pid: False)
    monkeypatch.setattr(module, "_qemu_pids", lambda uid: (99,))
    with pytest.raises(module.RecoveryError, match="QEMU"):
        module.recover(TARGET, 4242, state_path=state, temp_root=temp_root, uid=os.geteuid())

    monkeypatch.setattr(module, "_qemu_pids", lambda uid: ())
    with pytest.raises(module.RecoveryError, match="owner PID"):
        module.recover(TARGET, 4243, state_path=state, temp_root=temp_root, uid=os.geteuid())

    orphan = temp_root / "ssh-over-mcp-e2e-one"
    orphan.mkdir()
    with pytest.raises(module.RecoveryError, match="temp state remains"):
        module.recover(TARGET, 4242, state_path=state, temp_root=temp_root, uid=os.geteuid())
    assert state.exists() and orphan.exists()


def test_recover_unlinks_only_fixed_marker_when_no_temp_state(tmp_path: Path, monkeypatch) -> None:
    module = _load_module()
    state = tmp_path / "active-run.json"
    temp_root = tmp_path / "temp"
    temp_root.mkdir()
    unrelated = tmp_path / "unrelated"
    unrelated.write_bytes(b"must remain")
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
    assert unrelated.read_bytes() == b"must remain"


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
