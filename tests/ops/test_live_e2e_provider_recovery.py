from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "ops/live-e2e/provider_recovery.py"
WORKFLOW = ROOT / ".github/workflows/recover-live-local-e2e-provider.yml"
TARGET = "a" * 40


def _load_module() -> ModuleType:
    assert MODULE.is_file(), "manual provider recovery tool is missing"
    name = "ssh_over_mcp_provider_recovery"
    spec = importlib.util.spec_from_file_location(name, MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


def _marker(tmp_path: Path, *, target: str = TARGET, owner_pid: int = 4242) -> Path:
    path = tmp_path / "active-run.json"
    path.write_text(json.dumps({"target": target, "owner_pid": owner_pid}) + "\n")
    path.chmod(0o600)
    return path


def test_loads_exact_owned_regular_0600_marker(tmp_path: Path) -> None:
    module = _load_module()
    marker = _marker(tmp_path)

    state = module.load_stale_state(marker, expected_uid=os.getuid())

    assert state.target == TARGET
    assert state.owner_pid == 4242
    assert state.device == marker.stat().st_dev
    assert state.inode == marker.stat().st_ino


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"target": TARGET},
        {"target": TARGET, "owner_pid": 0},
        {"target": "bad", "owner_pid": 4242},
        {"target": TARGET, "owner_pid": "4242"},
        {"target": TARGET, "owner_pid": 4242, "extra": True},
    ],
)
def test_rejects_malformed_marker_payload(tmp_path: Path, payload: dict[str, object]) -> None:
    module = _load_module()
    marker = tmp_path / "active-run.json"
    marker.write_text(json.dumps(payload) + "\n")
    marker.chmod(0o600)

    with pytest.raises(module.RecoveryError, match="^live E2E recovery validation failed$"):
        module.load_stale_state(marker, expected_uid=os.getuid())


def test_rejects_symlink_wrong_mode_and_oversize_marker(tmp_path: Path) -> None:
    module = _load_module()
    real = _marker(tmp_path)
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(module.RecoveryError):
        module.load_stale_state(link, expected_uid=os.getuid())

    real.chmod(0o644)
    with pytest.raises(module.RecoveryError):
        module.load_stale_state(real, expected_uid=os.getuid())

    real.write_bytes(b"x" * (module.MAX_MARKER_BYTES + 1))
    real.chmod(0o600)
    with pytest.raises(module.RecoveryError):
        module.load_stale_state(real, expected_uid=os.getuid())


def test_inventory_refuses_active_qemu_or_marker_owner_pid() -> None:
    module = _load_module()
    clean = "10 launchd\n11 python3\n"
    assert module.validate_process_inventory(clean, owner_pid=4242) == 0

    with pytest.raises(module.RecoveryError):
        module.validate_process_inventory("10 qemu-system-x86_64\n", owner_pid=4242)
    with pytest.raises(module.RecoveryError):
        module.validate_process_inventory("4242 python3\n", owner_pid=4242)
    with pytest.raises(module.RecoveryError):
        module.validate_process_inventory("", owner_pid=4242)


def test_clear_requires_exact_confirmation_and_stable_marker(tmp_path: Path) -> None:
    module = _load_module()
    marker = _marker(tmp_path)
    state = module.load_stale_state(marker, expected_uid=os.getuid())

    with pytest.raises(module.RecoveryError):
        module.clear_stale_state(
            marker,
            state,
            expected_target="b" * 40,
            expected_owner_pid=4242,
        )
    assert marker.exists()

    with pytest.raises(module.RecoveryError):
        module.clear_stale_state(
            marker,
            state,
            expected_target=TARGET,
            expected_owner_pid=9999,
        )
    assert marker.exists()

    replacement = tmp_path / "replacement"
    replacement.write_text(marker.read_text())
    replacement.chmod(0o600)
    os.replace(replacement, marker)
    with pytest.raises(module.RecoveryError):
        module.clear_stale_state(
            marker,
            state,
            expected_target=TARGET,
            expected_owner_pid=4242,
        )
    assert marker.exists()


def test_clear_unlinks_only_confirmed_marker(tmp_path: Path) -> None:
    module = _load_module()
    marker = _marker(tmp_path)
    state = module.load_stale_state(marker, expected_uid=os.getuid())

    module.clear_stale_state(
        marker,
        state,
        expected_target=TARGET,
        expected_owner_pid=4242,
    )

    assert not marker.exists()


def test_workflow_is_manual_only_on_dedicated_runner() -> None:
    import yaml

    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"workflow_dispatch"}
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
    rendered = WORKFLOW.read_text(encoding="utf-8")
    assert "pull_request" not in rendered
    assert "\n  push:" not in rendered
    assert "workflow_run" not in rendered
    assert "provider_recovery.py" in rendered
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in rendered
    assert "persist-credentials: false" in rendered
    assert "sudo " not in rendered
