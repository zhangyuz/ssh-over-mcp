from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "scripts" / "run-live-local-e2e-probe.py"


def _load_probe() -> ModuleType:
    assert PROBE.is_file()
    name = "ssh_over_mcp_live_e2e_probe_contract"
    spec = importlib.util.spec_from_file_location(name, PROBE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


def test_probe_git_commands_use_only_command_scoped_safe_directory() -> None:
    module = _load_probe()

    assert module._git_command("rev-parse", "HEAD") == [
        "/usr/bin/git",
        "-c",
        "safe.directory=/opt/ssh-over-mcp-e2e/workspace",
        "-C",
        "/opt/ssh-over-mcp-e2e/workspace",
        "rev-parse",
        "HEAD",
    ]
    assert module._git_command("status", "--porcelain=v1") == [
        "/usr/bin/git",
        "-c",
        "safe.directory=/opt/ssh-over-mcp-e2e/workspace",
        "-C",
        "/opt/ssh-over-mcp-e2e/workspace",
        "status",
        "--porcelain=v1",
    ]


def test_probe_does_not_persist_git_safe_directory_configuration() -> None:
    source = PROBE.read_text(encoding="utf-8")

    assert "git config --global" not in source
    assert "git config --system" not in source
    assert "safe.directory=*" not in source
