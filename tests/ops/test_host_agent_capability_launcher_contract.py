from __future__ import annotations

import ast
import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_LAUNCHER = _REPO_ROOT / "ops" / "live-e2e" / "ssh-over-mcp-host-agent-launcher.py"


def _load_launcher() -> ModuleType:
    assert _LAUNCHER.is_file(), "reviewed host-agent capability launcher must exist"
    name = "ssh_over_mcp_live_e2e_host_agent_launcher"
    spec = importlib.util.spec_from_file_location(name, _LAUNCHER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


def _application_import_scopes() -> list[str]:
    tree = ast.parse(_LAUNCHER.read_text(encoding="utf-8"))
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    scopes: list[str] = []
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            names = [node.module]
        if not any(name == "ssh_over_mcp" or name.startswith("ssh_over_mcp.") for name in names):
            continue

        current: ast.AST | None = node
        owner = "<module>"
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                owner = current.name
                break
            current = parents.get(current)
        scopes.append(owner)
    return scopes


def _valid_env() -> dict[str, str]:
    return {
        "SSH_ORIGINAL_COMMAND": "mcp-v1",
        "SUDO_USER": "ssh-over-mcp-e2e-host",
        "SUDO_UID": "2202",
        "SUDO_GID": "3202",
        "PATH": "/evil/path",
        "HOME": "/tmp/evil-home",
        "LANG": "fr_CA.UTF-8",
        "LC_ALL": "fr_CA.UTF-8",
        "PYTHONPATH": "/tmp/inject",
        "PYTHONHOME": "/tmp/python",
        "LD_PRELOAD": "/tmp/libinject.so",
        "LD_LIBRARY_PATH": "/tmp/lib",
        "PYTHONINSPECT": "1",
        "PYTHONSTARTUP": "/tmp/startup.py",
        "RANDOM_CALLER_VALUE": "secret",
    }


def test_launcher_exists_and_application_import_is_delayed() -> None:
    assert _LAUNCHER.is_file()
    assert _application_import_scopes() == ["_run_application"]


def test_launcher_constants_pin_identity_paths_and_capability_mask() -> None:
    module = _load_launcher()

    assert module.HOST_AGENT_UID == 2202
    assert module.HOST_AGENT_GID == 3202
    assert module.MANAGER_CLIENT_GID == 3299
    assert module.EXPECTED_SUDO_USER == "ssh-over-mcp-e2e-host"
    assert module.APPLICATION_SOURCE == Path(
        "/opt/ssh-over-mcp-e2e/workspace/src"
    )
    assert module.APPLICATION_SITE_PACKAGES == Path(
        "/opt/ssh-over-mcp-e2e/venv/lib/python3.13/site-packages"
    )
    assert module.CAP_SETGID == 6
    assert module.CAP_SETUID == 7
    assert module.EXPECTED_CAPABILITY_MASK == (1 << 6) | (1 << 7)


@pytest.mark.parametrize(
    ("argv", "updates"),
    [
        (["unexpected"], {}),
        ([], {"SSH_ORIGINAL_COMMAND": ""}),
        ([], {"SSH_ORIGINAL_COMMAND": "uname"}),
        ([], {"SSH_TTY": "/dev/pts/0"}),
        ([], {"SUDO_USER": "someone-else"}),
        ([], {"SUDO_UID": "9999"}),
        ([], {"SUDO_GID": "9999"}),
    ],
)
def test_launcher_rejects_non_exact_invocation_context(
    argv: list[str],
    updates: dict[str, str],
) -> None:
    module = _load_launcher()
    env = _valid_env()
    env.update(updates)

    with pytest.raises(module.LauncherError):
        module._validated_environment(argv, env)


def test_launcher_rejects_missing_required_invocation_context() -> None:
    module = _load_launcher()

    for key in ("SSH_ORIGINAL_COMMAND", "SUDO_USER", "SUDO_UID", "SUDO_GID"):
        env = _valid_env()
        del env[key]
        with pytest.raises(module.LauncherError):
            module._validated_environment([], env)


def test_launcher_environment_is_fixed_and_drops_caller_controlled_values() -> None:
    module = _load_launcher()

    sanitized = module._validated_environment([], _valid_env())

    assert sanitized == {
        "HOME": "/home/ssh-over-mcp-e2e-host",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LOGNAME": "ssh-over-mcp-e2e-host",
        "PATH": "/usr/bin:/bin",
        "SSH_ORIGINAL_COMMAND": "mcp-v1",
        "USER": "ssh-over-mcp-e2e-host",
    }
    assert not any(name.startswith("LD_") for name in sanitized)
    assert not any(name.startswith("PYTHON") for name in sanitized)


class _FakeOps:
    def __init__(self, module: ModuleType, *, bad_snapshot: bool = False) -> None:
        self.module = module
        self.bad_snapshot = bad_snapshot
        self.calls: list[object] = []

    def effective_uid(self) -> int:
        self.calls.append("effective_uid")
        return 0

    def set_keepcaps(self, enabled: bool) -> None:
        self.calls.append(("keepcaps", enabled))

    def set_groups(self, groups: tuple[int, ...]) -> None:
        self.calls.append(("groups", groups))

    def set_res_gid(self, gid: int) -> None:
        self.calls.append(("gid", gid))

    def set_res_uid(self, uid: int) -> None:
        self.calls.append(("uid", uid))

    def set_capabilities(self, mask: int) -> None:
        self.calls.append(("capset", mask))

    def clear_ambient_capabilities(self) -> None:
        self.calls.append("clear_ambient")

    def snapshot(self):
        self.calls.append("snapshot")
        uid = 9999 if self.bad_snapshot else self.module.HOST_AGENT_UID
        return self.module._PrivilegeSnapshot(
            real_uid=uid,
            effective_uid=uid,
            saved_uid=uid,
            real_gid=self.module.HOST_AGENT_GID,
            effective_gid=self.module.HOST_AGENT_GID,
            saved_gid=self.module.HOST_AGENT_GID,
            supplementary_gids=(self.module.MANAGER_CLIENT_GID,),
            cap_inheritable=0,
            cap_permitted=self.module.EXPECTED_CAPABILITY_MASK,
            cap_effective=self.module.EXPECTED_CAPABILITY_MASK,
            cap_ambient=0,
        )


def test_drop_and_verify_has_exact_security_order() -> None:
    module = _load_launcher()
    ops = _FakeOps(module)

    module._drop_and_verify(ops)

    assert ops.calls == [
        "effective_uid",
        ("keepcaps", True),
        ("groups", (3299,)),
        ("gid", 3202),
        ("uid", 2202),
        ("capset", (1 << 6) | (1 << 7)),
        "clear_ambient",
        ("keepcaps", False),
        "snapshot",
    ]


def test_drop_and_verify_rejects_any_readback_mismatch() -> None:
    module = _load_launcher()
    ops = _FakeOps(module, bad_snapshot=True)

    with pytest.raises(module.LauncherError):
        module._drop_and_verify(ops)

    assert "snapshot" in ops.calls


def test_main_sanitizes_environment_drops_privilege_then_enters_application(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_launcher()
    events: list[object] = []
    sanitized = {"PATH": "/usr/bin:/bin", "SSH_ORIGINAL_COMMAND": "mcp-v1"}

    monkeypatch.setattr(
        module,
        "_validated_environment",
        lambda argv, env: events.append(("validate", tuple(argv))) or sanitized,
    )
    monkeypatch.setattr(
        module,
        "_drop_and_verify",
        lambda ops: events.append("drop_and_verify"),
    )
    monkeypatch.setattr(
        module,
        "_run_application",
        lambda: events.append("application") or 17,
    )
    monkeypatch.setattr(module, "_SYSTEM_OPS", object())

    original = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(_valid_env())
        result = module.main([])
        assert dict(os.environ) == sanitized
    finally:
        os.environ.clear()
        os.environ.update(original)

    assert result == 17
    assert events == [
        ("validate", ()),
        "drop_and_verify",
        "application",
    ]
