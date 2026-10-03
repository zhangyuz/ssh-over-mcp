from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "ops" / "live-e2e" / "ssh-over-mcp-live-e2e-gate"


def _load_gate() -> ModuleType:
    assert GATE.is_file(), "disposable-guest E2E gate must exist"
    name = "ssh_over_mcp_live_e2e_gate"
    spec = importlib.util.spec_from_file_location(name, GATE)
    if spec is None or spec.loader is None:
        from importlib.machinery import SourceFileLoader
        spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(GATE)))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module
def test_gate_constants_pin_guest_only_authority() -> None:
    module = _load_gate()

    assert module.WORKSPACE == Path("/opt/ssh-over-mcp-e2e/workspace")
    assert module.CONFIG == Path("/etc/ssh-over-mcp/live-e2e-gate.conf")
    assert module.RUNTIME == Path("/opt/ssh-over-mcp-e2e/runtime")
    assert module.CGROUP_ROOT == Path("/sys/fs/cgroup/ssh-over-mcp-e2e")
    assert module.SSHD_PORT == 22222
    assert (module.MANAGER_UID, module.MANAGER_GID) == (2201, 3201)
    assert (module.HOST_UID, module.HOST_GID) == (2202, 3202)
    assert (module.WORKLOAD_UID, module.WORKLOAD_GID) == (2203, 3203)
    assert (module.PROBE_UID, module.PROBE_GID) == (2204, 3204)
    assert module.MANAGER_CLIENT_GID == 3299


@pytest.mark.parametrize(
    "text",
    [
        "",
        "EXPECTED_COMMIT=abc\n",
        "EXPECTED_COMMIT=" + "g" * 40 + "\n",
        "EXPECTED_COMMIT=" + "a" * 40 + "\nEXTRA=1\n",
    ],
)
def test_gate_rejects_non_exact_expected_commit_config(
    tmp_path: Path, text: str
) -> None:
    module = _load_gate()
    config = tmp_path / "gate.conf"
    config.write_text(text, encoding="ascii")

    with pytest.raises(module.GateError):
        module._read_expected_commit(config)
def test_gate_accepts_one_exact_expected_commit_line(tmp_path: Path) -> None:
    module = _load_gate()
    config = tmp_path / "gate.conf"
    config.write_text("EXPECTED_COMMIT=" + "A" * 40 + "\n", encoding="ascii")

    assert module._read_expected_commit(config) == "a" * 40


def test_gate_source_has_no_target_selected_authority_parameters() -> None:
    assert GATE.is_file()
    source = GATE.read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert "argparse" not in source
    assert "shell=True" not in source
    assert "os.system" not in source
    assert "DOCKER_HOST" not in source
    assert "/var/run/docker.sock" not in source

    main = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    assert len(main.args.args) <= 1


def test_gate_refuses_stale_runtime_and_cgroup_state(tmp_path: Path) -> None:
    module = _load_gate()
    runtime = tmp_path / "runtime"
    cgroup = tmp_path / "cgroup"

    runtime.mkdir()
    with pytest.raises(module.GateError, match="stale"):
        module._require_clean_start(runtime, cgroup)

    runtime.rmdir()
    cgroup.mkdir()
    with pytest.raises(module.GateError, match="stale"):
        module._require_clean_start(runtime, cgroup)
class _FakeGuestOps:
    def __init__(self, *, fail_probe: bool = False) -> None:
        self.fail_probe = fail_probe
        self.events: list[str] = []

    def verify_root_and_workspace(self) -> None:
        self.events.append("verify")

    def require_clean_start(self) -> None:
        self.events.append("clean_start")

    def prepare(self) -> None:
        self.events.append("prepare")

    def run_probe(self) -> int:
        self.events.append("run_probe")
        if self.fail_probe:
            raise RuntimeError("probe failed")
        return 0

    def cleanup(self) -> None:
        self.events.append("cleanup")

    def verify_clean(self) -> None:
        self.events.append("verify_clean")


def test_guest_gate_cleanup_runs_after_success() -> None:
    module = _load_gate()
    ops = _FakeGuestOps()

    assert module._run_gate(ops) == 0
    assert ops.events == [
        "verify",
        "clean_start",
        "prepare",
        "run_probe",
        "cleanup",
        "verify_clean",
    ]
def test_guest_gate_cleanup_runs_after_probe_failure() -> None:
    module = _load_gate()
    ops = _FakeGuestOps(fail_probe=True)

    with pytest.raises(RuntimeError, match="probe failed"):
        module._run_gate(ops)

    assert ops.events[-2:] == ["cleanup", "verify_clean"]


def test_gate_never_contains_host_orchestrator_paths() -> None:
    assert GATE.is_file()
    source = GATE.read_text(encoding="utf-8")

    assert "/Users/" not in source
    assert "gha-e2e-orchestrator" not in source
    assert "limactl" not in source
