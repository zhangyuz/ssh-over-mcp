from __future__ import annotations

import ast
import importlib.util
import inspect
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
def test_target_e2e_fixture_sources_exist_in_checkout() -> None:
    required = (
        ROOT / "scripts" / "run-live-local-e2e-manager.py",
        ROOT / "scripts" / "run-live-local-e2e-probe.py",
        ROOT / "tests" / "live" / "local_e2e_support.py",
        ROOT / "tests" / "live" / "test_local_e2e.py",
    )
    assert all(path.is_file() for path in required)


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


def test_guest_gate_cleanup_reports_only_fixed_stage_labels() -> None:
    module = _load_gate()
    source = inspect.getsource(module._SystemGuestOps.cleanup)

    for stage in (
        "sshd",
        "manager",
        "cgroup",
        "sudoers",
        "launcher",
        "host_policy",
        "identities",
        "runtime",
    ):
        assert f'"{stage}"' in source
    assert 'f"{stage}:{type(exc).__name__}"' in source


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


def test_gate_constants_pin_real_ssh_containment_fixture() -> None:
    module = _load_gate()

    assert module.HOST_SOURCE_CGROUP == Path(
        "/sys/fs/cgroup/ssh-over-mcp-e2e/host-agent-source"
    )
    assert module.MANAGER_ENDPOINT == Path(
        "/opt/ssh-over-mcp-e2e/runtime/manager/containment.sock"
    )
    assert module.CLIENT_KEY == Path(
        "/opt/ssh-over-mcp-e2e/runtime/client_ed25519"
    )
    assert module.HOST_KEY == Path(
        "/opt/ssh-over-mcp-e2e/runtime/sshd_host_ed25519"
    )
    assert module.HOST_KEY_PUBLIC == Path(
        "/opt/ssh-over-mcp-e2e/runtime/sshd_host_ed25519.pub"
    )
    assert module.AUTHORIZED_KEYS == Path(
        "/opt/ssh-over-mcp-e2e/runtime/authorized_keys"
    )
    assert module.SSHD_CONFIG == Path(
        "/opt/ssh-over-mcp-e2e/runtime/sshd_config"
    )
    assert module.SSHD_LOG == Path(
        "/opt/ssh-over-mcp-e2e/runtime/sshd.log"
    )
    assert module.HOST_POLICY == Path("/etc/ssh-over-mcp/host-policy.yaml")
    assert module.LAUNCHER_INSTALL == Path(
        "/usr/local/libexec/ssh-over-mcp-host-agent-launcher.py"
    )
    assert module.SUDOERS_DROPIN == Path(
        "/etc/sudoers.d/ssh-over-mcp-e2e-host-agent"
    )
    assert module.STATE_SCRIPT == Path(
        "/opt/ssh-over-mcp-e2e/runtime/workload_state.py"
    )


def test_gate_source_pins_forcecommand_and_nonroot_children() -> None:
    module = _load_gate()
    source = GATE.read_text(encoding="utf-8")

    exact_launcher = (
        "/usr/bin/python3 -I -S "
        "/usr/local/libexec/ssh-over-mcp-host-agent-launcher.py"
    )
    assert module._LAUNCHER_COMMAND == exact_launcher
    assert module._FORCECOMMAND == f"/usr/bin/sudo -n {exact_launcher}"
    assert 'NOPASSWD: {_LAUNCHER_COMMAND}' in source
    assert 'NOPASSWD: {_FORCECOMMAND}' not in source
    assert "NOPASSWD: /usr/bin/sudo" not in source
    assert "NOPASSWD: ALL" not in source
    assert "PermitTTY no" in source
    assert "AllowTcpForwarding no" in source
    assert "AllowAgentForwarding no" in source
    assert "X11Forwarding no" in source
    assert "PermitTunnel no" in source
    assert "UsePAM no" in source
    assert "PasswordAuthentication no" in source
    assert "KbdInteractiveAuthentication no" in source
    assert "ListenAddress 127.0.0.1" in source
    assert "Port 22222" in source
    assert "_spawn_nonroot_child" in source
    assert "uid=MANAGER_UID" in source
    assert "uid=PROBE_UID" in source


def test_gate_source_prepares_delegated_host_source_not_sshd_master() -> None:
    source = GATE.read_text(encoding="utf-8")

    assert "HOST_SOURCE_CGROUP" in source
    assert "host-agent-source" in source
    assert "cgroup.subtree_control" in source
    assert "cgroup.procs" in source
    assert "sshd" not in source[source.find("def _prepare_cgroup"):source.find("def _prepare_cgroup") + 1800]


def test_gate_source_never_runs_probe_as_root() -> None:
    module = _load_gate()
    body = inspect.getsource(module._SystemGuestOps.run_probe)

    assert "_spawn_nonroot_child" in body
    assert "PROBE_UID" in body
    assert "PROBE_GID" in body
    assert "subprocess.run(" not in body


def test_guest_gate_trusts_only_root_gate_and_executes_target_helpers_after_drop() -> None:
    module = _load_gate()
    assert module.TRUSTED_HARNESS_ROOT == Path('/mnt/som-trusted-harness')
    assert module._TRUSTED_GATE == (
        module.TRUSTED_HARNESS_ROOT
        / 'ops/live-e2e/ssh-over-mcp-live-e2e-gate'
    )
    assert module._MANAGER_SCRIPT == module.WORKSPACE / 'scripts/run-live-local-e2e-manager.py'
    assert module._PROBE == module.WORKSPACE / 'scripts/run-live-local-e2e-probe.py'
    assert module._SUPPORT == module.WORKSPACE / 'tests/live/local_e2e_support.py'
    assert module.LAUNCHER_SOURCE == module.WORKSPACE / 'ops/live-e2e/ssh-over-mcp-host-agent-launcher.py'

    verify = inspect.getsource(module._SystemGuestOps.verify_root_and_workspace)
    for name in ('LAUNCHER_SOURCE', '_MANAGER_SCRIPT', '_PROBE', '_SUPPORT'):
        assert f'_require_target_regular({name})' in verify

    manager = inspect.getsource(module._SystemGuestOps._start_manager)
    assert '_spawn_nonroot_child' in manager
    assert 'uid=MANAGER_UID' in manager
    assert 'gid=MANAGER_GID' in manager

    probe = inspect.getsource(module._SystemGuestOps.run_probe)
    assert '_spawn_nonroot_child' in probe
    assert 'uid=PROBE_UID' in probe
    assert 'gid=PROBE_GID' in probe


def test_workload_state_detects_any_inherited_socket_fd() -> None:
    source = GATE.read_text(encoding='utf-8')
    start = source.index('state_source = ')
    end = source.index('STATE_SCRIPT.write_text', start)
    state_source_builder = source[start:end]
    assert 'stat.S_ISSOCK' in state_source_builder
    assert 'os.fstat' in state_source_builder
    assert 'os.readlink(entry)' not in state_source_builder


def test_guest_gate_requires_target_launcher_regular_non_symlink() -> None:
    module = _load_gate()
    source = inspect.getsource(module._SystemGuestOps.verify_root_and_workspace)
    assert '_require_target_regular(LAUNCHER_SOURCE)' in source
    helper = inspect.getsource(module._require_target_regular)
    assert 'lstat' in helper
    assert 'stat.S_ISLNK' in helper
    assert 'stat.S_ISREG' in helper
    assert 'resolved' in helper


def test_guest_gate_runtime_verifies_only_trusted_root_gate_payload() -> None:
    module = _load_gate()
    assert module.TRUSTED_HARNESS_ROOT == Path("/mnt/som-trusted-harness")
    source = inspect.getsource(module._SystemGuestOps.verify_root_and_workspace)
    assert '_require_trusted_harness()' in source
    helper = inspect.getsource(module._require_trusted_harness)
    assert 'os.statvfs' in helper
    assert 'os.ST_RDONLY' in helper
    assert 'lstat' in helper
    assert 'stat.S_ISLNK' in helper
    assert 'stat.S_ISREG' in helper
    assert '_TRUSTED_GATE' in helper
    assert '_MANAGER_SCRIPT' not in helper
    assert '_PROBE' not in helper
    assert '_SUPPORT' not in helper


def test_root_gate_verifies_privileged_fixture_before_probe_drop() -> None:
    module = _load_gate()
    run_probe = inspect.getsource(module._SystemGuestOps.run_probe)
    helper = inspect.getsource(module._SystemGuestOps._verify_privileged_fixture)

    assert run_probe.index("_verify_privileged_fixture()") < run_probe.index(
        "_spawn_nonroot_child"
    )
    for required in (
        "MANAGER_ENDPOINT",
        "CGROUP_ROOT",
        "HOST_SOURCE_CGROUP",
        "MANAGER_UID",
        "MANAGER_GID",
        "MANAGER_CLIENT_GID",
        "stat.S_ISSOCK",
        "stat.S_ISDIR",
        "0o660",
    ):
        assert required in helper


def test_nonroot_probe_does_not_inspect_privileged_manager_surfaces() -> None:
    support = (
        ROOT / "tests" / "live" / "local_e2e_support.py"
    ).read_text(encoding="utf-8")
    start = support.index("    def verify_filesystem_contract")
    end = support.index("\n    def host_key_line", start)
    body = support[start:end]

    assert "self.manager_endpoint.lstat()" not in body
    assert "self.host_source_cgroup" not in body


def test_identity_cleanup_accepts_primary_group_already_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_gate()
    ops = module._SystemGuestOps()
    ops._created_groups = [module.PROBE_GROUP]

    def unexpected_run(*args, **kwargs):
        del args, kwargs
        raise AssertionError("groupdel must not run for an already-absent primary group")

    monkeypatch.setattr(module, "_run", unexpected_run)

    ops._remove_identities()

    assert ops._created_groups == []


def test_identity_cleanup_rejects_absent_name_with_reused_numeric_gid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_gate()
    ops = module._SystemGuestOps()
    ops._created_groups = [module.PROBE_GROUP]

    monkeypatch.setattr(
        module.grp,
        "getgrnam",
        lambda _name: (_ for _ in ()).throw(KeyError()),
    )
    monkeypatch.setattr(module.grp, "getgrgid", lambda _gid: object())

    with pytest.raises(module.GateError, match="numeric identity"):
        ops._remove_identities()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", "NO_SSH_ACTIVITY"),
        ("Connection from 127.0.0.1 port 50000 on 127.0.0.1 port 22222\n", "TCP_CONNECTED"),
        (
            (
                "Connection from 127.0.0.1 port 50000 on 127.0.0.1 port 22222\n"
                "Failed publickey for ssh-over-mcp-e2e-host from 127.0.0.1 port 50000 ssh2\n"
            ),
            "AUTH_REJECTED",
        ),
        (
            "Accepted publickey for ssh-over-mcp-e2e-host from 127.0.0.1 port 50000 ssh2: ED25519 SHA256:SECRET\n",
            "AUTH_ACCEPTED",
        ),
        (
            (
                "Accepted publickey for ssh-over-mcp-e2e-host from 127.0.0.1 port 50000 ssh2: ED25519 SHA256:SECRET\n"
                "Starting session: forced-command (config) for ssh-over-mcp-e2e-host from 127.0.0.1 port 50000 id 0\n"
            ),
            "FORCECOMMAND_STARTED",
        ),
    ],
)
def test_sshd_failure_stage_is_fixed_enum(raw: str, expected: str) -> None:
    module = _load_gate()

    observed = module._classify_sshd_stage(raw)

    assert observed == expected
    assert observed in {
        "NO_SSH_ACTIVITY",
        "TCP_CONNECTED",
        "AUTH_REJECTED",
        "AUTH_ACCEPTED",
        "FORCECOMMAND_STARTED",
    }
    assert "SECRET" not in observed
    assert "127.0.0.1" not in observed


def test_failed_probe_emits_only_fixed_sshd_stage(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_gate()
    ops = module._SystemGuestOps()
    ops._expected_commit = "a" * 40
    monkeypatch.setattr(ops, "_verify_privileged_fixture", lambda: None)
    monkeypatch.setattr(
        module,
        "_spawn_nonroot_child",
        lambda *args, **kwargs: 123,
    )
    monkeypatch.setattr(module, "_wait_pid", lambda *args, **kwargs: 70)
    monkeypatch.setattr(module, "_read_sshd_stage", lambda: "AUTH_ACCEPTED")

    assert ops.run_probe() == 70

    captured = capsys.readouterr()
    assert captured.err == "local E2E sshd stage: AUTH_ACCEPTED\n"
    assert "SUPERSECRET" not in captured.err


def test_authorized_keys_is_root_owned_user_readable_and_not_writable() -> None:
    module = _load_gate()
    source = inspect.getsource(module._SystemGuestOps._prepare_keys)

    assert "os.chown(AUTHORIZED_KEYS, 0, 0)" in source
    assert "os.chmod(AUTHORIZED_KEYS, 0o644)" in source
    assert "os.chmod(AUTHORIZED_KEYS, 0o600)" not in source


def test_guest_policy_limits_match_production_executor_defaults() -> None:
    module = _load_gate()
    from ssh_over_mcp.ssh.executor import SSHExecutor

    signature = inspect.signature(SSHExecutor.__init__)
    assert module.EXECUTOR_DEFAULT_MAX_OUTPUT_BYTES == (
        signature.parameters["default_max_output_bytes"].default
    )
    assert module.EXECUTOR_DEFAULT_MAX_STDIN_BYTES == (
        signature.parameters["default_max_stdin_bytes"].default
    )

    source = inspect.getsource(module._SystemGuestOps._prepare_state_and_policy)
    assert '"max_output_bytes": EXECUTOR_DEFAULT_MAX_OUTPUT_BYTES' in source
    assert '"max_stdin_bytes": EXECUTOR_DEFAULT_MAX_STDIN_BYTES' in source
