from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run-live-local-e2e-orchestrator.py"
LIMA_CONFIG = ROOT / "ops" / "live-e2e" / "lima-ubuntu-26.04.yaml"
WORKFLOW = ROOT / ".github" / "workflows" / "live-local-e2e.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
IMAGE_URL = (
    "https://cloud-images.ubuntu.com/releases/resolute/release-20260720/"
    "ubuntu-26.04-server-cloudimg-amd64.img"
)
IMAGE_DIGEST = (
    "sha256:117816726abbdefc5ef3e38902e81a76f1c76c3610e709999d0885f9d5d9b477"
)
def _load_script() -> ModuleType:
    assert SCRIPT.is_file(), "trusted Mac E2E orchestrator must exist"
    name = "ssh_over_mcp_live_e2e_orchestrator"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


def test_lima_config_pins_disposable_ubuntu_guest_without_host_mounts() -> None:
    assert LIMA_CONFIG.is_file()
    document = yaml.safe_load(LIMA_CONFIG.read_text(encoding="utf-8"))

    assert document["arch"] == "x86_64"
    assert document["vmType"] == "vz"
    assert document["images"] == [
        {"location": IMAGE_URL, "arch": "x86_64", "digest": IMAGE_DIGEST}
    ]
    assert document["mounts"] == []
    assert document["containerd"] == {"system": False, "user": False}
    assert document.get("portForwards", []) == []
    assert document["propagateProxyEnv"] is False
    assert document["hostResolver"] == {"enabled": False}
    assert document["cpus"] >= 2
    assert document["memory"].endswith("GiB")
    assert document["disk"].endswith("GiB")


def test_orchestrator_constants_pin_provider_and_guest_boundary() -> None:
    module = _load_script()

    assert module.LIMA_VERSION == "2.2.0"
    assert module.INSTANCE_NAME == "ssh-over-mcp-e2e"
    assert module.EXPECTED_REPOSITORY == "zhangyuz/ssh-over-mcp"
    assert module.GUEST_BUNDLE == Path("/tmp/ssh-over-mcp-target.bundle")
    assert module.GUEST_WORKSPACE == Path("/opt/ssh-over-mcp-e2e/workspace")
    assert module.GUEST_CONFIG == Path("/etc/ssh-over-mcp/live-e2e-gate.conf")
    assert module.IMAGE_DIGEST == IMAGE_DIGEST


@pytest.mark.parametrize(
    "value",
    ["", "abc", "g" * 40, "a" * 39, "a" * 41, "a" * 40 + "\nmain"],
)
def test_orchestrator_rejects_non_exact_target_commit(value: str) -> None:
    module = _load_script()
    with pytest.raises(module.OrchestratorError):
        module._validated_target_commit(value)


def test_orchestrator_normalizes_exact_target_commit() -> None:
    module = _load_script()
    assert module._validated_target_commit("A" * 40) == "a" * 40


def test_guest_environment_drops_host_tokens_and_runner_secrets() -> None:
    module = _load_script()
    env = {
        "HOME": "/Users/gha-e2e-orchestrator",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "GITHUB_TOKEN": "token",
        "GH_TOKEN": "gh-token",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc",
        "SSH_AUTH_SOCK": "/tmp/agent",
        "RANDOM_SECRET": "secret",
    }
    assert module._guest_command_environment(env) == {
        "HOME": "/Users/gha-e2e-orchestrator",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    }


def test_host_git_plan_is_bare_bundle_only() -> None:
    module = _load_script()
    bare = Path("/tmp/e2e/bare.git")
    bundle = Path("/tmp/e2e/target.bundle")
    target = "1" * 40

    commands = module._host_git_commands(bare, bundle, target)
    assert commands[0] == ["git", "init", "--bare", str(bare)]
    assert commands[1][-1] == target
    assert commands[2] == [
        "git", "-C", str(bare), "update-ref", "refs/e2e/target", "FETCH_HEAD"
    ]
    assert commands[3][-1] == "refs/e2e/target^{commit}"
    assert commands[4] == [
        "git", "-C", str(bare), "bundle", "create", str(bundle), "refs/e2e/target"
    ]
    assert all("checkout" not in command for command in commands)


def test_lima_start_command_uses_fixed_plain_no_mount_guest() -> None:
    module = _load_script()
    assert module._lima_start_command(LIMA_CONFIG) == [
        "limactl",
        "start",
        "--name=ssh-over-mcp-e2e",
        "--tty=false",
        "--plain",
        "--mount-none",
        "--timeout=10m",
        str(LIMA_CONFIG),
    ]


def test_orchestrator_source_never_uses_shell_true_or_os_system() -> None:
    assert SCRIPT.is_file()
    source = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert "shell=True" not in source
    assert "os.system" not in source
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg == "shell":
                assert isinstance(keyword.value, ast.Constant)
                assert keyword.value.value is False


class _FakeLifecycle:
    def __init__(self, *, preexisting: bool = False, fail_gate: bool = False) -> None:
        self.preexisting = preexisting
        self.fail_gate = fail_gate
        self.events: list[object] = []

    def verify_host(self) -> None:
        self.events.append("verify_host")

    def instance_exists(self) -> bool:
        self.events.append("instance_exists")
        return self.preexisting

    def create_bundle(self, target: str) -> Path:
        self.events.append(("create_bundle", target))
        return Path("/tmp/target.bundle")

    def start_guest(self) -> None:
        self.events.append("start_guest")

    def copy_bundle(self, bundle: Path) -> None:
        self.events.append(("copy_bundle", bundle))

    def bootstrap_guest(self, target: str) -> None:
        self.events.append(("bootstrap_guest", target))

    def guest_head(self) -> str:
        self.events.append("guest_head")
        return "a" * 40

    def run_guest_gate(self) -> int:
        self.events.append("run_guest_gate")
        if self.fail_gate:
            raise RuntimeError("gate failed")
        return 0

    def delete_guest(self) -> None:
        self.events.append("delete_guest")

    def verify_guest_absent(self) -> None:
        self.events.append("verify_guest_absent")

    def cleanup_host(self) -> None:
        self.events.append("cleanup_host")


def test_orchestrator_lifecycle_destroys_guest_after_success() -> None:
    module = _load_script()
    ops = _FakeLifecycle()
    assert module._orchestrate("a" * 40, ops) == 0
    assert ops.events == [
        "verify_host",
        "instance_exists",
        ("create_bundle", "a" * 40),
        "start_guest",
        ("copy_bundle", Path("/tmp/target.bundle")),
        ("bootstrap_guest", "a" * 40),
        "guest_head",
        "run_guest_gate",
        "delete_guest",
        "verify_guest_absent",
        "cleanup_host",
    ]


def test_orchestrator_lifecycle_destroys_guest_after_gate_failure() -> None:
    module = _load_script()
    ops = _FakeLifecycle(fail_gate=True)
    with pytest.raises(RuntimeError, match="gate failed"):
        module._orchestrate("a" * 40, ops)
    assert ops.events[-3:] == [
        "delete_guest",
        "verify_guest_absent",
        "cleanup_host",
    ]


def test_orchestrator_does_not_delete_preexisting_guest() -> None:
    module = _load_script()
    ops = _FakeLifecycle(preexisting=True)
    with pytest.raises(module.OrchestratorError, match="already exists"):
        module._orchestrate("a" * 40, ops)
    assert "delete_guest" not in ops.events
    assert "cleanup_host" in ops.events


def test_workflow_is_trusted_main_manual_mac_orchestrator_only() -> None:
    assert WORKFLOW.is_file()
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"workflow_dispatch"}
    commit = workflow["on"]["workflow_dispatch"]["inputs"]["commit_sha"]
    assert commit["required"] == "true"
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"]["cancel-in-progress"] == "false"
    job = workflow["jobs"]["e2e"]
    assert job["runs-on"] == [
        "self-hosted", "macOS", "X64", "ssh-over-mcp-e2e-orchestrator"
    ]

    rendered = WORKFLOW.read_text(encoding="utf-8")
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in rendered
    assert "persist-credentials: false" in rendered
    assert "ref: ${{ github.sha }}" in rendered
    assert "scripts/run-live-local-e2e-orchestrator.py" in rendered
    assert "${{ inputs.commit_sha }}" in rendered
    assert "sudo " not in rendered
    assert "/var/run/docker.sock" not in rendered


def test_ordinary_ci_runner_contract_is_not_replaced_by_e2e_orchestrator() -> None:
    rendered = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "runs-on: [self-hosted, linux, x64, ssh-over-mcp-mac-x86]" in rendered
    assert "ssh-over-mcp-e2e-orchestrator" not in rendered


class _PartialStartFailureLifecycle(_FakeLifecycle):
    def __init__(self) -> None:
        super().__init__()
        self._exists_checks = 0

    def instance_exists(self) -> bool:
        self.events.append("instance_exists")
        self._exists_checks += 1
        return self._exists_checks > 1

    def start_guest(self) -> None:
        self.events.append("start_guest")
        raise RuntimeError("partial start failure")


def test_orchestrator_deletes_guest_created_by_failed_start_attempt() -> None:
    module = _load_script()
    ops = _PartialStartFailureLifecycle()

    with pytest.raises(RuntimeError, match="partial start failure"):
        module._orchestrate("a" * 40, ops)

    assert ops.events == [
        "verify_host",
        "instance_exists",
        ("create_bundle", "a" * 40),
        "start_guest",
        "instance_exists",
        "delete_guest",
        "verify_guest_absent",
        "cleanup_host",
    ]


def test_orchestrator_pins_dedicated_host_account_and_environment() -> None:
    module = _load_script()

    assert module.ORCHESTRATOR_USER == "gha-e2e-orchestrator"
    assert module.ORCHESTRATOR_HOME == Path("/Users/gha-e2e-orchestrator")
    assert module.ORCHESTRATOR_PATH == "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

    hostile = {
        "HOME": "/tmp/attacker-home",
        "PATH": "/tmp/attacker-bin",
        "PYTHONPATH": "/tmp/inject",
        "DYLD_INSERT_LIBRARIES": "/tmp/inject.dylib",
        "GITHUB_TOKEN": "token",
    }
    assert module._guest_command_environment(hostile) == {
        "HOME": "/Users/gha-e2e-orchestrator",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    }


def test_operator_docs_pin_disposable_guest_trust_model() -> None:
    ops_readme = (ROOT / "ops" / "live-e2e" / "README.md").read_text(encoding="utf-8")
    runner_doc = (ROOT / "docs" / "self-hosted-runner.md").read_text(encoding="utf-8")
    combined = ops_readme + "\n" + runner_doc

    for required in (
        "gha-e2e-orchestrator",
        "ssh-over-mcp-e2e-orchestrator",
        "Lima 2.2.0",
        "117816726abbdefc5ef3e38902e81a76f1c76c3610e709999d0885f9d5d9b477",
        "no host filesystem mounts",
        "no sudo",
        "Git bundle",
        "commit_sha",
        "EXPECTED_COMMIT",
        "limactl delete --force",
    ):
        assert required in combined

    assert "whole disposable guest" in combined.lower()
    assert "workflow run `headSha`" in combined


def test_orchestrator_requires_trusted_main_actions_context() -> None:
    module = _load_script()
    valid = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": "zhangyuz/ssh-over-mcp",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": "a" * 40,
    }
    assert module._validated_workflow_context(valid) == "a" * 40

    bad_cases = [
        {**valid, "GITHUB_ACTIONS": "false"},
        {**valid, "GITHUB_EVENT_NAME": "pull_request_target"},
        {**valid, "GITHUB_REPOSITORY": "someone/else"},
        {**valid, "GITHUB_REF": "refs/heads/feature"},
        {**valid, "GITHUB_SHA": "abc"},
    ]
    for case in bad_cases:
        with pytest.raises(module.OrchestratorError):
            module._validated_workflow_context(case)


def test_bundle_failure_drops_host_read_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script()
    lifecycle = module._SystemLifecycle(
        {module.HOST_TOKEN_ENV: "test-read-token"}
    )

    def fail_run(*args, **kwargs):
        del args, kwargs
        raise RuntimeError("git failed")

    monkeypatch.setattr(module, "_run", fail_run)
    try:
        with pytest.raises(RuntimeError, match="git failed"):
            lifecycle.create_bundle("a" * 40)
        assert module.HOST_TOKEN_ENV not in lifecycle._host_env
    finally:
        lifecycle.cleanup_host()
