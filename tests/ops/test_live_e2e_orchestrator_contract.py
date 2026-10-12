from __future__ import annotations

import ast
import importlib.util
import inspect
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from types import ModuleType

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run-live-local-e2e-orchestrator.py"
PROVIDER = ROOT / "ops" / "live-e2e" / "qemu-ubuntu-26.04.json"
OLD_LIMA = ROOT / "ops" / "live-e2e" / "lima-ubuntu-26.04.yaml"
WORKFLOW = ROOT / ".github" / "workflows" / "live-local-e2e.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RUNTIME_LOCK = ROOT / "requirements" / "runtime.lock"

IMAGE_URL = (
    "https://cloud-images.ubuntu.com/releases/resolute/release-20260720/"
    "ubuntu-26.04-server-cloudimg-amd64.img"
)
IMAGE_DIGEST = (
    "sha256:117816726abbdefc5ef3e38902e81a76f1c76c3610e709999d0885f9d5d9b477"
)


def _load_script() -> ModuleType:
    assert SCRIPT.is_file()
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


def test_provider_pins_qemu_hvf_no_network_guest() -> None:
    assert PROVIDER.is_file(), "QEMU/HVF provider metadata must exist"
    assert not OLD_LIMA.exists(), "Lima provider must not remain authoritative"

    document = json.loads(PROVIDER.read_text(encoding="utf-8"))
    assert document == {
        "qemu_version": "11.1.2",
        "arch": "x86_64",
        "accelerator": "hvf",
        "image_url": IMAGE_URL,
        "image_digest": IMAGE_DIGEST,
        "cpus": 4,
        "memory_mib": 6144,
        "disk_gib": 8,
        "python_version": "3.14",
        "python_abi": "cp314",
        "network": False,
        "host_shares": False,
        "serial_result_prefix": "SSH_OVER_MCP_E2E_RESULT=",
    }


def test_orchestrator_constants_pin_no_network_provider() -> None:
    module = _load_script()

    assert module.QEMU_VERSION == "11.1.2"
    assert module.QEMU_SYSTEM == Path("/usr/local/bin/qemu-system-x86_64")
    assert module.QEMU_IMG == Path("/usr/local/bin/qemu-img")
    assert module.HDIUTIL == Path("/usr/bin/hdiutil")
    assert module.IMAGE_URL == IMAGE_URL
    assert module.IMAGE_DIGEST == IMAGE_DIGEST
    assert module.PYTHON_VERSION == "3.14"
    assert module.PYTHON_ABI == "cp314"
    assert module.RESULT_PREFIX == "SSH_OVER_MCP_E2E_RESULT="
    assert module.TRUSTED_RUNTIME_LOCK == RUNTIME_LOCK
    assert module.BASE_IMAGE == Path(
        "/Users/gha-e2e-orchestrator/Library/Caches/ssh-over-mcp-e2e/"
        "ubuntu-26.04-server-cloudimg-amd64.img"
    )


@pytest.mark.parametrize(
    "value",
    ["", "abc", "g" * 40, "a" * 39, "a" * 41, "a" * 40 + "\nmain"],
)
def test_orchestrator_rejects_non_exact_target_commit(value: str) -> None:
    module = _load_script()
    with pytest.raises(module.OrchestratorError):
        module._validated_target_commit(value)


def test_orchestrator_requires_trusted_main_actions_context() -> None:
    module = _load_script()
    valid = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": "zhangyuz/ssh-over-mcp",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": "a" * 40,
        "SSH_OVER_MCP_E2E_SOURCE_REPOSITORY": "zhangyuz/ssh-over-mcp",
    }
    for event in ("workflow_dispatch", "push"):
        assert module._validated_workflow_context(
            {**valid, "GITHUB_EVENT_NAME": event}
        ) == "a" * 40

    for case in (
        {**valid, "GITHUB_ACTIONS": "false"},
        {**valid, "GITHUB_EVENT_NAME": "pull_request_target"},
        {**valid, "GITHUB_EVENT_NAME": "workflow_run"},
        {**valid, "GITHUB_REPOSITORY": "someone/else"},
        {**valid, "GITHUB_REF": "refs/heads/feature"},
        {**valid, "GITHUB_SHA": "abc"},
        {**valid, "SSH_OVER_MCP_E2E_SOURCE_REPOSITORY": "someone/else"},
    ):
        with pytest.raises(module.OrchestratorError):
            module._validated_workflow_context(case)


def test_provider_environment_drops_host_tokens_and_secrets() -> None:
    module = _load_script()
    hostile = {
        "HOME": "/tmp/attacker-home",
        "PATH": "/tmp/attacker-bin",
        "PYTHONPATH": "/tmp/inject",
        "DYLD_INSERT_LIBRARIES": "/tmp/inject.dylib",
        "GITHUB_TOKEN": "token",
        "GH_TOKEN": "gh-token",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc",
        "SSH_AUTH_SOCK": "/tmp/agent",
        "SSH_OVER_MCP_E2E_GITHUB_TOKEN": "read-token",
    }
    assert module._provider_environment(hostile) == {
        "HOME": "/Users/gha-e2e-orchestrator",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    }


def test_git_environment_resets_credential_helpers() -> None:
    module = _load_script()
    askpass = Path("/tmp/e2e/git-askpass")
    hostile = {
        module.HOST_TOKEN_ENV: "read-token",
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "credential.helper",
        "GIT_CONFIG_VALUE_0": "attacker-helper",
        "GIT_CONFIG_KEY_1": "http.proxy",
        "GIT_CONFIG_VALUE_1": "http://attacker.invalid",
    }

    git_env = module._git_environment(hostile, askpass=askpass)

    assert git_env["GIT_ASKPASS"] == str(askpass)
    assert git_env["GIT_TERMINAL_PROMPT"] == "0"
    assert git_env["GIT_CONFIG_COUNT"] == "1"
    assert git_env["GIT_CONFIG_KEY_0"] == "credential.helper"
    assert git_env["GIT_CONFIG_VALUE_0"] == ""
    assert "attacker-helper" not in git_env.values()
    assert "http://attacker.invalid" not in git_env.values()


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


def test_wheel_download_is_hash_locked_cp314_linux_x86() -> None:
    module = _load_script()
    wheelhouse = Path("/tmp/e2e/wheels")
    command = module._wheel_download_command(RUNTIME_LOCK, wheelhouse)

    assert command[:3] == [sys.executable, "-m", "pip"]
    for flag in ("--require-hashes", "--only-binary=:all:", "--no-deps"):
        assert flag in command
    assert command[command.index("--implementation") + 1] == "cp"
    assert command[command.index("--python-version") + 1] == "3.14"
    assert command[command.index("--abi") + 1] == "cp314"
    platforms = [
        command[index + 1]
        for index, value in enumerate(command)
        if value == "--platform"
    ]
    assert platforms == ["manylinux_2_17_x86_64", "manylinux2014_x86_64"]
    assert command[command.index("-r") + 1] == str(RUNTIME_LOCK)
    assert command[command.index("-d") + 1] == str(wheelhouse)
    assert "--index-url" not in command
    assert "--extra-index-url" not in command


def test_bootstrap_pip_is_separately_hash_locked() -> None:
    module = _load_script()

    assert module.BOOTSTRAP_LOCK == ROOT / "requirements" / "e2e-bootstrap.lock"
    lock = module.BOOTSTRAP_LOCK.read_text(encoding="utf-8")
    expected = (
        "pip==26.2.1 "
        + chr(92)
        + "\n    --hash=sha256:71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e\n"
    )
    assert lock == expected

    wheelhouse = Path("/tmp/e2e/bootstrap-wheels")
    command = module._bootstrap_wheel_download_command(module.BOOTSTRAP_LOCK, wheelhouse)
    assert command[:3] == [sys.executable, "-m", "pip"]
    for flag in ("--require-hashes", "--only-binary=:all:", "--no-deps"):
        assert flag in command
    assert command[command.index("-r") + 1] == str(module.BOOTSTRAP_LOCK)
    assert command[command.index("-d") + 1] == str(wheelhouse)
    assert "--index-url" not in command
    assert "--extra-index-url" not in command


def test_qemu_overlay_plan_uses_verified_base_only() -> None:
    module = _load_script()
    base = Path("/cache/base.img")
    overlay = Path("/tmp/e2e/overlay.qcow2")
    assert module._overlay_command(base, overlay) == [
        "/usr/local/bin/qemu-img",
        "create",
        "-f",
        "qcow2",
        "-F",
        "qcow2",
        "-b",
        str(base),
        str(overlay),
        "8G",
    ]


def test_qemu_command_has_no_network_or_host_share_channel() -> None:
    module = _load_script()
    overlay = Path("/tmp/e2e/overlay.qcow2")
    seed = Path("/tmp/e2e/seed.iso")
    payload = Path("/tmp/e2e/payload.iso")
    command = module._qemu_command(overlay, seed, payload)
    rendered = " ".join(command)

    assert command[0] == "/usr/local/bin/qemu-system-x86_64"
    assert ["-accel", "hvf"] == command[command.index("-accel"): command.index("-accel") + 2]
    assert ["-nic", "none"] == command[command.index("-nic"): command.index("-nic") + 2]
    assert ["-display", "none"] == command[
        command.index("-display"): command.index("-display") + 2
    ]
    assert ["-monitor", "none"] == command[
        command.index("-monitor"): command.index("-monitor") + 2
    ]
    assert ["-serial", "stdio"] == command[
        command.index("-serial"): command.index("-serial") + 2
    ]
    assert f"file={seed},format=raw,media=cdrom,readonly=on" in command
    assert f"file={payload},format=raw,media=cdrom,readonly=on" in command

    forbidden = (
        "-net ",
        "-netdev",
        "user,",
        "tap,",
        "socket,",
        "virtiofs",
        "9p",
        "hostfwd",
        "vnc",
        "usb-redir",
        "smb=",
    )
    assert not any(token in rendered for token in forbidden)


def test_iso_command_is_fixed() -> None:
    module = _load_script()
    source = Path("/tmp/e2e/payload")
    output = Path("/tmp/e2e/payload.iso")
    assert module._iso_command(source, output, "SOM_E2E_PAYLOAD") == [
        "/usr/bin/hdiutil",
        "makehybrid",
        "-o",
        str(output),
        str(source),
        "-iso",
        "-joliet",
        "-iso-volume-name",
        "SOM_E2E_PAYLOAD",
        "-joliet-volume-name",
        "SOM_E2E_PAYLOAD",
    ]


def test_payload_archive_preserves_long_wheel_names(tmp_path: Path) -> None:
    module = _load_script()
    content = tmp_path / "payload-content"
    wheels = content / "wheels"
    wheels.mkdir(parents=True)
    long_name = "annotated_types-0.8.0-py3-none-any.whl"
    (wheels / long_name).write_bytes(b"wheel-bytes")
    (content / "runtime.lock").write_text("locked\n", encoding="utf-8")
    archive = tmp_path / "payload.tar"

    module._write_payload_archive(content, archive)

    with tarfile.open(archive, mode="r:") as stream:
        names = stream.getnames()
        assert f"wheels/{long_name}" in names
        assert "runtime.lock" in names
        for member in stream.getmembers():
            assert member.isfile() or member.isdir()
            assert member.uid == 0
            assert member.gid == 0
            assert member.uname == ""
            assert member.gname == ""


def test_prepare_guest_archives_long_name_content_before_iso() -> None:
    module = _load_script()
    source = inspect.getsource(module._SystemLifecycle.prepare_guest)

    assert "payload-content" in source
    assert "payload-iso" in source
    assert "_write_manifest(payload_content)" in source
    assert "_bootstrap_wheel_download_command(BOOTSTRAP_LOCK, bootstrap_wheelhouse)" in source
    assert 'shutil.copytree(bootstrap_wheelhouse, payload_content / "bootstrap-wheels")' in source
    assert 'shutil.copy2(BOOTSTRAP_LOCK, payload_content / "e2e-bootstrap.lock")' in source
    assert "_write_payload_archive(payload_content, payload_archive)" in source
    assert "_sha256(payload_archive)" in source
    assert "_bootstrap_script(target, payload_archive_digest)" in source
    assert "_iso_command(payload_iso" in source
    assert "shutil.copytree(wheelhouse, payload_content / \"wheels\")" in source


def test_seed_masks_wait_online_before_no_network_final_stage() -> None:
    module = _load_script()
    user_data = module._seed_user_data()

    assert user_data.startswith("#cloud-config\n")
    assert "bootcmd:" in user_data
    assert (
        "[ systemctl, mask, --runtime, systemd-networkd-wait-online.service ]"
        in user_data
    )
    assert user_data.index("bootcmd:") < user_data.index("runcmd:")
    for forbidden in ("apt-get", "curl ", "wget ", "dhclient", "networkctl up"):
        assert forbidden not in user_data


def test_trusted_bootstrap_is_offline_and_commit_bound() -> None:
    module = _load_script()
    target = "a" * 40
    archive_digest = "b" * 64
    script = module._bootstrap_script(target, archive_digest)

    assert target in script
    assert archive_digest in script
    assert "--no-index" in script
    assert "--require-hashes" in script
    assert "/opt/ssh-over-mcp-e2e/venv" in script
    assert 'python3 -m venv --without-pip "$VENV"' in script
    assert 'PIP_WHEEL="$EXTRACTED/bootstrap-wheels/pip-26.2.1-py3-none-any.whl"' in script
    assert 'PYTHONPATH="$PIP_WHEEL" "$VENV/bin/python" -m pip install' in script
    assert '"$EXTRACTED/e2e-bootstrap.lock"' in script
    assert "ensurepip" not in script
    assert 'ARCHIVE="$PAYLOAD/payload.tar"' in script
    assert "tarfile.open" in script
    assert 'EXTRACTED="/opt/ssh-over-mcp-e2e/payload"' in script
    assert 'git -C "$WORKSPACE" init' in script
    assert 'git -C "$WORKSPACE" fetch "$EXTRACTED/target.bundle" refs/e2e/target' in script
    assert 'git -C "$WORKSPACE" checkout --detach FETCH_HEAD' in script
    assert 'git clone "$EXTRACTED/target.bundle"' not in script
    assert '"$EXTRACTED/wheels"' in script
    assert '"$EXTRACTED/runtime.lock"' in script
    assert 'root = Path(sys.argv[1])' in script
    assert 'TRUSTED_HARNESS="/mnt/som-trusted-harness"' in script
    assert 'mount -t tmpfs -o size=1m,mode=0755,nosuid,nodev,noexec tmpfs "$TRUSTED_HARNESS"' in script
    assert 'install -D -o root -g root -m 0444' in script
    assert '"$EXTRACTED/trusted-harness/ops/live-e2e/ssh-over-mcp-live-e2e-gate"' in script
    assert '"$TRUSTED_HARNESS/ops/live-e2e/ssh-over-mcp-live-e2e-gate"' in script
    assert 'mount -o remount,ro,nosuid,nodev,noexec "$TRUSTED_HARNESS"' in script
    assert 'PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 "$TRUSTED_HARNESS/ops/live-e2e/ssh-over-mcp-live-e2e-gate"' in script
    assert "SSH_OVER_MCP_E2E_RESULT=" in script
    assert "/dev/ttyS0" in script
    assert "trap - EXIT" in script
    assert 'mountpoint -q "$PAYLOAD"' in script
    assert "mount -o rw" not in script
    assert "mount -o remount,rw" not in script
    assert "/mnt/som-payload/wheels" not in script
    for forbidden in (
        "apt-get",
        "apt ",
        "curl ",
        "wget ",
        "https://",
        "http://",
        "git fetch",
        "git clone https",
        "pip install -U",
    ):
        assert forbidden not in script


def test_serial_result_requires_exact_commit_and_single_pass_record() -> None:
    module = _load_script()
    target = "a" * 40
    assert module._parse_serial_result(
        f"boot noise\nSSH_OVER_MCP_E2E_RESULT={target}:PASS\n", target
    ) is True

    for raw in (
        "",
        f"SSH_OVER_MCP_E2E_RESULT={'b' * 40}:PASS\n",
        f"SSH_OVER_MCP_E2E_RESULT={target}:FAIL:70\n",
        (
            f"SSH_OVER_MCP_E2E_RESULT={target}:PASS\n"
            f"SSH_OVER_MCP_E2E_RESULT={target}:PASS\n"
        ),
    ):
        with pytest.raises(module.OrchestratorError):
            module._parse_serial_result(raw, target)


def test_serial_failure_reports_only_fixed_diagnostics() -> None:
    module = _load_script()
    target = "a" * 40
    raw = (
        "SUPERSECRET bearer-token\n"
        "local E2E sshd stage: NOT_A_REAL_STAGE\n"
        "local E2E sshd stage: AUTH_ACCEPTED\n"
        f"SSH_OVER_MCP_E2E_RESULT={target}:FAIL:70\n"
    )

    with pytest.raises(module.OrchestratorError) as caught:
        module._parse_serial_result(raw, target)

    assert str(caught.value) == (
        "guest E2E reported failure: code=70 sshd_stage=AUTH_ACCEPTED"
    )
    assert "SUPERSECRET" not in str(caught.value)
    assert "NOT_A_REAL_STAGE" not in str(caught.value)


def test_orchestrator_source_never_uses_shell_true_or_os_system() -> None:
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
    def __init__(self, *, stale: bool = False, fail_wait: bool = False) -> None:
        self.stale = stale
        self.fail_wait = fail_wait
        self.events: list[object] = []

    def verify_host(self) -> None:
        self.events.append("verify_host")

    def provider_state_exists(self) -> bool:
        self.events.append("provider_state_exists")
        return self.stale

    def create_bundle(self, target: str) -> Path:
        self.events.append(("create_bundle", target))
        return Path("/tmp/target.bundle")

    def prepare_guest(self, target: str, bundle: Path) -> None:
        self.events.append(("prepare_guest", target, bundle))

    def start_guest(self) -> None:
        self.events.append("start_guest")

    def wait_guest(self) -> int:
        self.events.append("wait_guest")
        if self.fail_wait:
            raise RuntimeError("guest failed")
        return 0

    def verify_result(self, target: str) -> None:
        self.events.append(("verify_result", target))

    def cleanup_guest(self) -> None:
        self.events.append("cleanup_guest")

    def cleanup_host(self) -> None:
        self.events.append("cleanup_host")


def test_orchestrator_lifecycle_always_cleans_guest_and_host() -> None:
    module = _load_script()
    ops = _FakeLifecycle()
    assert module._orchestrate("a" * 40, ops) == 0
    assert ops.events == [
        "verify_host",
        "provider_state_exists",
        ("create_bundle", "a" * 40),
        ("prepare_guest", "a" * 40, Path("/tmp/target.bundle")),
        "start_guest",
        "wait_guest",
        ("verify_result", "a" * 40),
        "cleanup_guest",
        "cleanup_host",
    ]


def test_orchestrator_cleanup_runs_after_guest_failure() -> None:
    module = _load_script()
    ops = _FakeLifecycle(fail_wait=True)
    with pytest.raises(RuntimeError, match="guest failed"):
        module._orchestrate("a" * 40, ops)
    assert ops.events[-2:] == ["cleanup_guest", "cleanup_host"]


def test_orchestrator_refuses_stale_provider_state_without_deleting_it() -> None:
    module = _load_script()
    ops = _FakeLifecycle(stale=True)
    with pytest.raises(module.OrchestratorError, match="stale"):
        module._orchestrate("a" * 40, ops)
    assert "start_guest" not in ops.events
    assert "cleanup_guest" not in ops.events
    assert ops.events[-1] == "cleanup_host"


def test_workflow_is_reusable_from_trusted_main_and_keeps_manual_fallback() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"workflow_call", "workflow_dispatch"}
    assert workflow["on"]["workflow_call"]["inputs"]["commit_sha"] == {
        "required": "true",
        "type": "string",
    }
    assert workflow["on"]["workflow_dispatch"]["inputs"]["commit_sha"]["required"] == "true"
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"]["cancel-in-progress"] == "false"
    job = workflow["jobs"]["e2e"]
    assert job["runs-on"] == [
        "self-hosted", "macOS", "X64", "ssh-over-mcp-e2e-orchestrator"
    ]
    assert job["env"]["SSH_OVER_MCP_E2E_SOURCE_REPOSITORY"] == "${{ github.repository }}"

    rendered = WORKFLOW.read_text(encoding="utf-8")
    assert "\n  push:" not in rendered
    assert "pull_request_target:" not in rendered
    assert "workflow_run:" not in rendered
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in rendered
    assert "ref: ${{ github.sha }}" in rendered
    assert "persist-credentials: false" in rendered
    assert "scripts/run-live-local-e2e-orchestrator.py" in rendered
    assert "inputs.commit_sha" in rendered
    assert "qemu-system-x86_64" in rendered
    assert "limactl" not in rendered
    assert "sudo " not in rendered
    assert "/var/run/docker.sock" not in rendered


def test_ci_calls_live_local_e2e_only_after_successful_main_validation() -> None:
    workflow = yaml.load(CI_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    job = workflow["jobs"]["live-local-e2e"]
    assert job["if"] == "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    assert job["needs"] == "required"
    assert job["uses"] == "./.github/workflows/live-local-e2e.yml"
    assert job["with"] == {"commit_sha": "${{ github.sha }}"}
    assert job["permissions"] == {"contents": "read"}


def test_primary_ci_is_hosted_and_native_e2e_keeps_dedicated_self_hosted_runner() -> None:
    workflow = yaml.load(CI_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert workflow["jobs"]["shards"]["runs-on"] == "ubuntu-26.04"
    assert workflow["jobs"]["required"]["needs"] == ["shards"]
    assert workflow["jobs"]["live-local-e2e"]["uses"] == "./.github/workflows/live-local-e2e.yml"
    assert "ssh-over-mcp-e2e-orchestrator" not in CI_WORKFLOW.read_text(encoding="utf-8")
    native = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert native["jobs"]["e2e"]["runs-on"] == [
        "self-hosted", "macOS", "X64", "ssh-over-mcp-e2e-orchestrator"
    ]


def test_operator_docs_pin_no_network_qemu_boundary() -> None:
    combined = (
        (ROOT / "ops" / "live-e2e" / "README.md").read_text(encoding="utf-8")
        + "\n"
        + (ROOT / "docs" / "self-hosted-runner.md").read_text(encoding="utf-8")
    )
    for required in (
        "QEMU 11.1.2",
        "`-nic none`",
        "117816726abbdefc5ef3e38902e81a76f1c76c3610e709999d0885f9d5d9b477",
        "Python 3.14",
        "wheelhouse",
        "serial",
        "commit_sha",
        "EXPECTED_COMMIT",
    ):
        assert required in combined
    assert "Lima/VZ" in combined


def test_target_fetch_retries_once_from_fresh_bare_repo_on_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script()
    bare = tmp_path / "target.git"
    target = "a" * 40
    events: list[str] = []
    fetch_attempts = 0

    def fake_run(command, *, env, timeout, check=True):
        nonlocal fetch_attempts
        del env, check
        if command[:3] == ["git", "init", "--bare"]:
            assert not bare.exists()
            bare.mkdir()
            events.append(f"init:{timeout}")
            return subprocess.CompletedProcess(command, 0, "", "")
        if "fetch" in command:
            fetch_attempts += 1
            events.append(f"fetch:{timeout}")
            if fetch_attempts == 1:
                (bare / "partial").write_text("partial", encoding="ascii")
                raise subprocess.TimeoutExpired(command, timeout)
            assert not (bare / "partial").exists()
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(module, "_run", fake_run)
    module._fetch_target_into_bare(bare, target, {})

    assert events == ["init:30", "fetch:120", "init:30", "fetch:120"]


def test_target_fetch_does_not_retry_non_timeout_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script()
    bare = tmp_path / "target.git"
    target = "b" * 40
    fetch_attempts = 0

    def fake_run(command, *, env, timeout, check=True):
        nonlocal fetch_attempts
        del env, timeout, check
        if command[:3] == ["git", "init", "--bare"]:
            bare.mkdir()
            return subprocess.CompletedProcess(command, 0, "", "")
        if "fetch" in command:
            fetch_attempts += 1
            raise subprocess.CalledProcessError(128, command)
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(module, "_run", fake_run)
    with pytest.raises(subprocess.CalledProcessError):
        module._fetch_target_into_bare(bare, target, {})

    assert fetch_attempts == 1


def test_target_fetch_fails_closed_after_second_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script()
    bare = tmp_path / "target.git"
    target = "c" * 40
    fetch_attempts = 0

    def fake_run(command, *, env, timeout, check=True):
        nonlocal fetch_attempts
        del env, check
        if command[:3] == ["git", "init", "--bare"]:
            bare.mkdir()
            return subprocess.CompletedProcess(command, 0, "", "")
        if "fetch" in command:
            fetch_attempts += 1
            raise subprocess.TimeoutExpired(command, timeout)
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(module, "_run", fake_run)
    with pytest.raises(module.OrchestratorError, match="target fetch timed out after retry"):
        module._fetch_target_into_bare(bare, target, {})

    assert fetch_attempts == 2


def test_provider_state_marker_precedes_target_fetch_and_is_removed_on_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script()
    cache = tmp_path / "cache"
    state = cache / "active-run.json"
    monkeypatch.setattr(module, "CACHE_DIR", cache)
    monkeypatch.setattr(module, "PROVIDER_STATE", state)

    lifecycle = module._SystemLifecycle({module.HOST_TOKEN_ENV: "read-token"})

    def fail_run(*args, **kwargs):
        del args, kwargs
        raise RuntimeError("git failed")

    monkeypatch.setattr(module, "_run", fail_run)
    with pytest.raises(RuntimeError, match="git failed"):
        lifecycle.create_bundle("a" * 40)

    assert state.is_file()
    lifecycle.cleanup_host()
    assert not state.exists()


def test_serial_channel_is_host_bounded_not_unbounded_file_sink() -> None:
    module = _load_script()
    assert module.SERIAL_MAX_BYTES == 2 * 1024 * 1024
    command = module._qemu_command(
        Path('/tmp/e2e/overlay.qcow2'),
        Path('/tmp/e2e/seed.iso'),
        Path('/tmp/e2e/payload.iso'),
    )
    serial_index = command.index('-serial')
    assert command[serial_index + 1] == 'stdio'
    rendered = ' '.join(command)
    assert 'file:/tmp/e2e/serial.log' not in rendered

    source = inspect.getsource(module._SystemLifecycle.wait_guest)
    assert 'SERIAL_MAX_BYTES' in source
    assert 'serial output exceeded limit' in source


def test_payload_trusts_only_the_root_guest_gate_from_main() -> None:
    module = _load_script()
    assert module.TRUSTED_HARNESS_FILES == (
        'ops/live-e2e/ssh-over-mcp-live-e2e-gate',
        'ops/live-e2e/ledger_guest_preflight.py',
    )

    bootstrap = module._bootstrap_script('a' * 40, 'b' * 64)
    assert '"$EXTRACTED/trusted-harness/ops/live-e2e/ledger_guest_preflight.py"' in bootstrap
    assert '"$TRUSTED_HARNESS/ops/live-e2e/ledger_guest_preflight.py"' in bootstrap
    assert '$EXTRACTED/trusted-harness/ops/live-e2e/ssh-over-mcp-live-e2e-gate' in bootstrap
    assert '$WORKSPACE/ops/live-e2e/ssh-over-mcp-live-e2e-gate' not in bootstrap

    source = inspect.getsource(module._SystemLifecycle.prepare_guest)
    assert 'TRUSTED_HARNESS_FILES' in source
    assert 'trusted-harness' in source
    for target_only in (
        'scripts/run-live-local-e2e-manager.py',
        'scripts/run-live-local-e2e-probe.py',
        'tests/live/local_e2e_support.py',
    ):
        assert target_only not in module.TRUSTED_HARNESS_FILES


def test_provider_bounds_guest_disk_and_requires_host_free_space(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_script()
    assert module.GUEST_DISK_GIB == 8
    assert module.HOST_MIN_FREE_BYTES == 16 * 1024**3
    assert module._overlay_command(Path('/cache/base.img'), Path('/tmp/e2e/overlay.qcow2'))[-1] == '8G'

    class Usage:
        total = 100 * 1024**3
        used = 90 * 1024**3
        free = 10 * 1024**3

    monkeypatch.setattr(module.shutil, 'disk_usage', lambda _path: Usage())
    with pytest.raises(module.OrchestratorError, match='free space'):
        module._require_host_free_space(Path('/tmp'))


def test_target_bundle_size_is_hard_bounded(tmp_path: Path) -> None:
    module = _load_script()
    assert module.TARGET_BUNDLE_MAX_BYTES == 256 * 1024**2
    bundle = tmp_path / 'target.bundle'
    bundle.write_bytes(b'12345')
    module._require_bounded_file(bundle, max_bytes=5, label='target bundle')
    with pytest.raises(module.OrchestratorError, match='target bundle exceeds size limit'):
        module._require_bounded_file(bundle, max_bytes=4, label='target bundle')
    source = inspect.getsource(module._SystemLifecycle.create_bundle)
    assert 'TARGET_BUNDLE_MAX_BYTES' in source


def test_orchestrator_self_verifies_trusted_main_checkout() -> None:
    module = _load_script()
    source = inspect.getsource(module._SystemLifecycle.verify_host)
    assert 'workflow_sha = _validated_workflow_context' in source
    assert 'rev-parse' in source and 'HEAD' in source
    assert 'status' in source and '--porcelain=v1' in source
    assert 'trusted orchestrator checkout mismatch' in source
    assert 'trusted orchestrator checkout is dirty' in source


def test_wait_guest_rejects_serial_flood_behaviorally() -> None:
    module = _load_script()
    lifecycle = module._SystemLifecycle({})
    payload_size = module.SERIAL_MAX_BYTES + 65536
    writer_code = f"""
import os
data = b"x" * {payload_size}
offset = 0
while offset < len(data):
    offset += os.write(1, data[offset:])
"""
    lifecycle._qemu = subprocess.Popen(
        [sys.executable, "-c", writer_code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        with pytest.raises(module.OrchestratorError, match='serial output exceeded limit'):
            lifecycle.wait_guest()
    finally:
        lifecycle.cleanup_guest()


@pytest.mark.parametrize(
    ("inventory", "expected"),
    [
        ("/bin/ps\n/usr/local/bin/qemu-system-x86_64\n", True),
        ("/bin/ps\n/usr/local/bin/qemu-img\n", False),
        ("/bin/ps\n/usr/local/bin/qemu-system-x86_64-helper\n", False),
    ],
)
def test_provider_rejects_existing_qemu_without_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    inventory: str,
    expected: bool,
) -> None:
    module = _load_script()
    state = tmp_path / "absent.json"
    monkeypatch.setattr(module, "PROVIDER_STATE", state)

    def process_inventory(command, *, env, timeout):
        assert command == ["/bin/ps", "-ww", "-U", str(os.getuid()), "-o", "comm="]
        assert timeout == 10
        return subprocess.CompletedProcess(command, 0, inventory, "")

    monkeypatch.setattr(module, "_run", process_inventory)
    lifecycle = module._SystemLifecycle({})
    assert lifecycle.provider_state_exists() is expected
    assert not state.exists()


def test_provider_rejects_dangling_state_marker_without_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script()
    state = tmp_path / "active-run.json"
    state.symlink_to(tmp_path / "missing")
    monkeypatch.setattr(module, "PROVIDER_STATE", state)
    assert module._SystemLifecycle({}).provider_state_exists()
    assert state.is_symlink()


def test_provider_process_inventory_failure_remains_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script()
    monkeypatch.setattr(module, "PROVIDER_STATE", tmp_path / "absent.json")

    def unavailable(*args, **kwargs):
        raise subprocess.TimeoutExpired("ps", 10)

    monkeypatch.setattr(module, "_run", unavailable)
    with pytest.raises(subprocess.TimeoutExpired):
        module._SystemLifecycle({}).provider_state_exists()


def test_provider_empty_inventory_is_not_treated_as_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script()
    monkeypatch.setattr(module, "PROVIDER_STATE", tmp_path / "absent.json")
    monkeypatch.setattr(
        module, "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", ""),
    )
    with pytest.raises(module.OrchestratorError, match="process inventory is unavailable"):
        module._SystemLifecycle({}).provider_state_exists()
