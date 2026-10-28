"""Disposable real Compose startup is isolated from production rollout."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_hosted_compose_startup_is_actual_and_disposable() -> None:
    script = (ROOT / "ops/mvp/mode_a_hosted_online_compose_startup.py").read_text()
    assert 'os.getenv("GITHUB_ACTIONS") == "true"' in script
    assert 'os.getenv("RUNNER_ENVIRONMENT") == "github-hosted"' in script
    assert 'os.getenv("GITHUB_EVENT_NAME") == "pull_request"' in script
    assert '"--project-name"' in script
    assert '"--wait"' in script
    assert '"up",' in script and '"-d",' in script
    assert '"down", "--volumes", "--remove-orphans"' in script or (
        '"down",' in script and '"--volumes",' in script and '"--remove-orphans",' in script
    )
    assert "docker build" not in script
    assert '"docker", "build"' in script
    assert '"Dockerfile"' in script
    assert '"linux/amd64", "linux/x86_64"' in script
    assert "entrypoint: !reset null" in script
    assert "command: !reset null" in script
    assert "mvp-fs-review" in script
    assert "no-production-keys" in script
    assert "MODE_A_COMPOSE_ALL_FIVE_SERVICES_HEALTHY_CI_ONLY_PASS" in script
    assert "docker push" not in script


def test_running_compose_mcp_ledger_reaches_both_sshd_nodes_and_rejects_replay() -> None:
    runner = (ROOT / "ops/mvp/mode_a_hosted_online_compose_startup.py").read_text()
    probe = (ROOT / "ops/mvp/mode_a_hosted_compose_mcp_client.py").read_text()
    assert "def prove_live_fs_with_approvals(" in runner
    assert "prove_live_fs_with_approvals(cmd, env)" in runner
    assert "approvalctl" in runner and '"grant"' in runner
    assert '"--profile",' in runner and '"admin",' in runner
    assert "MODE_A_COMPOSE_REAL_MCP_LEDGER_TWO_NODE_FS_PASS" in runner
    assert '"node01", "node02"' in runner
    assert "streamable_http_client(" in probe and "from mcp import Client" in probe
    assert "origin-bearer" in probe
    assert "fs_mkdir" in probe and "fs_write" in probe and "fs_read" in probe
    assert "approval_id" in probe and "replay" in probe
    assert "origin authentication failed" in probe
    assert "ssh-keygen" not in probe


def test_real_hosted_workflow_runs_compose_after_default_boot_before_export() -> None:
    wf = yaml.safe_load((ROOT / ".github/workflows/mvp-342-oci-source-build.yml").read_text())
    steps = wf["jobs"]["build-source"]["steps"]
    names = [x["name"] for x in steps]
    previous = next(i for i, n in enumerate(names) if n.startswith("Prove default runnable"))
    startup = next(i for i, n in enumerate(names) if n.startswith("Bring up full Compose"))
    export = next(i for i, n in enumerate(names) if n.startswith("Export runnable"))
    assert previous < startup < export
    assert "python3 ops/mvp/mode_a_hosted_online_compose_startup.py" in steps[startup]["run"]
    assert "MODE_A_COMPOSE_ALL_FIVE_SERVICES_HEALTHY_CI_ONLY_PASS" in steps[startup]["run"]
    assert "docker compose up" not in steps[startup]["run"]
    assert "DOCKER_CONFIG" in steps[startup]["run"]
    assert "mktemp -d /tmp/som342-docker-cli-XXXXXX" in steps[startup]["run"]
    assert 'rm -r -- "$DOCKER_CONFIG"' in steps[startup]["run"]
