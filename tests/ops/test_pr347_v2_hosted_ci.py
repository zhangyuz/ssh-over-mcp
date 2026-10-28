"""Guard PR347 disposable v2 OCI admission against accidental live execution."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FLOW = ROOT / ".github/workflows/pr347-v2-two-openssh-ci.yml"
RUNNER = ROOT / "ops/mvp/mode_a_hosted_v2_two_openssh.py"
CLIENT = ROOT / "ops/mvp/mode_a_hosted_v2_client_probe.py"


def test_oci_ci_only_exact_pr347_same_repo_no_release_promotions():
    text = FLOW.read_text()
    assert "pull_request.number == 347" in text
    assert "head.repo.full_name == 'zhangyuz/ssh-over-mcp'" in text
    assert "runs-on: ubuntu-26.04" in text
    assert "mode_a_hosted_v2_two_openssh.py" in text
    assert "mvp-342-oci-source-build.yml" not in text
    assert "workflow_dispatch" not in text
    assert "docker push" not in text and "docker save" not in text
    assert "PRODUCTION_DEPLOY" not in text


def test_v2_real_ssh_stage_never_uses_live_keys_host_daemon_or_ports():
    text = RUNNER.read_text()
    assert 'RUNNER_ENVIRONMENT") == "github-hosted"' in text
    assert 'network="none"' in text
    assert "v5_host_id=host" in text
    assert '"docker", "rm", "-f", name' in text
    assert "127.0.0.1:18801" not in text
    assert "som-mode-a-netpilot-oct27" not in text
    assert "docker system prune" not in text
    assert "/var/lib/ssh-over-mcp/mode-a-fs-pilot" not in text
    assert "REAL_OPENSSH_SMCP_V2_FS_LIST" in CLIENT.read_text()
    assert "REAL_OPENSSH_SMCP_V2_DENIAL_REPLAY_DOWNGRADE" in CLIENT.read_text()
