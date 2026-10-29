"""Guard the disposable fs_list v2 OCI proof against accidental live execution."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FLOW = ROOT / ".github/workflows/mvp-fs-list-v2-two-openssh-ci.yml"
RUNNER = ROOT / "ops/mvp/mode_a_hosted_v2_two_openssh.py"
CLIENT = ROOT / "ops/mvp/mode_a_hosted_v2_client_probe.py"


def test_oci_ci_only_same_repo_pull_request_no_release_promotions():
    text = FLOW.read_text()
    # Not tied to one PR number: it must keep running after #347 merges.
    assert "pull_request.number" not in text
    assert "pull_request_target" not in text
    assert "contents: read" in text and "persist-credentials: false" in text
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


def test_reported_markers_match_what_the_job_actually_proves():
    text = FLOW.read_text()
    assert "prove_central_v2()" in RUNNER.read_text()
    assert "CI_ONLY_CENTRAL_MCP_LEDGER_TWO_OPENSSH_V2_PASS=true" in text
    assert "MCP_LEDGER_V2_REAL_E2E_PROVEN=false" not in text
    for marker in ("PRODUCTION_KEYS_USED=false", "DEPLOYED=false", "MODE_A_LIVE_ACCEPTED=false"):
        assert marker in text


def test_markers_and_resource_names_are_not_tied_to_one_pull_request():
    # After merge this job runs on every same-repo PR; PR-numbered markers
    # would misattribute evidence (review round 3).
    central = ROOT / "ops/mvp/mode_a_hosted_v2_central_e2e.py"
    smoke = ROOT / "ops/mvp/mode_a_hosted_oci_fs_smoke.py"
    for path in (RUNNER, central, smoke):
        text = path.read_text()
        assert "pr347" not in text.lower() and "som347" not in text, path
    assert "CI_FS_LIST_V2_REAL_TWO_OPENSSH_DISTINCT_KEYS_PASS" in RUNNER.read_text()
    assert "FS_LIST_V2_REAL_CENTRAL_MCP_LEDGER_TWO_OPENSSH_E2E_PASS" in central.read_text()
