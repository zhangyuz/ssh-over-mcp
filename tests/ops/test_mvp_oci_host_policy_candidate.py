"""MVP OCI FS-only Host Policy and writable scratch-root integration contracts."""

from __future__ import annotations

from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.policy import (
    authorize_filesystem_mkdir,
    authorize_filesystem_read,
    authorize_filesystem_stat,
    authorize_filesystem_write_create,
    load_host_policy,
)

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "deploy/ssh-target/host-policy.review-candidate.yaml"
SSH_IMAGE = ROOT / "deploy/ssh-target/Dockerfile.review-candidate"
MANAGER_IMAGE = ROOT / "deploy/ssh-target/Dockerfile.manager-review-candidate"
PROFILE = "rw-operator"
DATA = "/srv/data"


def test_ssh_image_installs_exact_root_owned_policy_and_agent_writable_scratch():
    image = SSH_IMAGE.read_text()
    assert (
        "COPY deploy/ssh-target/host-policy.review-candidate.yaml "
        "/etc/ssh-over-mcp/host-policy.yaml"
    ) in image
    assert "chmod 0444 /etc/ssh-over-mcp/host-policy.yaml" in image
    assert "mkdir -p /etc/ssh/hostkeys /etc/ssh/authorized_keys /run/sshd /srv/data" in image
    assert "chown 2202:3202 /srv/data" in image
    assert "chmod 0700 /srv/data" in image
    assert "host-policy.review-candidate.yaml" not in MANAGER_IMAGE.read_text()
    assert 'ENTRYPOINT ["/usr/local/libexec/ssh-over-mcp-image-hold"]' in image
    assert "exit 78" in (ROOT / "deploy/ssh-target/entrypoint.review-hold").read_text()


def test_guest_policy_is_v3_filesystem_only_and_matches_actual_compose_profile():
    policy = load_host_policy(POLICY, require_root_owner=False)
    assert policy.version == 3
    assert policy.containment is None  # v3 never enters command-execution supervisor
    assert policy.allowed_profiles == {PROFILE}
    assert list(policy.filesystem) == [PROFILE]
    assert list(policy.commands) == ["/usr/bin/true"]  # mandatory benign schema placeholder
    assert policy.env_allow == set()
    env = (ROOT / "deploy/compose/reference.mode-a.env.example").read_text()
    assert f"SSH_OVER_MCP_PROFILE={PROFILE}" in env
    rules = policy.filesystem[PROFILE]
    assert rules.stat_roots == (DATA,)
    assert rules.read_roots == (DATA,)
    assert rules.mkdir_roots == (DATA,)
    assert rules.write_create_roots == (DATA,)
    assert rules.max_read_bytes == rules.max_write_bytes == 4096


@pytest.mark.parametrize(
    "path,allowed",
    [
        ("/srv/data/probe", True),
        ("/srv/data/probe/new-file", True),
        ("/srv/data", True),
        ("/srv/dataset/probe", False),
        ("/srv/other/probe", False),
        ("/etc/shadow", False),
        ("/srv/data/../etc/shadow", False),
        ("/srv/data//probe", False),
    ],
)
def test_all_four_host_filesystem_ops_share_only_fixed_root(path, allowed):
    policy = load_host_policy(POLICY, require_root_owner=False)
    decisions = (
        authorize_filesystem_stat(policy, profile=PROFILE, path=path),
        authorize_filesystem_read(policy, profile=PROFILE, path=path, max_bytes=4096),
        authorize_filesystem_mkdir(policy, profile=PROFILE, path=path),
        authorize_filesystem_write_create(policy, profile=PROFILE, path=path, content_length=4096),
    )
    assert {decision.allowed for decision in decisions} == {allowed}


def test_wrong_profile_and_oversized_content_denied_without_io():
    policy = load_host_policy(POLICY, require_root_owner=False)
    assert not authorize_filesystem_stat(
        policy, profile="developer", path="/srv/data/probe"
    ).allowed
    assert not authorize_filesystem_read(
        policy, profile=PROFILE, path="/srv/data/probe", max_bytes=4097
    ).allowed
    assert not authorize_filesystem_write_create(
        policy, profile=PROFILE, path="/srv/data/probe", content_length=4097
    ).allowed
