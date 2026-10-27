"""No-runtime guard checks for PR342's single-use signed APT test packet."""

from pathlib import Path

import yaml

WORKFLOW = (
    Path(__file__).resolve().parents[2]
    / ".github/workflows/mvp-342-authorized-signed-apt-20261027.yml"
)


def test_packet_restricts_pr_head_and_unique_approval():
    raw = WORKFLOW.read_text()
    job = yaml.safe_load(raw)["jobs"]["signed-apt"]
    assert "pull_request.number == 342" in job["if"]
    assert "head.ref == 'feat/mvp-mode-a-compose-overlay-oct24'" in job["if"]
    assert job["runs-on"] == "ubuntu-26.04"
    assert job["timeout-minutes"] <= 15
    steps = job["steps"]
    assert steps[0]["with"]["persist-credentials"] is False
    assert "github.event.pull_request.head.sha" in steps[0]["with"]["ref"]
    gate = steps[1]
    assert gate["id"] == "packet"
    assert "Approved-Builder-Packet: one-off-20261027-signed-apt" in gate["run"]
    assert "authorized=false" in gate["run"]
    assert "GITHUB_RUN_ATTEMPT" in gate["run"]
    assert "vars.SOM342_APPROVED_SOURCE_SHA" in gate["env"]["APPROVED_SHA"]
    assert 'test "$TRIGGERED_SHA" = "$APPROVED_SHA"' in gate["run"]
    assert "tinysshd" in WORKFLOW.read_text()
    assert "authorized=true" in gate["run"]
    assert all(step["if"] == "steps.packet.outputs.authorized == 'true'" for step in steps[2:])


def test_packet_acquires_verified_offline_bytes_without_activating_runtime():
    text = WORKFLOW.read_text()
    for required in (
        "Dir::State::status=/dev/null",
        "install --download-only",
        "Signed-By:",
        "apt-get update",
        "_InRelease",
        "_Packages",
        "sha256sum -c SHA256SUMS",
        "SOURCE_SHA",
        "ENGINE_INSTALLED=false",
        "SSH_IMAGE_BUILT=false",
        "GUEST_BOOTED=false",
        "SSH_MCP_E2E=false",
        "INDEPENDENT_OFFLINE_VERIFICATION_REQUIRED=true",
    ):
        assert required in text
    for forbidden in (
        "docker build",
        "docker run",
        "docker compose",
        "--privileged",
        "pull_request_target",
    ):
        assert forbidden not in text
