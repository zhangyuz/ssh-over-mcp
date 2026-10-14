"""Static, fail-closed contracts for the hosted-only trust boundary."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/pr-native-e2e-shadow.yml"


def _workflow() -> dict:
    assert WORKFLOW.is_file(), "new trusted hosted-only workflow is required"
    return yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def test_only_workflow_run_completed_trigger() -> None:
    wf = _workflow()
    assert wf["on"] == {"workflow_run": {"workflows": ["CI"], "types": ["completed"]}}
    assert wf["permissions"] == {
        "contents": "read",
        "actions": "read",
        "pull-requests": "read",
    }
    assert wf["concurrency"]["cancel-in-progress"] == "false"
    assert "github.event.workflow_run.id" in wf["concurrency"]["group"]
    assert "github.event.workflow_run.run_attempt" in wf["concurrency"]["group"]


def test_trusted_sha_checkout_and_no_host_authority() -> None:
    wf = _workflow()
    assert len(wf["jobs"]) == 1
    job = wf["jobs"]["admit"]
    assert job["runs-on"] == "ubuntu-26.04"
    assert int(job["timeout-minutes"]) <= 5
    assert job["if"] == "${{ github.event.workflow_run.event == 'pull_request' }}"
    steps = job["steps"]
    assert steps[0]["uses"] == (
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    )
    assert steps[0]["with"] == {
        "ref": "${{ github.sha }}",
        "persist-credentials": "false",
        "clean": "true",
    }
    assert "git rev-parse HEAD" in steps[1]["run"]
    assert "GITHUB_SHA" in steps[1]["run"]
    assert steps[2]["uses"] == (
        "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
    )
    assert steps[2]["with"] == {"python-version": "3.13"}


def test_shadow_no_status_write_and_no_native_caller() -> None:
    wf = _workflow()
    text = WORKFLOW.read_text(encoding="utf-8")
    for forbidden in (
        "pull_request_target",
        "self-hosted",
        "workflow_dispatch:",
        "workflow_call:",
        "statuses: write",
        "checks: write",
        "actions: write",
        "GITHUB_OUTPUT",
        "live-local-e2e.yml",
        "github.event.workflow_run.head_sha",
    ):
        assert forbidden not in text
    steps = wf["jobs"]["admit"]["steps"]
    assert len(steps) == 4
    assert "pr_ci_shadow.py" in steps[-1]["run"]
    assert steps[-1]["env"] == {"GITHUB_TOKEN": "${{ github.token }}"}
    assert "github.event" not in steps[-1]["run"]
    assert "GITHUB_EVENT_PATH" in steps[-1]["run"]
