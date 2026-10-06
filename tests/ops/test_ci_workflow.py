from __future__ import annotations

import shlex
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def test_ci_cancels_only_stale_pr_runs_and_preserves_main_pushes() -> None:
    workflow = yaml.load(
        WORKFLOW.read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )

    assert workflow["concurrency"] == {
        "group": (
            "${{ github.workflow }}-${{ github.event_name == 'pull_request_target' "
            "&& github.event.pull_request.number || github.run_id }}"
        ),
        "cancel-in-progress": ("${{ github.event_name == 'pull_request_target' }}"),
    }


@pytest.mark.parametrize(
    "step_name",
    [
        "Lint source and tests",
        "Compile on Python 3.13",
        "Compile on Python 3.14",
    ],
)
def test_operator_provisioning_tools_are_linted_and_compiled(step_name: str) -> None:
    workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
    step = next(item for item in workflow["jobs"]["validate"]["steps"] if item["name"] == step_name)
    command = shlex.split(step["run"])
    assert "ops/systemd" in command, "privileged operator tools must not escape validation"


@pytest.mark.parametrize(
    "step_name",
    ["Lint source and tests", "Compile on Python 3.13", "Compile on Python 3.14"],
)
def test_trusted_live_e2e_python_is_linted_and_compiled(step_name: str) -> None:
    workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
    step = next(
        item for item in workflow["jobs"]["validate"]["steps"] if item["name"] == step_name
    )
    command = shlex.split(step["run"])
    assert "ops/live-e2e" in command
