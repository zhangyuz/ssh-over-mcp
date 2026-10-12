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
    ["Lint source and tests", "Compile on Python ${{ matrix.python-version }}"],
)
def test_operator_provisioning_tools_are_linted_and_compiled(step_name: str) -> None:
    workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
    step = next(item for item in workflow["jobs"]["validate"]["steps"] if item["name"] == step_name)
    command = shlex.split(step["run"])
    assert "ops/systemd" in command, "privileged operator tools must not escape validation"


@pytest.mark.parametrize(
    "step_name",
    ["Lint source and tests", "Compile on Python ${{ matrix.python-version }}"],
)
def test_trusted_live_e2e_python_is_linted_and_compiled(step_name: str) -> None:
    workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
    step = next(item for item in workflow["jobs"]["validate"]["steps"] if item["name"] == step_name)
    command = shlex.split(step["run"])
    assert "ops/live-e2e" in command


@pytest.mark.parametrize("filename", ["ci.yml", "self-hosted-security.yml"])
def test_both_python_versions_run_complete_isolated_hardened_matrix(filename: str) -> None:
    workflow = yaml.load(
        (ROOT / ".github" / "workflows" / filename).read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    job = workflow["jobs"]["validate"]
    assert job["strategy"]["matrix"]["python-version"] == ["3.13", "3.14"]
    assert job["strategy"]["fail-fast"] == "false"
    assert job["timeout-minutes"] == "20"
    assert job["runs-on"] == ["self-hosted", "linux", "x64", "ssh-over-mcp-mac-x86"]
    if filename == "self-hosted-security.yml":
        assert "github.ref == 'refs/heads/main'" in job["if"]
    else:
        assert "github.event.pull_request.head.repo.full_name == github.repository" in job["if"]
    steps = job["steps"]
    names = [step.get("name") for step in steps]
    assert "Verify hardened Ubuntu 26.04 x86 runner container" in names
    assert "Set up Python ${{ matrix.python-version }}" in names
    assert "Compile on Python ${{ matrix.python-version }}" in names
    assert "Test on Python ${{ matrix.python-version }}" in names
    test_step = next(
        step for step in steps if step.get("name") == "Test on Python ${{ matrix.python-version }}"
    )
    assert shlex.split(test_step["run"]) == (
        ["python", "-m", "pytest", "-q", "--durations=15", "-n", "3", "--dist=load"]
        if filename == "ci.yml"
        else ["python", "-m", "pytest", "-q"]
    )
    if filename == "ci.yml":
        assert workflow["jobs"]["live-local-e2e"]["needs"] == "validate"
        assert workflow["jobs"]["live-local-e2e"]["if"] == (
            "github.event_name == 'push' && github.ref == 'refs/heads/main'"
        )
