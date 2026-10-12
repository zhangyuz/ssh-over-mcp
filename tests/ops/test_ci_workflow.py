from __future__ import annotations

import shlex
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SHARD_WORKFLOW = ROOT / ".github" / "workflows" / "ci-validation-shard.yml"
RUNNER = ["self-hosted", "linux", "x64", "ssh-over-mcp-mac-x86"]


def _load(path: Path) -> dict:
    # BaseLoader leaves Actions expression strings untouched.
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def test_ci_cancels_only_stale_pr_runs_and_preserves_main_pushes() -> None:
    workflow = _load(WORKFLOW)
    assert workflow["concurrency"] == {
        "group": (
            "${{ github.workflow }}-${{ github.event_name == 'pull_request_target' "
            "&& github.event.pull_request.number || github.run_id }}"
        ),
        "cancel-in-progress": ("${{ github.event_name == 'pull_request_target' }}"),
    }


@pytest.mark.parametrize(
    "step_name",
    ["Lint source and tests", "Compile on Python ${{ inputs.python-version }}"],
)
def test_operator_provisioning_tools_are_linted_and_compiled(step_name: str) -> None:
    steps = _load(SHARD_WORKFLOW)["jobs"]["validate"]["steps"]
    step = next(item for item in steps if item["name"] == step_name)
    assert "ops/systemd" in shlex.split(step["run"]), (
        "privileged operator tools must not escape validation"
    )


@pytest.mark.parametrize(
    "step_name",
    ["Lint source and tests", "Compile on Python ${{ inputs.python-version }}"],
)
def test_trusted_live_e2e_python_is_linted_and_compiled(step_name: str) -> None:
    steps = _load(SHARD_WORKFLOW)["jobs"]["validate"]["steps"]
    step = next(item for item in steps if item["name"] == step_name)
    assert "ops/live-e2e" in shlex.split(step["run"])


def test_ci_four_reusable_shards_preserve_complete_hardened_validation() -> None:
    workflow = _load(WORKFLOW)
    reusable = _load(SHARD_WORKFLOW)
    shard = reusable["jobs"]["validate"]
    assert reusable["on"]["workflow_call"]["inputs"]["python-version"]["required"] == "true"
    assert reusable["on"]["workflow_call"]["inputs"]["suite"]["required"] == "true"
    assert reusable["permissions"] == {"contents": "read"}
    assert shard["timeout-minutes"] == "20"
    assert shard["runs-on"] == RUNNER
    assert "github.event.pull_request.head.repo.full_name == github.repository" in shard["if"]
    steps = shard["steps"]
    names = [step.get("name") for step in steps]
    assert "Verify hardened Ubuntu 26.04 x86 runner container" in names
    assert "Set up Python ${{ inputs.python-version }}" in names
    assert "Lint source and tests" in names
    assert "Compile on Python ${{ inputs.python-version }}" in names
    assert "Test ${{ inputs.suite }} on Python ${{ inputs.python-version }}" in names
    test_step = next(step for step in steps if step["name"].startswith("Test "))
    script = test_step["run"]
    assert "--ignore=tests/ops/test_live_e2e_staging_projection.py" in script
    assert ' -k "${heavy}"' in script
    assert ' -k "not (${heavy})"' in script
    assert "set -euo pipefail" in script
    expected = {
        "validate-py313-heavy": ("3.13", "source-heavy"),
        "validate-py313-rest": ("3.13", "everything-else"),
        "validate-py314-heavy": ("3.14", "source-heavy"),
        "validate-py314-rest": ("3.14", "everything-else"),
    }
    assert set(expected) <= set(workflow["jobs"])
    for job_id, (python_version, suite) in expected.items():
        job = workflow["jobs"][job_id]
        assert job["uses"] == "./.github/workflows/ci-validation-shard.yml"
        assert job["with"] == {"python-version": python_version, "suite": suite}
        assert job["permissions"] == {"contents": "read"}
        assert "github.event.pull_request.head.repo.full_name == github.repository" in job["if"]
    gate = workflow["jobs"]["validate"]
    assert gate["strategy"]["matrix"]["python-version"] == ["3.13", "3.14"]
    assert gate["strategy"]["fail-fast"] == "false"
    assert gate["timeout-minutes"] == "5"
    assert gate["runs-on"] == RUNNER
    assert set(gate["needs"]) == set(expected)
    assert "always()" in gate["if"]
    assert workflow["jobs"]["live-local-e2e"]["needs"] == "validate"
    assert workflow["jobs"]["live-local-e2e"]["if"] == (
        "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    )


def test_self_hosted_security_retains_full_hardened_dual_python_matrix() -> None:
    workflow = _load(ROOT / ".github" / "workflows" / "self-hosted-security.yml")
    job = workflow["jobs"]["validate"]
    assert job["strategy"]["matrix"]["python-version"] == ["3.13", "3.14"]
    assert job["strategy"]["fail-fast"] == "false"
    assert job["timeout-minutes"] == "20"
    assert job["runs-on"] == RUNNER
    assert "github.ref == 'refs/heads/main'" in job["if"]
    names = [step.get("name") for step in job["steps"]]
    assert "Verify hardened Ubuntu 26.04 x86 runner container" in names
    assert "Set up Python ${{ matrix.python-version }}" in names
    assert "Compile on Python ${{ matrix.python-version }}" in names
    assert "Test on Python ${{ matrix.python-version }}" in names
    test_step = next(
        step
        for step in job["steps"]
        if step.get("name") == "Test on Python ${{ matrix.python-version }}"
    )
    assert shlex.split(test_step["run"]) == ["python", "-m", "pytest", "-q"]
