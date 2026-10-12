from __future__ import annotations

import shlex
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY = ROOT / ".github" / "workflows" / "self-hosted-security.yml"
NATIVE = ROOT / ".github" / "workflows" / "live-local-e2e.yml"


def _load(path: Path) -> dict:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def test_ci_cancels_only_stale_pr_runs_and_preserves_main_pushes() -> None:
    workflow = _load(WORKFLOW)
    assert "pull_request" in workflow["on"]
    assert "pull_request_target" not in workflow["on"]
    assert workflow["on"]["push"]["branches"] == ["main"]
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == {
        "group": (
            "${{ github.workflow }}-${{ github.event_name == 'pull_request' "
            "&& github.event.pull_request.number || github.run_id }}"
        ),
        "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
    }


@pytest.mark.parametrize(
    "step_name",
    ["Lint source and tests", "Compile on Python ${{ matrix.python-version }}"],
)
def test_operator_provisioning_tools_are_linted_and_compiled(step_name: str) -> None:
    workflow = _load(WORKFLOW)
    step = next(item for item in workflow["jobs"]["validate"]["steps"] if item["name"] == step_name)
    command = shlex.split(step["run"])
    assert "ops/systemd" in command, "privileged operator tools must not escape validation"


@pytest.mark.parametrize(
    "step_name",
    ["Lint source and tests", "Compile on Python ${{ matrix.python-version }}"],
)
def test_trusted_live_e2e_python_is_linted_and_compiled(step_name: str) -> None:
    workflow = _load(WORKFLOW)
    step = next(item for item in workflow["jobs"]["validate"]["steps"] if item["name"] == step_name)
    assert "ops/live-e2e" in shlex.split(step["run"])


def test_both_python_versions_run_full_suite_on_ephemeral_github_hosted_vms() -> None:
    workflow = _load(WORKFLOW)
    job = workflow["jobs"]["validate"]
    assert job["name"] == "Ubuntu 26.04 x86 / Python ${{ matrix.python-version }}"
    assert job["runs-on"] == "ubuntu-26.04"
    assert job["strategy"] == {
        "fail-fast": "false",
        "matrix": {"python-version": ["3.13", "3.14"]},
    }
    assert job["timeout-minutes"] == "20"
    assert "if" not in job, "skipped required PR checks must not silently pass"

    steps = {step["name"]: step for step in job["steps"]}
    assert "Verify GitHub-hosted Ubuntu 26.04 x86 runner" in steps
    checkout = steps["Checkout selected revision"]
    assert checkout["uses"].startswith("actions/checkout@3d3c42e5")
    assert checkout["with"] == {
        "persist-credentials": "false",
        "clean": "true",
        "fetch-depth": "0",
    }
    setup = steps["Set up Python ${{ matrix.python-version }}"]
    assert setup["uses"].startswith("actions/setup-python@5fda3b95")
    assert steps["Install complete test dependencies"]["run"] == "python -m pip install -e '.[dev]'"

    identity = steps["Verify strict non-root test identity"]["run"]
    assert "sudo /usr/bin/setpriv" in identity
    assert "--reuid" in identity and "--regid" in identity
    assert "--clear-groups" in identity and "os.getgroups()" in identity
    run = steps["Test on Python ${{ matrix.python-version }}"]["run"]
    assert "sudo /usr/bin/setpriv" in run
    assert "--clear-groups" in run
    assert "-m pytest -q" in run
    assert "--durations=15 -n 2 --dist=load" in run
    assert "--ignore" not in run
    assert "--deselect" not in run
    assert " -k " not in run
    assert "pytest-xdist>=3.8,<4" in (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_merge_main_level3_retains_exact_commit_fail_closed_dependency() -> None:
    workflow = _load(WORKFLOW)
    gate = workflow["jobs"]["live-local-e2e"]
    assert gate["name"] == "Merge-main no-network Level-3"
    assert gate["needs"] == "validate"
    assert gate["if"] == "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    assert gate["uses"] == "./.github/workflows/live-local-e2e.yml"
    assert gate["with"]["commit_sha"] == "${{ github.sha }}"
    assert gate["permissions"] == {"contents": "read"}
    native = _load(NATIVE)
    job = native["jobs"]["e2e"]
    assert "github.ref == 'refs/heads/main'" in job["if"]
    assert job["runs-on"] == ["self-hosted", "macOS", "X64", "ssh-over-mcp-e2e-orchestrator"]


def test_manual_hardened_security_matrix_remains_unchanged_and_complete() -> None:
    workflow = _load(SECURITY)
    job = workflow["jobs"]["validate"]
    assert job["strategy"]["matrix"]["python-version"] == ["3.13", "3.14"]
    assert job["strategy"]["fail-fast"] == "false"
    assert job["timeout-minutes"] == "20"
    assert job["runs-on"] == ["self-hosted", "linux", "x64", "ssh-over-mcp-mac-x86"]
    assert "github.ref == 'refs/heads/main'" in job["if"]
    names = [step["name"] for step in job["steps"]]
    assert "Verify hardened Ubuntu 26.04 x86 runner container" in names
    assert "Verify project cgroup-v2 read-only probe" in names
    step = next(
        x for x in job["steps"] if x["name"] == "Test on Python ${{ matrix.python-version }}"
    )
    assert shlex.split(step["run"]) == ["python", "-m", "pytest", "-q"]
