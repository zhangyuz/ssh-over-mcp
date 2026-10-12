"""Contract for the opt-in, unprivileged GitHub-hosted comparison workflow."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci-hosted-benchmark.yml"


def test_hosted_benchmark_is_an_opt_in_unprivileged_pr_workflow() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert "pull_request" in workflow["on"]
    assert "pull_request_target" not in workflow["on"]
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"]["cancel-in-progress"] == "true"

    job = workflow["jobs"]["full-suite"]
    assert "github.event.pull_request.head.repo.full_name == github.repository" in job["if"]
    assert "startsWith(github.head_ref, 'ci/hosted-')" in job["if"]
    assert job["runs-on"] == "ubuntu-26.04"
    assert job["timeout-minutes"] == "20"
    assert job["strategy"]["matrix"]["python-version"] == ["3.13", "3.14"]
    assert job["strategy"]["fail-fast"] == "false"

    steps = {step["name"]: step for step in job["steps"]}
    checkout = steps["Checkout pull request merge revision"]
    assert checkout["uses"].startswith("actions/checkout@3d3c42e5")
    assert checkout["with"]["persist-credentials"] == "false"
    assert checkout["with"]["clean"] == "true"
    assert "ref" not in checkout["with"]
    assert steps["Set up Python ${{ matrix.python-version }}"]["uses"].startswith(
        "actions/setup-python@5fda3b95"
    )
    assert steps["Install complete development dependencies"]["run"] == (
        "python -m pip install -e '.[dev]'"
    )
    assert "ops/systemd" in steps["Lint source and tests"]["run"]
    assert "ops/live-e2e" in steps["Lint source and tests"]["run"]
    assert "ops/systemd" in steps["Compile source, tests and operator scripts"]["run"]
    assert "ops/live-e2e" in steps["Compile source, tests and operator scripts"]["run"]
    assert steps["Run complete suite on Python ${{ matrix.python-version }}"]["run"] == (
        "python -m pytest -q --durations=15 -n 2 --dist=load"
    )
