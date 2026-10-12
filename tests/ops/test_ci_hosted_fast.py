"""Fail-closed contract for the optional 2 x Python, 2 x partition hosted experiment."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci-hosted-fast.yml"
HEAVY = "tests/ops/test_live_e2e_staging_projection.py"


def test_hosted_fast_matrix_is_complete_and_partition_is_exactly_disjoint() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert "pull_request_target" not in workflow["on"]
    assert "pull_request" in workflow["on"]
    assert workflow["permissions"] == {"contents": "read"}

    validate = workflow["jobs"]["validate"]
    assert validate["runs-on"] == "ubuntu-26.04"
    assert validate["strategy"]["fail-fast"] == "false"
    assert validate["strategy"]["matrix"] == {
        "python-version": ["3.13", "3.14"],
        "partition": ["projection", "rest"],
    }
    assert validate["timeout-minutes"] == "15"
    assert "head.repo.full_name == github.repository" in validate["if"]
    assert "ci/fast-hosted-" in validate["if"]

    steps = {step["name"]: step for step in validate["steps"]}
    checkout = steps["Checkout exact pull request merge revision with history"]
    assert checkout["with"]["persist-credentials"] == "false"
    assert checkout["with"]["fetch-depth"] == "0"
    assert "ref" not in checkout["with"]
    assert checkout["uses"].startswith("actions/checkout@3d3c42e5")
    assert steps["Set up Python ${{ matrix.python-version }}"]["uses"].startswith(
        "actions/setup-python@5fda3b95"
    )
    assert steps["Install all test dependencies"]["run"] == "python -m pip install -e '.[dev]'"
    assert "ops/live-e2e" in steps["Lint source, tests, and operator tools"]["run"]
    assert "ops/systemd" in steps["Compile all source and operator tools"]["run"]

    run = steps["Execute complete disjoint partition"]["run"]
    assert run.count("sudo /usr/bin/setpriv") == 2
    assert run.count("--clear-groups") == 2
    assert run.count("-m pytest -q") == 2
    assert run.count("--durations=15 -n 2 --dist=load") == 2
    assert run.count(HEAVY) == 2
    assert f"--ignore={HEAVY}" in run
    assert any(line.strip() == HEAVY for line in run.splitlines())
    assert "Unknown test partition" in run
    assert "--deselect" not in run
    assert " -k " not in run

    gate = workflow["jobs"]["complete"]
    assert gate["needs"] == ["validate"]
    assert "always()" in gate["if"]
    assert gate["timeout-minutes"] == "3"
    assert gate["steps"][0]["env"]["SHARDS_RESULT"] == "${{ needs.validate.result }}"
    assert '"success"' in gate["steps"][0]["run"]
    assert "exit 1" in gate["steps"][0]["run"]
