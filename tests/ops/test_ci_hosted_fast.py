"""Fail-closed contract for the optional 2 x Python, 3 x partition hosted experiment."""

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
        "partition": ["projection-hot", "projection-rest", "rest"],
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
    assert run.count("sudo /usr/bin/setpriv") == 3
    assert run.count("--clear-groups") == 3
    assert run.count("-m pytest -q") == 3
    assert run.count("--durations=15 -n 2 --dist=load") == 3
    assert run.count(HEAVY) == 6
    assert f"--ignore={HEAVY}" in run
    assert any(line.strip().startswith(HEAVY + " ") for line in run.splitlines())
    assert "projection-hot)" in run and "projection-rest)" in run and "rest)" in run
    assert '"${hot_tests[@]}"' in run
    assert 'deselect_args+=("--deselect=${node}")' in run
    assert '"${deselect_args[@]}"' in run
    expected_hot = {
        "test_dispute_overlap_page_paginates_real_valid_overflow",
        "test_private_series_max_eight_segments_and_128_hops",
        "test_dispute_overlap_valid_source_index_can_exceed_wire_capacity",
        "test_dispute_overlap_coverage_remains_bounded_on_valid_large_index",
    }
    source = (ROOT / HEAVY).read_text(encoding="utf-8")
    for test_name in expected_hot:
        assert run.count(f'"{HEAVY}::{test_name}"') == 1
        assert f"def {test_name}(" in source, "hot source selector must resolve to a real test"
    assert run.count(f'"{HEAVY}::') == len(expected_hot)
    assert "Unknown test partition" in run
    assert run.count("--deselect=") == 1, "only the four exact hot IDs may be deselected"
    assert " -k " not in run

    gate = workflow["jobs"]["complete"]
    assert gate["needs"] == ["validate"]
    assert "always()" in gate["if"]
    assert gate["timeout-minutes"] == "3"
    assert gate["steps"][0]["env"]["SHARDS_RESULT"] == "${{ needs.validate.result }}"
    assert '"success"' in gate["steps"][0]["run"]
    assert "exit 1" in gate["steps"][0]["run"]
