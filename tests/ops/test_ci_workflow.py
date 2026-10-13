from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
SECURITY = ROOT / ".github/workflows/self-hosted-security.yml"
NATIVE = ROOT / ".github/workflows/live-local-e2e.yml"
PROJECTION = "tests/ops/test_live_e2e_staging_projection.py"
HOT = {
    "test_dispute_overlap_page_paginates_real_valid_overflow",
    "test_private_series_max_eight_segments_and_128_hops",
    "test_dispute_overlap_valid_source_index_can_exceed_wire_capacity",
    "test_dispute_overlap_coverage_remains_bounded_on_valid_large_index",
    "test_classified_hop_filtered_page_keeps_eight_same_class_source_groups",
    "test_dispute_gap_page_majority_leading_trailing_and_eight_gap_bound",
    "test_classified_multifilter_source_clipping_matches_single_class_pages[classes0]",
    "test_classified_multifilter_two_classes_interleave_original_hop_order",
    "test_classified_multifilter_source_clipping_matches_single_class_pages[classes1]",
    "test_classified_hop_filtered_page_majority_clips_inside_both_source_segments",
    "test_series_max_eight_segments_128_hops",
    "test_dossier_public_maximum_8x16_on_both_sides",
    "test_dispute_ranks_real_sixteen_distinct_windows_upper_bound",
    "test_classified_hop_multifilter_page_original_source_order_and_category_subset[categories2]",
    "test_classified_hop_page_original_source_all_pages_and_clipped_interval",
    "test_classified_hop_page_clips_inside_both_distinct_source_intervals",
    "test_portfolio_rejects_mismatched_genuine_pair_and_sources",
    "test_dossier_rejects_genuine_mismatched_pair_and_source_splice",
    "test_classified_multifilter_source_clipping_matches_single_class_pages[classes2]",
}


def _workflow(path: Path) -> dict:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def test_pr_ci_is_unprivileged_and_main_validation_is_non_cancelling() -> None:
    wf = _workflow(WORKFLOW)
    assert wf["on"]["push"]["branches"] == ["main"]
    assert "pull_request" in wf["on"]
    assert "pull_request_target" not in wf["on"]
    assert wf["permissions"] == {"contents": "read"}
    assert wf["concurrency"] == {
        "group": (
            "${{ github.workflow }}-${{ github.event_name }}-"
            "${{ github.event_name == 'pull_request' "
            "&& github.event.pull_request.number || github.run_id }}"
        ),
        "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
    }


def test_complete_dual_python_eight_shard_matrix_and_operator_checks() -> None:
    job = _workflow(WORKFLOW)["jobs"]["validate"]
    assert (
        job["name"]
        == "Full validation / Python ${{ matrix.python-version }} / ${{ matrix.partition }}"
    )
    assert job["runs-on"] == "ubuntu-26.04"
    assert job["strategy"] == {
        "fail-fast": "false",
        "matrix": {
            "python-version": ["3.13", "3.14"],
            "partition": ["projection-hot", "projection-rest-classified", "projection-rest-other", "rest"],
        },
    }
    assert job["timeout-minutes"] == "15"
    doc = (ROOT / "docs/ci-hosted-primary.md").read_text(encoding="utf-8")
    assert "eight independent" in doc
    assert "four disjoint, jointly exhaustive" in doc
    assert "795 = 19 + 408 + 368" in doc
    assert "all eight jobs" in doc
    assert "if" not in job
    steps = {step["name"]: step for step in job["steps"]}
    assert "Verify Ubuntu 26.04 non-root x86" in steps
    checkout = steps["Checkout exact pull request merge revision with history"]
    assert checkout["uses"].startswith("actions/checkout@3d3c42e5")
    assert checkout["with"] == {"persist-credentials": "false", "clean": "true", "fetch-depth": "0"}
    assert "ref" not in checkout["with"]
    assert steps["Set up Python ${{ matrix.python-version }}"]["uses"].startswith(
        "actions/setup-python@5fda3b95"
    )
    assert steps["Install all test dependencies"]["run"] == "python -m pip install -e '.[dev]'"
    for name in ["Lint source, tests, and operator tools", "Compile all source and operator tools"]:
        cmd = steps[name]["run"]
        assert "src" in cmd and "tests" in cmd
        assert "ops/systemd" in cmd and "ops/live-e2e" in cmd
    identity = steps["Verify hosted-only minimal non-root Linux groups"]["run"]
    assert "sudo /usr/bin/setpriv" in identity and "--clear-groups" in identity
    assert "os.getgroups()" in identity
    assert "pytest-xdist>=3.8,<4" in (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_disjoint_partitions_select_all_exact_hot_tests_without_dropping_others() -> None:
    run = next(
        step["run"]
        for step in _workflow(WORKFLOW)["jobs"]["validate"]["steps"]
        if step["name"] == "Execute complete disjoint partition"
    )
    assert run.count("sudo /usr/bin/setpriv") == 3
    assert run.count("--clear-groups") == 3
    assert run.count("-m pytest -q") == 3
    assert run.count("--durations=15 -n 2 --dist=load") == 3
    assert "projection-hot)" in run and "projection-rest-classified|projection-rest-other)" in run and "rest)" in run
    assert '"${hot_tests[@]}"' in run
    assert 'deselect_args+=("--deselect=${node}")' in run
    assert '"${deselect_args[@]}"' in run
    assert run.count("--deselect=") == 1
    assert f"--ignore={PROJECTION}" in run
    assert '-k "$keyword_filter"' in run
    assert 'keyword_filter="classified or dispute"' in run
    assert 'keyword_filter="not (classified or dispute)"' in run
    assert "--ignore=tests/ops/test_live_e2e_staging_projection.py" in run
    source = (ROOT / PROJECTION).read_text(encoding="utf-8")
    for test_name in HOT:
        assert run.count(f'"{PROJECTION}::{test_name}"') == 1
        assert f"def {test_name.partition(chr(91))[0]}(" in source
    assert run.count(f'"{PROJECTION}::') == len(HOT)
    assert "Unknown test partition" in run


def test_historical_required_check_names_fail_closed_on_all_eight_shards() -> None:
    jobs = _workflow(WORKFLOW)["jobs"]
    gate = jobs["required-python"]
    assert gate["name"] == "Ubuntu 26.04 x86 / Python ${{ matrix.python-version }}"
    assert gate["if"] == "always()"
    assert gate["needs"] == ["validate"]
    assert gate["strategy"] == {
        "fail-fast": "false",
        "matrix": {"python-version": ["3.13", "3.14"]},
    }
    assert gate["runs-on"] == "ubuntu-26.04"
    assert gate["timeout-minutes"] == "3"
    assert gate["permissions"] == {"contents": "read"}
    step = gate["steps"][0]
    assert step["env"]["SHARDS_RESULT"] == "${{ needs.validate.result }}"
    assert '"success"' in step["run"] and "exit 1" in step["run"]


def test_main_native_e2e_waits_for_both_required_checks_and_exact_sha() -> None:
    gate = _workflow(WORKFLOW)["jobs"]["live-local-e2e"]
    assert gate["name"] == "Merge-main no-network Level-3"
    assert gate["needs"] == ["required-python"]
    assert gate["if"] == "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    assert gate["uses"] == "./.github/workflows/live-local-e2e.yml"
    assert gate["with"]["commit_sha"] == "${{ github.sha }}"
    assert gate["permissions"] == {"contents": "read"}
    native = _workflow(NATIVE)["jobs"]["e2e"]
    assert "github.ref == 'refs/heads/main'" in native["if"]
    assert native["runs-on"] == ["self-hosted", "macOS", "X64", "ssh-over-mcp-e2e-orchestrator"]


def test_manual_hardened_security_runner_stays_complete_and_independent() -> None:
    job = _workflow(SECURITY)["jobs"]["validate"]
    assert job["runs-on"] == ["self-hosted", "linux", "x64", "ssh-over-mcp-mac-x86"]
    assert job["strategy"]["matrix"]["python-version"] == ["3.13", "3.14"]
    assert job["strategy"]["fail-fast"] == "false"
    assert job["timeout-minutes"] == "20"
    assert "github.ref == 'refs/heads/main'" in job["if"]
    steps = {step["name"]: step for step in job["steps"]}
    assert "Verify hardened Ubuntu 26.04 x86 runner container" in steps
    assert "Verify project cgroup-v2 read-only probe" in steps
    assert steps["Test on Python ${{ matrix.python-version }}"]["run"] == "python -m pytest -q"


@pytest.mark.parametrize(
    ("matrix_result", "expected_exit"),
    [
        ("success", 0),
        ("failure", 1),
        ("cancelled", 1),
        ("skipped", 1),
        ("", 1),
    ],
)
def test_required_check_gate_script_rejects_incomplete_shards(
    matrix_result: str, expected_exit: int
) -> None:
    script = _workflow(WORKFLOW)["jobs"]["required-python"]["steps"][0]["run"]
    result = subprocess.run(
        ["bash", "-c", script],
        env={**os.environ, "SHARDS_RESULT": matrix_result},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == expected_exit
    if expected_exit:
        assert "::error::" in result.stdout
    else:
        assert "passed" in result.stdout
