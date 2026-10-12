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
            "${{ github.workflow }}-${{ github.event_name }}-"
            "${{ github.event_name == 'pull_request' "
            "&& github.event.pull_request.number || github.run_id }}"
        ),
        "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
    }


@pytest.mark.parametrize(
    "step_name",
    ["Lint source, tests, and operator tools", "Compile all source and operator tools"],
)
def test_operator_provisioning_tools_are_linted_and_compiled(step_name: str) -> None:
    workflow = _load(WORKFLOW)
    step = next(item for item in workflow["jobs"]["shards"]["steps"] if item["name"] == step_name)
    command = shlex.split(step["run"])
    assert "ops/systemd" in command, "privileged operator tools must not escape validation"


@pytest.mark.parametrize(
    "step_name",
    ["Lint source, tests, and operator tools", "Compile all source and operator tools"],
)
def test_trusted_live_e2e_python_is_linted_and_compiled(step_name: str) -> None:
    workflow = _load(WORKFLOW)
    step = next(item for item in workflow["jobs"]["shards"]["steps"] if item["name"] == step_name)
    assert "ops/live-e2e" in shlex.split(step["run"])


def test_six_hosted_shards_cover_all_tests_without_suppressing_failures() -> None:
    workflow = _load(WORKFLOW)
    job = workflow["jobs"]["shards"]
    assert (
        job["name"]
        == "Hosted CI shard / Python ${{ matrix.python-version }} / ${{ matrix.partition }}"
    )
    assert job["runs-on"] == "ubuntu-26.04"
    assert job["timeout-minutes"] == "15"
    assert "if" not in job
    assert job["strategy"] == {
        "fail-fast": "false",
        "matrix": {
            "python-version": ["3.13", "3.14"],
            "partition": ["projection-hot", "projection-rest", "rest"],
        },
    }
    steps = {item["name"]: item for item in job["steps"]}
    checkout = steps["Checkout exact pull request merge revision with history"]
    assert checkout["uses"].startswith("actions/checkout@3d3c42e5")
    assert checkout["with"] == {
        "persist-credentials": "false",
        "clean": "true",
        "fetch-depth": "0",
    }
    assert steps["Set up Python ${{ matrix.python-version }}"]["uses"].startswith(
        "actions/setup-python@5fda3b95"
    )
    assert steps["Install all test dependencies"]["run"] == "python -m pip install -e '.[dev]'"
    run = steps["Execute complete disjoint partition"]["run"]
    assert run.count("sudo /usr/bin/setpriv") == 3
    assert run.count("--clear-groups") == 3
    assert run.count("--durations=15 -n 2 --dist=load") == 3
    assert run.count("-m pytest -q") == 3
    heavy = "tests/ops/test_live_e2e_staging_projection.py"
    expected = {
        "test_dispute_overlap_page_paginates_real_valid_overflow",
        "test_private_series_max_eight_segments_and_128_hops",
        "test_dispute_overlap_valid_source_index_can_exceed_wire_capacity",
        "test_dispute_overlap_coverage_remains_bounded_on_valid_large_index",
    }
    for node in expected:
        assert run.count(f'"{heavy}::{node}"') == 1
        assert f"def {node}(" in (ROOT / heavy).read_text(encoding="utf-8")
    assert run.count(f'"{heavy}::') == len(expected)
    assert run.count("--deselect=") == 1
    assert 'deselect_args+=("--deselect=${node}")' in run
    assert '"${deselect_args[@]}"' in run
    assert f"--ignore={heavy}" in run
    assert "projection-hot)" in run
    assert "projection-rest)" in run
    assert "rest)" in run
    assert "Unknown test partition" in run
    assert " -k " not in run
    assert "pytest-xdist>=3.8,<4" in (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_historical_two_required_check_names_fail_closed_on_all_six_shards() -> None:
    workflow = _load(WORKFLOW)
    gate = workflow["jobs"]["required"]
    assert gate["name"] == "Ubuntu 26.04 x86 / Python ${{ matrix.python-version }}"
    assert gate["if"] == "always()"
    assert gate["needs"] == ["shards"]
    assert gate["runs-on"] == "ubuntu-26.04"
    assert gate["strategy"] == {
        "fail-fast": "false",
        "matrix": {"python-version": ["3.13", "3.14"]},
    }
    assert gate["timeout-minutes"] == "3"
    assert gate["permissions"] == {"contents": "read"}
    step = gate["steps"][0]
    assert step["env"]["SHARDS_RESULT"] == "${{ needs.shards.result }}"
    assert '"success"' in step["run"]
    assert "exit 1" in step["run"]


def test_merge_main_level3_retains_exact_commit_fail_closed_dependency() -> None:
    workflow = _load(WORKFLOW)
    gate = workflow["jobs"]["live-local-e2e"]
    assert gate["name"] == "Merge-main no-network Level-3"
    assert gate["needs"] == "required"
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
