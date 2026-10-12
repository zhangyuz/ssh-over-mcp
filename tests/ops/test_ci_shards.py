"""Fail closed on every CI shard outcome; prove collection partitions."""

from __future__ import annotations

import ast
import itertools
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SOURCE = "tests/ops/test_live_e2e_staging_projection.py"
SHARDS = {
    "validate-py313-heavy": ("3.13", "source-heavy"),
    "validate-py313-rest": ("3.13", "everything-else"),
    "validate-py314-heavy": ("3.14", "source-heavy"),
    "validate-py314-rest": ("3.14", "everything-else"),
}
ENV_MAP = {
    "CI_PY313_HEAVY": "validate-py313-heavy",
    "CI_PY313_REST": "validate-py313-rest",
    "CI_PY314_HEAVY": "validate-py314-heavy",
    "CI_PY314_REST": "validate-py314-rest",
}


def _workflow():
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())


def _shard_workflow():
    return yaml.safe_load((ROOT / ".github/workflows/ci-validation-shard.yml").read_text())


def _suite_run():
    steps = _shard_workflow()["jobs"]["validate"]["steps"]
    return next(step["run"] for step in steps if step["name"].startswith("Test "))


def _collect(*args):
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-o",
            "addopts=--import-mode=importlib",
            SOURCE,
            *args,
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        text=True,
        capture_output=True,
        check=True,
    )
    return {line.strip() for line in process.stdout.splitlines() if line.startswith(SOURCE + "::")}


def test_ci_shards_use_explicit_nonmatrix_dependencies_and_hardened_reusable_workflow():
    jobs = _workflow()["jobs"]
    assert set(SHARDS).issubset(jobs)
    assert "validate-shards" not in jobs
    for job, (python_version, suite) in SHARDS.items():
        defined = jobs[job]
        assert defined["uses"] == "./.github/workflows/ci-validation-shard.yml"
        assert defined["with"] == {"python-version": python_version, "suite": suite}
        assert defined["permissions"] == {"contents": "read"}
        assert "head.repo.full_name == github.repository" in defined["if"]
    shared = _shard_workflow()["jobs"]["validate"]
    assert shared["timeout-minutes"] == 20
    assert shared["runs-on"] == ["self-hosted", "linux", "x64", "ssh-over-mcp-mac-x86"]
    body = "\n".join(str(step.get("run", "")) for step in shared["steps"])
    for invariant in (
        "id -u",
        "CapEff",
        "NoNewPrivs",
        "docker.sock",
        "cgroup.controllers",
        "python -m ruff check",
        "python -m compileall",
        "python -m pip install",
    ):
        assert invariant in body
    assert "pull_request.head.sha" in str(shared["steps"])
    assert "persist-credentials" in str(shared["steps"])


def test_ci_preserves_both_required_names_and_four_explicit_fail_closed_needs():
    gate = _workflow()["jobs"]["validate"]
    assert gate["name"] == "Ubuntu 26.04 x86 / Python ${{ matrix.python-version }}"
    assert gate["strategy"]["matrix"]["python-version"] == ["3.13", "3.14"]
    assert set(gate["needs"]) == set(SHARDS)
    assert "always()" in gate["if"]
    assert gate["timeout-minutes"] == 5
    step = gate["steps"][0]
    assert set(step["env"]) == set(ENV_MAP)
    for name, job in ENV_MAP.items():
        assert step["env"][name] == "${{ needs['" + job + "'].result }}"
    assert "exit 1" in step["run"]


def test_ci_gate_shell_rejects_every_non_success_conclusion_and_partial_rerun():
    gate_run = _workflow()["jobs"]["validate"]["steps"][0]["run"]
    for bad_job in ENV_MAP:
        for bad in ("failure", "cancelled", "skipped", ""):
            env = {name: "success" for name in ENV_MAP}
            env[bad_job] = bad
            result = subprocess.run(
                ["bash", "-e", "-o", "pipefail", "-c", gate_run],
                text=True,
                capture_output=True,
                env={**os.environ, **env},
                check=False,
            )
            assert result.returncode != 0, (bad_job, bad, result.stdout)
    # A partial-rerun of one successful shard must not hide another's failure.
    for bad_a, bad_b in itertools.combinations(ENV_MAP, 2):
        env = {name: "success" for name in ENV_MAP}
        env[bad_a] = env[bad_b] = "failure"
        env[bad_a] = "success"  # one failed cell was successfully retried
        result = subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", gate_run],
            text=True,
            capture_output=True,
            env={**os.environ, **env},
            check=False,
        )
        assert result.returncode != 0, (bad_a, bad_b, result.stdout)
    good = {name: "success" for name in ENV_MAP}
    assert (
        subprocess.run(
            ["bash", "-e", "-o", "pipefail", "-c", gate_run],
            capture_output=True,
            env={**os.environ, **good},
            check=False,
        ).returncode
        == 0
    )


def test_ci_collection_partitions_are_exact_nodeid_complements():
    run = _suite_run()
    match = re.search(r'^\s*heavy="([^"]+)"$', run, re.MULTILINE)
    assert match is not None
    selectors = match.group(1).split(" or ")
    assert len(selectors) == len(set(selectors)) >= 8
    tree = ast.parse((ROOT / SOURCE).read_text())
    defined = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    pending_upstream = {"test_dispute_gap_page_majority_leading_trailing_and_eight_gap_bound"}
    assert set(selectors) - defined <= pending_upstream
    assert f'{SOURCE} -k "${{heavy}}"' in run
    assert f'{SOURCE} -k "not (${{heavy}})"' in run
    assert f"--ignore={SOURCE}" in run
    all_ids = _collect()
    heavy_ids = _collect("-k", match.group(1))
    rest_ids = _collect("-k", f"not ({match.group(1)})")
    assert all_ids
    assert heavy_ids  # never let a missing/mistyped selector yield an empty shard
    assert not heavy_ids & rest_ids
    assert heavy_ids | rest_ids == all_ids
