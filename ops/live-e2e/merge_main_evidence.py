"""Read-only exact-main GitHub Actions acceptance. Never dispatches a workflow.

A successful PR run or a successful unrelated main run is NOT merge-main proof.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Callable
from typing import Any

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_REPO = "zhangyuz/ssh-over-mcp"
_PARTITIONS = ("projection-hot", "projection-rest-classified", "projection-rest-other", "rest")
_EXPECTED = {
    *(f"Full validation / Python {version} / {part}" for version in ("3.13", "3.14") for part in _PARTITIONS),
    "Ubuntu 26.04 x86 / Python 3.13",
    "Ubuntu 26.04 x86 / Python 3.14",
    "Merge-main no-network Level-3 / No-network Ubuntu 26.04 local E2E",
}


class Refused(Exception):
    """No verified exact-main acceptance evidence."""


def _dict(value: object) -> dict[str, Any]:
    if type(value) is not dict:
        raise Refused("INVALID_API_SHAPE")
    return value


def _list(value: object) -> list[Any]:
    if type(value) is not list:
        raise Refused("INVALID_API_SHAPE")
    return value


def verify_snapshot(sha: str, runs: object, get_jobs: Callable[[int], object]) -> int:
    """Check exact SHA, push/main/CI provenance and the complete eleven-job matrix."""
    if type(sha) is not str or _SHA.fullmatch(sha) is None:
        raise Refused("INVALID_SHA")
    response = _dict(runs)
    total = response.get("total_count")
    candidates = _list(response.get("workflow_runs"))
    if type(total) is not int or total < 0 or total > 100 or len(candidates) > 100 or total != len(candidates):
        raise Refused("RUNS_INCOMPLETE")
    matched = []
    for entry in candidates:
        run = _dict(entry)
        if run.get("head_sha") != sha:
            continue
        if (run.get("event") == "push" and run.get("head_branch") == "main"
                and run.get("path") == ".github/workflows/ci.yml"
                and run.get("name") == "CI"):
            matched.append(run)
    if len(matched) != 1:
        raise Refused("EXACT_MAIN_PUSH_RUN_MISSING_OR_AMBIGUOUS")
    run = matched[0]
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise Refused("MAIN_CI_NOT_SUCCESSFUL")
    run_id = run.get("id")
    if type(run_id) is not int or run_id < 1:
        raise Refused("INVALID_RUN_ID")
    job_response = _dict(get_jobs(run_id))
    jobs = _list(job_response.get("jobs"))
    count = job_response.get("total_count")
    if type(count) is not int or count != len(jobs) or count != len(_EXPECTED):
        raise Refused("JOBS_INCOMPLETE")
    seen: set[str] = set()
    for item in jobs:
        job = _dict(item)
        name = job.get("name")
        if type(name) is not str or name not in _EXPECTED or name in seen:
            raise Refused("JOB_MISSING_DUPLICATE_OR_UNEXPECTED")
        seen.add(name)
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            raise Refused("JOB_NOT_SUCCESSFUL")
        if job.get("run_id") != run_id:
            raise Refused("JOB_RUN_MISMATCH")
    if seen != _EXPECTED:
        raise Refused("JOB_MISSING_DUPLICATE_OR_UNEXPECTED")
    return run_id


def _gh_api(path: str) -> object:
    try:
        process = subprocess.run(
            ["gh", "api", path], capture_output=True, timeout=15, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("GITHUB_API_UNAVAILABLE") from None
    if process.returncode != 0 or len(process.stdout) > 1024 * 1024:
        raise Refused("GITHUB_API_UNAVAILABLE")
    try:
        return json.loads(process.stdout)
    except (UnicodeDecodeError, ValueError):
        raise Refused("INVALID_API_JSON") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True, help="Exact 40-hex merged main commit")
    args = parser.parse_args(argv)
    try:
        if _SHA.fullmatch(args.sha) is None:
            raise Refused("INVALID_SHA")
        runs = _gh_api(f"repos/{_REPO}/actions/runs?head_sha={args.sha}&per_page=100")
        run_id = verify_snapshot(
            args.sha, runs,
            lambda rid: _gh_api(f"repos/{_REPO}/actions/runs/{rid}/jobs?per_page=100"),
        )
    except Refused as exc:
        print(f"MERGE_MAIN_UNVERIFIED: {exc}", file=sys.stderr)
        return 2
    print(f"MERGE_MAIN_VERIFIED: sha={args.sha} run_id={run_id} jobs=11/11")
    return 0


if __name__ == "__main__":
    sys.exit(main())
