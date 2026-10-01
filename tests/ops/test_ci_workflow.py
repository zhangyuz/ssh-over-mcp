from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def test_ci_cancels_stale_pull_request_runs_without_coalescing_main_pushes() -> None:
    workflow = yaml.load(
        CI_WORKFLOW.read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )

    assert workflow["concurrency"] == {
        "group": (
            "ci-${{ github.event_name == 'pull_request_target' "
            "&& github.event.pull_request.number || github.run_id }}"
        ),
        "cancel-in-progress": (
            "${{ github.event_name == 'pull_request_target' }}"
        ),
    }
