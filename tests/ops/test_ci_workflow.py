from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def test_ci_cancels_stale_runs_with_pr_scoped_concurrency() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "concurrency:" in workflow
    assert "cancel-in-progress: true" in workflow
    assert "github.workflow" in workflow
    assert "github.event.pull_request.number" in workflow
    assert "github.ref" in workflow
