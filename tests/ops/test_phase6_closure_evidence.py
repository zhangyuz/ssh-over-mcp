from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SPEC = (
    _REPO_ROOT
    / "docs"
    / "superpowers"
    / "specs"
    / "2026-10-02-phase-6-cloudflare-reference-deployment-design.md"
)
_DEVELOPMENT_PLAN = _REPO_ROOT / "docs" / "development-plan.md"


def test_phase6_spec_records_implementation_complete_without_premature_closure() -> None:
    text = _SPEC.read_text(encoding="utf-8")

    assert (
        "Status: implementation complete; final closure requires exact-head CI "
        "and post-merge cleanup"
    ) in " ".join(text.split())
    assert "## 26. Phase 6 implementation evidence" in text
    assert "final merge-main CI is a post-merge gate" in text


def test_phase6_spec_has_all_twenty_acceptance_evidence_rows() -> None:
    text = _SPEC.read_text(encoding="utf-8")

    for number in range(1, 21):
        assert f"| {number} |" in text


def test_phase6_spec_has_all_eighteen_carried_phase5_invariant_rows() -> None:
    text = _SPEC.read_text(encoding="utf-8")

    for number in range(1, 19):
        assert f"| P5-{number} |" in text


def test_development_plan_marks_phase6_implementation_complete_with_final_gates() -> None:
    text = " ".join(_DEVELOPMENT_PLAN.read_text(encoding="utf-8").split())

    assert "Phase 6 implementation complete" in text
    assert "exact-head PR and merge-main CI" in text
    assert "post-merge branch/worktree cleanup" in text
    assert "live Cloudflare account provisioning remains an operator action" in text
