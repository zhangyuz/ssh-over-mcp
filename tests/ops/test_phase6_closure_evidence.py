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


def test_phase6_spec_records_final_closure_with_exact_external_evidence() -> None:
    text = _SPEC.read_text(encoding="utf-8")
    normalized = " ".join(text.split())

    assert "Status: **closed**" in text
    assert "## 26. Phase 6 implementation evidence" in text
    assert "37059153723" in text
    assert "37059622970" in text
    assert "2e2486a3b536ad600be5e6439ede36268c08b06f" in text
    assert "a5c7c2d13c504f1e68beb0e7fc55db90539fbcc0" in text
    assert "post-merge Phase 6 branch/worktree cleanup completed" in normalized
    assert "Pending Task 4" not in text
    assert "Phase 6 is **not closed**" not in text


def test_phase6_spec_has_all_twenty_acceptance_evidence_rows() -> None:
    text = _SPEC.read_text(encoding="utf-8")

    for number in range(1, 21):
        assert f"| {number} |" in text


def test_phase6_spec_has_all_eighteen_carried_phase5_invariant_rows() -> None:
    text = _SPEC.read_text(encoding="utf-8")

    for number in range(1, 19):
        assert f"| P5-{number} |" in text


def test_development_plan_marks_phase6_closed_with_final_gate_evidence() -> None:
    text = " ".join(_DEVELOPMENT_PLAN.read_text(encoding="utf-8").split())

    assert "Status: **Phase 6 closed.**" in text
    assert "37059153723" in text
    assert "37059622970" in text
    assert "a5c7c2d13c504f1e68beb0e7fc55db90539fbcc0" in text
    assert "Phase 6 worktree/branch cleanup completed" in text
    assert "live Cloudflare account provisioning remains an operator action" in text
