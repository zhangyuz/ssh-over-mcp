"""Regression guards for user-facing implemented-vs-pending status."""

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_README = _ROOT / "README.md"
_ROADMAP = _ROOT / "docs" / "development-plan.md"


def test_readme_reports_implemented_approval_lifecycle() -> None:
    text = _README.read_text(encoding="utf-8")
    status = text.split("## Current status\n", 1)[1].split("\n## ", 1)[0]
    assert "Phase 5D" in status and "Phase 5E" in status
    assert "single-use" in status
    assert "Approval consumption is intentionally not enabled yet" not in text
    assert "**Phase 5C — mandatory audit lifecycle integration.**" not in text


def test_readme_distinguishes_closed_phases_from_open_native_gates() -> None:
    text = _README.read_text(encoding="utf-8")
    status = text.split("## Current status\n", 1)[1].split("\n## ", 1)[0]
    for phrase in ("Phase 6", "Phase 7A", "Level-3", "A1", "B8", "N1c", "UID-502"):
        assert phrase in status
    assert "static principal" in status
    assert "does **not** establish native acceptance" in status
    assert "not per-user OAuth-claim-to-role mapping" in status


def test_roadmap_records_merged_dispute_slices_and_open_native_gate() -> None:
    text = _ROADMAP.read_text(encoding="utf-8")
    assert "**PR #190** — merged" in text
    assert "**PR #191** — merged" in text
    assert "**PR #193** — merged" in text
    assert "38014380038" in text
    assert "9e5b94d7" in text
    assert "38014354645" in text
    assert (
        text.index("**PR #191** — merged")
        < text.index("**PR #190** — merged")
        < text.index("**PR #193** — merged")
    )
    assert "FAIL-CLOSED" in text
    assert "**Next smaller complete functional slice (#190)**" not in text


def test_authoritative_audit_doc_reports_phase_5e_filesystem_approvals() -> None:
    text = (_ROOT / "docs" / "audit-and-approvals.md").read_text(encoding="utf-8")
    status = text.split("## Current implementation status\n", 1)[1].split("\n## ", 1)[0]
    assert "Phase 5E" in status
    assert "Ledger" in status and "single-use" in status
    for tool in ("fs_stat", "fs_read", "fs_mkdir", "fs_write"):
        assert tool in status
    assert "Filesystem approvals remain fail-closed until Phase 5E" not in text
