"""Keep native-provider disposition evidence and safety gates explicit."""

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_RUNBOOK = _ROOT / "docs/plans/2026-10-09-native-provider-disposition.md"
_ROADMAP = _ROOT / "docs/development-plan.md"
_RECOVERY_README = _ROOT / "ops/live-e2e/README.md"
_WORKFLOW = _ROOT / ".github/workflows/live-local-e2e-recovery.yml"


def test_disposition_records_current_exact_source_evidence() -> None:
    text = _RUNBOOK.read_text(encoding="utf-8")
    for expected in (
        "38017034795",
        "38015831978",
        "47531dadb58d365f74089dd5f52ce1b61bb0fdd1",
        "38013",
        "ssh-over-mcp-e2e-i8ow1ni6",
        "ssh-over-mcp-e2e-recover.cc8Del",
        "ssh-over-mcp-e2e-w_kn4rus",
        "3 E2E temp directories",
        "RECOVERY_MODE=inspect-only",
        "FAIL-CLOSED",
    ):
        assert expected in text


def test_disposition_separates_observation_from_cleanup_authority() -> None:
    text = _RUNBOOK.read_text(encoding="utf-8")
    for expected in (
        "No cleanup authorized",
        "does not establish whether the owner PID or QEMU is still alive",
        "no E2E temp directories remain",
        "explicit operator authorization",
        "do not remove",
        "Level-3",
        "A1",
        "B8",
        "N1c",
        "UID-502",
    ):
        assert expected in text
    assert "rm -rf" not in text
    assert "kill -9" not in text


def test_roadmap_links_disposition_and_current_native_failure() -> None:
    roadmap = _ROADMAP.read_text(encoding="utf-8")
    assert "docs/plans/2026-10-09-native-provider-disposition.md" in roadmap
    assert "38017034795" in roadmap
    assert "38015831978" in roadmap
    assert "no native acceptance" in roadmap.lower()


def test_runbook_reflects_recovery_workflow_and_documented_contract() -> None:
    workflow = _WORKFLOW.read_text(encoding="utf-8")
    recovery_readme = _RECOVERY_README.read_text(encoding="utf-8")
    runbook = _RUNBOOK.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in workflow
    assert "group: live-local-e2e" in workflow
    assert "if: github.ref == 'refs/heads/main'" in workflow
    assert "owner PID `0`" in recovery_readme
    assert "**no E2E temp directories remain**" in recovery_readme
    assert "trusted `main`" in runbook
    assert "owner PID `0`" in runbook
