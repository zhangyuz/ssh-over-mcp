from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "docs/superpowers/specs/2026-10-02-phase-7a-local-e2e-foundation-design.md"
TRIGGERS = (
    "SSH", "authorization", "approvals/Ledger", "credentials", "host-agent",
    "containment", "filesystem mutation", "audit", "workload identity",
    "OS hardening", "egress", "SSH CA", "secret-manager", "E2E fixture",
    "phase closure", "release",
)


def test_level3_trigger_guidance_agrees_with_normative_methodology() -> None:
    for relative in (
        "docs/development-methodology.md",
        "docs/self-hosted-runner.md",
        "docs/superpowers/specs/2026-10-02-phase-7a-local-e2e-foundation-design.md",
    ):
        normalized = " ".join((ROOT / relative).read_text().split()).lower()
        for trigger in TRIGGERS:
            assert trigger.lower() in normalized, (relative, trigger)


def test_phase7a_matrix_has_25_resolvable_executable_evidence_rows() -> None:
    text = SPEC.read_text()
    section = text.split("## 18. Phase 7A evidence matrix", 1)[1]
    rows = re.findall(r"^\| (\d+) \| (.+)$", section, re.MULTILINE)
    assert [int(number) for number, _ in rows] == list(range(1, 26))
    for number, row in rows:
        evidence_paths = re.findall(r"`((?:tests|scripts|ops)/[^`]+)`", row)
        assert evidence_paths, number
        for relative in evidence_paths:
            assert (ROOT / relative).is_file(), (number, relative)


def test_phase7a_evidence_distinguishes_verified_task7_from_pending_closure() -> None:
    text = SPEC.read_text()
    assert "d373598e7d0b5371765354a9ba89bf93f822828f" in text
    for run in ("37396007211", "37396022348", "37396564506", "37396581780"):
        assert f"https://github.com/zhangyuz/ssh-over-mcp/actions/runs/{run}" in text
    assert "Phase 7A4 exact-head gates and cleanup remain pending" in text
    assert "target manager/probe/support" in text
    assert "not its own attestation harness" not in text
