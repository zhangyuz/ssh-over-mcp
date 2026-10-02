from __future__ import annotations

import subprocess
import sys


def _run_import_probe(source: str) -> None:
    result = subprocess.run(
        [sys.executable, "-c", source],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_audit_models_can_import_before_approvals_heavy_exports() -> None:
    _run_import_probe(
        """
import ssh_over_mcp.audit.models as audit_models
import ssh_over_mcp.approvals as approvals

assert audit_models.AuditEventInput is not None
assert approvals.SecurityLedgerClient is not None
assert approvals.SecurityLedgerService is not None
"""
    )


def test_audit_recorder_can_import_before_dispatcher_and_ssh_executor() -> None:
    _run_import_probe(
        """
import ssh_over_mcp.audit.recorder as recorder
import ssh_over_mcp.approvals.dispatcher as dispatcher
import ssh_over_mcp.ssh.executor as executor

assert recorder.AuditRecorder is not None
assert dispatcher.ExecutionLedgerDispatcher is not None
assert executor.SSHExecutor is not None
"""
    )
