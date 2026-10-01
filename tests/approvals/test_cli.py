from __future__ import annotations

import inspect
import io
import os
from datetime import UTC, datetime

import pytest

from ssh_over_mcp.approvals.models import (
    ApprovalSafeSummary,
    ApprovalState,
    ApprovalStatus,
)
from ssh_over_mcp.approvals.protocol import ApprovalListItem
from ssh_over_mcp.policy.models import RiskLevel


def _status() -> ApprovalStatus:
    summary = ApprovalSafeSummary(
        principal_id="static:developer",
        profile="developer",
        host="dev01",
        tool="fs_mkdir",
        privilege="user",
        policy_version="sha256:policy",
        risk=RiskLevel.HIGH,
        normalized_path="/srv/app/new",
        argv_count=0,
        argv_fingerprint="sha256:" + "a" * 64,
    )
    return ApprovalStatus(
        approval_id="apr_" + "1" * 32,
        state=ApprovalState.PENDING,
        expires_at=datetime(2026, 10, 1, 18, 10, tzinfo=UTC),
        host="dev01",
        tool="fs_mkdir",
        risk=RiskLevel.HIGH,
        safe_summary=summary,
        binding_fingerprint="hmac-sha256:v1:" + "b" * 16,
    )


class FakeAdminClient:
    def __init__(self) -> None:
        self.calls = []

    async def list_approvals(self, *, limit=100):
        self.calls.append(("list", limit))
        status = _status()
        return (
            ApprovalListItem(
                approval_id=status.approval_id,
                state=status.state,
                expires_at=status.expires_at,
                host=status.host,
                tool=status.tool,
                risk=status.risk,
                binding_fingerprint=status.binding_fingerprint,
            ),
        )

    async def show_approval(self, approval_id):
        self.calls.append(("show", approval_id))
        return _status()

    async def grant(self, approval_id):
        self.calls.append(("grant", approval_id))
        return _status().model_copy(update={"state": ApprovalState.GRANTED})

    async def deny(self, approval_id):
        self.calls.append(("deny", approval_id))
        return _status().model_copy(update={"state": ApprovalState.DENIED})


@pytest.mark.asyncio
@pytest.mark.parametrize("command", ["show", "grant", "deny"])
async def test_cli_commands_use_admin_client_without_actor_override(
    command: str,
) -> None:
    from ssh_over_mcp.approvals.cli import build_parser, execute_command

    client = FakeAdminClient()
    output = io.StringIO()
    approval_id = "apr_" + "1" * 32
    args = build_parser().parse_args([command, approval_id])

    result = await execute_command(args, client=client, stdout=output)

    assert result == 0
    assert client.calls == [(command, approval_id)]
    rendered = output.getvalue()
    assert approval_id in rendered
    assert "SUPERSECRET" not in rendered


@pytest.mark.asyncio
async def test_cli_list_output_is_bounded_safe_json() -> None:
    from ssh_over_mcp.approvals.cli import build_parser, execute_command

    client = FakeAdminClient()
    output = io.StringIO()
    args = build_parser().parse_args(["list"])

    result = await execute_command(args, client=client, stdout=output)

    assert result == 0
    assert client.calls == [("list", 100)]
    rendered = output.getvalue()
    assert '"approval_id"' in rendered
    assert '"binding_fingerprint"' in rendered
    assert "SUPERSECRET" not in rendered


def test_cli_parser_exposes_exact_commands_and_no_actor_option() -> None:
    from ssh_over_mcp.approvals.cli import build_parser

    parser = build_parser()
    for command in ("list", "show", "grant", "deny"):
        argv = [command] if command == "list" else [command, "apr_" + "1" * 32]
        assert parser.parse_args(argv).command == command

    with pytest.raises(SystemExit):
        parser.parse_args(["grant", "apr_" + "1" * 32, "--actor", "root"])


def test_cli_client_factory_requires_no_database_or_key_configuration(
    tmp_path,
) -> None:
    from ssh_over_mcp.approvals.cli import create_admin_client_from_env

    env = {
        "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_PATH": str(tmp_path / "admin.sock"),
        "SSH_OVER_MCP_LEDGER_SERVICE_UID": str(os.getuid()),
        "SSH_OVER_MCP_LEDGER_SERVICE_GID": str(os.getgid()),
    }

    client = create_admin_client_from_env(env)

    assert client is not None
    source = inspect.getsource(
        __import__("ssh_over_mcp.approvals.cli", fromlist=["*"])
    )
    for forbidden in (
        "sqlite3",
        "LedgerDatabase",
        "HMAC_KEY_PATH",
        "DB_PATH",
    ):
        assert forbidden not in source
