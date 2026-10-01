from __future__ import annotations

import pytest

from ssh_over_mcp.approvals.binding import fingerprint_argv
from ssh_over_mcp.approvals.models import ApprovalBindingInput, ApprovalState
from ssh_over_mcp.approvals.protocol import (
    ApprovalStatusResponse,
    ErrorResponse,
    PongResponse,
    decode_ledger_request,
    encode_ledger_message,
)
from ssh_over_mcp.policy.models import RiskLevel


class FakeTransport:
    def __init__(self, responder):
        self.responder = responder
        self.frames: list[bytes] = []

    def round_trip(self, frame: bytes) -> bytes:
        self.frames.append(frame)
        request = decode_ledger_request(frame)
        return encode_ledger_message(self.responder(request))


def _binding() -> ApprovalBindingInput:
    return ApprovalBindingInput(
        principal_id="static:developer",
        profile="developer",
        host="dev01",
        tool="fs_mkdir",
        privilege="user",
        policy_version="sha256:policy",
        normalized_path="/srv/app/new",
        argv_count=0,
        argv_fingerprint=fingerprint_argv(()),
        effective_timeout_seconds=60.0,
        effective_max_output_bytes=4096,
    )


@pytest.mark.asyncio
async def test_execution_client_builds_typed_requests_and_correlates_response() -> None:
    from ssh_over_mcp.approvals.client import SecurityLedgerClient
    from ssh_over_mcp.approvals.dispatcher import safe_summary_from_binding
    from ssh_over_mcp.approvals.models import ApprovalStatus

    binding = _binding()

    def responder(request):
        summary = safe_summary_from_binding(binding, RiskLevel.HIGH)
        return ApprovalStatusResponse(
            message_id=request.message_id,
            status=ApprovalStatus(
                approval_id="apr_" + "a" * 32,
                state=ApprovalState.PENDING,
                expires_at=__import__("datetime").datetime(
                    2026,
                    10,
                    1,
                    18,
                    10,
                    tzinfo=__import__("datetime").UTC,
                ),
                host=binding.host,
                tool=binding.tool,
                risk=RiskLevel.HIGH,
                safe_summary=summary,
                binding_fingerprint="hmac-sha256:v1:" + "b" * 16,
            ),
        )

    transport = FakeTransport(responder)
    client = SecurityLedgerClient(transport)

    status = await client.ensure_approval(
        binding=binding,
        risk=RiskLevel.HIGH,
        request_id="req_" + "1" * 32,
    )

    assert status.approval_id == "apr_" + "a" * 32
    request = decode_ledger_request(transport.frames[0])
    assert request.op == "ensure_approval"
    assert request.binding == binding


@pytest.mark.asyncio
async def test_client_rejects_response_message_id_mismatch() -> None:
    from ssh_over_mcp.approvals.client import LedgerClientProtocolError, SecurityLedgerClient

    transport = FakeTransport(
        lambda _request: PongResponse(message_id="msg_" + "f" * 32)
    )
    client = SecurityLedgerClient(transport)

    with pytest.raises(LedgerClientProtocolError, match="correlation"):
        await client.ping()


@pytest.mark.asyncio
async def test_client_maps_remote_error_without_echoing_request_data() -> None:
    from ssh_over_mcp.approvals.client import LedgerRemoteError, SecurityLedgerClient

    transport = FakeTransport(
        lambda request: ErrorResponse(
            message_id=request.message_id,
            code="not_authorized",
        )
    )
    client = SecurityLedgerClient(transport)

    with pytest.raises(LedgerRemoteError, match="not_authorized") as exc_info:
        await client.ping()

    assert "SUPERSECRET" not in str(exc_info.value)
