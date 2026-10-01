from __future__ import annotations

import json
import struct
from datetime import UTC, datetime

import pytest
from pydantic import BaseModel, ConfigDict

from ssh_over_mcp.approvals.models import (
    ApprovalBindingInput,
    ApprovalEnvFingerprint,
    ApprovalSafeSummary,
    ApprovalState,
    ApprovalStatus,
)
from ssh_over_mcp.audit.models import AuditEventInput, AuditEventType
from ssh_over_mcp.policy.models import RiskLevel

MSG_ID = "msg_" + ("1" * 32)
REQ_ID = "req_" + ("2" * 32)
APR_ID = "apr_" + ("3" * 32)
EVENT_ID = "evt_" + ("4" * 32)
FP = "sha256:" + ("a" * 64)
SHORT_HMAC = "hmac-sha256:v1:" + ("b" * 16)


def _binding() -> ApprovalBindingInput:
    return ApprovalBindingInput(
        principal_id="static:developer",
        profile="developer",
        host="dev01",
        tool="ssh_exec",
        privilege="user",
        policy_version="sha256:test",
        normalized_executable="/usr/bin/id",
        normalized_cwd="/srv/app",
        argv_count=1,
        argv_fingerprint=FP,
        env_fingerprints=(
            ApprovalEnvFingerprint(
                name="LANG",
                value_fingerprint=FP,
            ),
        ),
        effective_timeout_seconds=30.0,
        effective_max_output_bytes=65536,
        effective_max_stdin_bytes=65536,
    )


def _summary() -> ApprovalSafeSummary:
    return ApprovalSafeSummary(
        principal_id="static:developer",
        profile="developer",
        host="dev01",
        tool="ssh_exec",
        privilege="user",
        policy_version="sha256:test",
        risk=RiskLevel.HIGH,
        normalized_executable="/usr/bin/id",
        normalized_cwd="/srv/app",
        argv_count=1,
        argv_fingerprint=FP,
        env_names=("LANG",),
        effective_timeout_seconds=30.0,
        effective_max_output_bytes=65536,
        effective_max_stdin_bytes=65536,
    )


def _status() -> ApprovalStatus:
    return ApprovalStatus(
        approval_id=APR_ID,
        state=ApprovalState.PENDING,
        expires_at=datetime(2026, 10, 1, 17, 0, tzinfo=UTC),
        host="dev01",
        tool="ssh_exec",
        risk=RiskLevel.HIGH,
        safe_summary=_summary(),
        binding_fingerprint=SHORT_HMAC,
    )


def _audit() -> AuditEventInput:
    return AuditEventInput(
        event_type=AuditEventType.REQUEST_RECEIVED,
        request_id=REQ_ID,
        principal_id="static:developer",
        profile="developer",
        host="dev01",
        tool="ssh_exec",
    )


def _frame(raw: bytes, *, magic: bytes | None = None) -> bytes:
    from ssh_over_mcp.approvals.protocol import LEDGER_PROTOCOL_MAGIC

    prefix = LEDGER_PROTOCOL_MAGIC if magic is None else magic
    return prefix + struct.pack(">I", len(raw)) + raw


def test_execution_and_admin_requests_round_trip_strictly() -> None:
    from ssh_over_mcp.approvals.protocol import (
        AppendAuditRequest,
        ApprovalStatusRequest,
        ConsumeApprovalRequest,
        DenyApprovalRequest,
        EnsureApprovalRequest,
        GrantApprovalRequest,
        ListApprovalsRequest,
        PingRequest,
        ShowApprovalRequest,
        decode_ledger_request,
        encode_ledger_message,
    )

    requests = (
        PingRequest(message_id=MSG_ID),
        AppendAuditRequest(message_id=MSG_ID, event=_audit()),
        EnsureApprovalRequest(
            message_id=MSG_ID,
            request_id=REQ_ID,
            binding=_binding(),
            risk=RiskLevel.HIGH,
        ),
        ApprovalStatusRequest(
            message_id=MSG_ID,
            approval_id=APR_ID,
            principal_id="static:developer",
            profile="developer",
        ),
        ConsumeApprovalRequest(
            message_id=MSG_ID,
            approval_id=APR_ID,
            binding=_binding(),
        ),
        ListApprovalsRequest(message_id=MSG_ID, limit=100),
        ShowApprovalRequest(message_id=MSG_ID, approval_id=APR_ID),
        GrantApprovalRequest(message_id=MSG_ID, approval_id=APR_ID),
        DenyApprovalRequest(message_id=MSG_ID, approval_id=APR_ID),
    )

    for request in requests:
        decoded = decode_ledger_request(encode_ledger_message(request))
        assert decoded == request
        assert decoded.version == 1
        assert decoded.message_id == MSG_ID


def test_responses_round_trip_strictly() -> None:
    from ssh_over_mcp.approvals.protocol import (
        ApprovalListItem,
        ApprovalListResponse,
        ApprovalStatusResponse,
        AuditAppendedResponse,
        ErrorResponse,
        PongResponse,
        decode_ledger_response,
        encode_ledger_message,
    )

    item = ApprovalListItem(
        approval_id=APR_ID,
        state=ApprovalState.PENDING,
        expires_at=datetime(2026, 10, 1, 17, 0, tzinfo=UTC),
        host="dev01",
        tool="ssh_exec",
        risk=RiskLevel.HIGH,
        binding_fingerprint=SHORT_HMAC,
    )
    responses = (
        PongResponse(message_id=MSG_ID),
        AuditAppendedResponse(message_id=MSG_ID, event_id=EVENT_ID),
        ApprovalStatusResponse(message_id=MSG_ID, status=_status()),
        ApprovalListResponse(message_id=MSG_ID, approvals=(item,)),
        ErrorResponse(message_id=MSG_ID, code="not_authorized"),
    )

    for response in responses:
        decoded = decode_ledger_response(encode_ledger_message(response))
        assert decoded == response


@pytest.mark.parametrize(
    "payload",
    [
        {
            "version": 2,
            "message_id": MSG_ID,
            "op": "ping",
        },
        {
            "version": 1,
            "message_id": "msg_bad",
            "op": "ping",
        },
        {
            "version": 1,
            "message_id": MSG_ID,
            "op": "ensure_approval",
            "request_id": REQ_ID,
            "binding": _binding().model_dump(mode="json"),
            "risk": RiskLevel.HIGH.value,
            "ttl_seconds": 600,
        },
        {
            "version": 1,
            "message_id": MSG_ID,
            "op": "grant_approval",
            "approval_id": APR_ID,
            "operator_identity": "uid:0",
        },
        {
            "version": 1,
            "message_id": MSG_ID,
            "op": "consume_approval",
            "approval_id": APR_ID,
            "binding": _binding().model_dump(mode="json"),
            "binding_hmac": "SUPERSECRET",
        },
    ],
)
def test_requests_reject_wrong_version_ids_and_caller_owned_authority_fields(
    payload: dict[str, object],
) -> None:
    from ssh_over_mcp.approvals.protocol import (
        LedgerProtocolError,
        decode_ledger_request,
    )

    raw = json.dumps(payload, separators=(",", ":")).encode()
    with pytest.raises(LedgerProtocolError):
        decode_ledger_request(_frame(raw))


def test_request_response_discriminator_confusion_is_rejected() -> None:
    from ssh_over_mcp.approvals.protocol import (
        LedgerProtocolError,
        PingRequest,
        PongResponse,
        decode_ledger_request,
        decode_ledger_response,
        encode_ledger_message,
    )

    with pytest.raises(LedgerProtocolError):
        decode_ledger_response(
            encode_ledger_message(PingRequest(message_id=MSG_ID))
        )
    with pytest.raises(LedgerProtocolError):
        decode_ledger_request(
            encode_ledger_message(PongResponse(message_id=MSG_ID))
        )


@pytest.mark.parametrize(
    "frame_factory",
    [
        lambda: b"",
        lambda: b"wrong-magic",
        lambda: _frame(b"{}", magic=b"WRONG!"),
        lambda: (
            __import__("ssh_over_mcp.approvals.protocol", fromlist=["x"])
            .LEDGER_PROTOCOL_MAGIC
            + struct.pack(">I", 100)
            + b"{}"
        ),
        lambda: (
            __import__("ssh_over_mcp.approvals.protocol", fromlist=["x"])
            .LEDGER_PROTOCOL_MAGIC
            + struct.pack(
                ">I",
                __import__(
                    "ssh_over_mcp.approvals.protocol",
                    fromlist=["x"],
                ).MAX_LEDGER_MESSAGE_BYTES
                + 1,
            )
        ),
    ],
)
def test_invalid_frames_fail_closed(frame_factory) -> None:
    from ssh_over_mcp.approvals.protocol import (
        LedgerProtocolError,
        decode_ledger_request,
    )

    with pytest.raises(LedgerProtocolError):
        decode_ledger_request(frame_factory())


def test_maximum_legal_ensure_request_fits_ledger_frame() -> None:
    from ssh_over_mcp.approvals.protocol import (
        MAX_LEDGER_MESSAGE_BYTES,
        EnsureApprovalRequest,
        encode_ledger_message,
    )

    def fixed(prefix: str, length: int) -> str:
        return prefix + ("x" * (length - len(prefix)))

    envs = tuple(
        ApprovalEnvFingerprint(
            name=fixed(f"E{i:03d}_", 128),
            value_fingerprint=FP,
        )
        for i in range(128)
    )
    binding = ApprovalBindingInput(
        principal_id="p" * 256,
        profile="r" * 256,
        host="h" * 256,
        tool="t" * 128,
        privilege="u" * 256,
        policy_version="v" * 256,
        normalized_executable="e" * 4096,
        normalized_cwd="c" * 4096,
        normalized_path="x" * 4096,
        argv_count=256,
        argv_fingerprint=FP,
        env_fingerprints=envs,
        stdin_length=65536,
        stdin_fingerprint=FP,
        content_length=65536,
        content_fingerprint=FP,
        effective_timeout_seconds=60.0,
        effective_max_output_bytes=64 * 1024 * 1024,
        effective_max_stdin_bytes=65536,
        effective_tool_bytes=64 * 1024 * 1024,
    )

    frame = encode_ledger_message(
        EnsureApprovalRequest(
            message_id=MSG_ID,
            request_id=REQ_ID,
            binding=binding,
            risk=RiskLevel.CRITICAL,
        )
    )

    header_bytes = 10
    assert len(frame) <= header_bytes + MAX_LEDGER_MESSAGE_BYTES
    assert b"SUPERSECRET" not in frame


def test_encoding_rejects_payload_over_message_limit() -> None:
    from ssh_over_mcp.approvals.protocol import (
        MAX_LEDGER_MESSAGE_BYTES,
        LedgerProtocolError,
        encode_ledger_message,
    )

    class Oversized(BaseModel):
        model_config = ConfigDict(extra="forbid", frozen=True)
        data: str

    with pytest.raises(
        LedgerProtocolError,
        match="message exceeds maximum",
    ):
        encode_ledger_message(
            Oversized(data="x" * (MAX_LEDGER_MESSAGE_BYTES + 1))
        )
