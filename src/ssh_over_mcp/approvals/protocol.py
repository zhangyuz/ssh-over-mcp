from __future__ import annotations

import struct
from datetime import datetime, timedelta
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    field_validator,
)

from ssh_over_mcp.audit.models import AuditEventInput
from ssh_over_mcp.policy.models import RiskLevel

from .models import ApprovalBindingInput, ApprovalState, ApprovalStatus

LEDGER_PROTOCOL_MAGIC = b"SLED\x00\x01"
MAX_LEDGER_MESSAGE_BYTES = 64 * 1024

_MESSAGE_ID = r"^msg_[0-9a-f]{32}$"
_REQUEST_ID = r"^req_[0-9a-f]{32}$"
_APPROVAL_ID = r"^apr_[0-9a-f]{32}$"
_EVENT_ID = r"^evt_[0-9a-f]{32}$"
_SHORT_HMAC = r"^hmac-sha256:v1:[0-9a-f]{16}$"

_MAX_IDENTITY_CHARS = 256
_MAX_TOOL_CHARS = 128


class LedgerProtocolError(ValueError):
    """Invalid Security Ledger framing or message schema."""


class _Message(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal[1] = 1
    message_id: str = Field(pattern=_MESSAGE_ID)


class PingRequest(_Message):
    op: Literal["ping"] = "ping"


class AppendAuditRequest(_Message):
    op: Literal["append_audit"] = "append_audit"
    event: AuditEventInput


class EnsureApprovalRequest(_Message):
    op: Literal["ensure_approval"] = "ensure_approval"
    request_id: str = Field(pattern=_REQUEST_ID)
    binding: ApprovalBindingInput
    risk: RiskLevel


class ApprovalStatusRequest(_Message):
    op: Literal["approval_status"] = "approval_status"
    approval_id: str = Field(pattern=_APPROVAL_ID)
    principal_id: str = Field(min_length=1, max_length=_MAX_IDENTITY_CHARS)
    profile: str = Field(min_length=1, max_length=_MAX_IDENTITY_CHARS)


class ConsumeApprovalRequest(_Message):
    op: Literal["consume_approval"] = "consume_approval"
    approval_id: str = Field(pattern=_APPROVAL_ID)
    binding: ApprovalBindingInput


class ListApprovalsRequest(_Message):
    op: Literal["list_approvals"] = "list_approvals"
    limit: int = Field(default=100, strict=True, ge=1, le=100)


class ShowApprovalRequest(_Message):
    op: Literal["show_approval"] = "show_approval"
    approval_id: str = Field(pattern=_APPROVAL_ID)


class GrantApprovalRequest(_Message):
    op: Literal["grant_approval"] = "grant_approval"
    approval_id: str = Field(pattern=_APPROVAL_ID)


class DenyApprovalRequest(_Message):
    op: Literal["deny_approval"] = "deny_approval"
    approval_id: str = Field(pattern=_APPROVAL_ID)


LedgerRequest = Annotated[
    PingRequest
    | AppendAuditRequest
    | EnsureApprovalRequest
    | ApprovalStatusRequest
    | ConsumeApprovalRequest
    | ListApprovalsRequest
    | ShowApprovalRequest
    | GrantApprovalRequest
    | DenyApprovalRequest,
    Field(discriminator="op"),
]


class PongResponse(_Message):
    type: Literal["pong"] = "pong"


class AuditAppendedResponse(_Message):
    type: Literal["audit_appended"] = "audit_appended"
    event_id: str = Field(pattern=_EVENT_ID)


class ApprovalStatusResponse(_Message):
    type: Literal["approval_status"] = "approval_status"
    status: ApprovalStatus


class ApprovalListItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    approval_id: str = Field(pattern=_APPROVAL_ID)
    state: ApprovalState
    expires_at: datetime
    host: str = Field(min_length=1, max_length=_MAX_IDENTITY_CHARS)
    tool: str = Field(min_length=1, max_length=_MAX_TOOL_CHARS)
    risk: RiskLevel
    binding_fingerprint: str = Field(pattern=_SHORT_HMAC)

    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("expires_at must be timezone-aware UTC")
        return value


class ApprovalListResponse(_Message):
    type: Literal["approval_list"] = "approval_list"
    approvals: tuple[ApprovalListItem, ...] = Field(
        default_factory=tuple,
        max_length=100,
    )


class ErrorResponse(_Message):
    type: Literal["error"] = "error"
    code: Literal[
        "invalid_request",
        "not_authorized",
        "not_found",
        "conflict",
        "expired",
        "unavailable",
        "internal",
    ]


LedgerResponse = Annotated[
    PongResponse
    | AuditAppendedResponse
    | ApprovalStatusResponse
    | ApprovalListResponse
    | ErrorResponse,
    Field(discriminator="type"),
]

_REQUEST_ADAPTER = TypeAdapter(LedgerRequest)
_RESPONSE_ADAPTER = TypeAdapter(LedgerResponse)


def encode_ledger_message(message: BaseModel) -> bytes:
    payload = message.model_dump_json(
        exclude_none=True,
        by_alias=True,
    ).encode("utf-8")
    if len(payload) > MAX_LEDGER_MESSAGE_BYTES:
        raise LedgerProtocolError(
            "Security Ledger message exceeds maximum"
        )
    return (
        LEDGER_PROTOCOL_MAGIC
        + struct.pack(">I", len(payload))
        + payload
    )


def _decode_payload(frame: bytes) -> bytes:
    header_size = len(LEDGER_PROTOCOL_MAGIC) + 4
    if len(frame) < header_size:
        raise LedgerProtocolError("truncated Security Ledger frame")
    if frame[: len(LEDGER_PROTOCOL_MAGIC)] != LEDGER_PROTOCOL_MAGIC:
        raise LedgerProtocolError("invalid Security Ledger magic")

    (length,) = struct.unpack(
        ">I",
        frame[len(LEDGER_PROTOCOL_MAGIC) : header_size],
    )
    if length > MAX_LEDGER_MESSAGE_BYTES:
        raise LedgerProtocolError(
            "Security Ledger message exceeds maximum"
        )
    if len(frame) != header_size + length:
        raise LedgerProtocolError(
            "invalid Security Ledger frame length"
        )
    return frame[header_size:]


def decode_ledger_request(frame: bytes) -> LedgerRequest:
    try:
        return _REQUEST_ADAPTER.validate_json(_decode_payload(frame))
    except LedgerProtocolError:
        raise
    except Exception as exc:
        raise LedgerProtocolError(
            "invalid Security Ledger request"
        ) from exc


def decode_ledger_response(frame: bytes) -> LedgerResponse:
    try:
        return _RESPONSE_ADAPTER.validate_json(_decode_payload(frame))
    except LedgerProtocolError:
        raise
    except Exception as exc:
        raise LedgerProtocolError(
            "invalid Security Ledger response"
        ) from exc
