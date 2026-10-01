from __future__ import annotations

import asyncio
import uuid

from ssh_over_mcp.audit.models import AuditEventInput
from ssh_over_mcp.policy.models import RiskLevel

from .models import ApprovalBindingInput, ApprovalStatus
from .protocol import (
    AppendAuditRequest,
    ApprovalListItem,
    ApprovalListResponse,
    ApprovalStatusRequest,
    ApprovalStatusResponse,
    AuditAppendedResponse,
    ConsumeApprovalRequest,
    DenyApprovalRequest,
    EnsureApprovalRequest,
    ErrorResponse,
    GrantApprovalRequest,
    LedgerProtocolError,
    LedgerRequest,
    ListApprovalsRequest,
    PingRequest,
    PongResponse,
    ShowApprovalRequest,
    decode_ledger_response,
    encode_ledger_message,
)
from .transport import LedgerTransport


class LedgerClientError(RuntimeError):
    """Base class for stable local Security Ledger client failures."""


class LedgerClientProtocolError(LedgerClientError):
    """The ledger returned an invalid or mismatched response."""


class LedgerRemoteError(LedgerClientError):
    def __init__(self, code: str) -> None:
        super().__init__(f"Security Ledger request failed: {code}")
        self.code = code


class _BaseLedgerClient:
    def __init__(self, transport: LedgerTransport) -> None:
        self._transport = transport

    @staticmethod
    def _message_id() -> str:
        return f"msg_{uuid.uuid4().hex}"

    async def _call(self, request: LedgerRequest):
        frame = encode_ledger_message(request)
        response_frame = await asyncio.to_thread(
            self._transport.round_trip,
            frame,
        )
        try:
            response = decode_ledger_response(response_frame)
        except LedgerProtocolError:
            raise LedgerClientProtocolError(
                "Security Ledger response is invalid"
            ) from None
        if response.message_id != request.message_id:
            raise LedgerClientProtocolError(
                "Security Ledger response correlation failed"
            )
        if isinstance(response, ErrorResponse):
            raise LedgerRemoteError(response.code)
        return response


class SecurityLedgerClient(_BaseLedgerClient):
    async def ping(self) -> None:
        response = await self._call(
            PingRequest(message_id=self._message_id())
        )
        if not isinstance(response, PongResponse):
            raise LedgerClientProtocolError(
                "Security Ledger response type is invalid"
            )

    async def append_audit(self, event: AuditEventInput) -> str:
        response = await self._call(
            AppendAuditRequest(
                message_id=self._message_id(),
                event=event,
            )
        )
        if not isinstance(response, AuditAppendedResponse):
            raise LedgerClientProtocolError(
                "Security Ledger response type is invalid"
            )
        return response.event_id

    async def ensure_approval(
        self,
        *,
        binding: ApprovalBindingInput,
        risk: RiskLevel,
        request_id: str,
    ) -> ApprovalStatus:
        response = await self._call(
            EnsureApprovalRequest(
                message_id=self._message_id(),
                request_id=request_id,
                binding=binding,
                risk=risk,
            )
        )
        if not isinstance(response, ApprovalStatusResponse):
            raise LedgerClientProtocolError(
                "Security Ledger response type is invalid"
            )
        return response.status

    async def approval_status(
        self,
        *,
        approval_id: str,
        principal_id: str,
        profile: str,
    ) -> ApprovalStatus:
        response = await self._call(
            ApprovalStatusRequest(
                message_id=self._message_id(),
                approval_id=approval_id,
                principal_id=principal_id,
                profile=profile,
            )
        )
        if not isinstance(response, ApprovalStatusResponse):
            raise LedgerClientProtocolError(
                "Security Ledger response type is invalid"
            )
        return response.status

    async def consume_approval(
        self,
        *,
        approval_id: str,
        binding: ApprovalBindingInput,
        request_id: str,
    ) -> ApprovalStatus:
        response = await self._call(
            ConsumeApprovalRequest(
                message_id=self._message_id(),
                request_id=request_id,
                approval_id=approval_id,
                binding=binding,
            )
        )
        if not isinstance(response, ApprovalStatusResponse):
            raise LedgerClientProtocolError(
                "Security Ledger response type is invalid"
            )
        return response.status


class SecurityLedgerAdminClient(_BaseLedgerClient):
    async def list_approvals(
        self,
        *,
        limit: int = 100,
    ) -> tuple[ApprovalListItem, ...]:
        response = await self._call(
            ListApprovalsRequest(
                message_id=self._message_id(),
                limit=limit,
            )
        )
        if not isinstance(response, ApprovalListResponse):
            raise LedgerClientProtocolError(
                "Security Ledger response type is invalid"
            )
        return response.approvals

    async def show_approval(self, approval_id: str) -> ApprovalStatus:
        response = await self._call(
            ShowApprovalRequest(
                message_id=self._message_id(),
                approval_id=approval_id,
            )
        )
        if not isinstance(response, ApprovalStatusResponse):
            raise LedgerClientProtocolError(
                "Security Ledger response type is invalid"
            )
        return response.status

    async def grant(self, approval_id: str) -> ApprovalStatus:
        response = await self._call(
            GrantApprovalRequest(
                message_id=self._message_id(),
                approval_id=approval_id,
            )
        )
        if not isinstance(response, ApprovalStatusResponse):
            raise LedgerClientProtocolError(
                "Security Ledger response type is invalid"
            )
        return response.status

    async def deny(self, approval_id: str) -> ApprovalStatus:
        response = await self._call(
            DenyApprovalRequest(
                message_id=self._message_id(),
                approval_id=approval_id,
            )
        )
        if not isinstance(response, ApprovalStatusResponse):
            raise LedgerClientProtocolError(
                "Security Ledger response type is invalid"
            )
        return response.status
