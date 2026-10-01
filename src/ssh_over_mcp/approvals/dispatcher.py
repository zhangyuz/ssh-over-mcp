from __future__ import annotations

from ssh_over_mcp.host_agent.containment_manager_peer import LinuxPeerCredentials
from ssh_over_mcp.policy.models import RiskLevel

from .ledger import (
    LedgerConflictError,
    LedgerExpiredError,
    LedgerNotAuthorizedError,
    LedgerNotFoundError,
    LedgerPersistenceError,
    SecurityLedgerStore,
)
from .models import ApprovalBindingInput, ApprovalSafeSummary, ApprovalStatus
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
    LedgerRequest,
    LedgerResponse,
    ListApprovalsRequest,
    PingRequest,
    PongResponse,
    ShowApprovalRequest,
)


def safe_summary_from_binding(
    binding: ApprovalBindingInput,
    risk: RiskLevel,
) -> ApprovalSafeSummary:
    return ApprovalSafeSummary(
        principal_id=binding.principal_id,
        profile=binding.profile,
        host=binding.host,
        tool=binding.tool,
        privilege=binding.privilege,
        policy_version=binding.policy_version,
        risk=risk,
        normalized_executable=binding.normalized_executable,
        normalized_cwd=binding.normalized_cwd,
        normalized_path=binding.normalized_path,
        argv_count=binding.argv_count,
        argv_fingerprint=binding.argv_fingerprint,
        env_names=tuple(item.name for item in binding.env_fingerprints),
        stdin_length=binding.stdin_length,
        stdin_fingerprint=binding.stdin_fingerprint,
        content_length=binding.content_length,
        content_fingerprint=binding.content_fingerprint,
        effective_timeout_seconds=binding.effective_timeout_seconds,
        effective_max_output_bytes=binding.effective_max_output_bytes,
        effective_max_stdin_bytes=binding.effective_max_stdin_bytes,
        effective_tool_bytes=binding.effective_tool_bytes,
    )


def _error(message_id: str, code: str) -> ErrorResponse:
    return ErrorResponse(message_id=message_id, code=code)


def _map_store_error(message_id: str, exc: Exception) -> ErrorResponse:
    if isinstance(exc, LedgerExpiredError):
        return _error(message_id, "expired")
    if isinstance(exc, LedgerNotAuthorizedError):
        return _error(message_id, "not_authorized")
    if isinstance(exc, LedgerNotFoundError):
        return _error(message_id, "not_found")
    if isinstance(exc, LedgerConflictError):
        return _error(message_id, "conflict")
    if isinstance(exc, LedgerPersistenceError):
        return _error(message_id, "unavailable")
    if isinstance(exc, ValueError):
        return _error(message_id, "invalid_request")
    return _error(message_id, "internal")


def _status_response(
    message_id: str,
    status: ApprovalStatus,
) -> ApprovalStatusResponse:
    return ApprovalStatusResponse(
        message_id=message_id,
        status=status,
    )


class ExecutionLedgerDispatcher:
    def __init__(self, store: SecurityLedgerStore) -> None:
        self._store = store

    def dispatch(
        self,
        request: LedgerRequest,
        *,
        peer: LinuxPeerCredentials,
    ) -> LedgerResponse:
        del peer
        try:
            if isinstance(request, PingRequest):
                return PongResponse(message_id=request.message_id)
            if isinstance(request, AppendAuditRequest):
                event_id = self._store.append_audit(request.event)
                return AuditAppendedResponse(
                    message_id=request.message_id,
                    event_id=event_id,
                )
            if isinstance(request, EnsureApprovalRequest):
                summary = safe_summary_from_binding(
                    request.binding,
                    request.risk,
                )
                status = self._store.ensure_approval(
                    request.binding,
                    summary,
                    request.request_id,
                )
                return _status_response(request.message_id, status)
            if isinstance(request, ApprovalStatusRequest):
                status = self._store.get_approval(
                    request.approval_id,
                    principal_id=request.principal_id,
                    profile=request.profile,
                )
                if status is None:
                    return _error(request.message_id, "not_found")
                return _status_response(request.message_id, status)
            if isinstance(request, ConsumeApprovalRequest):
                status = self._store.consume(
                    request.approval_id,
                    request.binding,
                    request.request_id,
                )
                return _status_response(request.message_id, status)
            return _error(request.message_id, "not_authorized")
        except Exception as exc:  # noqa: BLE001
            return _map_store_error(request.message_id, exc)


class AdminLedgerDispatcher:
    def __init__(self, store: SecurityLedgerStore) -> None:
        self._store = store

    def dispatch(
        self,
        request: LedgerRequest,
        *,
        peer: LinuxPeerCredentials,
    ) -> LedgerResponse:
        try:
            if isinstance(request, ListApprovalsRequest):
                statuses = self._store.list_active(request.limit)
                return ApprovalListResponse(
                    message_id=request.message_id,
                    approvals=tuple(
                        ApprovalListItem(
                            approval_id=item.approval_id,
                            state=item.state,
                            expires_at=item.expires_at,
                            host=item.host,
                            tool=item.tool,
                            risk=item.risk,
                            binding_fingerprint=item.binding_fingerprint,
                        )
                        for item in statuses
                    ),
                )
            if isinstance(request, ShowApprovalRequest):
                status = self._store.get_approval(request.approval_id)
                if status is None:
                    return _error(request.message_id, "not_found")
                return _status_response(request.message_id, status)

            operator_identity = f"uid:{peer.uid}:gid:{peer.gid}"
            if isinstance(request, GrantApprovalRequest):
                status = self._store.grant(
                    request.approval_id,
                    operator_identity=operator_identity,
                )
                return _status_response(request.message_id, status)
            if isinstance(request, DenyApprovalRequest):
                status = self._store.deny(
                    request.approval_id,
                    operator_identity=operator_identity,
                )
                return _status_response(request.message_id, status)
            return _error(request.message_id, "not_authorized")
        except Exception as exc:  # noqa: BLE001
            return _map_store_error(request.message_id, exc)
