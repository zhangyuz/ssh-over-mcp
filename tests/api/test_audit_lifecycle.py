from __future__ import annotations

import pytest
from mcp import Client

from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.api.errors import HostNotVisibleError
from ssh_over_mcp.api.models import (
    FsMkdirResult,
    FsReadResult,
    FsStatResult,
    FsWriteResult,
    HostsListResult,
    HostSummary,
    PolicyExplainResult,
    PrincipalContext,
    SSHExecResult,
)
from ssh_over_mcp.api.server import build_mcp_server
from ssh_over_mcp.audit.models import AuditEventType
from ssh_over_mcp.audit.recorder import AuditRecorder
from ssh_over_mcp.policy.models import Decision, RiskLevel


class PrincipalProvider:
    def get_principal(self) -> PrincipalContext:
        return PrincipalContext(
            principal_id="static:developer",
            profile="developer",
        )


class RecordingLedger:
    def __init__(self) -> None:
        self.events = []
        self.error: Exception | None = None

    async def append_audit(self, event):
        if self.error is not None:
            raise self.error
        self.events.append(event)
        return "evt_" + ("a" * 32)


class RecordingService:
    def __init__(self) -> None:
        self.calls = []

    def list_hosts(self, context: OperationContext) -> HostsListResult:
        self.calls.append(("hosts_list", context))
        return HostsListResult(hosts=(HostSummary(alias="host-a"),))

    def get_host(
        self,
        context: OperationContext,
        alias: str,
    ) -> HostSummary:
        self.calls.append(("host_info", context, alias))
        if alias == "hidden":
            raise HostNotVisibleError("host is not visible")
        return HostSummary(alias=alias)

    def explain_policy(
        self,
        context: OperationContext,
        request,
    ) -> PolicyExplainResult:
        self.calls.append(("policy_explain", context, request))
        return PolicyExplainResult(
            decision=Decision.ALLOW,
            reason="allowed by central policy",
            risk=RiskLevel.LOW,
            normalized_path=request.path,
            approval_required=False,
            policy_version="sha256:test",
        )

    async def ssh_exec(self, context, request) -> SSHExecResult:
        self.calls.append(("ssh_exec", context, request))
        return SSHExecResult(
            request_id=context.request_id,
            host=request.host,
            exit_status=0,
            duration_ms=1,
        )

    async def fs_stat(self, context, request) -> FsStatResult:
        self.calls.append(("fs_stat", context, request))
        return FsStatResult(
            request_id=context.request_id,
            host=request.host,
            path=request.path,
            kind="regular",
            size=1,
            mode=0o600,
            uid=1000,
            gid=1000,
            mtime_ns=1,
        )

    async def fs_read(self, context, request) -> FsReadResult:
        self.calls.append(("fs_read", context, request))
        return FsReadResult(
            request_id=context.request_id,
            host=request.host,
            path=request.path,
            data_base64="eA==",
        )

    async def fs_mkdir(self, context, request) -> FsMkdirResult:
        self.calls.append(("fs_mkdir", context, request))
        return FsMkdirResult(
            request_id=context.request_id,
            host=request.host,
            path=request.path,
        )

    async def fs_write(self, context, request) -> FsWriteResult:
        self.calls.append(("fs_write", context, request))
        return FsWriteResult(
            request_id=context.request_id,
            host=request.host,
            path=request.path,
            content_length=len(request.decoded_data()),
        )


_CALLS = (
    ("hosts_list", {}),
    ("host_info", {"alias": "host-a"}),
    (
        "policy_explain",
        {"host": "host-a", "tool": "fs_stat", "path": "/srv/app/file"},
    ),
    (
        "ssh_exec",
        {"host": "host-a", "executable": "/bin/echo", "args": ["ok"]},
    ),
    ("fs_stat", {"host": "host-a", "path": "/srv/app/file"}),
    (
        "fs_read",
        {"host": "host-a", "path": "/srv/app/file", "max_bytes": 1},
    ),
    ("fs_mkdir", {"host": "host-a", "path": "/srv/app/new"}),
    (
        "fs_write",
        {
            "host": "host-a",
            "path": "/srv/app/new.bin",
            "data_base64": "eA==",
        },
    ),
)


@pytest.mark.asyncio
async def test_all_tools_append_request_received_before_domain_call() -> None:
    ledger = RecordingLedger()
    service = RecordingService()
    server = build_mcp_server(
        service=service,
        principal_provider=PrincipalProvider(),
        audit=AuditRecorder(ledger),
    )

    async with Client(server) as client:
        for name, arguments in _CALLS:
            result = await client.call_tool(name, arguments)
            assert result.is_error is False

    request_events = [
        event
        for event in ledger.events
        if event.event_type is AuditEventType.REQUEST_RECEIVED
    ]
    assert [event.tool for event in request_events] == [
        name for name, _arguments in _CALLS
    ]
    assert len(service.calls) == len(_CALLS)

    for event, call in zip(request_events, service.calls, strict=True):
        context = call[1]
        assert event.request_id == context.request_id
        assert event.principal_id == "static:developer"
        assert event.profile == "developer"

    assert request_events[0].host is None
    assert request_events[1].host == "host-a"


@pytest.mark.asyncio
async def test_discovery_tools_append_completion_and_failure() -> None:
    ledger = RecordingLedger()
    service = RecordingService()
    server = build_mcp_server(
        service=service,
        principal_provider=PrincipalProvider(),
        audit=AuditRecorder(ledger),
    )

    async with Client(server) as client:
        ok = await client.call_tool("hosts_list", {})
        hidden = await client.call_tool("host_info", {"alias": "hidden"})
        explained = await client.call_tool(
            "policy_explain",
            {
                "host": "host-a",
                "tool": "fs_stat",
                "path": "/srv/app/file",
            },
        )

    assert ok.is_error is False
    assert hidden.is_error is True
    assert explained.is_error is False

    lifecycle = [
        (event.tool, event.event_type)
        for event in ledger.events
    ]
    assert lifecycle == [
        ("hosts_list", AuditEventType.REQUEST_RECEIVED),
        ("hosts_list", AuditEventType.EXECUTION_COMPLETED),
        ("host_info", AuditEventType.REQUEST_RECEIVED),
        ("host_info", AuditEventType.EXECUTION_FAILED),
        ("policy_explain", AuditEventType.REQUEST_RECEIVED),
        ("policy_explain", AuditEventType.EXECUTION_COMPLETED),
    ]


@pytest.mark.asyncio
async def test_request_received_audit_failure_blocks_domain_call() -> None:
    ledger = RecordingLedger()
    ledger.error = RuntimeError("SUPERSECRET ledger detail")
    service = RecordingService()
    server = build_mcp_server(
        service=service,
        principal_provider=PrincipalProvider(),
        audit=AuditRecorder(ledger),
    )

    async with Client(server) as client:
        for name, arguments in _CALLS:
            result = await client.call_tool(name, arguments)
            assert result.is_error is True
            text = "\n".join(
                getattr(block, "text", "")
                for block in result.content
            )
            assert "audit persistence failed" in text
            assert "SUPERSECRET" not in text

    assert service.calls == []
