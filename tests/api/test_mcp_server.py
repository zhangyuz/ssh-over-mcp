from __future__ import annotations

from datetime import UTC
from typing import Any

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
from ssh_over_mcp.policy.models import Decision, RiskLevel


class StaticTestPrincipalProvider:
    def get_principal(self) -> PrincipalContext:
        return PrincipalContext(principal_id="static:developer", profile="developer")


class RecordingService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []

    def list_hosts(self, context: OperationContext) -> HostsListResult:
        self.calls.append(("hosts_list", context.principal))
        return HostsListResult(
            hosts=(HostSummary(alias="host-a"),)
        )

    def get_host(
        self,
        context: OperationContext,
        alias: str,
    ) -> HostSummary:
        self.calls.append(("host_info", (context.principal, alias)))
        if alias != "host-a":
            raise HostNotVisibleError("host is not visible")
        return HostSummary(alias=alias)

    def explain_policy(
        self,
        context: OperationContext,
        request,
    ) -> PolicyExplainResult:
        self.calls.append(("policy_explain", (context.principal, request)))
        return PolicyExplainResult(
            decision=Decision.ALLOW,
            reason="allowed by central policy",
            risk=RiskLevel.LOW,
            normalized_executable=request.executable,
            normalized_cwd=request.cwd,
            normalized_path=request.path,
            approval_required=False,
            policy_version="sha256:test",
        )


def tool_error_text(result) -> str:
    return "\n".join(
        getattr(block, "text", "")
        for block in result.content
    )


@pytest.mark.asyncio
async def test_server_registers_closed_world_tool_surface() -> None:
    service = RecordingService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticTestPrincipalProvider(),
    )

    async with Client(server) as client:
        listed = await client.list_tools()

    assert {tool.name for tool in listed.tools} == {
        "hosts_list",
        "host_info",
        "policy_explain",
        "ssh_exec",
        "fs_stat",
        "fs_read",
        "fs_mkdir",
        "fs_write",
    }
    for tool in listed.tools:
        assert tool.annotations is not None
        if tool.name == "ssh_exec":
            assert tool.annotations.read_only_hint is False
            assert tool.annotations.destructive_hint is True
        elif tool.name in {"fs_mkdir", "fs_write"}:
            assert tool.annotations.read_only_hint is False
            assert tool.annotations.destructive_hint is False
            assert tool.annotations.idempotent_hint is False
        else:
            assert tool.annotations.read_only_hint is True
        assert tool.annotations.open_world_hint is False
        assert tool.input_schema["additionalProperties"] is False
        properties = tool.input_schema.get("properties", {})
        for forbidden in (
            "profile",
            "address",
            "port",
            "ssh_user",
            "credential_ref",
            "host_key",
            "credential_map",
            "key_path",
        ):
            assert forbidden not in properties


@pytest.mark.asyncio
async def test_policy_explain_schema_restricts_tool_names() -> None:
    server = build_mcp_server(
        service=RecordingService(),
        principal_provider=StaticTestPrincipalProvider(),
    )

    async with Client(server) as client:
        listed = await client.list_tools()

    tool = next(
        item for item in listed.tools
        if item.name == "policy_explain"
    )
    schema_text = repr(tool.input_schema)
    for name in (
        "ssh_exec",
        "fs_stat",
        "fs_read",
        "fs_mkdir",
        "fs_write",
    ):
        assert name in schema_text
    assert "ssh_shell" not in schema_text


@pytest.mark.asyncio
async def test_hosts_list_returns_safe_structured_output() -> None:
    service = RecordingService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticTestPrincipalProvider(),
    )

    async with Client(server) as client:
        result = await client.call_tool("hosts_list", {})

    assert result.is_error is False
    assert result.structured_content == {
        "hosts": [
            {
                "alias": "host-a",
                "labels": [],
                "capabilities": [],
            }
        ]
    }
    assert service.calls == [
        ("hosts_list", PrincipalContext(principal_id="static:developer", profile="developer"))
    ]


@pytest.mark.asyncio
async def test_host_info_hides_missing_and_hidden_with_public_error() -> None:
    service = RecordingService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticTestPrincipalProvider(),
    )

    async with Client(server) as client:
        result = await client.call_tool(
            "host_info",
            {"alias": "hidden-or-missing"},
        )

    assert result.is_error is True
    assert "host is not visible" in tool_error_text(result)
    assert "credential" not in tool_error_text(result)


@pytest.mark.asyncio
async def test_policy_explain_returns_sanitized_structured_output() -> None:
    service = RecordingService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticTestPrincipalProvider(),
    )

    async with Client(server) as client:
        result = await client.call_tool(
            "policy_explain",
            {
                "host": "host-a",
                "tool": "ssh_exec",
                "executable": "/bin/echo",
                "args": ["hello"],
                "cwd": "/srv/app",
            },
        )

    assert result.is_error is False
    assert result.structured_content == {
        "decision": "allow",
        "reason": "allowed by central policy",
        "risk": "low",
        "normalized_executable": "/bin/echo",
        "normalized_cwd": "/srv/app",
        "normalized_path": None,
        "approval_required": False,
        "policy_version": "sha256:test",
    }


@pytest.mark.asyncio
async def test_extra_profile_is_rejected_before_service_execution() -> None:
    service = RecordingService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticTestPrincipalProvider(),
    )

    async with Client(server) as client:
        result = await client.call_tool(
            "host_info",
            {
                "alias": "host-a",
                "profile": "ops",
            },
        )

    assert result.is_error is True
    assert service.calls == []



@pytest.mark.asyncio
async def test_oversized_policy_explain_is_rejected_before_service_execution() -> None:
    service = RecordingService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticTestPrincipalProvider(),
    )

    async with Client(server) as client:
        result = await client.call_tool(
            "policy_explain",
            {
                "host": "host-a",
                "tool": "ssh_exec",
                "args": ["x" * 4097],
            },
        )

    assert result.is_error is True
    assert service.calls == []

@pytest.mark.asyncio
async def test_malformed_tool_input_is_rejected_before_service_execution() -> None:
    service = RecordingService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticTestPrincipalProvider(),
    )

    async with Client(server) as client:
        result = await client.call_tool("host_info", {})

    assert result.is_error is True
    assert service.calls == []


class ContextRecordingService:
    def __init__(self) -> None:
        self.contexts: list[tuple[str, OperationContext]] = []

    def _record(self, tool: str, context: OperationContext) -> None:
        self.contexts.append((tool, context))

    def list_hosts(self, context: OperationContext) -> HostsListResult:
        self._record("hosts_list", context)
        return HostsListResult(hosts=(HostSummary(alias="host-a"),))

    def get_host(
        self,
        context: OperationContext,
        alias: str,
    ) -> HostSummary:
        self._record("host_info", context)
        return HostSummary(alias=alias)

    def explain_policy(
        self,
        context: OperationContext,
        request,
    ) -> PolicyExplainResult:
        self._record("policy_explain", context)
        return PolicyExplainResult(
            decision=Decision.ALLOW,
            reason="allowed by central policy",
            risk=RiskLevel.LOW,
            normalized_executable=request.executable,
            normalized_cwd=request.cwd,
            normalized_path=request.path,
            approval_required=False,
            policy_version="sha256:test",
        )

    async def ssh_exec(
        self,
        context: OperationContext,
        request,
    ) -> SSHExecResult:
        self._record("ssh_exec", context)
        return SSHExecResult(
            request_id=context.request_id,
            host=request.host,
            exit_status=0,
            duration_ms=1,
        )

    async def fs_stat(
        self,
        context: OperationContext,
        request,
    ) -> FsStatResult:
        self._record("fs_stat", context)
        return FsStatResult(
            request_id=context.request_id,
            host=request.host,
            path=request.path,
            kind="regular",
            size=4,
            mode=0o600,
            uid=1000,
            gid=1000,
            mtime_ns=1,
        )

    async def fs_read(
        self,
        context: OperationContext,
        request,
    ) -> FsReadResult:
        self._record("fs_read", context)
        return FsReadResult(
            request_id=context.request_id,
            host=request.host,
            path=request.path,
            data_base64="ZGF0YQ==",
        )

    async def fs_mkdir(
        self,
        context: OperationContext,
        request,
    ) -> FsMkdirResult:
        self._record("fs_mkdir", context)
        return FsMkdirResult(
            request_id=context.request_id,
            host=request.host,
            path=request.path,
        )

    async def fs_write(
        self,
        context: OperationContext,
        request,
    ) -> FsWriteResult:
        self._record("fs_write", context)
        return FsWriteResult(
            request_id=context.request_id,
            host=request.host,
            path=request.path,
            content_length=len(request.decoded_data()),
        )


@pytest.mark.asyncio
async def test_valid_tools_receive_unique_server_owned_operation_contexts() -> None:
    service = ContextRecordingService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticTestPrincipalProvider(),
    )

    async with Client(server) as client:
        calls = (
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
                {"host": "host-a", "path": "/srv/app/file", "max_bytes": 4},
            ),
            ("fs_mkdir", {"host": "host-a", "path": "/srv/app/new"}),
            (
                "fs_write",
                {
                    "host": "host-a",
                    "path": "/srv/app/new.bin",
                    "data_base64": "ZGF0YQ==",
                },
            ),
        )
        for name, arguments in calls:
            result = await client.call_tool(name, arguments)
            assert result.is_error is False

    assert [name for name, _context in service.contexts] == [
        name for name, _arguments in calls
    ]
    request_ids = set()
    for _name, context in service.contexts:
        assert isinstance(context, OperationContext)
        assert context.principal == PrincipalContext(
            principal_id="static:developer",
            profile="developer",
        )
        assert context.received_at.tzinfo is UTC
        assert context.approval_id is None
        request_ids.add(context.request_id)

    assert len(request_ids) == len(calls)
