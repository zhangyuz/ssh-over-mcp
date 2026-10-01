from __future__ import annotations

from datetime import UTC, datetime

import pytest
from mcp import Client
from pydantic import ValidationError

from ssh_over_mcp.api import errors as api_errors
from ssh_over_mcp.api import models
from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.api.server import build_mcp_server
from ssh_over_mcp.api.service import MCPService
from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.ssh import (
    SSHConnectionError,
    SSHFilesystemMkdirResult,
    SSHRequestOutcomeUncertain,
)


def _operation_context() -> OperationContext:
    return OperationContext(
        request_id="req_" + "1" * 32,
        principal=models.PrincipalContext(
            principal_id="static:developer",
            profile="developer",
        ),
        received_at=datetime(2026, 10, 1, tzinfo=UTC),
    )


def _inventory() -> Inventory:
    return Inventory(
        hosts={
            "visible": Host(
                address="10.0.0.1",
                ssh_user="secret-user",
                credential_ref="secret://visible",
                host_key="secret-host-key",
                allowed_roles=frozenset({"developer"}),
            ),
            "hidden": Host(
                address="10.0.0.2",
                ssh_user="hidden-user",
                credential_ref="secret://hidden",
                host_key="hidden-host-key",
                allowed_roles=frozenset({"ops"}),
            ),
        }
    )


class RecordingFilesystem:
    def __init__(self) -> None:
        self.calls = []
        self.error: Exception | None = None

    async def mkdir(self, request):
        self.calls.append(request)
        if self.error is not None:
            raise self.error
        return SSHFilesystemMkdirResult(
            request_id="req_mkdir_1234",
            host=request.host,
            path="/srv/app/new-directory",
        )


def _service(filesystem: RecordingFilesystem) -> MCPService:
    return MCPService(
        inventory=_inventory(),
        policy=object(),
        ssh_filesystem=filesystem,
    )


def test_fs_mkdir_request_is_closed_world() -> None:
    request_type = models.FsMkdirRequest
    request = request_type(
        host="visible",
        path="/srv/app/new-directory",
    )
    assert request.host == "visible"
    assert request.path == "/srv/app/new-directory"

    for extra in (
        {"mode": 0o755},
        {"owner": "root"},
        {"recursive": True},
        {"parents": True},
        {"overwrite": True},
        {"profile": "ops"},
        {"request_id": "attacker"},
        {"credential_ref": "secret://attacker"},
    ):
        with pytest.raises(ValidationError):
            request_type(
                host="visible",
                path="/srv/app/new-directory",
                **extra,
            )


@pytest.mark.asyncio
async def test_fs_mkdir_hides_host_before_filesystem_client() -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)

    with pytest.raises(
        api_errors.HostNotVisibleError,
        match="host is not visible",
    ):
        await service.fs_mkdir(
            _operation_context(),
            models.FsMkdirRequest(
                host="hidden",
                path="/srv/app/new-directory",
            ),
        )

    assert filesystem.calls == []


@pytest.mark.asyncio
async def test_fs_mkdir_injects_principal_and_returns_created_path() -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)

    result = await service.fs_mkdir(
        _operation_context(),
        models.FsMkdirRequest(
            host="visible",
            path="/srv/app/./new-directory",
        ),
    )

    assert len(filesystem.calls) == 1
    evaluation = filesystem.calls[0]
    assert evaluation.profile == "developer"
    assert evaluation.host == "visible"
    assert evaluation.tool == "fs_mkdir"
    assert evaluation.path == "/srv/app/./new-directory"
    assert evaluation.privilege == "user"
    assert result == models.FsMkdirResult(
        request_id="req_mkdir_1234",
        host="visible",
        path="/srv/app/new-directory",
    )


@pytest.mark.asyncio
async def test_fs_mkdir_uncertain_outcome_is_sanitized_and_non_retryable() -> None:
    filesystem = RecordingFilesystem()
    filesystem.error = SSHRequestOutcomeUncertain(
        "SUPERSECRET remote uncertainty"
    )
    service = _service(filesystem)

    with pytest.raises(
        api_errors.FilesystemMutationOutcomeUncertainError,
        match="do not retry blindly",
    ) as exc_info:
        await service.fs_mkdir(
            _operation_context(),
            models.FsMkdirRequest(
                host="visible",
                path="/srv/app/new-directory",
            ),
        )

    rendered = str(exc_info.value)
    assert "SUPERSECRET" not in rendered
    assert "secret://" not in rendered


@pytest.mark.asyncio
async def test_fs_mkdir_pre_request_connection_failure_is_definite_transport_error() -> None:
    filesystem = RecordingFilesystem()
    filesystem.error = SSHConnectionError("SUPERSECRET channel open detail")
    service = _service(filesystem)
    with pytest.raises(
        api_errors.SSHTransportError,
        match="SSH transport failed",
    ) as exc_info:
        await service.fs_mkdir(
            _operation_context(),
            models.FsMkdirRequest(
                host="visible",
                path="/srv/app/new-directory",
            ),
        )

    assert "SUPERSECRET" not in str(exc_info.value)


class StaticPrincipalProvider:
    def get_principal(self) -> models.PrincipalContext:
        return models.PrincipalContext(principal_id="static:developer", profile="developer")


class ToolService:
    def __init__(self) -> None:
        self.calls = []

    async def fs_mkdir(self, principal, request):
        self.calls.append((principal, request))
        return models.FsMkdirResult(
            request_id="req_tool_mkdir_1234",
            host=request.host,
            path="/srv/app/new-directory",
        )


def _tool_error_text(result) -> str:
    return "\n".join(
        getattr(block, "text", "")
        for block in result.content
    )


@pytest.mark.asyncio
async def test_server_registers_strict_create_only_fs_mkdir_tool() -> None:
    service = ToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
    )

    async with Client(server) as client:
        listed = await client.list_tools()

    tool = next(item for item in listed.tools if item.name == "fs_mkdir")
    assert set(tool.input_schema["properties"]) == {"host", "path"}
    assert tool.input_schema["additionalProperties"] is False
    assert tool.annotations is not None
    assert tool.annotations.read_only_hint is False
    assert tool.annotations.destructive_hint is False
    assert tool.annotations.idempotent_hint is False
    assert tool.annotations.open_world_hint is False

    schema_text = repr(tool.input_schema)
    for forbidden in (
        "mode",
        "owner",
        "recursive",
        "parents",
        "overwrite",
        "profile",
        "request_id",
        "address",
        "ssh_user",
        "credential_ref",
        "host_key",
    ):
        assert forbidden not in schema_text


@pytest.mark.asyncio
async def test_server_fs_mkdir_injects_principal_and_rejects_extra_fields() -> None:
    service = ToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
    )
    async with Client(server) as client:
        ok = await client.call_tool(
            "fs_mkdir",
            {
                "host": "visible",
                "path": "/srv/app/new-directory",
            },
        )
        rejected = await client.call_tool(
            "fs_mkdir",
            {
                "host": "visible",
                "path": "/srv/app/new-directory",
                "profile": "SUPERSECRET",
            },
        )

    assert ok.is_error is False
    assert ok.structured_content["request_id"] == "req_tool_mkdir_1234"
    assert len(service.calls) == 1
    context, request = service.calls[0]
    assert isinstance(context, OperationContext)
    assert context.principal == models.PrincipalContext(
        principal_id="static:developer",
        profile="developer",
    )
    assert request.path == "/srv/app/new-directory"

    assert rejected.is_error is True
    assert "SUPERSECRET" not in _tool_error_text(rejected)
    assert len(service.calls) == 1


@pytest.mark.asyncio
async def test_fs_mkdir_unexpected_failure_is_conservatively_uncertain() -> None:
    filesystem = RecordingFilesystem()
    filesystem.error = RuntimeError("SUPERSECRET foreign failure")
    service = _service(filesystem)

    with pytest.raises(
        api_errors.FilesystemMutationOutcomeUncertainError,
        match="do not retry blindly",
    ) as exc_info:
        await service.fs_mkdir(
            _operation_context(),
            models.FsMkdirRequest(
                host="visible",
                path="/srv/app/new-directory",
            ),
        )

    assert "SUPERSECRET" not in str(exc_info.value)
