from __future__ import annotations

import base64

import pytest
from mcp import Client
from pydantic import ValidationError

from ssh_over_mcp.api import errors as api_errors
from ssh_over_mcp.api import models
from ssh_over_mcp.api.server import build_mcp_server
from ssh_over_mcp.api.service import MCPService
from ssh_over_mcp.inventory.models import Host, Inventory
from ssh_over_mcp.ssh import (
    SSHConnectionError,
    SSHFilesystemWriteCommittedUncertain,
    SSHFilesystemWriteResult,
    SSHRequestOutcomeUncertain,
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

    async def write(self, request, data):
        self.calls.append((request, data))
        if self.error is not None:
            raise self.error
        return SSHFilesystemWriteResult(
            request_id="req_write_1234",
            host=request.host,
            path="/srv/app/new.bin",
            content_length=len(data),
        )


def _service(filesystem: RecordingFilesystem) -> MCPService:
    return MCPService(
        inventory=_inventory(),
        policy=object(),
        ssh_filesystem=filesystem,
    )


def test_fs_write_request_accepts_binary_and_empty_content() -> None:
    request_type = models.FsWriteRequest

    binary = request_type(
        host="visible",
        path="/srv/app/new.bin",
        data_base64=base64.b64encode(b"\x00\xffAB").decode("ascii"),
    )
    assert binary.decoded_data() == b"\x00\xffAB"

    empty = request_type(
        host="visible",
        path="/srv/app/empty.bin",
        data_base64="",
    )
    assert empty.decoded_data() == b""


@pytest.mark.parametrize(
    "data_base64",
    [
        "%%%",
        "A",
        "====",
        "éA==",
    ],
)
def test_fs_write_request_rejects_invalid_base64(data_base64: str) -> None:
    with pytest.raises(ValidationError):
        models.FsWriteRequest(
            host="visible",
            path="/srv/app/new.bin",
            data_base64=data_base64,
        )


def test_fs_write_request_enforces_64_kib_decoded_cap() -> None:
    accepted = base64.b64encode(b"x" * (64 * 1024)).decode("ascii")
    models.FsWriteRequest(
        host="visible",
        path="/srv/app/max.bin",
        data_base64=accepted,
    )

    oversized = base64.b64encode(
        b"x" * ((64 * 1024) + 1)
    ).decode("ascii")
    with pytest.raises(ValidationError):
        models.FsWriteRequest(
            host="visible",
            path="/srv/app/too-large.bin",
            data_base64=oversized,
        )


def test_fs_write_request_is_closed_world() -> None:
    request_type = models.FsWriteRequest
    for extra in (
        {"content_length": 4},
        {"overwrite": True},
        {"append": True},
        {"mode": 0o644},
        {"owner": "root"},
        {"profile": "ops"},
        {"request_id": "attacker"},
        {"credential_ref": "secret://attacker"},
    ):
        with pytest.raises(ValidationError):
            request_type(
                host="visible",
                path="/srv/app/new.bin",
                data_base64="ZGF0YQ==",
                **extra,
            )


@pytest.mark.asyncio
async def test_fs_write_hides_host_before_filesystem_client() -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)

    with pytest.raises(
        api_errors.HostNotVisibleError,
        match="host is not visible",
    ):
        await service.fs_write(
            models.PrincipalContext(profile="developer"),
            models.FsWriteRequest(
                host="hidden",
                path="/srv/app/new.bin",
                data_base64="ZGF0YQ==",
            ),
        )

    assert filesystem.calls == []


@pytest.mark.asyncio
async def test_fs_write_injects_principal_and_derives_content_length() -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)

    result = await service.fs_write(
        models.PrincipalContext(profile="developer"),
        models.FsWriteRequest(
            host="visible",
            path="/srv/app/./new.bin",
            data_base64="AP9BQg==",
        ),
    )

    assert len(filesystem.calls) == 1
    evaluation, data = filesystem.calls[0]
    assert evaluation.profile == "developer"
    assert evaluation.host == "visible"
    assert evaluation.tool == "fs_write"
    assert evaluation.path == "/srv/app/./new.bin"
    assert evaluation.privilege == "user"
    assert data == b"\x00\xffAB"
    assert result == models.FsWriteResult(
        request_id="req_write_1234",
        host="visible",
        path="/srv/app/new.bin",
        content_length=4,
    )


@pytest.mark.asyncio
async def test_fs_write_committed_uncertain_outcome_is_preserved() -> None:
    filesystem = RecordingFilesystem()
    filesystem.error = SSHFilesystemWriteCommittedUncertain(
        "SUPERSECRET committed detail"
    )
    service = _service(filesystem)

    with pytest.raises(
        api_errors.FilesystemWriteCommittedUncertainError,
        match="filesystem write committed; durability uncertain; do not retry blindly",
    ) as exc_info:
        await service.fs_write(
            models.PrincipalContext(profile="developer"),
            models.FsWriteRequest(
                host="visible",
                path="/srv/app/new.bin",
                data_base64="ZGF0YQ==",
            ),
        )

    assert "SUPERSECRET" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_fs_write_generic_uncertainty_remains_non_retryable() -> None:
    filesystem = RecordingFilesystem()
    filesystem.error = SSHRequestOutcomeUncertain(
        "SUPERSECRET transport uncertainty"
    )
    service = _service(filesystem)

    with pytest.raises(
        api_errors.FilesystemMutationOutcomeUncertainError,
        match="do not retry blindly",
    ) as exc_info:
        await service.fs_write(
            models.PrincipalContext(profile="developer"),
            models.FsWriteRequest(
                host="visible",
                path="/srv/app/new.bin",
                data_base64="ZGF0YQ==",
            ),
        )

    assert "SUPERSECRET" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_fs_write_pre_request_connection_failure_is_definite() -> None:
    filesystem = RecordingFilesystem()
    filesystem.error = SSHConnectionError(
        "SUPERSECRET channel open detail"
    )
    service = _service(filesystem)

    with pytest.raises(
        api_errors.SSHTransportError,
        match="SSH transport failed",
    ) as exc_info:
        await service.fs_write(
            models.PrincipalContext(profile="developer"),
            models.FsWriteRequest(
                host="visible",
                path="/srv/app/new.bin",
                data_base64="ZGF0YQ==",
            ),
        )

    assert "SUPERSECRET" not in str(exc_info.value)


class StaticPrincipalProvider:
    def get_principal(self) -> models.PrincipalContext:
        return models.PrincipalContext(profile="developer")


class ToolService:
    def __init__(self) -> None:
        self.calls = []

    async def fs_write(self, principal, request):
        self.calls.append((principal, request))
        return models.FsWriteResult(
            request_id="req_tool_write_1234",
            host=request.host,
            path="/srv/app/new.bin",
            content_length=len(request.decoded_data()),
        )


def _tool_error_text(result) -> str:
    return "\n".join(
        getattr(block, "text", "")
        for block in result.content
    )


@pytest.mark.asyncio
async def test_server_registers_strict_create_only_fs_write_tool() -> None:
    service = ToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
    )

    async with Client(server) as client:
        listed = await client.list_tools()

    tool = next(item for item in listed.tools if item.name == "fs_write")
    assert set(tool.input_schema["properties"]) == {
        "host",
        "path",
        "data_base64",
    }
    assert tool.input_schema["additionalProperties"] is False
    assert tool.annotations is not None
    assert tool.annotations.read_only_hint is False
    assert tool.annotations.destructive_hint is False
    assert tool.annotations.idempotent_hint is False
    assert tool.annotations.open_world_hint is False

    schema_text = repr(tool.input_schema)
    for forbidden in (
        "content_length",
        "overwrite",
        "append",
        "mode",
        "owner",
        "profile",
        "request_id",
        "address",
        "ssh_user",
        "credential_ref",
        "host_key",
    ):
        assert forbidden not in schema_text


@pytest.mark.asyncio
async def test_server_fs_write_injects_principal_and_rejects_bad_input() -> None:
    service = ToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
    )

    async with Client(server) as client:
        ok = await client.call_tool(
            "fs_write",
            {
                "host": "visible",
                "path": "/srv/app/new.bin",
                "data_base64": "AP9BQg==",
            },
        )
        invalid = await client.call_tool(
            "fs_write",
            {
                "host": "visible",
                "path": "/srv/app/new.bin",
                "data_base64": "SUPERSECRET%%%",
            },
        )
        extra = await client.call_tool(
            "fs_write",
            {
                "host": "visible",
                "path": "/srv/app/new.bin",
                "data_base64": "ZGF0YQ==",
                "overwrite": True,
            },
        )

    assert ok.is_error is False
    assert ok.structured_content["content_length"] == 4
    assert len(service.calls) == 1
    principal, request = service.calls[0]
    assert principal == models.PrincipalContext(profile="developer")
    assert request.decoded_data() == b"\x00\xffAB"

    assert invalid.is_error is True
    assert "SUPERSECRET" not in _tool_error_text(invalid)
    assert extra.is_error is True
    assert len(service.calls) == 1
