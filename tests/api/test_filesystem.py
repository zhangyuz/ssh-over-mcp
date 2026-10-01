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
from ssh_over_mcp.policy.models import Decision, PolicyDecision, RiskLevel
from ssh_over_mcp.ssh import (
    SSHApprovalRequired,
    SSHConnectionError,
    SSHCredentialError,
    SSHFilesystemReadResult,
    SSHFilesystemStatResult,
    SSHHostKeyVerificationError,
    SSHOutputLimitExceeded,
    SSHPolicyDenied,
    SSHRemoteOperationError,
    SSHRemotePolicyDenied,
    SSHRemoteResponseError,
    SSHRequestTimeout,
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

    async def stat(self, request):
        self.calls.append(("stat", request))
        if self.error is not None:
            raise self.error
        return SSHFilesystemStatResult(
            request_id="req_stat_1234",
            host=request.host,
            path="/srv/app/file",
            kind="regular",
            size=7,
            mode=0o640,
            uid=2103,
            gid=3103,
            mtime_ns=123456,
        )

    async def read(self, request, *, max_bytes):
        self.calls.append(("read", request, max_bytes))
        if self.error is not None:
            raise self.error
        return SSHFilesystemReadResult(
            request_id="req_read_1234",
            host=request.host,
            path="/srv/app/file",
            data=b"\x00\xffAB",
        )


def _service(filesystem: RecordingFilesystem) -> MCPService:
    return MCPService(
        inventory=_inventory(),
        policy=object(),
        ssh_filesystem=filesystem,
    )


@pytest.mark.asyncio
async def test_fs_stat_hides_host_before_filesystem_client() -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)

    with pytest.raises(
        api_errors.HostNotVisibleError,
        match="host is not visible",
    ):
        await service.fs_stat(
            models.PrincipalContext(profile="developer"),
            models.FsStatRequest(host="hidden", path="/srv/app/file"),
        )

    assert filesystem.calls == []


@pytest.mark.asyncio
async def test_fs_stat_injects_principal_and_returns_metadata() -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)

    result = await service.fs_stat(
        models.PrincipalContext(profile="developer"),
        models.FsStatRequest(host="visible", path="/srv/app/file"),
    )

    operation, evaluation = filesystem.calls[0]
    assert operation == "stat"
    assert evaluation.profile == "developer"
    assert evaluation.host == "visible"
    assert evaluation.tool == "fs_stat"
    assert evaluation.path == "/srv/app/file"
    assert evaluation.privilege == "user"
    assert result.request_id == "req_stat_1234"
    assert result.path == "/srv/app/file"
    assert result.kind == "regular"
    assert result.mode == 0o640
    assert result.uid == 2103
    assert result.gid == 3103


@pytest.mark.asyncio
async def test_fs_read_is_bounded_and_returns_lossless_base64() -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)

    result = await service.fs_read(
        models.PrincipalContext(profile="developer"),
        models.FsReadRequest(
            host="visible",
            path="/srv/app/file",
            max_bytes=4096,
        ),
    )

    operation, evaluation, max_bytes = filesystem.calls[0]
    assert operation == "read"
    assert evaluation.profile == "developer"
    assert evaluation.tool == "fs_read"
    assert evaluation.path == "/srv/app/file"
    assert max_bytes == 4096
    assert result.request_id == "req_read_1234"
    assert result.data_base64 == base64.b64encode(b"\x00\xffAB").decode("ascii")


def test_fs_read_request_has_one_mib_hard_cap() -> None:
    request = models.FsReadRequest(
        host="visible",
        path="/srv/app/file",
        max_bytes=1024 * 1024,
    )
    assert request.max_bytes == 1024 * 1024
    with pytest.raises(ValidationError):
        models.FsReadRequest(
            host="visible",
            path="/srv/app/file",
            max_bytes=(1024 * 1024) + 1,
        )
    with pytest.raises(ValidationError):
        models.FsReadRequest(
            host="visible",
            path="/srv/app/file",
            max_bytes=True,
        )


def _policy_failure(
    decision: Decision,
    *,
    approval_required: bool = False,
) -> PolicyDecision:
    return PolicyDecision(
        decision=decision,
        reason="SUPERSECRET policy detail",
        risk=RiskLevel.HIGH,
        approval_required=approval_required,
        policy_version="sha256:test",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "public_error", "message"),
    [
        (
            SSHPolicyDenied(_policy_failure(Decision.DENY)),
            "PolicyDeniedError",
            "request denied by central policy",
        ),
        (
            SSHApprovalRequired(
                _policy_failure(
                    Decision.APPROVAL_REQUIRED,
                    approval_required=True,
                )
            ),
            "ApprovalRequiredError",
            "approval required by central policy",
        ),
        (
            SSHCredentialError("SUPERSECRET credential"),
            "SSHCredentialUnavailableError",
            "SSH credential is unavailable",
        ),
        (
            SSHHostKeyVerificationError("SUPERSECRET host key"),
            "SSHHostKeyError",
            "SSH host key verification failed",
        ),
        (
            SSHConnectionError("SUPERSECRET transport"),
            "SSHTransportError",
            "SSH transport failed",
        ),
        (
            SSHRemotePolicyDenied("SUPERSECRET remote denial"),
            "RemotePolicyDeniedError",
            "remote filesystem policy denied request",
        ),
        (
            SSHRequestTimeout("SUPERSECRET timeout"),
            "RemoteTimeoutError",
            "remote filesystem request timed out",
        ),
        (
            SSHOutputLimitExceeded("SUPERSECRET overflow"),
            "RemoteOutputLimitError",
            "remote filesystem response exceeded output limit",
        ),
        (
            SSHRemoteOperationError("SUPERSECRET remote failure"),
            "FilesystemOperationError",
            "remote filesystem operation failed",
        ),
        (
            SSHRemoteResponseError("SUPERSECRET malformed response"),
            "FilesystemOperationError",
            "remote filesystem operation failed",
        ),
    ],
)
async def test_filesystem_service_sanitizes_remote_failures(
    error: Exception,
    public_error: str,
    message: str,
) -> None:
    filesystem = RecordingFilesystem()
    filesystem.error = error
    service = _service(filesystem)

    with pytest.raises(
        getattr(api_errors, public_error),
        match=message,
    ) as exc_info:
        await service.fs_stat(
            models.PrincipalContext(profile="developer"),
            models.FsStatRequest(host="visible", path="/srv/app/file"),
        )
    assert "SUPERSECRET" not in str(exc_info.value)


class StaticPrincipalProvider:
    def get_principal(self) -> models.PrincipalContext:
        return models.PrincipalContext(profile="developer")


class ToolService:
    def __init__(self) -> None:
        self.calls = []

    async def fs_stat(self, principal, request):
        self.calls.append(("fs_stat", principal, request))
        return models.FsStatResult(
            request_id="req_stat_1234",
            host=request.host,
            path=request.path,
            kind="regular",
            size=7,
            mode=0o640,
            uid=2103,
            gid=3103,
            mtime_ns=123456,
        )

    async def fs_read(self, principal, request):
        self.calls.append(("fs_read", principal, request))
        return models.FsReadResult(
            request_id="req_read_1234",
            host=request.host,
            path=request.path,
            data_base64="AP9BQg==",
        )


@pytest.mark.asyncio
async def test_server_registers_strict_read_only_filesystem_tools() -> None:
    service = ToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
    )

    async with Client(server) as client:
        listed = await client.list_tools()

    tools = {tool.name: tool for tool in listed.tools}
    assert {"fs_stat", "fs_read"}.issubset(tools)
    assert set(tools["fs_stat"].input_schema["properties"]) == {"host", "path"}
    assert set(tools["fs_read"].input_schema["properties"]) == {
        "host",
        "path",
        "max_bytes",
    }
    for name in ("fs_stat", "fs_read"):
        tool = tools[name]
        assert tool.input_schema["additionalProperties"] is False
        assert tool.annotations is not None
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is not True
        assert tool.annotations.open_world_hint is False
        schema = repr(tool.input_schema)
        for forbidden in (
            "profile",
            "address",
            "ssh_user",
            "credential_ref",
            "host_key",
            "request_id",
        ):
            assert forbidden not in schema


@pytest.mark.asyncio
async def test_server_fs_read_injects_principal_and_rejects_extra_fields() -> None:
    service = ToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
    )
    async with Client(server) as client:
        ok = await client.call_tool(
            "fs_read",
            {
                "host": "visible",
                "path": "/srv/app/file",
                "max_bytes": 4096,
            },
        )
        rejected = await client.call_tool(
            "fs_read",
            {
                "host": "visible",
                "path": "/srv/app/file",
                "max_bytes": 4096,
                "profile": "ops",
            },
        )

    assert ok.is_error is False
    assert ok.structured_content["data_base64"] == "AP9BQg=="
    _, principal, request = service.calls[0]
    assert principal == models.PrincipalContext(profile="developer")
    assert request.max_bytes == 4096
    assert rejected.is_error is True
    assert len(service.calls) == 1

@pytest.mark.asyncio
async def test_server_invalid_fs_read_input_is_sanitized() -> None:
    service = ToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
    )

    async with Client(server) as client:
        result = await client.call_tool(
            "fs_read",
            {
                "host": "visible",
                "path": "/srv/app/file",
                "max_bytes": "SUPERSECRET",
            },
        )

    assert result.is_error is True
    text = "\n".join(
        getattr(block, "text", "")
        for block in result.content
    )
    assert "invalid tool input" in text
    assert "SUPERSECRET" not in text
    assert service.calls == []
