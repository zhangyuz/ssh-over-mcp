from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
from mcp import Client
from pydantic import ValidationError

from ssh_over_mcp.api import errors as api_errors
from ssh_over_mcp.api import models
from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.api.server import build_mcp_server
from ssh_over_mcp.api.service import MCPService
from ssh_over_mcp.approvals.models import (
    ApprovalSafeSummary,
    ApprovalState,
    ApprovalStatus,
)
from ssh_over_mcp.audit.recorder import AuditRecorder
from ssh_over_mcp.inventory.models import Host, Inventory


class _AuditLedger:
    async def append_audit(self, event) -> str:
        return "evt_" + ("0" * 32)


def _audit() -> AuditRecorder:
    return AuditRecorder(_AuditLedger())
from ssh_over_mcp.policy.models import Decision, PolicyDecision, RiskLevel
from ssh_over_mcp.ssh import (
    SSHApprovalRequired,
    SSHAuditPersistenceError,
    SSHAuditPersistenceOutcomeUncertain,
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

APR_ID = "apr_" + ("a" * 32)


def _operation_context(approval_id: str | None = None) -> OperationContext:
    return OperationContext(
        request_id="req_" + "1" * 32,
        principal=models.PrincipalContext(
            principal_id="static:developer",
            profile="developer",
        ),
        received_at=datetime(2026, 10, 1, tzinfo=UTC),
        approval_id=approval_id,
    )


def _approval_status(tool: str = "fs_stat") -> ApprovalStatus:
    return ApprovalStatus(
        approval_id=APR_ID,
        state=ApprovalState.PENDING,
        expires_at=datetime(2026, 10, 1, 18, 10, tzinfo=UTC),
        host="visible",
        tool=tool,
        risk=RiskLevel.HIGH,
        safe_summary=ApprovalSafeSummary(
            principal_id="static:developer",
            profile="developer",
            host="visible",
            tool=tool,
            privilege="user",
            policy_version="sha256:test",
            risk=RiskLevel.HIGH,
            normalized_executable=None,
            normalized_cwd=None,
            normalized_path="/srv/app/file",
            argv_count=0,
            argv_fingerprint="sha256:" + ("1" * 64),
            env_names=(),
            stdin_length=None,
            stdin_fingerprint=None,
            content_length=None,
            content_fingerprint=None,
            effective_timeout_seconds=60.0,
            effective_max_output_bytes=64 * 1024 if tool == "fs_stat" else 4096,
            effective_max_stdin_bytes=None,
            effective_tool_bytes=None if tool == "fs_stat" else 4096,
        ),
        binding_fingerprint="hmac-sha256:v1:" + ("2" * 16),
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

    async def stat(self, request, *, context):
        self.calls.append(("stat", context, request))
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

    async def read(self, request, *, context, max_bytes):
        self.calls.append(("read", context, request, max_bytes))
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


def test_read_only_filesystem_requests_accept_only_opaque_approval_id() -> None:
    stat = models.FsStatRequest(
        host="visible",
        path="/srv/app/file",
        approval_id=APR_ID,
    )
    read = models.FsReadRequest(
        host="visible",
        path="/srv/app/file",
        max_bytes=4096,
        approval_id=APR_ID,
    )
    assert stat.approval_id == APR_ID
    assert read.approval_id == APR_ID

    for request_type, kwargs in (
        (models.FsStatRequest, {"host": "visible", "path": "/srv/app/file"}),
        (
            models.FsReadRequest,
            {"host": "visible", "path": "/srv/app/file", "max_bytes": 4096},
        ),
    ):
        with pytest.raises(ValidationError):
            request_type(**kwargs, approval_id="apr_SUPERSECRET")
        for field, value in (
            ("grant", True),
            ("deny", True),
            ("approval_ttl_seconds", 600),
            ("binding_hmac", "SUPERSECRET"),
        ):
            with pytest.raises(ValidationError):
                request_type(**kwargs, **{field: value})


@pytest.mark.asyncio
async def test_fs_stat_hides_host_before_filesystem_client() -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)

    with pytest.raises(
        api_errors.HostNotVisibleError,
        match="host is not visible",
    ):
        await service.fs_stat(
            _operation_context(),
            models.FsStatRequest(host="hidden", path="/srv/app/file"),
        )

    assert filesystem.calls == []


@pytest.mark.asyncio
async def test_fs_stat_injects_principal_and_returns_metadata() -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)

    result = await service.fs_stat(
        _operation_context(),
        models.FsStatRequest(host="visible", path="/srv/app/file"),
    )

    operation, seen_context, evaluation = filesystem.calls[0]
    assert operation == "stat"
    assert seen_context == _operation_context()
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
@pytest.mark.parametrize("operation", ["fs_stat", "fs_read"])
async def test_read_only_filesystem_threads_approval_only_through_context(
    operation: str,
) -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)
    context = _operation_context(approval_id=APR_ID)

    if operation == "fs_stat":
        await service.fs_stat(
            context,
            models.FsStatRequest(
                host="visible",
                path="/srv/app/file",
                approval_id=APR_ID,
            ),
        )
        _, seen_context, evaluation = filesystem.calls[0]
    else:
        await service.fs_read(
            context,
            models.FsReadRequest(
                host="visible",
                path="/srv/app/file",
                max_bytes=4096,
                approval_id=APR_ID,
            ),
        )
        _, seen_context, evaluation, _ = filesystem.calls[0]

    assert seen_context.approval_id == APR_ID
    assert "approval_id" not in type(evaluation).model_fields


@pytest.mark.asyncio
async def test_fs_read_is_bounded_and_returns_lossless_base64() -> None:
    filesystem = RecordingFilesystem()
    service = _service(filesystem)

    result = await service.fs_read(
        _operation_context(),
        models.FsReadRequest(
            host="visible",
            path="/srv/app/file",
            max_bytes=4096,
        ),
    )

    operation, seen_context, evaluation, max_bytes = filesystem.calls[0]
    assert operation == "read"
    assert seen_context == _operation_context()
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
@pytest.mark.parametrize("operation", ["fs_stat", "fs_read"])
async def test_filesystem_approval_required_returns_safe_retry_handle(
    operation: str,
) -> None:
    filesystem = RecordingFilesystem()
    decision = _policy_failure(
        Decision.APPROVAL_REQUIRED,
        approval_required=True,
    )
    filesystem.error = SSHApprovalRequired(
        decision,
        approval_status=_approval_status(operation),
    )
    service = _service(filesystem)

    with pytest.raises(api_errors.ApprovalRequiredError) as exc_info:
        if operation == "fs_stat":
            await service.fs_stat(
                _operation_context(),
                models.FsStatRequest(host="visible", path="/srv/app/file"),
            )
        else:
            await service.fs_read(
                _operation_context(),
                models.FsReadRequest(
                    host="visible",
                    path="/srv/app/file",
                    max_bytes=4096,
                ),
            )

    rendered = str(exc_info.value)
    assert f"approval_id={APR_ID}" in rendered
    assert "state=pending" in rendered
    assert "expires_at=2026-10-01T18:10:00+00:00" in rendered
    assert "retry the exact operation with this approval_id only after approval" in rendered
    for forbidden in ("SUPERSECRET", "/srv/app/file", "sha256:", "hmac-sha256:"):
        assert forbidden not in rendered


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
        (
            SSHAuditPersistenceError("SUPERSECRET audit detail"),
            "AuditPersistenceError",
            "audit persistence failed",
        ),
        (
            SSHAuditPersistenceOutcomeUncertain("SUPERSECRET audit uncertainty"),
            "AuditPersistenceOutcomeUncertainError",
            "audit persistence outcome is uncertain; do not retry blindly",
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
            _operation_context(),
            models.FsStatRequest(host="visible", path="/srv/app/file"),
        )
    assert "SUPERSECRET" not in str(exc_info.value)


class StaticPrincipalProvider:
    def get_principal(self) -> models.PrincipalContext:
        return models.PrincipalContext(principal_id="static:developer", profile="developer")


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
        audit=_audit(),
    )

    async with Client(server) as client:
        listed = await client.list_tools()

    tools = {tool.name: tool for tool in listed.tools}
    assert {"fs_stat", "fs_read"}.issubset(tools)
    assert set(tools["fs_stat"].input_schema["properties"]) == {
        "host", "path", "approval_id"
    }
    assert set(tools["fs_read"].input_schema["properties"]) == {
        "host",
        "path",
        "max_bytes",
        "approval_id",
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
            "grant",
            "deny",
            "approval_ttl_seconds",
            "binding_hmac",
        ):
            assert forbidden not in schema


@pytest.mark.asyncio
async def test_server_fs_read_injects_principal_and_rejects_extra_fields() -> None:
    service = ToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
        audit=_audit(),
    )
    async with Client(server) as client:
        ok = await client.call_tool(
            "fs_read",
            {
                "host": "visible",
                "path": "/srv/app/file",
                "max_bytes": 4096,
                "approval_id": APR_ID,
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
    _, context, request = service.calls[0]
    assert isinstance(context, OperationContext)
    assert context.principal == models.PrincipalContext(
        principal_id="static:developer",
        profile="developer",
    )
    assert request.max_bytes == 4096
    assert request.approval_id == APR_ID
    assert context.approval_id == APR_ID
    assert rejected.is_error is True
    assert len(service.calls) == 1

@pytest.mark.asyncio
async def test_server_invalid_fs_read_input_is_sanitized() -> None:
    service = ToolService()
    server = build_mcp_server(
        service=service,
        principal_provider=StaticPrincipalProvider(),
        audit=_audit(),
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

    async with Client(server) as client:
        malformed = await client.call_tool(
            "fs_read",
            {
                "host": "visible",
                "path": "/srv/app/file",
                "max_bytes": 4096,
                "approval_id": "apr_SUPERSECRET-invalid",
            },
        )
    assert malformed.is_error is True
    text = "\n".join(getattr(block, "text", "") for block in malformed.content)
    assert "invalid tool input" in text
    assert "SUPERSECRET" not in text
    assert service.calls == []


# Real service/client/authorizer path; only the remote channel and trust provider
# are synthetic. These fixtures do not confer production signing authority.
@pytest.fixture
def list_stack():
    import json
    from types import SimpleNamespace

    import asyncssh

    from ssh_over_mcp.approvals.authorization import ExecutionAuthorizer
    from ssh_over_mcp.host_agent.visibility_snapshot_v5 import sign_snapshot
    from ssh_over_mcp.policy.engine import PolicyEngine
    from ssh_over_mcp.policy.models import Effect, PolicyDocument, PolicyRule, RoleSpec
    from ssh_over_mcp.ssh.filesystem import SSHFilesystemClient
    from ssh_over_mcp.ssh.protocol_v2 import decode_request_v2
    from ssh_over_mcp.ssh.transport import SSHExecutionResult

    inventory = _inventory()
    inventory.hosts["visible"] = inventory.hosts["visible"].model_copy(
        update={
            "host_key": asyncssh.generate_private_key("ssh-ed25519")
            .export_public_key()
            .decode()
            .strip(),
        }
    )
    engine = PolicyEngine(
        inventory=inventory,
        policy=PolicyDocument(
            roles={"developer": RoleSpec(), "ops": RoleSpec()},
            rules=(
                PolicyRule(
                    id="list",
                    effect=Effect.ALLOW,
                    roles=("developer",),
                    tools=("fs_list",),
                    paths=("/srv/app", "/srv/app/**"),
                ),
                PolicyRule(
                    id="deny",
                    effect=Effect.DENY,
                    roles=("developer",),
                    tools=("fs_list",),
                    paths=("/srv/app/private/**",),
                ),
            ),
        ),
    )
    state = SimpleNamespace(
        calls=[], events=[], signed=[], error=None, fail_audit=None, child="/srv/app/file"
    )

    class Ledger:
        async def append_audit(self, event):
            if event.event_type == state.fail_audit:
                raise RuntimeError("SUPERSECRET ledger")
            state.events.append(event)
            return "evt_" + "a" * 32

    class Authority:
        def __init__(self):
            self.engine = engine

        def current_epoch(self, **kwargs):
            return 7

        def is_active(self, snapshot):
            return snapshot.principal == "static:developer"

        def sign(self, snapshot):
            state.signed.append(snapshot)
            return sign_snapshot(snapshot, key=b"t" * 32)

    async def run_v2(**kwargs):
        state.calls.append(kwargs)
        if state.error:
            raise state.error
        snap = decode_request_v2(kwargs["payload"]).signed_snapshot.payload
        body = {
            "request_id": snap.request_id,
            "host": snap.host,
            "root": snap.root,
            "policy_epoch": snap.policy_epoch,
            "snapshot_id": snap.snapshot_id,
            "entries": [
                {
                    "path": state.child,
                    "kind": "regular",
                    "size": 1,
                    "mode": 0o600,
                    "uid": 1000,
                    "gid": 1000,
                    "mtime_ns": 123,
                }
            ],
        }
        return SSHExecutionResult(
            request_id=snap.request_id,
            host=snap.host,
            exit_status=0,
            duration_ms=1,
            stdout=json.dumps(body).encode(),
        )

    ledger = Ledger()
    state.audit = AuditRecorder(ledger)
    state.filesystem = SSHFilesystemClient(
        authorizer=ExecutionAuthorizer(policy=engine, ledger=ledger),
        audit=state.audit,
        transport=SimpleNamespace(run_v2=run_v2, connections=SimpleNamespace(inventory=inventory)),
        visibility_authority=Authority(),
    )
    state.service = MCPService(inventory=inventory, policy=engine, ssh_filesystem=state.filesystem)
    return state


def _list_server(s, **kwargs):
    return build_mcp_server(
        service=s.service,
        audit=s.audit,
        principal_provider=kwargs.pop("principal_provider", StaticPrincipalProvider()),
        **kwargs,
    )


@pytest.mark.asyncio
async def test_fs_list_default_absent_even_with_authority(list_stack):
    async with Client(_list_server(list_stack)) as client:
        assert "fs_list" not in {t.name for t in (await client.list_tools()).tools}
        result = await client.call_tool(
            "fs_list", {"host": "visible", "path": "/srv/app", "max_entries": 8}
        )
        assert result.is_error
    assert not list_stack.calls


def test_fs_list_opt_in_requires_existing_authority(list_stack):
    list_stack.filesystem.visibility_authority = None
    with pytest.raises(ValueError, match="visibility authority"):
        _list_server(list_stack, enable_fs_list=True)


@pytest.mark.asyncio
async def test_fs_list_real_client_context_audit_and_schema(list_stack):
    from ssh_over_mcp.audit.models import AuditEventType as E

    s = list_stack
    async with Client(_list_server(s, enable_fs_list=True)) as client:
        tool = next(t for t in (await client.list_tools()).tools if t.name == "fs_list")
        assert set(tool.input_schema["properties"]) == {"host", "path", "max_entries"}
        assert tool.input_schema["additionalProperties"] is False
        assert tool.input_schema["properties"]["max_entries"]["maximum"] == 64
        assert tool.annotations.read_only_hint and not tool.annotations.open_world_hint
        result = await client.call_tool(
            "fs_list", {"host": "visible", "path": "/srv/app", "max_entries": 8}
        )
    assert not result.is_error
    assert set(result.structured_content) == {"request_id", "host", "path", "entries"}
    assert result.structured_content["entries"][0]["path"] == "/srv/app/file"
    snap = s.signed[0]
    assert (snap.principal, snap.profile, snap.max_entries) == ("static:developer", "developer", 8)
    assert result.structured_content["request_id"] == snap.request_id
    assert [e.event_type for e in s.events] == [
        E.REQUEST_RECEIVED,
        E.POLICY_ALLOWED,
        E.EXECUTION_STARTED,
        E.EXECUTION_COMPLETED,
    ]
    assert all(e.request_id == snap.request_id for e in s.events)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "patch",
    [
        {"max_entries": True},
        {"max_entries": "8"},
        {"max_entries": 0},
        {"max_entries": 65},
        {"path": "/srv/../app"},
        {"path": "x"},
        {"path": "/" + "é" * 2048},
        {"host": "h" * 257},
        {"profile": "ops"},
        {"principal_id": "other"},
        {"enable_fs_list": True},
        {"key": "SUPERSECRET"},
        {"epoch": 7},
        {"command": "mcp-v1"},
        {"approval_id": APR_ID},
    ],
)
async def test_fs_list_rejects_untrusted_input_before_network(list_stack, patch):
    s = list_stack
    async with Client(_list_server(s, enable_fs_list=True)) as client:
        result = await client.call_tool(
            "fs_list",
            {
                "host": "visible",
                "path": "/srv/app",
                "max_entries": 8,
                **patch,
            },
        )
    assert result.is_error
    assert "SUPERSECRET" not in str(result.content)
    assert not s.calls and not s.signed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "host,path", [("hidden", "/srv/app"), ("visible", "/etc"), ("visible", "/srv/app/private")]
)
async def test_fs_list_denied_host_or_path_never_opens_ssh(list_stack, host, path):
    s = list_stack
    async with Client(_list_server(s, enable_fs_list=True)) as client:
        result = await client.call_tool("fs_list", {"host": host, "path": path, "max_entries": 8})
    assert result.is_error and not s.calls


@pytest.mark.asyncio
async def test_fs_list_mismatched_trusted_principal_never_opens_ssh(list_stack):
    class OtherPrincipal:
        def get_principal(self):
            return models.PrincipalContext(principal_id="other", profile="developer")

    s = list_stack
    async with Client(
        _list_server(s, enable_fs_list=True, principal_provider=OtherPrincipal())
    ) as client:
        result = await client.call_tool(
            "fs_list", {"host": "visible", "path": "/srv/app", "max_entries": 8}
        )
    assert result.is_error and not s.calls


@pytest.mark.asyncio
async def test_fs_list_denied_response_is_not_disclosed(list_stack):
    list_stack.child = "/srv/app/private/SECRET"
    async with Client(_list_server(list_stack, enable_fs_list=True)) as client:
        result = await client.call_tool(
            "fs_list", {"host": "visible", "path": "/srv/app", "max_entries": 8}
        )
    assert result.is_error
    assert "SECRET" not in str(result.content)
    assert result.structured_content is None


@pytest.mark.asyncio
@pytest.mark.parametrize("event", ["request_received", "policy_allowed", "execution_started"])
async def test_fs_list_audit_failure_never_opens_ssh(list_stack, event):
    from ssh_over_mcp.audit.models import AuditEventType

    list_stack.fail_audit = AuditEventType(event)
    async with Client(_list_server(list_stack, enable_fs_list=True)) as client:
        result = await client.call_tool(
            "fs_list", {"host": "visible", "path": "/srv/app", "max_entries": 8}
        )
    assert result.is_error and not list_stack.calls
    assert "SUPERSECRET" not in str(result.content)


def test_fs_list_unauthenticated_http_never_opens_ssh(list_stack):
    from starlette.testclient import TestClient

    from ssh_over_mcp.api.origin_auth import OriginBearerAuthMiddleware

    server = _list_server(list_stack, enable_fs_list=True)
    app = server.streamable_http_app(stateless_http=True, json_response=True)
    app.add_middleware(OriginBearerAuthMiddleware, token=b"test-only-token")
    with TestClient(app) as client:
        response = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "fs_list",
                    "arguments": {"host": "visible", "path": "/srv/app", "max_entries": 8},
                },
            },
        )
    assert response.status_code == 401
    assert not list_stack.calls and not list_stack.events


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error,message",
    [
        (SSHCredentialError("SUPERSECRET"), "SSH credential is unavailable"),
        (SSHHostKeyVerificationError("SUPERSECRET"), "SSH host key verification failed"),
        (SSHConnectionError("SUPERSECRET"), "SSH transport failed"),
        (SSHRemotePolicyDenied("SUPERSECRET"), "remote filesystem policy denied request"),
        (SSHRequestTimeout("SUPERSECRET"), "remote filesystem request timed out"),
        (SSHOutputLimitExceeded("SUPERSECRET"), "remote filesystem response exceeded output limit"),
        (SSHRemoteResponseError("SUPERSECRET"), "remote filesystem operation failed"),
        (RuntimeError("SUPERSECRET"), "remote filesystem operation failed"),
    ],
)
async def test_fs_list_sanitizes_transport_errors(list_stack, error, message):
    list_stack.error = error
    async with Client(_list_server(list_stack, enable_fs_list=True)) as client:
        result = await client.call_tool(
            "fs_list",
            {
                "host": "visible",
                "path": "/srv/app",
                "max_entries": 8,
            },
        )
    assert result.is_error
    assert message in str(result.content) and "SUPERSECRET" not in str(result.content)
    assert result.structured_content is None


@pytest.mark.asyncio
async def test_fs_list_removed_authority_fails_closed(list_stack):
    server = _list_server(list_stack, enable_fs_list=True)
    list_stack.filesystem.visibility_authority = None
    async with Client(server) as client:
        result = await client.call_tool(
            "fs_list",
            {
                "host": "visible",
                "path": "/srv/app",
                "max_entries": 8,
            },
        )
    assert result.is_error and not list_stack.calls


@pytest.mark.asyncio
async def test_fs_list_completion_audit_failure_discloses_no_result(list_stack):
    from ssh_over_mcp.audit.models import AuditEventType

    list_stack.fail_audit = AuditEventType.EXECUTION_COMPLETED
    async with Client(_list_server(list_stack, enable_fs_list=True)) as client:
        result = await client.call_tool(
            "fs_list",
            {
                "host": "visible",
                "path": "/srv/app",
                "max_entries": 8,
            },
        )
    assert result.is_error and len(list_stack.calls) == 1
    assert result.structured_content is None
    assert "SUPERSECRET" not in str(result.content)


def test_fs_list_production_runtime_has_no_authority(list_stack, tmp_path):
    from ssh_over_mcp.api.ssh_runtime import build_ssh_runtime

    engine = list_stack.filesystem.visibility_authority.engine
    key = tmp_path / "synthetic-key"
    key.write_text("test-only-not-a-private-key")
    runtime = build_ssh_runtime(
        inventory=engine.inventory,
        policy=engine,
        credential_map={h.credential_ref: key for h in engine.inventory.hosts.values()},
        ledger=_AuditLedger(),
    )
    assert runtime.filesystem.visibility_authority is None
    service = MCPService(
        inventory=engine.inventory, policy=engine, ssh_filesystem=runtime.filesystem
    )
    with pytest.raises(ValueError, match="visibility authority"):
        build_mcp_server(
            service=service,
            audit=runtime.audit,
            principal_provider=StaticPrincipalProvider(),
            enable_fs_list=True,
        )


@pytest.mark.asyncio
async def test_fs_list_approval_required_does_not_offer_unsupported_retry(list_stack):
    async def requires_approval(**kwargs):
        raise SSHApprovalRequired(
            _policy_failure(Decision.APPROVAL_REQUIRED, approval_required=True),
            approval_status=_approval_status("fs_list"),
        )

    list_stack.filesystem.list = requires_approval
    async with Client(_list_server(list_stack, enable_fs_list=True)) as client:
        result = await client.call_tool("fs_list", {
            "host": "visible", "path": "/srv/app", "max_entries": 8,
        })
    assert result.is_error and not list_stack.calls
    assert "approval required by central policy" in str(result.content)
    assert APR_ID not in str(result.content) and "retry" not in str(result.content)
