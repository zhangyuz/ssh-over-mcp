import hashlib
import json
from datetime import UTC, datetime

import pytest

import ssh_over_mcp.ssh as ssh_package
from ssh_over_mcp.api.context import OperationContext
from ssh_over_mcp.api.models import PrincipalContext
from ssh_over_mcp.policy.models import (
    Decision,
    EvaluationRequest,
    PolicyDecision,
    RiskLevel,
)
from ssh_over_mcp.ssh.protocol import (
    FsMkdirEnvelope,
    FsReadEnvelope,
    FsStatEnvelope,
    FsWriteEnvelope,
    decode_request,
)
from ssh_over_mcp.ssh.transport import SSHExecutionResult


class Policy:
    def __init__(self, decision):
        self.decision = decision
        self.calls = []

    def evaluate(self, request):
        self.calls.append(request)
        return self.decision

    async def authorize(self, context, request, facts):
        decision = self.evaluate(request)
        if decision.decision is Decision.DENY:
            raise ssh_package.SSHPolicyDenied(decision)
        if decision.decision is Decision.APPROVAL_REQUIRED:
            raise ssh_package.SSHApprovalRequired(decision)
        return decision


def operation_context(label: str = "default") -> OperationContext:
    request_hex = hashlib.sha256(label.encode("utf-8")).hexdigest()[:32]
    return OperationContext(
        request_id=f"req_{request_hex}",
        principal=PrincipalContext(
            principal_id="static:developer",
            profile="developer",
        ),
        received_at=datetime(2026, 10, 1, tzinfo=UTC),
    )


class RecordingTransport:
    def __init__(self, result):
        self.result = result
        self.calls = []

    async def run(self, **kwargs):
        self.calls.append(kwargs)
        return self.result


def allow(*, normalized_path: str) -> PolicyDecision:
    return PolicyDecision(
        decision=Decision.ALLOW,
        reason="ok",
        risk=RiskLevel.LOW,
        normalized_path=normalized_path,
        policy_version="sha256:test",
    )


def request(tool: str, path: str) -> EvaluationRequest:
    return EvaluationRequest(
        profile="developer",
        host="dev01",
        tool=tool,
        path=path,
        privilege="user",
    )


@pytest.mark.asyncio
async def test_fs_stat_policy_normalizes_path_before_typed_transport():
    client_type = getattr(ssh_package, "SSHFilesystemClient", None)
    assert client_type is not None

    payload = json.dumps(
        {
            "gid": 3103,
            "kind": "regular",
            "mode": 0o640,
            "mtime_ns": 123456,
            "path": "/srv/app/config.yaml",
            "size": 7,
            "uid": 2103,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    policy = Policy(allow(normalized_path="/srv/app/config.yaml"))
    transport = RecordingTransport(
        SSHExecutionResult(
            request_id="req_fs_stat_1234",
            host="dev01",
            exit_status=0,
            stdout=payload,
            duration_ms=4,
        )
    )
    client = client_type(authorizer=policy, transport=transport)

    result = await client.stat(
        request("fs_stat", "/srv/app/./config.yaml"),
        context=operation_context('req_fs_stat_1234'),
    )

    assert len(policy.calls) == 1
    assert policy.calls[0].tool == "fs_stat"
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["host"] == "dev01"
    assert call["request_id"] == operation_context("req_fs_stat_1234").request_id
    assert call["timeout_seconds"] == 60.0
    assert call["max_output_bytes"] == 64 * 1024

    envelope, stdin = decode_request(call["payload"])
    assert isinstance(envelope, FsStatEnvelope)
    assert envelope.profile == "developer"
    assert envelope.path == "/srv/app/config.yaml"
    assert stdin == b""

    assert result.request_id == operation_context("req_fs_stat_1234").request_id
    assert result.host == "dev01"
    assert result.path == "/srv/app/config.yaml"
    assert result.kind == "regular"
    assert result.size == 7
    assert result.mode == 0o640
    assert result.uid == 2103
    assert result.gid == 3103
    assert result.mtime_ns == 123456


@pytest.mark.asyncio
async def test_fs_read_policy_normalizes_path_and_returns_raw_bytes():
    client_type = getattr(ssh_package, "SSHFilesystemClient", None)
    assert client_type is not None

    policy = Policy(allow(normalized_path="/srv/app/data.bin"))
    transport = RecordingTransport(
        SSHExecutionResult(
            request_id="req_fs_read_1234",
            host="dev01",
            exit_status=0,
            stdout=b"\x00\xffAB",
            duration_ms=5,
        )
    )
    client = client_type(authorizer=policy, transport=transport)

    result = await client.read(
        request("fs_read", "/srv/app/./data.bin"),
        max_bytes=4096,
        context=operation_context('req_fs_read_1234'),
    )

    assert len(policy.calls) == 1
    call = transport.calls[0]
    assert call["host"] == "dev01"
    assert call["request_id"] == operation_context("req_fs_read_1234").request_id
    assert call["timeout_seconds"] == 60.0
    assert call["max_output_bytes"] == 4096

    envelope, stdin = decode_request(call["payload"])
    assert isinstance(envelope, FsReadEnvelope)
    assert envelope.profile == "developer"
    assert envelope.path == "/srv/app/data.bin"
    assert envelope.max_bytes == 4096
    assert stdin == b""
    assert result.request_id == operation_context("req_fs_read_1234").request_id
    assert result.host == "dev01"
    assert result.path == "/srv/app/data.bin"
    assert result.data == b"\x00\xffAB"


def deny(decision: Decision) -> PolicyDecision:
    return PolicyDecision(
        decision=decision,
        reason="SUPERSECRET policy detail",
        risk=RiskLevel.HIGH,
        approval_required=decision == Decision.APPROVAL_REQUIRED,
        normalized_path="/srv/app/secret",
        policy_version="sha256:test",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "decision", "error_type"),
    [
        ("fs_stat", Decision.DENY, ssh_package.SSHPolicyDenied),
        ("fs_stat", Decision.APPROVAL_REQUIRED, ssh_package.SSHApprovalRequired),
        ("fs_read", Decision.DENY, ssh_package.SSHPolicyDenied),
        ("fs_read", Decision.APPROVAL_REQUIRED, ssh_package.SSHApprovalRequired),
    ],
)
async def test_filesystem_policy_failure_happens_before_transport(
    tool,
    decision,
    error_type,
):
    policy = Policy(deny(decision))
    transport = RecordingTransport(
        SSHExecutionResult(
            request_id="unused_request",
            host="dev01",
            exit_status=0,
            duration_ms=0,
        )
    )
    client = ssh_package.SSHFilesystemClient(
        authorizer=policy,
        transport=transport,
    )

    with pytest.raises(error_type):
        if tool == "fs_stat":
            await client.stat(request(tool, "/srv/app/secret"), context=operation_context())
        else:
            await client.read(
                request(tool, "/srv/app/secret"),
                max_bytes=4096,
                context=operation_context(),
            )

    assert len(policy.calls) == 1
    assert transport.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("max_bytes", [0, -1, True, 1024 * 1024 + 1])
async def test_fs_read_invalid_bound_fails_before_policy_and_transport(max_bytes):
    policy = Policy(allow(normalized_path="/srv/app/data.bin"))
    transport = RecordingTransport(
        SSHExecutionResult(
            request_id="unused_request",
            host="dev01",
            exit_status=0,
            duration_ms=0,
        )
    )
    client = ssh_package.SSHFilesystemClient(
        authorizer=policy,
        transport=transport,
    )

    with pytest.raises(ValueError, match="read bound"):
        await client.read(
            request("fs_read", "/srv/app/data.bin"),
            max_bytes=max_bytes,
            context=operation_context(),
        )

    assert policy.calls == []
    assert transport.calls == []


@pytest.mark.asyncio
async def test_fs_read_reserves_bounded_remote_diagnostic_budget():
    policy = Policy(allow(normalized_path="/srv/app/data.bin"))
    transport = RecordingTransport(
        SSHExecutionResult(
            request_id="req_diag_1234",
            host="dev01",
            exit_status=0,
            stdout=b"x",
            duration_ms=1,
        )
    )
    client = ssh_package.SSHFilesystemClient(
        authorizer=policy,
        transport=transport,
    )

    await client.read(
        request("fs_read", "/srv/app/data.bin"),
        max_bytes=1,
        context=operation_context('req_diag_1234'),
    )

    assert transport.calls[0]["max_output_bytes"] == 4096


@pytest.mark.asyncio
async def test_fs_read_never_returns_success_data_over_requested_bound():
    response_error = getattr(ssh_package, "SSHRemoteResponseError", None)
    assert response_error is not None

    policy = Policy(allow(normalized_path="/srv/app/data.bin"))
    transport = RecordingTransport(
        SSHExecutionResult(
            request_id="req_overread_1234",
            host="dev01",
            exit_status=0,
            stdout=b"AB",
            duration_ms=1,
        )
    )
    client = ssh_package.SSHFilesystemClient(
        authorizer=policy,
        transport=transport,
    )

    with pytest.raises(response_error, match="invalid remote filesystem response"):
        await client.read(
            request("fs_read", "/srv/app/data.bin"),
            max_bytes=1,
            context=operation_context('req_overread_1234'),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("remote_result", "error_name", "public_message"),
    [
        (
            SSHExecutionResult(
                request_id="req_timeout_1234",
                host="dev01",
                duration_ms=10,
                timed_out=True,
            ),
            "SSHRequestTimeout",
            "remote filesystem request timed out",
        ),
        (
            SSHExecutionResult(
                request_id="req_truncated_1234",
                host="dev01",
                duration_ms=2,
                truncated=True,
                stderr=b"SUPERSECRET truncated diagnostic",
            ),
            "SSHOutputLimitExceeded",
            "remote filesystem response exceeded output limit",
        ),
        (
            SSHExecutionResult(
                request_id="req_denied_1234",
                host="dev01",
                exit_status=77,
                duration_ms=2,
                stderr=b"SUPERSECRET host policy detail",
            ),
            "SSHRemotePolicyDenied",
            "remote filesystem policy denied request",
        ),
        (
            SSHExecutionResult(
                request_id="req_failure_1234",
                host="dev01",
                exit_status=69,
                duration_ms=2,
                stderr=b"SUPERSECRET filesystem detail",
            ),
            "SSHRemoteOperationError",
            "remote filesystem operation failed",
        ),
        (
            SSHExecutionResult(
                request_id="req_stderr_1234",
                host="dev01",
                exit_status=0,
                duration_ms=2,
                stdout=b"x",
                stderr=b"SUPERSECRET unexpected stderr",
            ),
            "SSHRemoteResponseError",
            "invalid remote filesystem response",
        ),
    ],
)
async def test_fs_read_normalizes_remote_failures_without_secret_echo(
    remote_result,
    error_name,
    public_message,
):
    error_type = getattr(ssh_package, error_name, None)
    assert error_type is not None

    client = ssh_package.SSHFilesystemClient(
        authorizer=Policy(allow(normalized_path="/srv/app/data.bin")),
        transport=RecordingTransport(remote_result),
    )

    with pytest.raises(error_type, match=public_message) as exc_info:
        await client.read(
            request("fs_read", "/srv/app/data.bin"),
            max_bytes=4096,
            context=operation_context(),
        )

    assert "SUPERSECRET" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_fs_stat_rejects_mismatched_remote_path():
    response_error = getattr(ssh_package, "SSHRemoteResponseError", None)
    assert response_error is not None

    payload = json.dumps(
        {
            "gid": 3103,
            "kind": "regular",
            "mode": 0o640,
            "mtime_ns": 123456,
            "path": "/srv/app/other.yaml",
            "size": 7,
            "uid": 2103,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    client = ssh_package.SSHFilesystemClient(
        authorizer=Policy(allow(normalized_path="/srv/app/config.yaml")),
        transport=RecordingTransport(
            SSHExecutionResult(
                request_id="req_path_1234",
                host="dev01",
                exit_status=0,
                stdout=payload,
                duration_ms=1,
            )
        ),
    )

    with pytest.raises(
        response_error,
        match="invalid remote filesystem response",
    ):
        await client.stat(
            request("fs_stat", "/srv/app/config.yaml"),
            context=operation_context(),
        )


@pytest.mark.asyncio
async def test_fs_stat_rejects_invalid_remote_json_without_echoing_payload():
    response_error = getattr(ssh_package, "SSHRemoteResponseError", None)
    assert response_error is not None

    client = ssh_package.SSHFilesystemClient(
        authorizer=Policy(allow(normalized_path="/srv/app/config.yaml")),
        transport=RecordingTransport(
            SSHExecutionResult(
                request_id="req_json_1234",
                host="dev01",
                exit_status=0,
                stdout=b'{"path":"SUPERSECRET","unknown":true}',
                duration_ms=1,
            )
        ),
    )

    with pytest.raises(response_error) as exc_info:
        await client.stat(
            request("fs_stat", "/srv/app/config.yaml"),
            context=operation_context(),
        )

    assert str(exc_info.value) == "invalid remote filesystem response"
    assert "SUPERSECRET" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_fs_mkdir_policy_normalizes_path_before_typed_transport():
    client_type = getattr(ssh_package, "SSHFilesystemClient", None)
    assert client_type is not None

    policy = Policy(allow(normalized_path="/srv/app/new-directory"))
    transport = RecordingTransport(
        SSHExecutionResult(
            request_id="req_fs_mkdir_1234",
            host="dev01",
            exit_status=0,
            duration_ms=3,
        )
    )
    client = client_type(authorizer=policy, transport=transport)

    result = await client.mkdir(
        request("fs_mkdir", "/srv/app/./new-directory"),
        context=operation_context('req_fs_mkdir_1234'),
    )

    assert len(policy.calls) == 1
    assert policy.calls[0].tool == "fs_mkdir"
    call = transport.calls[0]
    assert call["host"] == "dev01"
    assert call["request_id"] == operation_context("req_fs_mkdir_1234").request_id
    assert call["timeout_seconds"] == 60.0
    assert call["max_output_bytes"] == 4096

    envelope, stdin = decode_request(call["payload"])
    assert isinstance(envelope, FsMkdirEnvelope)
    assert envelope.profile == "developer"
    assert envelope.path == "/srv/app/new-directory"
    assert stdin == b""

    assert result.request_id == operation_context("req_fs_mkdir_1234").request_id
    assert result.host == "dev01"
    assert result.path == "/srv/app/new-directory"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("decision", "error_type"),
    [
        (Decision.DENY, ssh_package.SSHPolicyDenied),
        (Decision.APPROVAL_REQUIRED, ssh_package.SSHApprovalRequired),
    ],
)
async def test_fs_mkdir_policy_failure_happens_before_transport(
    decision,
    error_type,
):
    policy = Policy(deny(decision))
    transport = RecordingTransport(
        SSHExecutionResult(
            request_id="unused_request",
            host="dev01",
            exit_status=0,
            duration_ms=0,
        )
    )
    client = ssh_package.SSHFilesystemClient(
        authorizer=policy,
        transport=transport,
    )

    with pytest.raises(error_type):
        await client.mkdir(
            request("fs_mkdir", "/srv/app/new-directory"),
            context=operation_context(),
        )

    assert len(policy.calls) == 1
    assert transport.calls == []


@pytest.mark.asyncio
async def test_fs_mkdir_remote_policy_denial_is_definite():
    client = ssh_package.SSHFilesystemClient(
        authorizer=Policy(allow(normalized_path="/srv/app/new-directory")),
        transport=RecordingTransport(
            SSHExecutionResult(
                request_id="req_mkdir_deny_1234",
                host="dev01",
                exit_status=77,
                stderr=b"SUPERSECRET host policy detail",
                duration_ms=2,
            )
        ),
    )

    with pytest.raises(
        ssh_package.SSHRemotePolicyDenied,
        match="remote filesystem policy denied request",
    ) as exc_info:
        await client.mkdir(
            request("fs_mkdir", "/srv/app/new-directory"),
            context=operation_context(),
        )

    assert "SUPERSECRET" not in str(exc_info.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "remote_result",
    [
        SSHExecutionResult(
            request_id="req_timeout_1234",
            host="dev01",
            duration_ms=10,
            timed_out=True,
        ),
        SSHExecutionResult(
            request_id="req_truncated_1234",
            host="dev01",
            duration_ms=2,
            truncated=True,
            stderr=b"SUPERSECRET truncated diagnostic",
        ),
        SSHExecutionResult(
            request_id="req_failure_1234",
            host="dev01",
            exit_status=69,
            duration_ms=2,
            stderr=b"SUPERSECRET remote failure",
        ),
        SSHExecutionResult(
            request_id="req_stdout_1234",
            host="dev01",
            exit_status=0,
            duration_ms=2,
            stdout=b"SUPERSECRET unexpected output",
        ),
        SSHExecutionResult(
            request_id="req_stderr_1234",
            host="dev01",
            exit_status=0,
            duration_ms=2,
            stderr=b"SUPERSECRET unexpected stderr",
        ),
    ],
)
async def test_fs_mkdir_post_send_abnormal_result_is_outcome_uncertain(
    remote_result,
):
    uncertain_error = getattr(
        ssh_package,
        "SSHRequestOutcomeUncertain",
        None,
    )
    assert uncertain_error is not None

    client = ssh_package.SSHFilesystemClient(
        authorizer=Policy(allow(normalized_path="/srv/app/new-directory")),
        transport=RecordingTransport(remote_result),
    )

    with pytest.raises(
        uncertain_error,
        match="remote filesystem mutation outcome is uncertain",
    ) as exc_info:
        await client.mkdir(
            request("fs_mkdir", "/srv/app/new-directory"),
            context=operation_context(),
        )

    assert "SUPERSECRET" not in str(exc_info.value)


class RaisingTransport:
    def __init__(self, error):
        self.error = error
        self.calls = []

    async def run(self, **kwargs):
        self.calls.append(kwargs)
        raise self.error


@pytest.mark.asyncio
async def test_fs_mkdir_transport_uncertain_failure_stays_uncertain():
    uncertain_error = getattr(
        ssh_package,
        "SSHRequestOutcomeUncertain",
        None,
    )
    assert uncertain_error is not None
    client = ssh_package.SSHFilesystemClient(
        authorizer=Policy(allow(normalized_path="/srv/app/new-directory")),
        transport=RaisingTransport(
            uncertain_error("SUPERSECRET transport uncertainty")
        ),
    )

    with pytest.raises(
        uncertain_error,
        match="remote filesystem mutation outcome is uncertain",
    ) as exc_info:
        await client.mkdir(
            request("fs_mkdir", "/srv/app/new-directory"),
            context=operation_context(),
        )

    assert "SUPERSECRET" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_fs_mkdir_status_77_with_local_timeout_is_still_uncertain():
    client = ssh_package.SSHFilesystemClient(
        authorizer=Policy(allow(normalized_path="/srv/app/new-directory")),
        transport=RecordingTransport(
            SSHExecutionResult(
                request_id="req_mkdir_ambiguous_1234",
                host="dev01",
                exit_status=77,
                duration_ms=10,
                timed_out=True,
                stderr=b"SUPERSECRET partial denial",
            )
        ),
    )

    with pytest.raises(
        ssh_package.SSHRequestOutcomeUncertain,
        match="remote filesystem mutation outcome is uncertain",
    ) as exc_info:
        await client.mkdir(
            request("fs_mkdir", "/srv/app/new-directory"),
            context=operation_context(),
        )

    assert "SUPERSECRET" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_fs_write_policy_normalizes_path_and_sends_binary_body():
    committed_type = getattr(
        ssh_package,
        "SSHFilesystemWriteCommittedUncertain",
        None,
    )
    assert committed_type is not None

    policy = Policy(allow(normalized_path="/srv/app/new.bin"))
    transport = RecordingTransport(
        SSHExecutionResult(
            request_id="req_fs_write_1234",
            host="dev01",
            exit_status=0,
            duration_ms=3,
        )
    )
    client = ssh_package.SSHFilesystemClient(
        authorizer=policy,
        transport=transport,
    )

    result = await client.write(
        request("fs_write", "/srv/app/./new.bin"),
        b"\x00\xffAB",
        context=operation_context('req_fs_write_1234'),
    )

    assert len(policy.calls) == 1
    assert policy.calls[0].tool == "fs_write"
    call = transport.calls[0]
    assert call["host"] == "dev01"
    assert call["request_id"] == operation_context("req_fs_write_1234").request_id
    assert call["timeout_seconds"] == 60.0
    assert call["max_output_bytes"] == 4096

    envelope, body = decode_request(call["payload"])
    assert isinstance(envelope, FsWriteEnvelope)
    assert envelope.profile == "developer"
    assert envelope.path == "/srv/app/new.bin"
    assert envelope.content_length == 4
    assert body == b"\x00\xffAB"

    assert result.request_id == operation_context("req_fs_write_1234").request_id
    assert result.host == "dev01"
    assert result.path == "/srv/app/new.bin"
    assert result.content_length == 4


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("decision", "error_type"),
    [
        (Decision.DENY, ssh_package.SSHPolicyDenied),
        (Decision.APPROVAL_REQUIRED, ssh_package.SSHApprovalRequired),
    ],
)
async def test_fs_write_policy_failure_happens_before_transport(
    decision,
    error_type,
):
    policy = Policy(deny(decision))
    transport = RecordingTransport(
        SSHExecutionResult(
            request_id="unused_request",
            host="dev01",
            exit_status=0,
            duration_ms=0,
        )
    )
    client = ssh_package.SSHFilesystemClient(
        authorizer=policy,
        transport=transport,
    )

    with pytest.raises(error_type):
        await client.write(
            request("fs_write", "/srv/app/new.bin"),
            b"secret",
            context=operation_context(),
        )

    assert len(policy.calls) == 1
    assert transport.calls == []


@pytest.mark.asyncio
async def test_fs_write_remote_policy_denial_is_definite():
    client = ssh_package.SSHFilesystemClient(
        authorizer=Policy(allow(normalized_path="/srv/app/new.bin")),
        transport=RecordingTransport(
            SSHExecutionResult(
                request_id="req_write_deny_1234",
                host="dev01",
                exit_status=77,
                stderr=b"SUPERSECRET host policy detail",
                duration_ms=2,
            )
        ),
    )

    with pytest.raises(
        ssh_package.SSHRemotePolicyDenied,
        match="remote filesystem policy denied request",
    ) as exc_info:
        await client.write(
            request("fs_write", "/srv/app/new.bin"),
            b"data",
            context=operation_context(),
        )

    assert "SUPERSECRET" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_fs_write_status_74_preserves_committed_durability_uncertain():
    committed_type = getattr(
        ssh_package,
        "SSHFilesystemWriteCommittedUncertain",
        None,
    )
    assert committed_type is not None

    client = ssh_package.SSHFilesystemClient(
        authorizer=Policy(allow(normalized_path="/srv/app/new.bin")),
        transport=RecordingTransport(
            SSHExecutionResult(
                request_id="req_write_commit_1234",
                host="dev01",
                exit_status=74,
                stderr=b"SUPERSECRET remote committed detail",
                duration_ms=2,
            )
        ),
    )

    with pytest.raises(
        committed_type,
        match="filesystem write committed; durability uncertain; do not retry blindly",
    ) as exc_info:
        await client.write(
            request("fs_write", "/srv/app/new.bin"),
            b"data",
            context=operation_context(),
        )

    assert "SUPERSECRET" not in str(exc_info.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "remote_result",
    [
        SSHExecutionResult(
            request_id="req_timeout_write_1234",
            host="dev01",
            duration_ms=10,
            timed_out=True,
        ),
        SSHExecutionResult(
            request_id="req_truncated_write_1234",
            host="dev01",
            duration_ms=2,
            truncated=True,
            stderr=b"SUPERSECRET truncated diagnostic",
        ),
        SSHExecutionResult(
            request_id="req_failure_write_1234",
            host="dev01",
            exit_status=69,
            duration_ms=2,
            stderr=b"SUPERSECRET remote failure",
        ),
        SSHExecutionResult(
            request_id="req_stdout_write_1234",
            host="dev01",
            exit_status=0,
            duration_ms=2,
            stdout=b"SUPERSECRET unexpected output",
        ),
        SSHExecutionResult(
            request_id="req_stderr_write_1234",
            host="dev01",
            exit_status=0,
            duration_ms=2,
            stderr=b"SUPERSECRET unexpected stderr",
        ),
    ],
)
async def test_fs_write_post_send_abnormal_result_is_outcome_uncertain(
    remote_result,
):
    client = ssh_package.SSHFilesystemClient(
        authorizer=Policy(allow(normalized_path="/srv/app/new.bin")),
        transport=RecordingTransport(remote_result),
    )

    with pytest.raises(
        ssh_package.SSHRequestOutcomeUncertain,
        match="remote filesystem mutation outcome is uncertain",
    ) as exc_info:
        await client.write(
            request("fs_write", "/srv/app/new.bin"),
            b"data",
            context=operation_context(),
        )

    assert "SUPERSECRET" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_fs_write_status_74_with_local_timeout_is_generic_uncertain():
    committed_type = getattr(
        ssh_package,
        "SSHFilesystemWriteCommittedUncertain",
        None,
    )
    assert committed_type is not None

    client = ssh_package.SSHFilesystemClient(
        authorizer=Policy(allow(normalized_path="/srv/app/new.bin")),
        transport=RecordingTransport(
            SSHExecutionResult(
                request_id="req_write_ambiguous_1234",
                host="dev01",
                exit_status=74,
                duration_ms=10,
                timed_out=True,
                stderr=b"SUPERSECRET partial committed diagnostic",
            )
        ),
    )

    with pytest.raises(
        ssh_package.SSHRequestOutcomeUncertain,
        match="remote filesystem mutation outcome is uncertain",
    ) as exc_info:
        await client.write(
            request("fs_write", "/srv/app/new.bin"),
            b"data",
            context=operation_context(),
        )

    assert not isinstance(exc_info.value, committed_type)
    assert "SUPERSECRET" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_fs_write_transport_uncertain_failure_stays_uncertain():
    client = ssh_package.SSHFilesystemClient(
        authorizer=Policy(allow(normalized_path="/srv/app/new.bin")),
        transport=RaisingTransport(
            ssh_package.SSHRequestOutcomeUncertain(
                "SUPERSECRET transport uncertainty"
            )
        ),
    )

    with pytest.raises(
        ssh_package.SSHRequestOutcomeUncertain,
        match="remote filesystem mutation outcome is uncertain",
    ) as exc_info:
        await client.write(
            request("fs_write", "/srv/app/new.bin"),
            b"data",
            context=operation_context(),
        )

    assert "SUPERSECRET" not in str(exc_info.value)
