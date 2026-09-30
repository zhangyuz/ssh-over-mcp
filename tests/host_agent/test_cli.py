import io
import json
import os
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.cli import (
    EX_FS_COMMITTED,
    EX_NOPERM,
    EX_PROTOCOL,
    EX_UNAVAILABLE,
    OutputDeliveryError,
    _deliver_execution_output,
    run,
)
from ssh_over_mcp.host_agent.containment import ContainmentStats
from ssh_over_mcp.host_agent.filesystem import (
    FilesystemAccessError,
    ReadFileResult,
    ReadOnlyFileStat,
)
from ssh_over_mcp.host_agent.filesystem_mutation import (
    FilesystemMutationCommittedError,
    FilesystemMutationError,
)
from ssh_over_mcp.host_agent.policy import (
    HostArgvRule,
    HostChildLimits,
    HostCommandRule,
    HostContainmentLimits,
    HostContainmentPolicy,
    HostExecutionPolicy,
    HostFilesystemProfilePolicy,
    HostLinuxIdentity,
)
from ssh_over_mcp.host_agent.run import SupervisedExecutionResult
from ssh_over_mcp.ssh.protocol import (
    ExecEnvelope,
    ExecutionLimits,
    FsMkdirEnvelope,
    FsReadEnvelope,
    FsStatEnvelope,
    FsWriteEnvelope,
    encode_request,
)


def _child_limits() -> HostChildLimits:
    return HostChildLimits(
        cpu_seconds=10,
        address_space_bytes=512 * 1024 * 1024,
        max_processes=64,
        file_size_bytes=64 * 1024 * 1024,
        open_files=128,
    )


def _containment_policy() -> HostContainmentPolicy:
    return HostContainmentPolicy(
        manager_endpoint="/run/ssh-over-mcp/containment-manager.sock",
        manager=HostLinuxIdentity(uid=2101, gid=3101),
        host_agent=HostLinuxIdentity(uid=2102, gid=3102),
        workload=HostLinuxIdentity(uid=2103, gid=3103),
        manager_client_gid=3199,
        limits=HostContainmentLimits(
            memory_max_bytes=256 * 1024 * 1024,
            pids_max=32,
            cpu_quota_us=25_000,
            cpu_period_us=100_000,
        ),
    )


def make_executable(tmp_path: Path, name: str = "tool") -> Path:
    path = tmp_path / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def payload(
    executable: Path,
    cwd: Path | None,
    *,
    argv: tuple[str, ...] = (),
    max_stdin_bytes: int = 0,
    stdin: bytes = b"",
) -> bytes:
    envelope = ExecEnvelope(
        request_id="req_12345678",
        profile="developer",
        executable=str(executable),
        argv=argv,
        cwd=str(cwd) if cwd is not None else None,
        limits=ExecutionLimits(
            timeout_seconds=10,
            max_output_bytes=1024,
            max_stdin_bytes=max_stdin_bytes,
        ),
    )
    return encode_request(envelope, stdin)


def policy(
    executable: Path,
    *,
    cwd_root: Path | None = None,
    max_stdin_bytes: int = 0,
) -> HostExecutionPolicy:
    return HostExecutionPolicy(
        allowed_profiles=frozenset({"developer"}),
        child_limits=_child_limits(),
        commands={
            str(executable): HostCommandRule(
                resolved_path=str(executable.resolve()),
                argv=(HostArgvRule(mode="exact", args=()),),
                cwd_roots=(str(cwd_root.resolve()),) if cwd_root else (),
                allow_no_cwd=cwd_root is None,
                require_root_owned=False,
            )
        },
        max_timeout_seconds=30,
        max_output_bytes=4096,
        max_stdin_bytes=max_stdin_bytes,
    )


def filesystem_policy(
    executable: Path,
    *,
    stat_roots: tuple[str, ...] = (),
    read_roots: tuple[str, ...] = (),
    mkdir_roots: tuple[str, ...] = (),
    write_create_roots: tuple[str, ...] = (),
    max_read_bytes: int | None = None,
    max_write_bytes: int | None = None,
) -> HostExecutionPolicy:
    values = policy(executable).model_dump()
    values["filesystem"] = {
        "developer": HostFilesystemProfilePolicy(
            stat_roots=stat_roots,
            read_roots=read_roots,
            mkdir_roots=mkdir_roots,
            write_create_roots=write_create_roots,
            max_read_bytes=max_read_bytes,
            max_write_bytes=max_write_bytes,
        ).model_dump()
    }
    return HostExecutionPolicy.model_validate(values)


def fs_stat_payload(path: str) -> bytes:
    return encode_request(
        FsStatEnvelope(
            request_id="req_fs_stat_1234",
            profile="developer",
            path=path,
        )
    )


def fs_read_payload(path: str, *, max_bytes: int) -> bytes:
    return encode_request(
        FsReadEnvelope(
            request_id="req_fs_read_1234",
            profile="developer",
            path=path,
            max_bytes=max_bytes,
        )
    )


def fs_mkdir_payload(path: str) -> bytes:
    return encode_request(
        FsMkdirEnvelope(
            request_id="req_fs_mkdir_1234",
            profile="developer",
            path=path,
        )
    )


def fs_write_payload(path: str, body: bytes) -> bytes:
    return encode_request(
        FsWriteEnvelope(
            request_id="req_fs_write_1234",
            profile="developer",
            path=path,
            content_length=len(body),
        ),
        body,
    )


def test_valid_authorized_request_still_fails_closed_until_execution_phase(
    tmp_path: Path,
):
    executable = make_executable(tmp_path)
    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(payload(executable, None)),
        stderr=stderr,
        policy=policy(executable),
    )

    assert status == EX_UNAVAILABLE
    assert "execution unavailable" in stderr.getvalue()


def test_policy_v4_executes_through_manager_and_server_owned_containment(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)
    base_policy = policy(executable, max_stdin_bytes=16)
    values = base_policy.model_dump()
    values["version"] = 4
    values["containment"] = _containment_policy().model_dump()
    execution_policy = HostExecutionPolicy.model_validate(values)

    class FakeClient:
        name = "containment-manager"

        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    client = FakeClient()
    observed: dict[str, object] = {}

    def fake_connect(path, *, identity_plan, timeout_seconds=2.0):
        observed["endpoint"] = str(path)
        observed["identity_plan"] = identity_plan
        observed["connect_timeout"] = timeout_seconds
        return client

    def fake_run(
        prepared,
        application_stdin,
        limits,
        *,
        workload_identity_policy,
        containment_backend,
        containment_request,
    ):
        observed["prepared_request_id"] = prepared.request_id
        observed["stdin"] = application_stdin
        observed["limits"] = limits
        observed["workload_identity_policy"] = workload_identity_policy
        observed["backend"] = containment_backend
        observed["containment_request"] = containment_request
        return SupervisedExecutionResult(
            returncode=7,
            stdout=b"stdout-\xff",
            stderr=b"stderr-\xfe",
            timed_out=False,
            output_exceeded=False,
            duration_seconds=0.01,
            containment_stats=ContainmentStats(populated=False),
        )

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.connect_authenticated_containment_manager",
        fake_connect,
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.run_prepared_native",
        fake_run,
    )

    stdout = io.BytesIO()
    execution_stderr = io.BytesIO()
    control_stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(
            payload(
                executable,
                None,
                max_stdin_bytes=16,
                stdin=b"request-stdin",
            )
        ),
        stdout=stdout,
        stderr=control_stderr,
        execution_stderr=execution_stderr,
        policy=execution_policy,
    )

    assert status == 7
    assert stdout.getvalue() == b"stdout-\xff"
    assert execution_stderr.getvalue() == b"stderr-\xfe"
    assert control_stderr.getvalue() == ""
    assert client.closed is True
    assert observed["endpoint"] == "/run/ssh-over-mcp/containment-manager.sock"
    assert observed["prepared_request_id"] == "req_12345678"
    assert observed["stdin"] == b"request-stdin"
    assert observed["backend"] is client

    identity_plan = observed["identity_plan"]
    assert identity_plan.manager.uid == 2101
    assert identity_plan.host_agent.uid == 2102
    assert identity_plan.workload.uid == 2103
    assert identity_plan.manager_client_gid == 3199

    workload_policy = observed["workload_identity_policy"]
    assert workload_policy.identity.uid == 2103
    assert workload_policy.identity.gid == 3103
    assert workload_policy.supplementary_gids == frozenset()

    containment_request = observed["containment_request"]
    assert containment_request.request_id == "req_12345678"
    assert containment_request.limits.memory_max_bytes == 256 * 1024 * 1024
    assert containment_request.limits.pids_max == 32
    assert containment_request.limits.cpu_quota_us == 25_000
    assert containment_request.limits.cpu_period_us == 100_000


def test_policy_v4_maps_signal_returncode_to_ssh_exit_status(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)
    values = policy(executable).model_dump()
    values["version"] = 4
    values["containment"] = _containment_policy().model_dump()
    execution_policy = HostExecutionPolicy.model_validate(values)

    class FakeClient:
        name = "containment-manager"

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.connect_authenticated_containment_manager",
        lambda *_args, **_kwargs: FakeClient(),
    )
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.run_prepared_native",
        lambda *_args, **_kwargs: SupervisedExecutionResult(
            returncode=-9,
            stdout=b"",
            stderr=b"",
            timed_out=False,
            output_exceeded=False,
            duration_seconds=0.01,
            containment_stats=ContainmentStats(populated=False),
        ),
    )

    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(payload(executable, None)),
        stdout=io.BytesIO(),
        stderr=io.StringIO(),
        execution_stderr=io.BytesIO(),
        policy=execution_policy,
    )

    assert status == 137


def test_policy_v4_manager_failure_is_generic_and_fail_closed(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)
    values = policy(executable).model_dump()
    values["version"] = 4
    values["containment"] = _containment_policy().model_dump()
    execution_policy = HostExecutionPolicy.model_validate(values)

    def fail_connect(*_args, **_kwargs):
        raise RuntimeError("sensitive manager detail")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.connect_authenticated_containment_manager",
        fail_connect,
    )

    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(payload(executable, None)),
        stdout=io.BytesIO(),
        stderr=stderr,
        execution_stderr=io.BytesIO(),
        policy=execution_policy,
    )

    assert status == EX_UNAVAILABLE
    assert stderr.getvalue() == "ssh-over-mcp-host-agent: execution failed\n"
    assert "sensitive manager detail" not in stderr.getvalue()


def test_host_policy_denial_stops_before_execution(tmp_path: Path):
    allowed = make_executable(tmp_path, "allowed")
    denied = make_executable(tmp_path, "denied")
    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(payload(denied, None)),
        stderr=stderr,
        policy=policy(allowed),
    )

    assert status == EX_NOPERM
    assert "denied" in stderr.getvalue()


def test_argv_denial_stops_before_execution(tmp_path: Path):
    executable = make_executable(tmp_path)
    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(
            payload(executable, None, argv=("unexpected",))
        ),
        stderr=stderr,
        policy=policy(executable),
    )

    assert status == EX_NOPERM
    assert "argv" in stderr.getvalue()


def test_resource_ceiling_denial_does_not_read_application_stdin(
    tmp_path: Path,
):
    executable = make_executable(tmp_path)
    framed = payload(
        executable,
        None,
        max_stdin_bytes=16,
        stdin=b"0123456789abcdef",
    )
    stream = io.BytesIO(framed)
    stderr = io.StringIO()

    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=stream,
        stderr=stderr,
        policy=policy(executable, max_stdin_bytes=0),
    )

    assert status == EX_NOPERM
    assert stream.tell() < len(framed)


def test_invalid_forcecommand_is_rejected_without_parsing(tmp_path: Path):
    executable = make_executable(tmp_path)
    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "bash"},
        stdin=io.BytesIO(b"not-a-frame"),
        stderr=stderr,
        policy=policy(executable),
    )

    assert status == EX_PROTOCOL
    assert "rejected" in stderr.getvalue()


def test_output_delivery_times_out_when_ssh_peer_stops_reading():
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    stdout = os.fdopen(stdout_write, "wb", buffering=0)
    execution_stderr = os.fdopen(stderr_write, "wb", buffering=0)
    try:
        with pytest.raises(OutputDeliveryError, match="timed out"):
            _deliver_execution_output(
                stdout,
                execution_stderr,
                b"x" * (1024 * 1024),
                b"",
                timeout_seconds=0.02,
            )
    finally:
        stdout.close()
        execution_stderr.close()
        os.close(stdout_read)
        os.close(stderr_read)



def test_fs_stat_runs_policy_then_typed_primitive(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)
    observed: dict[str, object] = {}

    def fake_stat(path: str) -> ReadOnlyFileStat:
        observed["path"] = path
        return ReadOnlyFileStat(
            path=path,
            kind="regular",
            size=7,
            mode=0o640,
            uid=2103,
            gid=3103,
            mtime_ns=123456,
        )

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.stat_path",
        fake_stat,
    )

    stdout = io.BytesIO()
    execution_stderr = io.BytesIO()
    control_stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(fs_stat_payload("/srv/app/config.yaml")),
        stdout=stdout,
        stderr=control_stderr,
        execution_stderr=execution_stderr,
        policy=filesystem_policy(
            executable,
            stat_roots=("/srv/app",),
        ),
    )

    assert status == 0
    assert observed["path"] == "/srv/app/config.yaml"
    assert json.loads(stdout.getvalue()) == {
        "gid": 3103,
        "kind": "regular",
        "mode": 0o640,
        "mtime_ns": 123456,
        "path": "/srv/app/config.yaml",
        "size": 7,
        "uid": 2103,
    }
    assert execution_stderr.getvalue() == b""
    assert control_stderr.getvalue() == ""


def test_fs_read_returns_raw_binary_bytes_with_authorized_bound(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)
    observed: dict[str, object] = {}
    stat = ReadOnlyFileStat(
        path="/srv/app/data.bin",
        kind="regular",
        size=4,
        mode=0o600,
        uid=2103,
        gid=3103,
        mtime_ns=1,
    )

    def fake_read(path: str, *, max_bytes: int) -> ReadFileResult:
        observed["path"] = path
        observed["max_bytes"] = max_bytes
        return ReadFileResult(data=b"\x00\xffAB", stat=stat)

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.read_file",
        fake_read,
    )

    stdout = io.BytesIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(
            fs_read_payload("/srv/app/data.bin", max_bytes=512)
        ),
        stdout=stdout,
        stderr=io.StringIO(),
        execution_stderr=io.BytesIO(),
        policy=filesystem_policy(
            executable,
            read_roots=("/srv/app",),
            max_read_bytes=1024,
        ),
    )

    assert status == 0
    assert stdout.getvalue() == b"\x00\xffAB"
    assert observed == {
        "path": "/srv/app/data.bin",
        "max_bytes": 512,
    }


def test_fs_policy_denial_is_generic_and_stops_before_primitive(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)

    def forbidden_read(*_args, **_kwargs):
        raise AssertionError("filesystem primitive must not run after denial")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.read_file",
        forbidden_read,
    )

    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(
            fs_read_payload("/srv/private/secret", max_bytes=1)
        ),
        stdout=io.BytesIO(),
        stderr=stderr,
        execution_stderr=io.BytesIO(),
        policy=filesystem_policy(
            executable,
            read_roots=("/srv/app",),
            max_read_bytes=1024,
        ),
    )

    assert status == EX_NOPERM
    assert stderr.getvalue() == (
        "ssh-over-mcp-host-agent: filesystem denied\n"
    )
    assert "/srv/app" not in stderr.getvalue()
    assert "/srv/private" not in stderr.getvalue()


def test_fs_trailing_stdin_is_rejected_before_primitive(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)

    def forbidden_read(*_args, **_kwargs):
        raise AssertionError("filesystem primitive must not run with stdin")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.read_file",
        forbidden_read,
    )

    framed = fs_read_payload("/srv/app/data", max_bytes=8) + b"x"
    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(framed),
        stdout=io.BytesIO(),
        stderr=stderr,
        execution_stderr=io.BytesIO(),
        policy=filesystem_policy(
            executable,
            read_roots=("/srv/app",),
            max_read_bytes=8,
        ),
    )

    assert status == EX_PROTOCOL
    assert "stdin exceeds configured maximum" in stderr.getvalue()


def test_fs_read_policy_ceiling_stops_before_primitive(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)

    def forbidden_read(*_args, **_kwargs):
        raise AssertionError("filesystem primitive must not exceed policy")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.read_file",
        forbidden_read,
    )

    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(
            fs_read_payload("/srv/app/data", max_bytes=1025)
        ),
        stdout=io.BytesIO(),
        stderr=io.StringIO(),
        execution_stderr=io.BytesIO(),
        policy=filesystem_policy(
            executable,
            read_roots=("/srv/app",),
            max_read_bytes=1024,
        ),
    )

    assert status == EX_NOPERM


def test_fs_primitive_failure_is_generic(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)

    def fail_stat(_path: str):
        raise FilesystemAccessError("sensitive inode/path detail")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.stat_path",
        fail_stat,
    )

    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(fs_stat_payload("/srv/app/missing")),
        stdout=io.BytesIO(),
        stderr=stderr,
        execution_stderr=io.BytesIO(),
        policy=filesystem_policy(
            executable,
            stat_roots=("/srv/app",),
        ),
    )

    assert status == EX_UNAVAILABLE
    assert stderr.getvalue() == (
        "ssh-over-mcp-host-agent: filesystem operation failed\n"
    )
    assert "sensitive" not in stderr.getvalue()


def test_fs_mkdir_runs_policy_then_create_only_primitive(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)
    observed: dict[str, object] = {}

    def fake_create(path: str) -> None:
        observed["path"] = path

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.create_directory",
        fake_create,
    )

    stdout = io.BytesIO()
    execution_stderr = io.BytesIO()
    control_stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(fs_mkdir_payload("/srv/app/new-directory")),
        stdout=stdout,
        stderr=control_stderr,
        execution_stderr=execution_stderr,
        policy=filesystem_policy(
            executable,
            mkdir_roots=("/srv/app",),
        ),
    )

    assert status == 0
    assert observed["path"] == "/srv/app/new-directory"
    assert stdout.getvalue() == b""
    assert execution_stderr.getvalue() == b""
    assert control_stderr.getvalue() == ""


def test_fs_mkdir_policy_denial_stops_before_mutation(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)

    def forbidden_create(*_args, **_kwargs):
        raise AssertionError("mkdir primitive must not run after policy denial")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.create_directory",
        forbidden_create,
    )

    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(fs_mkdir_payload("/srv/private/new-directory")),
        stdout=io.BytesIO(),
        stderr=stderr,
        execution_stderr=io.BytesIO(),
        policy=filesystem_policy(
            executable,
            mkdir_roots=("/srv/app",),
        ),
    )

    assert status == EX_NOPERM
    assert stderr.getvalue() == (
        "ssh-over-mcp-host-agent: filesystem denied\n"
    )


def test_fs_mkdir_trailing_stdin_is_rejected_before_mutation(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)

    def forbidden_create(*_args, **_kwargs):
        raise AssertionError("mkdir primitive must not run with stdin")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.create_directory",
        forbidden_create,
    )

    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(
            fs_mkdir_payload("/srv/app/new-directory") + b"x"
        ),
        stdout=io.BytesIO(),
        stderr=stderr,
        execution_stderr=io.BytesIO(),
        policy=filesystem_policy(
            executable,
            mkdir_roots=("/srv/app",),
        ),
    )

    assert status == EX_PROTOCOL
    assert "stdin exceeds configured maximum" in stderr.getvalue()


def test_fs_mkdir_primitive_failure_is_generic(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)

    def fail_create(_path: str) -> None:
        raise FilesystemMutationError("sensitive namespace detail")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.create_directory",
        fail_create,
    )

    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(fs_mkdir_payload("/srv/app/new-directory")),
        stdout=io.BytesIO(),
        stderr=stderr,
        execution_stderr=io.BytesIO(),
        policy=filesystem_policy(
            executable,
            mkdir_roots=("/srv/app",),
        ),
    )

    assert status == EX_UNAVAILABLE
    assert stderr.getvalue() == (
        "ssh-over-mcp-host-agent: filesystem operation failed\n"
    )
    assert "sensitive" not in stderr.getvalue()


def test_fs_write_authorizes_and_reads_complete_body_before_create(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)
    observed: dict[str, object] = {}

    def fake_create(path: str, data: bytes, *, expected_length: int) -> None:
        observed["path"] = path
        observed["data"] = data
        observed["expected_length"] = expected_length

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.create_regular_file",
        fake_create,
    )

    stdout = io.BytesIO()
    control_stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(fs_write_payload("/srv/app/new.bin", b"\x00\xffAB")),
        stdout=stdout,
        stderr=control_stderr,
        execution_stderr=io.BytesIO(),
        policy=filesystem_policy(
            executable,
            write_create_roots=("/srv/app",),
            max_write_bytes=1024,
        ),
    )

    assert status == 0
    assert observed == {
        "path": "/srv/app/new.bin",
        "data": b"\x00\xffAB",
        "expected_length": 4,
    }
    assert stdout.getvalue() == b""
    assert control_stderr.getvalue() == ""


def test_fs_write_policy_denial_does_not_read_body_or_mutate(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)
    framed = fs_write_payload("/srv/private/new.bin", b"secret")
    stream = io.BytesIO(framed)

    def forbidden_create(*_args, **_kwargs):
        raise AssertionError("write primitive must not run after policy denial")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.create_regular_file",
        forbidden_create,
    )

    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=stream,
        stdout=io.BytesIO(),
        stderr=stderr,
        execution_stderr=io.BytesIO(),
        policy=filesystem_policy(
            executable,
            write_create_roots=("/srv/app",),
            max_write_bytes=1024,
        ),
    )

    assert status == EX_NOPERM
    assert stream.tell() < len(framed)
    assert stderr.getvalue() == "ssh-over-mcp-host-agent: filesystem denied\n"


@pytest.mark.parametrize("delta", [-1, 1])
def test_fs_write_body_mismatch_stops_before_mutation(
    tmp_path: Path,
    monkeypatch,
    delta: int,
):
    executable = make_executable(tmp_path)
    valid = fs_write_payload("/srv/app/new.bin", b"ABCD")
    framed = valid[:-1] if delta < 0 else valid + b"x"

    def forbidden_create(*_args, **_kwargs):
        raise AssertionError("write primitive must not run with mismatched body")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.create_regular_file",
        forbidden_create,
    )

    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(framed),
        stdout=io.BytesIO(),
        stderr=stderr,
        execution_stderr=io.BytesIO(),
        policy=filesystem_policy(
            executable,
            write_create_roots=("/srv/app",),
            max_write_bytes=1024,
        ),
    )

    assert status == EX_PROTOCOL
    assert "body length mismatch" in stderr.getvalue()


def test_fs_write_missing_output_stream_stops_before_mutation(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)

    def forbidden_create(*_args, **_kwargs):
        raise AssertionError("write primitive must not run without output streams")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.create_regular_file",
        forbidden_create,
    )

    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(fs_write_payload("/srv/app/new.bin", b"ABCD")),
        stderr=io.StringIO(),
        policy=filesystem_policy(
            executable,
            write_create_roots=("/srv/app",),
            max_write_bytes=1024,
        ),
    )

    assert status == EX_UNAVAILABLE


def test_fs_write_prepublication_failure_is_generic(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)

    def fail_create(*_args, **_kwargs):
        raise FilesystemMutationError("sensitive prepublication detail")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.create_regular_file",
        fail_create,
    )

    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(fs_write_payload("/srv/app/new.bin", b"ABCD")),
        stdout=io.BytesIO(),
        stderr=stderr,
        execution_stderr=io.BytesIO(),
        policy=filesystem_policy(
            executable,
            write_create_roots=("/srv/app",),
            max_write_bytes=1024,
        ),
    )

    assert status == EX_UNAVAILABLE
    assert stderr.getvalue() == (
        "ssh-over-mcp-host-agent: filesystem operation failed\n"
    )
    assert "sensitive" not in stderr.getvalue()


def test_fs_write_committed_outcome_is_distinct_and_not_retryable(
    tmp_path: Path,
    monkeypatch,
):
    executable = make_executable(tmp_path)

    def committed_create(*_args, **_kwargs):
        raise FilesystemMutationCommittedError("sensitive fsync detail")

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.cli.create_regular_file",
        committed_create,
    )

    stderr = io.StringIO()
    status = run(
        env={"SSH_ORIGINAL_COMMAND": "mcp-v1"},
        stdin=io.BytesIO(fs_write_payload("/srv/app/new.bin", b"ABCD")),
        stdout=io.BytesIO(),
        stderr=stderr,
        execution_stderr=io.BytesIO(),
        policy=filesystem_policy(
            executable,
            write_create_roots=("/srv/app",),
            max_write_bytes=1024,
        ),
    )

    assert status == EX_FS_COMMITTED
    assert stderr.getvalue() == (
        "ssh-over-mcp-host-agent: filesystem write committed; "
        "durability uncertain; do not retry blindly\n"
    )
    assert "sensitive" not in stderr.getvalue()
