from __future__ import annotations

import io
import json
import os
import selectors
import sys
import time
from collections.abc import Sequence
from typing import BinaryIO, TextIO

from ssh_over_mcp.ssh.protocol import FsReadEnvelope, FsStatEnvelope

from .containment import ContainmentRequest
from .containment_manager_unix import connect_authenticated_containment_manager
from .filesystem import (
    FilesystemAccessError,
    ReadOnlyFileStat,
    read_file,
    stat_path,
)
from .policy import (
    DEFAULT_POLICY_PATH,
    HostExecutionPolicy,
    HostPolicyError,
    authorize_filesystem_read,
    authorize_filesystem_stat,
    authorize_request,
    load_host_policy,
)
from .prepare import CommandPreparationError, prepare_command
from .protocol import (
    HostAgentProtocolError,
    read_application_stdin,
    read_envelope,
    validate_ssh_context,
)
from .run import run_prepared_native

EX_PROTOCOL = 65
EX_UNAVAILABLE = 69
EX_NOPERM = 77
EX_CONFIG = 78
_OUTPUT_DELIVERY_TIMEOUT_SECONDS = 5.0


class OutputDeliveryError(RuntimeError):
    """Bounded SSH result delivery failed or exceeded its deadline."""



def run(
    *,
    env: dict[str, str],
    stdin: BinaryIO,
    stderr: TextIO,
    stdout: BinaryIO | None = None,
    execution_stderr: BinaryIO | None = None,
    policy: HostExecutionPolicy | None = None,
) -> int:
    """Parse and dispatch one authorized SMCP v1 request fail closed."""

    try:
        validate_ssh_context(env)
    except HostAgentProtocolError as exc:
        print(f"ssh-over-mcp-host-agent: rejected: {exc}", file=stderr)
        return EX_PROTOCOL

    if policy is None:
        try:
            policy = load_host_policy(DEFAULT_POLICY_PATH)
        except HostPolicyError:
            # Do not disclose policy-file details over the SSH channel.
            print("ssh-over-mcp-host-agent: host policy unavailable", file=stderr)
            return EX_CONFIG

    try:
        envelope = read_envelope(stdin)
    except HostAgentProtocolError as exc:
        print(f"ssh-over-mcp-host-agent: rejected: {exc}", file=stderr)
        return EX_PROTOCOL

    if isinstance(envelope, (FsStatEnvelope, FsReadEnvelope)):
        return _run_filesystem_request(
            envelope=envelope,
            policy=policy,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            execution_stderr=execution_stderr,
        )

    decision = authorize_request(policy, envelope)
    if not decision.allowed:
        print(
            f"ssh-over-mcp-host-agent: denied: {decision.reason}",
            file=stderr,
        )
        return EX_NOPERM

    # Pin the exact executable/cwd objects before accepting application stdin.
    # This closes pathname replacement races without enabling execution yet.
    try:
        prepared = prepare_command(policy, envelope, decision)
    except CommandPreparationError:
        print(
            "ssh-over-mcp-host-agent: command preparation failed",
            file=stderr,
        )
        return EX_NOPERM

    with prepared:
        try:
            application_stdin = read_application_stdin(
                stdin,
                envelope.limits.max_stdin_bytes,
            )
        except HostAgentProtocolError as exc:
            print(f"ssh-over-mcp-host-agent: rejected: {exc}", file=stderr)
            return EX_PROTOCOL

        # Policy v3 remains intentionally non-executing. Only the explicit v4
        # containment contract may enter the supervised native execution path.
        if policy.version != 4 or policy.containment is None:
            print(
                "ssh-over-mcp-host-agent: execution unavailable "
                f"for request {envelope.request_id}",
                file=stderr,
            )
            return EX_UNAVAILABLE

        if stdout is None or execution_stderr is None:
            print(
                "ssh-over-mcp-host-agent: execution unavailable",
                file=stderr,
            )
            return EX_UNAVAILABLE

        containment_policy = policy.containment
        identity_plan = containment_policy.to_identity_plan()
        client = None
        try:
            client = connect_authenticated_containment_manager(
                containment_policy.manager_endpoint,
                identity_plan=identity_plan,
            )
            result = run_prepared_native(
                prepared,
                application_stdin,
                envelope.limits,
                workload_identity_policy=identity_plan.workload_process_policy(),
                containment_backend=client,
                containment_request=ContainmentRequest(
                    request_id=envelope.request_id,
                    limits=containment_policy.to_containment_limits(),
                ),
            )
        except Exception:  # noqa: BLE001
            # Trust boundary: never expose manager/backend/supervisor details
            # over the SSH channel.
            print("ssh-over-mcp-host-agent: execution failed", file=stderr)
            return EX_UNAVAILABLE
        finally:
            if client is not None:
                client.close()

        try:
            _deliver_execution_output(
                stdout,
                execution_stderr,
                result.stdout,
                result.stderr,
            )
        except OutputDeliveryError:
            # The SSH peer is no longer draining bounded result output. Do not
            # risk another potentially blocking write to report this condition.
            return EX_UNAVAILABLE
        return _ssh_exit_status(result.returncode)


def _filesystem_stat_payload(result: ReadOnlyFileStat) -> bytes:
    return json.dumps(
        {
            "gid": result.gid,
            "kind": result.kind,
            "mode": result.mode,
            "mtime_ns": result.mtime_ns,
            "path": result.path,
            "size": result.size,
            "uid": result.uid,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _run_filesystem_request(
    *,
    envelope: FsStatEnvelope | FsReadEnvelope,
    policy: HostExecutionPolicy,
    stdin: BinaryIO,
    stdout: BinaryIO | None,
    stderr: TextIO,
    execution_stderr: BinaryIO | None,
) -> int:
    if isinstance(envelope, FsStatEnvelope):
        decision = authorize_filesystem_stat(
            policy,
            profile=envelope.profile,
            path=envelope.path,
        )
    else:
        decision = authorize_filesystem_read(
            policy,
            profile=envelope.profile,
            path=envelope.path,
            max_bytes=envelope.max_bytes,
        )

    if not decision.allowed:
        print("ssh-over-mcp-host-agent: filesystem denied", file=stderr)
        return EX_NOPERM

    try:
        trailing = read_application_stdin(stdin, 0)
    except HostAgentProtocolError as exc:
        print(f"ssh-over-mcp-host-agent: rejected: {exc}", file=stderr)
        return EX_PROTOCOL
    if trailing:
        # Defensive only: read_application_stdin(..., 0) already rejects data.
        print("ssh-over-mcp-host-agent: rejected: unexpected stdin", file=stderr)
        return EX_PROTOCOL

    if stdout is None or execution_stderr is None:
        print(
            "ssh-over-mcp-host-agent: filesystem operation unavailable",
            file=stderr,
        )
        return EX_UNAVAILABLE

    try:
        if isinstance(envelope, FsStatEnvelope):
            output = _filesystem_stat_payload(stat_path(envelope.path))
        else:
            max_bytes = decision.effective_max_read_bytes
            if max_bytes is None:
                raise FilesystemAccessError("missing authorized read bound")
            output = read_file(
                envelope.path,
                max_bytes=max_bytes,
            ).data
    except FilesystemAccessError:
        print(
            "ssh-over-mcp-host-agent: filesystem operation failed",
            file=stderr,
        )
        return EX_UNAVAILABLE

    try:
        _deliver_execution_output(
            stdout,
            execution_stderr,
            output,
            b"",
        )
    except OutputDeliveryError:
        return EX_UNAVAILABLE
    return 0


def _write_test_stream(stream: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = stream.write(view[offset:])
        if written is None or written <= 0:
            raise OutputDeliveryError("cannot write execution output")
        offset += written
    stream.flush()


def _deliver_execution_output(
    stdout: BinaryIO,
    stderr: BinaryIO,
    stdout_data: bytes,
    stderr_data: bytes,
    *,
    timeout_seconds: float = _OUTPUT_DELIVERY_TIMEOUT_SECONDS,
) -> None:
    if timeout_seconds <= 0:
        raise OutputDeliveryError("output delivery timeout must be positive")

    # BytesIO is used only by focused unit tests. Production ForceCommand
    # streams have real file descriptors and always take the bounded path.
    if isinstance(stdout, io.BytesIO) and isinstance(stderr, io.BytesIO):
        _write_test_stream(stdout, stdout_data)
        _write_test_stream(stderr, stderr_data)
        return

    try:
        stdout.flush()
        stderr.flush()
        stdout_fd = stdout.fileno()
        stderr_fd = stderr.fileno()
    except (AttributeError, OSError, ValueError) as exc:
        raise OutputDeliveryError("execution output has no usable fd") from exc

    if stdout_fd == stderr_fd:
        raise OutputDeliveryError("stdout and stderr must use distinct fds")

    pending = {
        stdout_fd: memoryview(stdout_data),
        stderr_fd: memoryview(stderr_data),
    }
    offsets = {stdout_fd: 0, stderr_fd: 0}
    original_blocking: dict[int, bool] = {}
    deadline = time.monotonic() + timeout_seconds

    try:
        selector = selectors.DefaultSelector()
    except Exception as exc:
        raise OutputDeliveryError("cannot create output selector") from exc

    try:
        for fd, data in pending.items():
            if not data:
                continue
            try:
                original_blocking[fd] = os.get_blocking(fd)
                os.set_blocking(fd, False)
                selector.register(fd, selectors.EVENT_WRITE)
            except (OSError, ValueError) as exc:
                raise OutputDeliveryError("cannot prepare output fd") from exc

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OutputDeliveryError("execution output delivery timed out")

            try:
                events = selector.select(min(0.05, remaining))
            except OSError as exc:
                raise OutputDeliveryError("execution output selector failed") from exc

            for key, _mask in events:
                fd = key.fd
                offset = offsets[fd]
                data = pending[fd]
                try:
                    written = os.write(fd, data[offset : offset + 64 * 1024])
                except BlockingIOError:
                    continue
                except OSError as exc:
                    raise OutputDeliveryError("execution output write failed") from exc

                if written <= 0:
                    raise OutputDeliveryError("execution output write made no progress")
                offset += written
                offsets[fd] = offset
                if offset >= len(data):
                    selector.unregister(fd)
    finally:
        selector.close()
        for fd, was_blocking in original_blocking.items():
            try:
                os.set_blocking(fd, was_blocking)
            except OSError:
                pass


def _ssh_exit_status(returncode: int) -> int:
    if returncode >= 0:
        return min(returncode, 255)
    signal_number = -returncode
    return min(128 + signal_number, 255)


def main(argv: Sequence[str] | None = None) -> int:
    argv = tuple(sys.argv[1:] if argv is None else argv)
    if argv:
        print(
            "ssh-over-mcp-host-agent: command-line arguments are not permitted",
            file=sys.stderr,
        )
        return EX_PROTOCOL

    return run(
        env=dict(os.environ),
        stdin=sys.stdin.buffer,
        stdout=sys.stdout.buffer,
        stderr=sys.stderr,
        execution_stderr=sys.stderr.buffer,
    )


if __name__ == "__main__":
    raise SystemExit(main())
