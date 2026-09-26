from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from typing import BinaryIO, TextIO

from .policy import (
    DEFAULT_POLICY_PATH,
    HostExecutionPolicy,
    HostPolicyError,
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

EX_PROTOCOL = 65
EX_UNAVAILABLE = 69
EX_NOPERM = 77
EX_CONFIG = 78


def run(
    *,
    env: dict[str, str],
    stdin: BinaryIO,
    stderr: TextIO,
    policy: HostExecutionPolicy | None = None,
) -> int:
    """Parse and host-authorize a request, but do not execute it yet."""

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
            _application_stdin = read_application_stdin(
                stdin,
                envelope.limits.max_stdin_bytes,
            )
        except HostAgentProtocolError as exc:
            print(f"ssh-over-mcp-host-agent: rejected: {exc}", file=stderr)
            return EX_PROTOCOL

        # Phase 3d1 remains intentionally non-executing. The pinned fds are
        # closed on exit from this block.
        print(
            "ssh-over-mcp-host-agent: execution unavailable "
            f"for request {envelope.request_id}",
            file=stderr,
        )
        return EX_UNAVAILABLE


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
        stderr=sys.stderr,
    )


if __name__ == "__main__":
    raise SystemExit(main())
