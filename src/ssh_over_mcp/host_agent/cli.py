from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from typing import BinaryIO, TextIO

from .protocol import HostAgentProtocolError, read_request, validate_ssh_context

EX_PROTOCOL = 65
EX_UNAVAILABLE = 69


def run(
    *,
    env: dict[str, str],
    stdin: BinaryIO,
    stderr: TextIO,
) -> int:
    """Validate and parse a ForceCommand request, but do not execute it yet."""

    try:
        validate_ssh_context(env)
        envelope, _application_stdin = read_request(stdin)
    except HostAgentProtocolError as exc:
        print(f"ssh-over-mcp-host-agent: rejected: {exc}", file=stderr)
        return EX_PROTOCOL

    # Phase 3a is intentionally parse-only. Reaching this point proves the
    # transport and ForceCommand context are valid, but no command is executed.
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
