from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TextIO

from ssh_over_mcp.host_agent.containment_manager_peer import (
    LinuxPeerCredentialPolicy,
)

from .client import (
    LedgerClientError,
    SecurityLedgerAdminClient,
)
from .transport import UnixLedgerTransport

_APPROVAL_ID = re.compile(r"^apr_[0-9a-f]{32}$")
_PREFIX = "SSH_OVER_MCP_LEDGER_"


def _parse_approval_id(value: str) -> str:
    if _APPROVAL_ID.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("invalid approval id")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh-over-mcp-approvalctl",
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )
    subparsers.add_parser("list")

    for command in ("show", "grant", "deny"):
        child = subparsers.add_parser(command)
        child.add_argument(
            "approval_id",
            type=_parse_approval_id,
        )
    return parser


def _required(env: Mapping[str, str], name: str) -> str:
    key = _PREFIX + name
    value = env.get(key)
    if value is None or value == "":
        raise ValueError(
            f"missing Security Ledger environment value: {key}"
        )
    return value


def _decimal(env: Mapping[str, str], name: str) -> int:
    raw = _required(env, name)
    try:
        return int(raw, 10)
    except ValueError:
        raise ValueError(
            f"invalid Security Ledger integer environment value: "
            f"{_PREFIX + name}"
        ) from None


def create_admin_client_from_env(
    env: Mapping[str, str] | None = None,
) -> SecurityLedgerAdminClient:
    source = os.environ if env is None else env
    expected_server = LinuxPeerCredentialPolicy(
        expected_uid=_decimal(source, "SERVICE_UID"),
        expected_gid=_decimal(source, "SERVICE_GID"),
    )
    transport = UnixLedgerTransport(
        Path(_required(source, "ADMIN_SOCKET_PATH")),
        expected_server,
    )
    return SecurityLedgerAdminClient(transport)


def _write_json(stdout: TextIO, payload) -> None:
    stdout.write(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    stdout.write("\n")


async def execute_command(
    args: argparse.Namespace,
    *,
    client: SecurityLedgerAdminClient,
    stdout: TextIO,
) -> int:
    if args.command == "list":
        approvals = await client.list_approvals(limit=100)
        _write_json(
            stdout,
            [
                item.model_dump(mode="json")
                for item in approvals
            ],
        )
        return 0

    if args.command == "show":
        status = await client.show_approval(args.approval_id)
    elif args.command == "grant":
        status = await client.grant(args.approval_id)
    elif args.command == "deny":
        status = await client.deny(args.approval_id)
    else:
        raise ValueError("unsupported approvalctl command")

    _write_json(
        stdout,
        status.model_dump(mode="json"),
    )
    return 0


def run(
    argv: list[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    output = sys.stdout if stdout is None else stdout
    errors = sys.stderr if stderr is None else stderr
    args = build_parser().parse_args(argv)

    try:
        client = create_admin_client_from_env(env)
        return asyncio.run(
            execute_command(
                args,
                client=client,
                stdout=output,
            )
        )
    except (LedgerClientError, ValueError):
        errors.write("Security Ledger approval command failed\n")
        return 1


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
