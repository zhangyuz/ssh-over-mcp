#!/usr/bin/python3
from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
from pathlib import Path

_WORKSPACE = Path("/opt/ssh-over-mcp-e2e/workspace")
_SUPPORT_DIR = _WORKSPACE / "tests" / "live"
_EXPECTED_UID = 2204
_EXPECTED_GID = 3204
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def _status() -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        key, sep, value = line.partition(":")
        if sep:
            rows[key] = value.strip()
    return rows


def _verify_process() -> None:
    if os.getresuid() != (_EXPECTED_UID,) * 3:
        raise RuntimeError("probe uid mismatch")
    if os.getresgid() != (_EXPECTED_GID,) * 3:
        raise RuntimeError("probe gid mismatch")
    if tuple(sorted(set(os.getgroups()) - {_EXPECTED_GID})) != ():
        raise RuntimeError("probe supplementary groups mismatch")
    rows = _status()
    for name in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
        if int(rows[name], 16) != 0:
            raise RuntimeError(f"probe retained {name}")
    if rows.get("NoNewPrivs") != "1":
        raise RuntimeError("probe does not have no_new_privs")


def _git_command(*args: str) -> list[str]:
    return [
        "/usr/bin/git",
        "-c",
        f"safe.directory={_WORKSPACE}",
        "-C",
        str(_WORKSPACE),
        *args,
    ]


def _verify_checkout() -> str:
    expected = os.environ.get("SSH_OVER_MCP_LIVE_EXPECTED_COMMIT", "").lower()
    if _COMMIT_RE.fullmatch(expected) is None:
        raise RuntimeError("expected commit is invalid")
    observed = subprocess.check_output(
        _git_command("rev-parse", "HEAD"),
        text=True,
        timeout=20,
    ).strip().lower()
    if observed != expected:
        raise RuntimeError("probe checkout commit mismatch")
    dirty = subprocess.check_output(
        _git_command("status", "--porcelain=v1"),
        text=True,
        timeout=20,
    )
    if dirty:
        raise RuntimeError("probe checkout is dirty")
    return expected


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        raise RuntimeError("local E2E probe accepts no arguments")

    _verify_process()
    expected = _verify_checkout()

    sys.path.insert(0, str(_SUPPORT_DIR))
    import local_e2e_support

    state = asyncio.run(local_e2e_support.run_real_ssh_fixture())
    mcp = asyncio.run(local_e2e_support.run_real_mcp_fixture())
    filesystem = asyncio.run(local_e2e_support.run_real_filesystem_profile_fixture())
    summary = {
        "commit": expected,
        "cgroup": state["cgroup"],
        "filesystem_audit_verified": filesystem["audit_verified"],
        "mcp_request_id": mcp["request_id"],
        "no_new_privs": state["no_new_privs"],
        "uid": state["uids"][0],
    }
    print(
        "SSH_OVER_MCP_LOCAL_E2E="
        + json.dumps(summary, sort_keys=True, separators=(",", ":"))
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"local E2E probe failed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(70) from None
