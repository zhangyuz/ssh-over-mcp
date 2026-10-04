#!/usr/bin/python3
from __future__ import annotations

import os
import signal
import sys
from pathlib import Path

from ssh_over_mcp.host_agent.cgroup_v2 import CgroupV2Backend
from ssh_over_mcp.host_agent.containment_manager import ContainmentManagerDispatcher
from ssh_over_mcp.host_agent.containment_manager_identity import (
    ContainmentServiceIdentityPlan,
    LinuxProcessIdentity,
    require_linux_process_identity,
)
from ssh_over_mcp.host_agent.containment_manager_service import ContainmentManagerService

_MANAGER_UID = 2201
_MANAGER_GID = 3201
_HOST_UID = 2202
_HOST_GID = 3202
_WORKLOAD_UID = 2203
_WORKLOAD_GID = 3203
_MANAGER_CLIENT_GID = 3299
_MANAGER_ENDPOINT = Path("/opt/ssh-over-mcp-e2e/runtime/manager/containment.sock")
_CGROUP_ROOT = Path("/sys/fs/cgroup/ssh-over-mcp-e2e")


def _require_exact_env() -> None:
    expected = {
        "SSH_OVER_MCP_LIVE_E2E_MANAGER_ENDPOINT": str(_MANAGER_ENDPOINT),
        "SSH_OVER_MCP_LIVE_E2E_CGROUP_ROOT": str(_CGROUP_ROOT),
        "SSH_OVER_MCP_LIVE_E2E_MANAGER_UID": str(_MANAGER_UID),
        "SSH_OVER_MCP_LIVE_E2E_MANAGER_GID": str(_MANAGER_GID),
        "SSH_OVER_MCP_LIVE_E2E_HOST_UID": str(_HOST_UID),
        "SSH_OVER_MCP_LIVE_E2E_HOST_GID": str(_HOST_GID),
        "SSH_OVER_MCP_LIVE_E2E_WORKLOAD_UID": str(_WORKLOAD_UID),
        "SSH_OVER_MCP_LIVE_E2E_WORKLOAD_GID": str(_WORKLOAD_GID),
        "SSH_OVER_MCP_LIVE_E2E_MANAGER_CLIENT_GID": str(_MANAGER_CLIENT_GID),
    }
    for name, value in expected.items():
        if os.environ.get(name) != value:
            raise RuntimeError(f"invalid fixed manager environment: {name}")


def _status() -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        key, sep, value = line.partition(":")
        if sep:
            rows[key] = value.strip()
    return rows


def _require_zero_caps_nnp() -> None:
    rows = _status()
    for name in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
        if int(rows[name], 16) != 0:
            raise RuntimeError(f"manager retained {name}")
    if rows.get("NoNewPrivs") != "1":
        raise RuntimeError("manager does not have no_new_privs")


def _current_unified_cgroup() -> str:
    for line in Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines():
        if line.startswith("0::"):
            return line[3:]
    raise RuntimeError("unified cgroup membership is unavailable")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        raise RuntimeError("manager runner accepts no arguments")

    _require_exact_env()
    plan = ContainmentServiceIdentityPlan(
        manager=LinuxProcessIdentity(uid=_MANAGER_UID, gid=_MANAGER_GID),
        host_agent=LinuxProcessIdentity(uid=_HOST_UID, gid=_HOST_GID),
        workload=LinuxProcessIdentity(uid=_WORKLOAD_UID, gid=_WORKLOAD_GID),
        manager_client_gid=_MANAGER_CLIENT_GID,
    )
    require_linux_process_identity(plan.manager_process_policy())
    _require_zero_caps_nnp()

    current_cgroup = _current_unified_cgroup()
    if current_cgroup == "/ssh-over-mcp-e2e" or current_cgroup.startswith(
        "/ssh-over-mcp-e2e/"
    ):
        raise RuntimeError("manager must remain outside delegated cgroup root")

    backend = CgroupV2Backend(_CGROUP_ROOT)
    dispatcher = ContainmentManagerDispatcher(backend)
    service = ContainmentManagerService.create(
        identity_policy=plan.manager_process_policy(),
        endpoint_policy=plan.endpoint_policy(_MANAGER_ENDPOINT),
        peer_policy=plan.manager_accept_peer_policy(),
        dispatcher=dispatcher,
    )

    stopping = False

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        service.serve_forever(stop_requested=lambda: stopping)
    finally:
        service.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"local E2E manager failed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(70) from None
