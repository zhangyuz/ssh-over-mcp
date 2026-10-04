from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

_LIVE_DIR = Path(__file__).resolve().parent
_SUPPORT = _LIVE_DIR / "local_e2e_support.py"
_RUN_LIVE = os.environ.get("SSH_OVER_MCP_RUN_LIVE_LOCAL_E2E") == "1"


def _load_support() -> ModuleType:
    assert _SUPPORT.is_file(), "local E2E support module must exist"
    name = "ssh_over_mcp_local_e2e_support"
    spec = importlib.util.spec_from_file_location(name, _SUPPORT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


def _valid_metadata() -> dict[str, str]:
    return {
        "SSH_OVER_MCP_LIVE_EXPECTED_COMMIT": "a" * 40,
        "SSH_OVER_MCP_LIVE_E2E_HOST": "127.0.0.1",
        "SSH_OVER_MCP_LIVE_E2E_PORT": "22222",
        "SSH_OVER_MCP_LIVE_E2E_SSH_USER": "ssh-over-mcp-e2e-host",
        "SSH_OVER_MCP_LIVE_E2E_PRIVATE_KEY": (
            "/opt/ssh-over-mcp-e2e/runtime/client_ed25519"
        ),
        "SSH_OVER_MCP_LIVE_E2E_HOST_KEY_PUBLIC": (
            "/opt/ssh-over-mcp-e2e/runtime/sshd_host_ed25519.pub"
        ),
        "SSH_OVER_MCP_LIVE_E2E_MANAGER_ENDPOINT": (
            "/opt/ssh-over-mcp-e2e/runtime/manager/containment.sock"
        ),
        "SSH_OVER_MCP_LIVE_E2E_CGROUP_ROOT": (
            "/sys/fs/cgroup/ssh-over-mcp-e2e"
        ),
        "SSH_OVER_MCP_LIVE_E2E_HOST_SOURCE_CGROUP": (
            "/sys/fs/cgroup/ssh-over-mcp-e2e/host-agent-source"
        ),
        "SSH_OVER_MCP_LIVE_E2E_STATE_SCRIPT": (
            "/opt/ssh-over-mcp-e2e/runtime/workload_state.py"
        ),
        "SSH_OVER_MCP_LIVE_E2E_WORK_DIR": (
            "/opt/ssh-over-mcp-e2e/runtime/work"
        ),
        "SSH_OVER_MCP_LIVE_E2E_MANAGER_UID": "2201",
        "SSH_OVER_MCP_LIVE_E2E_MANAGER_GID": "3201",
        "SSH_OVER_MCP_LIVE_E2E_HOST_UID": "2202",
        "SSH_OVER_MCP_LIVE_E2E_HOST_GID": "3202",
        "SSH_OVER_MCP_LIVE_E2E_WORKLOAD_UID": "2203",
        "SSH_OVER_MCP_LIVE_E2E_WORKLOAD_GID": "3203",
        "SSH_OVER_MCP_LIVE_E2E_PROBE_UID": "2204",
        "SSH_OVER_MCP_LIVE_E2E_PROBE_GID": "3204",
        "SSH_OVER_MCP_LIVE_E2E_MANAGER_CLIENT_GID": "3299",
    }


def test_fixture_metadata_contract_is_exact_and_server_owned() -> None:
    module = _load_support()
    fixture = module.LocalE2EFixture.from_mapping(_valid_metadata())

    assert fixture.expected_commit == "a" * 40
    assert fixture.host == "127.0.0.1"
    assert fixture.port == 22222
    assert fixture.ssh_user == "ssh-over-mcp-e2e-host"
    assert fixture.manager_uid == 2201
    assert fixture.manager_gid == 3201
    assert fixture.host_uid == 2202
    assert fixture.host_gid == 3202
    assert fixture.workload_uid == 2203
    assert fixture.workload_gid == 3203
    assert fixture.probe_uid == 2204
    assert fixture.probe_gid == 3204
    assert fixture.manager_client_gid == 3299


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("SSH_OVER_MCP_LIVE_E2E_HOST", "0.0.0.0"),
        ("SSH_OVER_MCP_LIVE_E2E_PORT", "22"),
        ("SSH_OVER_MCP_LIVE_E2E_SSH_USER", "root"),
        ("SSH_OVER_MCP_LIVE_E2E_MANAGER_UID", "0"),
        ("SSH_OVER_MCP_LIVE_E2E_WORKLOAD_UID", "2202"),
        (
            "SSH_OVER_MCP_LIVE_E2E_PRIVATE_KEY",
            "/tmp/caller-selected-key",
        ),
        (
            "SSH_OVER_MCP_LIVE_E2E_CGROUP_ROOT",
            "/sys/fs/cgroup/caller-selected",
        ),
    ],
)
def test_fixture_rejects_nonexact_operator_metadata(name: str, value: str) -> None:
    module = _load_support()
    metadata = _valid_metadata()
    metadata[name] = value

    with pytest.raises(module.LocalE2EFixtureError):
        module.LocalE2EFixture.from_mapping(metadata)


def test_fixture_rejects_missing_metadata() -> None:
    module = _load_support()
    metadata = _valid_metadata()
    del metadata["SSH_OVER_MCP_LIVE_E2E_HOST_KEY_PUBLIC"]

    with pytest.raises(module.LocalE2EFixtureError):
        module.LocalE2EFixture.from_mapping(metadata)


@pytest.mark.skipif(
    not _RUN_LIVE or not sys.platform.startswith("linux"),
    reason="dedicated no-network Linux guest only",
)
def test_real_sshd_forcecommand_containment_fixture() -> None:
    module = _load_support()
    state = asyncio.run(module.run_real_ssh_fixture())

    assert state["uids"] == [2203, 2203, 2203]
    assert state["gids"] == [3203, 3203, 3203]
    assert state["groups"] == []
    assert state["cap_inheritable"] == 0
    assert state["cap_permitted"] == 0
    assert state["cap_effective"] == 0
    assert state["cap_ambient"] == 0
    assert state["no_new_privs"] == 1
    assert state["manager_socket_fd_present"] is False
    assert state["cgroup"].endswith(
        "/ssh-over-mcp-e2e/ssh-over-mcp-req_0000000000000000000000000000e2e1"
    )


def test_fixture_request_id_matches_control_plane_shape() -> None:
    import re
    support = _load_support()
    assert re.fullmatch(r"req_[0-9a-f]{32}", support._REQUEST_ID)


def test_remote_result_classifies_fixed_launcher_failure_without_echoing_secret() -> None:
    module = _load_support()
    from ssh_over_mcp.ssh.transport import SSHExecutionResult

    result = SSHExecutionResult(
        request_id="req_" + ("1" * 32),
        host="e2e-host",
        exit_status=70,
        stderr=b"ssh-over-mcp host-agent launcher failed\n",
        duration_ms=1,
    )

    with pytest.raises(module.LocalE2ELauncherError) as exc:
        module._require_successful_remote_result(result)

    assert "launcher" in str(exc.value).lower()
    assert "ssh-over-mcp host-agent launcher failed" not in str(exc.value)


def test_remote_result_classifies_other_stderr_as_generic_without_echoing_secret() -> None:
    module = _load_support()
    from ssh_over_mcp.ssh.transport import SSHExecutionResult

    result = SSHExecutionResult(
        request_id="req_" + ("2" * 32),
        host="e2e-host",
        exit_status=70,
        stderr=b"SUPERSECRET remote failure\n",
        duration_ms=1,
    )

    with pytest.raises(module.LocalE2ERemoteExecutionError) as exc:
        module._require_successful_remote_result(result)

    assert "SUPERSECRET" not in str(exc.value)
