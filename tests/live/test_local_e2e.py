from __future__ import annotations

import asyncio
import importlib.util
import os
import shlex
import sqlite3
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


def test_ledger_audit_reader_sees_wal_and_returns_detached_rows(
    tmp_path: Path,
) -> None:
    module = _load_support()
    db_path = tmp_path / "ledger.db"
    writer = sqlite3.connect(db_path, isolation_level=None)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute(
            "CREATE TABLE audit_events("
            "event_type TEXT NOT NULL,"
            "request_id TEXT NOT NULL,"
            "principal_id TEXT,"
            "profile TEXT,"
            "host TEXT,"
            "tool TEXT,"
            "exit_status INTEGER,"
            "duration_ms INTEGER,"
            "stdout_bytes INTEGER,"
            "stderr_bytes INTEGER,"
            "timed_out INTEGER,"
            "truncated INTEGER"
            ")"
        )
        request_id = "req_" + ("a" * 32)
        writer.execute(
            "INSERT INTO audit_events("
            "event_type,request_id,principal_id,profile,host,tool"
            ") VALUES (?,?,?,?,?,?)",
            (
                "policy_denied",
                request_id,
                "developer",
                "developer",
                "e2e-host",
                "ssh_exec",
            ),
        )

        rows = module._read_ledger_audit_rows(db_path)
        assert len(rows) == 1
        assert rows[0]["event_type"] == "policy_denied"
        assert rows[0]["request_id"] == request_id

        filtered = module._read_ledger_audit_rows(
            db_path,
            request_id=request_id,
        )
        assert len(filtered) == 1
        assert module._read_ledger_audit_rows(
            db_path,
            request_id="req_" + ("b" * 32),
        ) == ()

        rows[0]["event_type"] = "mutated-in-test"
        live = writer.execute(
            "SELECT event_type FROM audit_events WHERE request_id=?",
            (request_id,),
        ).fetchone()
        assert live is not None and live[0] == "policy_denied"
    finally:
        writer.close()


@pytest.mark.asyncio
async def test_wait_for_audit_events_since_is_bounded_and_observes_delayed_rows() -> None:
    module = _load_support()

    class DelayedHarness:
        def __init__(self) -> None:
            self.calls = 0

        def audit_rows(self) -> tuple[dict[str, object], ...]:
            self.calls += 1
            if self.calls < 3:
                return ()
            return (
                {
                    "rowid": 2,
                    "event_type": "policy_denied",
                    "request_id": "req_" + ("a" * 32),
                    "tool": "ssh_exec",
                },
            )

    harness = DelayedHarness()
    rows = await module._wait_for_audit_events_since(
        harness,
        1,
        timeout_seconds=0.1,
        poll_interval_seconds=0.001,
    )
    assert len(rows) == 1
    assert rows[0]["event_type"] == "policy_denied"
    assert harness.calls >= 3

    class EmptyHarness:
        def audit_rows(self) -> tuple[dict[str, object], ...]:
            return ()

    with pytest.raises(
        module.LocalE2EFixtureError,
        match="expected audit event did not become visible",
    ):
        await module._wait_for_audit_events_since(
            EmptyHarness(),
            0,
            timeout_seconds=0.01,
            poll_interval_seconds=0.001,
        )


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



def test_workload_validator_binds_cgroup_to_exact_expected_request_id() -> None:
    module = _load_support()
    fixture = module.LocalE2EFixture.from_mapping(_valid_metadata())
    request_id = "req_" + ("a" * 32)
    state = {
        "uids": [2203, 2203, 2203],
        "gids": [3203, 3203, 3203],
        "groups": [],
        "cap_inheritable": 0,
        "cap_permitted": 0,
        "cap_effective": 0,
        "cap_ambient": 0,
        "no_new_privs": 1,
        "manager_socket_fd_present": False,
        "cgroup": f"/ssh-over-mcp-e2e/ssh-over-mcp-{request_id}",
    }

    observed = module._validate_workload_state(
        state,
        fixture,
        expected_request_id=request_id,
    )
    assert observed["cgroup"] == state["cgroup"]

    with pytest.raises(module.LocalE2EFixtureError, match="cgroup"):
        module._validate_workload_state(
            state,
            fixture,
            expected_request_id="req_" + ("b" * 32),
        )



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


def test_local_mcp_harness_contract_is_explicit() -> None:
    import inspect

    module = _load_support()
    harness = getattr(module, "LocalMCPHarness", None)
    assert harness is not None, "Task 4 requires a real local MCP/Ledger harness"

    client = getattr(harness, "client", None)
    assert client is not None
    parameters = inspect.signature(client).parameters
    assert tuple(parameters) == ("self", "profile", "policy_variant")
    assert parameters["profile"].default is inspect.Parameter.empty
    assert parameters["policy_variant"].default == "normal"


@pytest.mark.skipif(
    not _RUN_LIVE or not sys.platform.startswith("linux"),
    reason="dedicated no-network Linux guest only",
)
def test_real_mcp_origin_ledger_ssh_happy_path() -> None:
    module = _load_support()
    evidence = asyncio.run(module.run_real_mcp_fixture())

    assert evidence["hosts"] == ["e2e-host"]
    assert evidence["host_alias"] == "e2e-host"
    assert evidence["request_id"].startswith("req_")
    assert len(evidence["request_id"]) == 36
    state = evidence["workload_state"]
    assert state["uids"] == [2203, 2203, 2203]
    assert state["gids"] == [3203, 3203, 3203]
    assert state["groups"] == []
    assert state["cap_effective"] == 0
    assert state["no_new_privs"] == 1


def test_filesystem_profile_e2e_contract_is_explicit() -> None:
    import inspect

    module = _load_support()

    assert module.FS_DATA_ROOT == Path("/opt/ssh-over-mcp-e2e/fs-data")
    assert module.FS_SEED_FILE == module.FS_DATA_ROOT / "seed.txt"
    assert module.FS_CREATE_ROOT == module.FS_DATA_ROOT / "create"
    assert module.FS_MKDIR_TARGET == module.FS_CREATE_ROOT / "created-dir"
    assert module.FS_WRITE_TARGET == module.FS_CREATE_ROOT / "created.txt"
    assert module.FS_SEED_BYTES == b"ssh-over-mcp-e2e-seed\n"

    runner = getattr(module, "run_real_filesystem_profile_fixture", None)
    assert runner is not None, "Task 5 requires real filesystem/profile E2E"
    source = inspect.getsource(runner)
    for tool in ("fs_stat", "fs_read", "fs_mkdir", "fs_write"):
        assert f'"{tool}"' in source
    assert 'harness.client("developer")' in source
    assert 'harness.client("readonly")' in source
    assert "_require_audit_lifecycle" in source
    audit_helper = inspect.getsource(module._require_audit_lifecycle)
    assert "audit_events" in audit_helper
    assert "secret" in source.lower()


@pytest.mark.skipif(
    not _RUN_LIVE or not sys.platform.startswith("linux"),
    reason="dedicated no-network Linux guest only",
)
def test_real_filesystem_profiles_audit_and_secret_retention() -> None:
    module = _load_support()
    evidence = asyncio.run(module.run_real_filesystem_profile_fixture())

    assert evidence["seed_bytes"] == module.FS_SEED_BYTES
    assert evidence["mkdir_created"] is True
    assert evidence["mkdir_replay_denied"] is True
    assert evidence["write_bytes"] == module.FS_WRITE_BYTES
    assert evidence["write_replay_denied"] is True
    assert evidence["readonly_read"] == module.FS_SEED_BYTES
    assert evidence["readonly_mutation_denied"] is True
    assert evidence["profile_override_rejected"] is True
    assert evidence["audit_verified"] is True
    assert evidence["secret_retention_clean"] is True


def test_fail_closed_e2e_contract_is_explicit() -> None:
    import inspect

    module = _load_support()
    assert module.SSHD_LOG == Path("/opt/ssh-over-mcp-e2e/runtime/sshd.log")
    assert module.WORKLOAD_DATA_ROOT == Path("/opt/ssh-over-mcp-e2e/workload-data")
    assert module.EXEC_MARKER == module.WORKLOAD_DATA_ROOT / "exec-marker"
    assert module.MARKER_SCRIPT == Path(
        "/opt/ssh-over-mcp-e2e/runtime/workload_marker.py"
    )
    assert module.WRONG_HOST_KEY_PUBLIC == Path(
        "/opt/ssh-over-mcp-e2e/runtime/wrong_host_ed25519.pub"
    )

    runner = getattr(module, "run_real_fail_closed_fixture", None)
    assert runner is not None, "Task 6 requires real fail-closed E2E"
    source = inspect.getsource(runner)
    for variant in ("central_deny", "remote_deny", "wrong_host_key"):
        assert f'"{variant}"' in source
    for event in ("policy_denied", "remote_policy_denied", "host_key_failure"):
        assert event in source
    assert "execution_started" in source
    assert "SSHD_LOG" in source
    assert "EXEC_MARKER" in source


def test_fail_closed_fixture_seals_ledger_before_audit_inspection() -> None:
    import inspect

    module = _load_support()
    source = inspect.getsource(module.run_real_fail_closed_fixture)

    assert source.count("async with LocalMCPHarness(fixture) as harness:") >= 4
    assert source.count("harness.stop_ledger()") >= 4
    assert "_read_sealed_audit_rows" in source
    assert "_wait_for_audit_events_since" not in source


@pytest.mark.skipif(
    not _RUN_LIVE or not sys.platform.startswith("linux"),
    reason="dedicated no-network Linux guest only",
)
def test_real_origin_policy_and_host_trust_fail_closed() -> None:
    module = _load_support()
    evidence = asyncio.run(module.run_real_fail_closed_fixture())

    assert evidence["origin_auth_rejected_early"] is True
    assert evidence["central_deny_before_ssh"] is True
    assert evidence["host_local_deny_after_ssh"] is True
    assert evidence["wrong_host_key_before_forcecommand"] is True
    assert evidence["marker_unchanged"] is True
    assert evidence["safe_errors"] is True


def test_task7_approval_outage_containment_contract_is_explicit() -> None:
    import inspect

    module = _load_support()
    assert module.APPROVAL_MARKER == module.WORKLOAD_DATA_ROOT / "approval-marker"
    assert module.APPROVAL_SCRIPT == Path(
        "/opt/ssh-over-mcp-e2e/runtime/approval_marker.py"
    )
    assert module.CONTROL_FD_ENV == "SSH_OVER_MCP_LIVE_E2E_CONTROL_FD"

    runner = getattr(module, "run_real_approval_outage_containment_fixture", None)
    assert runner is not None, "Task 7 requires real approval/outage/containment E2E"
    source = inspect.getsource(runner)
    for required in (
        "_grant_approval_via_cli",
        "approval_status",
        "/healthz",
        "/readyz",
        "STOP_MANAGER",
        "secret",
        "consumed",
    ):
        assert required in source
    assert source.index("STOP_MANAGER") > source.index("/readyz")
    assert source.rindex("harness.stop_ledger()") > source.index("STOP_MANAGER")
    assert "_wait_for_audit_events_since" not in source


@pytest.mark.skipif(
    not _RUN_LIVE or not sys.platform.startswith("linux"),
    reason="dedicated no-network Linux guest only",
)
def test_real_approval_outage_containment_and_secret_retention() -> None:
    module = _load_support()
    evidence = asyncio.run(module.run_real_approval_outage_containment_fixture())

    assert evidence["approval_required_before_ssh"] is True
    assert evidence["approval_granted_via_cli"] is True
    assert evidence["approval_consumed"] is True
    assert evidence["approval_replay_denied"] is True
    assert evidence["approval_binding_mismatch_denied"] is True
    assert evidence["ledger_outage_not_ready"] is True
    assert evidence["ledger_outage_no_side_effect"] is True
    assert evidence["containment_unavailable_fail_closed"] is True
    assert evidence["request_cgroup_clean"] is True
    assert evidence["secret_retention_clean"] is True


@pytest.mark.asyncio
async def test_approval_cli_runs_from_source_without_installed_console_script(
    tmp_path: Path,
) -> None:
    module = _load_support()
    python = tmp_path / "python"
    stderr_path = tmp_path / "cli-stderr"
    python.write_text(
        "#!/bin/sh\nLD_LIBRARY_PATH="
        + shlex.quote(os.environ.get("LD_LIBRARY_PATH", str(Path(sys.base_prefix) / "lib")))
        + " exec " + shlex.quote(sys.executable)
        + ' "$@" 2>' + shlex.quote(str(stderr_path)) + "\n",
        encoding="utf-8",
    )
    python.chmod(0o700)
    assert not python.with_name("ssh-over-mcp-approvalctl").exists()
    admin_env = {
        "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_PATH": str(tmp_path / "absent.sock"),
        "SSH_OVER_MCP_LEDGER_SERVICE_UID": str(os.getuid()),
        "SSH_OVER_MCP_LEDGER_SERVICE_GID": str(os.getgid()),
    }
    with pytest.raises(module.LocalE2EFixtureError, match="approvalctl grant failed"):
        await module._grant_approval_via_cli(python, "apr_" + "a" * 32, admin_env)
    # The real CLI must start and fail closed at its unavailable admin endpoint.
    assert stderr_path.read_bytes() == b"Security Ledger approval command failed\n"
