"""Proposed real Mode A admission/manager and no-NIC Level-2 contract.

Offline proof of a REVIEW CANDIDATE only. No Docker, VM, sudo or network calls.
"""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "deploy/ssh-target/mode-a-execution-contract.proposed.json"
SPEC = ROOT / "docs/superpowers/specs/2026-10-25-mode-a-runtime-execution-contract.md"
COMPOSE = ROOT / "deploy/compose/compose.dev-ssh.yaml"


def _contract():
    return json.loads(CONTRACT.read_text())


def test_separate_per_node_manager_not_reachable_through_agent_uid_impersonation():
    c = _contract()
    assert c["status"] == "PROPOSED_NOT_APPROVED"
    assert c["runtime_execution_authorized"] is False
    assert c["host_runtime_changes_authorized"] is False
    assert c["manager"]["placement"] == "SEPARATE_CONTAINER_PER_NODE"
    assert c["manager"]["network_mode"] == "none"
    assert c["manager"]["no_new_privileges"] is True
    assert c["manager"]["capabilities"] == []
    assert c["manager"]["host_cgroup_mount"] is False
    assert c["manager"]["peer_auth"] == "SO_PEERCRED_PLUS_SOCKET_ACL"
    assert c["manager"]["typed_operations"] == ["create", "attach", "kill_all", "stats", "close"]
    assert c["manager"]["pid_namespace_translation"] == "UNPROVEN_STOP"
    assert c["manager"]["cgroup_delegation"] == "UNPROVEN_STOP"
    assert c["manager"]["writable_cgroup_root_exposed_to_sshd"] is False
    assert set(c["nodes"]) == {"node01", "node02"}
    assert c["nodes"]["node01"]["manager_container"] != c["nodes"]["node02"]["manager_container"]
    assert c["nodes"]["node01"]["data_identity"] != c["nodes"]["node02"]["data_identity"]


def test_nnp_transition_is_not_described_as_reversible_or_auto_allowed():
    c = _contract()
    assert c["admission"]["oci_no_new_privileges"] is False
    assert c["admission"]["no_new_privileges_exception_approved"] is False
    assert c["admission"]["ssh_account_uid"] > 0
    assert c["admission"]["host_agent_uid"] > 0
    assert c["admission"]["workload_uid"] > 0
    assert (
        len(
            {
                c["admission"]["ssh_account_uid"],
                c["admission"]["host_agent_uid"],
                c["admission"]["workload_uid"],
            }
        )
        == 3
    )
    assert c["admission"]["launcher_exact_argv"] == []
    assert c["admission"]["force_command_exact"] == "mcp-v1"
    assert c["admission"]["sudo_allowed_targets"] == ["FIXED_NO_ARGV_LAUNCHER"]
    assert c["admission"]["trusted_agent_capabilities"] == ["CAP_SETGID", "CAP_SETUID"]
    assert c["admission"]["root_equivalent_tcb"] is True
    assert c["admission"]["additional_admission_caps_approved"] is False
    assert c["workload"]["no_new_privileges"] is True
    assert c["workload"]["cap_effective"] == []
    assert c["workload"]["cap_permitted"] == []
    assert c["workload"]["cap_inheritable"] == []
    assert c["workload"]["cap_ambient"] == []
    assert c["workload"]["manager_fd_inherited"] is False
    assert c["workload"]["writable_ancestor_cgroup"] is False
    assert c["workload"]["exec_before_attach_ack"] is False


def test_network_policy_requires_stateful_packet_proof():
    c = _contract()
    assert c["guest"]["vm_nic"] == "none"
    assert c["guest"]["host_mounts"] is False
    assert c["guest"]["trusted_main_provider_unchanged"] is True
    assert c["guest"]["docker_level2_media_contract_verified"] is False
    assert c["guest"]["boot_authorized"] is False
    assert c["network"]["bridge_internal_is_not_acl"] is True
    assert c["network"]["enforcement_implemented"] is False
    expected = {
        "mcp_to_node_ssh_new": "ALLOW",
        "node_ssh_to_mcp_established": "ALLOW",
        "node_to_mcp_8000_new": "DENY",
        "node_to_node_new": "DENY",
        "node_to_host_lan_internet_new": "DENY",
        "outside_guest_to_internal_new": "DENY",
    }
    assert c["network"]["matrix"] == expected
    assert c["network"]["packet_negative_tests_done"] is False


@pytest.mark.parametrize(
    "forbidden",
    ["privileged: true", "userns_mode: host", "pid: host", "cgroup: host", "/var/run/docker.sock"],
)
def test_no_execution_proposal_silently_weakens_production_compose(forbidden):
    # Documentation must explicitly forbid these options; only live Compose
    # configuration is required not to contain them.
    assert forbidden not in COMPOSE.read_text()


def test_read_only_proposal_cannot_satisfy_runtime_or_ready_gates():
    c = _contract()
    s = SPEC.read_text()
    assert c["admission"]["capability_oci_matrix_verified"] is False
    assert c["admission"]["sudo_exec_transition_verified"] is False
    assert c["workload"]["negative_cgroup_escape_test_done"] is False
    assert c["guest"]["level2_a01_a03_done"] is False
    assert c["guest"]["trusted_native_level3_pass"] is False
    assert c["merge_ready"] is False
    for word in (
        "NNP",
        "irreversible",
        "CAP_SETUID",
        "SO_PEERCRED",
        "cgroup",
        "pidfd",
        "UID",
        "GID",
        "read-only",
        "A01",
        "A03",
        "NEW",
        "ESTABLISHED",
        "DENY",
        "approval",
    ):
        assert word.lower() in s.lower()
