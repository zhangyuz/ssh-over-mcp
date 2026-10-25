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
    assert c["manager"]["typed_operations"] == [
        "move_source_self",
        "create",
        "attach",
        "kill_all",
        "stats",
        "close",
    ]
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


def test_launcher_migration_is_manager_owned_and_bound_to_self():
    c = _contract()
    m = c["manager"]
    a = c["admission"]
    assert m["source_cgroup_migration"] == "MOVE_SOURCE_SELF_ONLY"
    assert m["source_migration_request"] == "manager_moves_socket_peer_after_pidfd_check"
    assert m["source_migration_credential_phase"] == "ROOT_LAUNCHER_ONLY_NNP0"
    assert m["source_migration_target"] == "host-agent-source"
    assert m["root_phase_fd_retained_after_drop"] is False
    assert m["source_migration_ack_before_uid_drop"] is True
    assert m["source_migration_cgroup_readback_required"] is True
    assert m["writable_cgroup_root_exposed_to_sshd"] is False
    assert a["launcher_writes_cgroup_procs"] is False
    assert a["launcher_trusted_cgroup_path"] == "MANAGER_MOVE_SOURCE_SELF"
    assert a["source_move_ack_before_application_import"] is True
    assert m["typed_operations"] == [
        "move_source_self",
        "create",
        "attach",
        "kill_all",
        "stats",
        "close",
    ]
    assert c["runtime_execution_authorized"] is False


def test_cross_namespace_pid_attach_requires_kernel_bound_identity():
    c = _contract()
    m = c["manager"]
    assert m["attach_identity_mode"] == "SCM_RIGHTS_PIDFD_REQUIRED"
    assert m["integer_pid_sufficient"] is False
    assert m["current_attach_request_only_pid"] is True
    assert m["existing_protocol_compatible_without_extension"] is False
    assert m["pidfd_transport"] == "SCM_RIGHTS_AF_UNIX"
    assert m["attach_peer_validation"] == "SO_PEERCRED_AT_FRESH_POST_DROP_CONNECT"
    assert m["source_peer_validation"] == "SO_PEERCRED_AT_FRESH_ROOT_CONNECT"
    assert m["pidfd_source"] == "FORK_PARENT_PINNED_BEFORE_RELEASE"
    assert m["attach_target_ancestry"] == "DIRECT_CHILD_OF_AUTHENTICATED_AGENT"
    assert m["target_pre_attach_cgroup"] == "host-agent-source"
    assert m["pidfd_id_starttime_cgroup_checks_required"] is True
    assert m["userns_uid_gid_maps_runtime_proved"] is False
    assert m["pidfd_to_cgroup_procs_kernel_atomic"] is False
    assert m["post_attach_process_identity_recheck_required"] is True
    assert m["abort_on_exit_pid_reuse_or_unmapped_uid"] is True
    assert m["sibling_node_attach_allowed"] is False
    assert m["untrusted_integer_pid_attach_allowed"] is False
    assert m["pid_namespace_translation"] == "UNPROVEN_STOP"
    assert m["cgroup_delegation"] == "UNPROVEN_STOP"


def test_two_new_p1_handoff_hard_stops_remain_unapproved():
    c = _contract()
    for gate in (
        "manager_owned_source_cgroup_migration_protocol",
        "SCM_RIGHTS_pidfd_attach_transport_and_identity_verification",
        "cross_userns_SO_PEERCRED_UID_GID_mapping_and_kernel_validation",
        "PID_lifecycle_during_cgroup_procs_write",
    ):
        assert gate in c["open_p1_gates"]
    assert c["runtime_execution_authorized"] is False
    assert c["guest"]["boot_authorized"] is False
    assert c["manager"]["source_to_request_attach_ack_verified"] is False
    spec = SPEC.read_text().lower()
    for term in (
        "move_source_self",
        "scm_rights",
        "pidfd",
        "uid_map",
        "gid_map",
        "so_peercred",
        "attach-before-release",
        "pid reuse",
        "unreaped",
        "separate",
        "fail closed",
    ):
        assert term in spec
