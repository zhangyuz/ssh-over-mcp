from __future__ import annotations

import os
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.containment import ContainmentUnavailableError
from ssh_over_mcp.host_agent.containment_manager_identity import (
    ContainmentServiceIdentityPlan,
    LinuxProcessIdentity,
    LinuxProcessIdentityError,
    LinuxProcessIdentityPolicy,
    LinuxProcessIdentitySnapshot,
    read_linux_process_identity,
    require_linux_process_identity,
)


def identity(uid: int, gid: int) -> LinuxProcessIdentity:
    return LinuxProcessIdentity(uid=uid, gid=gid)


def plan() -> ContainmentServiceIdentityPlan:
    return ContainmentServiceIdentityPlan(
        manager=identity(2101, 3101),
        host_agent=identity(2102, 3102),
        workload=identity(2103, 3103),
        manager_client_gid=3199,
    )


def current_policy() -> LinuxProcessIdentityPolicy:
    groups = frozenset(set(os.getgroups()) - {os.getgid()})
    return LinuxProcessIdentityPolicy(
        identity=identity(os.getuid(), os.getgid()),
        supplementary_gids=groups,
    )


def test_current_process_identity_can_match_exact_policy():
    snapshot = require_linux_process_identity(current_policy())

    assert snapshot.real_uid == os.getuid()
    assert snapshot.effective_uid == os.geteuid()
    assert snapshot.real_gid == os.getgid()
    assert snapshot.effective_gid == os.getegid()


def test_saved_uid_mismatch_is_rejected(monkeypatch):
    expected_uid = os.getuid()
    different_uid = 0 if expected_uid != 0 else 1

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.containment_manager_identity.read_linux_process_identity",
        lambda: LinuxProcessIdentitySnapshot(
            real_uid=expected_uid,
            effective_uid=expected_uid,
            saved_uid=different_uid,
            real_gid=os.getgid(),
            effective_gid=os.getgid(),
            saved_gid=os.getgid(),
            supplementary_gids=tuple(os.getgroups()),
        ),
    )

    with pytest.raises(
        LinuxProcessIdentityError,
        match="identity does not match",
    ):
        require_linux_process_identity(current_policy())


def test_saved_gid_mismatch_is_rejected(monkeypatch):
    expected_gid = os.getgid()
    different_gid = 0 if expected_gid != 0 else 1

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.containment_manager_identity.read_linux_process_identity",
        lambda: LinuxProcessIdentitySnapshot(
            real_uid=os.getuid(),
            effective_uid=os.getuid(),
            saved_uid=os.getuid(),
            real_gid=expected_gid,
            effective_gid=expected_gid,
            saved_gid=different_gid,
            supplementary_gids=tuple(os.getgroups()),
        ),
    )

    with pytest.raises(
        LinuxProcessIdentityError,
        match="identity does not match",
    ):
        require_linux_process_identity(current_policy())


def test_unexpected_supplementary_group_is_rejected(monkeypatch):
    expected = identity(2102, 3102)
    policy = LinuxProcessIdentityPolicy(
        identity=expected,
        supplementary_gids=frozenset({3199}),
    )

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.containment_manager_identity.read_linux_process_identity",
        lambda: LinuxProcessIdentitySnapshot(
            real_uid=2102,
            effective_uid=2102,
            saved_uid=2102,
            real_gid=3102,
            effective_gid=3102,
            saved_gid=3102,
            supplementary_gids=(3199, 3999),
        ),
    )

    with pytest.raises(
        LinuxProcessIdentityError,
        match="supplementary groups",
    ):
        require_linux_process_identity(policy)


def test_primary_gid_in_group_list_does_not_count_as_extra(monkeypatch):
    policy = LinuxProcessIdentityPolicy(
        identity=identity(2102, 3102),
        supplementary_gids=frozenset({3199}),
    )

    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.containment_manager_identity.read_linux_process_identity",
        lambda: LinuxProcessIdentitySnapshot(
            real_uid=2102,
            effective_uid=2102,
            saved_uid=2102,
            real_gid=3102,
            effective_gid=3102,
            saved_gid=3102,
            supplementary_gids=(3102, 3199),
        ),
    )

    snapshot = require_linux_process_identity(policy)
    assert snapshot.supplementary_gids == (3102, 3199)


def test_missing_linux_identity_api_fails_closed(monkeypatch):
    if not hasattr(os, "getresuid"):
        pytest.skip("getresuid already unavailable")

    monkeypatch.delattr(os, "getresuid")

    with pytest.raises(
        ContainmentUnavailableError,
        match="identity API",
    ):
        read_linux_process_identity()


def test_service_plan_requires_three_distinct_uids():
    with pytest.raises(ValueError, match="UIDs must be distinct"):
        ContainmentServiceIdentityPlan(
            manager=identity(2101, 3101),
            host_agent=identity(2101, 3102),
            workload=identity(2103, 3103),
            manager_client_gid=3199,
        )


def test_workload_primary_gid_cannot_be_manager_client_gid():
    with pytest.raises(ValueError, match="workload primary GID"):
        ContainmentServiceIdentityPlan(
            manager=identity(2101, 3101),
            host_agent=identity(2102, 3102),
            workload=identity(2103, 3199),
            manager_client_gid=3199,
        )


def test_service_plan_derives_strict_process_policies():
    value = plan()

    manager = value.manager_process_policy()
    agent = value.host_agent_process_policy()
    workload = value.workload_process_policy()

    assert manager.identity == value.manager
    assert manager.supplementary_gids == frozenset()
    assert agent.identity == value.host_agent
    assert agent.supplementary_gids == frozenset({3199})
    assert workload.identity == value.workload
    assert workload.supplementary_gids == frozenset()


def test_host_agent_primary_gid_can_be_manager_client_gid():
    value = ContainmentServiceIdentityPlan(
        manager=identity(2101, 3101),
        host_agent=identity(2102, 3199),
        workload=identity(2103, 3103),
        manager_client_gid=3199,
    )

    assert value.host_agent_process_policy().supplementary_gids == frozenset()


def test_service_plan_derives_bidirectional_peer_policies():
    value = plan()

    accepted = value.manager_accept_peer_policy()
    connected = value.host_agent_connect_peer_policy()

    assert accepted.expected_uid == value.host_agent.uid
    assert accepted.expected_gid == value.host_agent.gid
    assert connected.expected_uid == value.manager.uid
    assert connected.expected_gid == value.manager.gid


def test_service_plan_derives_endpoint_policy():
    value = plan()
    endpoint = value.endpoint_policy(
        Path("/run/ssh-over-mcp-manager/manager.sock"),
        socket_mode=0o660,
        backlog=8,
    )

    assert endpoint.directory_uid == value.manager.uid
    assert endpoint.directory_gid == value.manager.gid
    assert endpoint.socket_uid == value.manager.uid
    assert endpoint.socket_gid == value.manager_client_gid
    assert endpoint.socket_mode == 0o660
    assert endpoint.backlog == 8


@pytest.mark.parametrize(
    ("uid", "gid"),
    [
        (-1, 1000),
        (1 << 32, 1000),
        (1000, -1),
        (1000, 1 << 32),
        (True, 1000),
        (1000, True),
    ],
)
def test_invalid_process_identity_ids_are_rejected(uid, gid):
    with pytest.raises(ValueError):
        LinuxProcessIdentity(uid=uid, gid=gid)
