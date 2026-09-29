from __future__ import annotations

from dataclasses import replace

import pytest

from ssh_over_mcp.host_agent import workload_identity
from ssh_over_mcp.host_agent.containment_manager_identity import (
    LinuxProcessIdentity,
    LinuxProcessIdentityPolicy,
    LinuxProcessIdentitySnapshot,
)
from ssh_over_mcp.host_agent.workload_identity import (
    WorkloadIdentityTransitionError,
    transition_to_workload_identity,
)

UINT32_MAX = (1 << 32) - 1


def snapshot(
    uid: int = 2102,
    gid: int = 3102,
    *,
    groups: tuple[int, ...] = (3199,),
) -> LinuxProcessIdentitySnapshot:
    return LinuxProcessIdentitySnapshot(
        real_uid=uid,
        effective_uid=uid,
        saved_uid=uid,
        real_gid=gid,
        effective_gid=gid,
        saved_gid=gid,
        supplementary_gids=groups,
    )


def policy(
    uid: int = 2103,
    gid: int = 3103,
    *,
    groups: frozenset[int] = frozenset(),
) -> LinuxProcessIdentityPolicy:
    return LinuxProcessIdentityPolicy(
        identity=LinuxProcessIdentity(uid=uid, gid=gid),
        supplementary_gids=groups,
    )


class FakeSyscalls:
    def __init__(
        self,
        *,
        source: LinuxProcessIdentitySnapshot | None = None,
        cap_last_cap: int = 40,
    ) -> None:
        self.identity = source or snapshot()
        self.cap_last_cap = cap_last_cap
        self.filesystem_uid = self.identity.effective_uid
        self.filesystem_gid = self.identity.effective_gid
        self.no_new_privs = 0
        self.effective_capabilities = (1 << 6) | (1 << 7)
        self.permitted_capabilities = (1 << 6) | (1 << 7)
        self.inheritable_capabilities = 0
        self.ambient_cleared = False
        self.operations: list[str] = []
        self.fail_at: str | None = None
        self.identity_after_override: LinuxProcessIdentitySnapshot | None = None
        self.filesystem_after_override: tuple[int, int] | None = None
        self.capabilities_after_override: tuple[int, int, int] | None = None
        self.no_new_privs_after_override: int | None = None

    def _record(self, operation: str) -> None:
        self.operations.append(operation)
        if self.fail_at == operation:
            raise WorkloadIdentityTransitionError(f"forced failure: {operation}")

    def read_identity(self) -> LinuxProcessIdentitySnapshot:
        self._record("read_identity")
        if (
            self.identity_after_override is not None
            and "clear_capability_sets" in self.operations
        ):
            return self.identity_after_override
        return self.identity

    def validate_capability_abi(self) -> int:
        self._record("validate_capability_abi")
        if self.cap_last_cap > 63:
            raise WorkloadIdentityTransitionError(
                "kernel capability range is unsupported"
            )
        return self.cap_last_cap

    def set_no_new_privs(self) -> None:
        self._record("set_no_new_privs")
        self.no_new_privs = 1

    def clear_ambient_capabilities(self) -> None:
        self._record("clear_ambient_capabilities")
        self.ambient_cleared = True

    def clear_supplementary_groups(self) -> None:
        self._record("clear_supplementary_groups")
        self.identity = replace(self.identity, supplementary_gids=())

    def setresgid(self, gid: int) -> None:
        self._record(f"setresgid:{gid}")
        self.identity = replace(
            self.identity,
            real_gid=gid,
            effective_gid=gid,
            saved_gid=gid,
        )
        self.filesystem_gid = gid

    def setresuid(self, uid: int) -> None:
        self._record(f"setresuid:{uid}")
        self.identity = replace(
            self.identity,
            real_uid=uid,
            effective_uid=uid,
            saved_uid=uid,
        )
        self.filesystem_uid = uid

    def read_filesystem_ids(self) -> tuple[int, int]:
        self._record("read_filesystem_ids")
        if self.filesystem_after_override is not None:
            return self.filesystem_after_override
        return self.filesystem_uid, self.filesystem_gid

    def clear_capability_sets(self) -> None:
        self._record("clear_capability_sets")
        self.effective_capabilities = 0
        self.permitted_capabilities = 0
        self.inheritable_capabilities = 0

    def read_capability_sets(self) -> tuple[int, int, int]:
        self._record("read_capability_sets")
        if self.capabilities_after_override is not None:
            return self.capabilities_after_override
        return (
            self.effective_capabilities,
            self.permitted_capabilities,
            self.inheritable_capabilities,
        )

    def get_no_new_privs(self) -> int:
        self._record("get_no_new_privs")
        if self.no_new_privs_after_override is not None:
            return self.no_new_privs_after_override
        return self.no_new_privs


@pytest.fixture
def fake(monkeypatch) -> FakeSyscalls:
    value = FakeSyscalls()
    monkeypatch.setattr(workload_identity, "_SYSCALLS", value)
    return value


def test_complete_transition_has_exact_order_and_snapshot(fake):
    result = transition_to_workload_identity(policy())

    assert fake.operations == [
        "read_identity",
        "validate_capability_abi",
        "set_no_new_privs",
        "clear_ambient_capabilities",
        "clear_supplementary_groups",
        "setresgid:3103",
        "setresuid:2103",
        "read_filesystem_ids",
        "clear_capability_sets",
        "read_identity",
        "read_capability_sets",
        "get_no_new_privs",
    ]
    assert result.identity == snapshot(2103, 3103, groups=())
    assert result.filesystem_uid == 2103
    assert result.filesystem_gid == 3103
    assert result.no_new_privs is True
    assert result.effective_capabilities == 0
    assert result.permitted_capabilities == 0
    assert result.inheritable_capabilities == 0
    assert result.ambient_capabilities_empty is True


@pytest.mark.parametrize(
    "source",
    [
        snapshot(uid=0),
        snapshot(gid=0),
        replace(snapshot(), effective_uid=2999),
        replace(snapshot(), saved_uid=2999),
        replace(snapshot(), effective_gid=3999),
        replace(snapshot(), saved_gid=3999),
    ],
)
def test_invalid_source_identity_fails_before_mutation(monkeypatch, source):
    fake = FakeSyscalls(source=source)
    monkeypatch.setattr(workload_identity, "_SYSCALLS", fake)

    with pytest.raises(
        WorkloadIdentityTransitionError,
        match="source",
    ):
        transition_to_workload_identity(policy())

    assert fake.operations == ["read_identity"]


@pytest.mark.parametrize(
    "target",
    [
        policy(uid=0),
        policy(gid=0),
        policy(uid=UINT32_MAX),
        policy(gid=UINT32_MAX),
        policy(uid=2102),
        policy(groups=frozenset({3199})),
    ],
)
def test_invalid_target_policy_fails_before_mutation(monkeypatch, target):
    fake = FakeSyscalls()
    monkeypatch.setattr(workload_identity, "_SYSCALLS", fake)

    with pytest.raises(WorkloadIdentityTransitionError):
        transition_to_workload_identity(target)

    assert fake.operations == ["read_identity"]


def test_unsupported_capability_range_fails_before_mutation(monkeypatch):
    fake = FakeSyscalls(cap_last_cap=64)
    monkeypatch.setattr(workload_identity, "_SYSCALLS", fake)

    with pytest.raises(
        WorkloadIdentityTransitionError,
        match="capability range",
    ):
        transition_to_workload_identity(policy())

    assert fake.operations == ["read_identity", "validate_capability_abi"]


@pytest.mark.parametrize(
    ("failure", "forbidden"),
    [
        ("set_no_new_privs", "clear_ambient_capabilities"),
        ("clear_ambient_capabilities", "clear_supplementary_groups"),
        ("clear_supplementary_groups", "setresgid:3103"),
        ("setresgid:3103", "setresuid:2103"),
        ("setresuid:2103", "read_filesystem_ids"),
        ("clear_capability_sets", "read_capability_sets"),
    ],
)
def test_transition_failure_stops_before_later_steps(
    monkeypatch,
    failure,
    forbidden,
):
    fake = FakeSyscalls()
    fake.fail_at = failure
    monkeypatch.setattr(workload_identity, "_SYSCALLS", fake)

    with pytest.raises(WorkloadIdentityTransitionError):
        transition_to_workload_identity(policy())

    assert forbidden not in fake.operations


def test_filesystem_uid_mismatch_fails(monkeypatch):
    fake = FakeSyscalls()
    fake.filesystem_after_override = (9999, 3103)
    monkeypatch.setattr(workload_identity, "_SYSCALLS", fake)

    with pytest.raises(WorkloadIdentityTransitionError, match="filesystem"):
        transition_to_workload_identity(policy())


def test_filesystem_gid_mismatch_fails(monkeypatch):
    fake = FakeSyscalls()
    fake.filesystem_after_override = (2103, 9999)
    monkeypatch.setattr(workload_identity, "_SYSCALLS", fake)

    with pytest.raises(WorkloadIdentityTransitionError, match="filesystem"):
        transition_to_workload_identity(policy())


@pytest.mark.parametrize(
    "identity_after",
    [
        replace(snapshot(2103, 3103, groups=()), saved_uid=2102),
        replace(snapshot(2103, 3103, groups=()), saved_gid=3102),
        snapshot(2103, 3103, groups=(3103,)),
        snapshot(2103, 3103, groups=(3999,)),
    ],
)
def test_post_drop_identity_mismatch_fails(monkeypatch, identity_after):
    fake = FakeSyscalls()
    fake.identity_after_override = identity_after
    monkeypatch.setattr(workload_identity, "_SYSCALLS", fake)

    with pytest.raises(WorkloadIdentityTransitionError, match="post-drop"):
        transition_to_workload_identity(policy())


@pytest.mark.parametrize(
    "capabilities",
    [
        (1, 0, 0),
        (0, 1 << 40, 0),
        (0, 0, 1),
    ],
)
def test_residual_capability_fails(monkeypatch, capabilities):
    fake = FakeSyscalls()
    fake.capabilities_after_override = capabilities
    monkeypatch.setattr(workload_identity, "_SYSCALLS", fake)

    with pytest.raises(WorkloadIdentityTransitionError, match="capabil"):
        transition_to_workload_identity(policy())


def test_no_new_privs_readback_must_be_one(monkeypatch):
    fake = FakeSyscalls()
    fake.no_new_privs_after_override = 0
    monkeypatch.setattr(workload_identity, "_SYSCALLS", fake)

    with pytest.raises(WorkloadIdentityTransitionError, match="no_new_privs"):
        transition_to_workload_identity(policy())


def test_missing_linux_syscall_boundary_fails_closed(monkeypatch):
    monkeypatch.setattr(workload_identity, "_SYSCALLS", None)

    def fail_loader():
        raise WorkloadIdentityTransitionError(
            "required Linux workload identity APIs are unavailable"
        )

    monkeypatch.setattr(workload_identity, "_create_linux_syscalls", fail_loader)
    with pytest.raises(
        WorkloadIdentityTransitionError,
        match="Linux workload identity APIs",
    ):
        transition_to_workload_identity(policy())


def test_capability_readback_combines_both_v3_words():
    syscalls = object.__new__(workload_identity._LinuxIdentitySyscalls)

    def fake_capget(_header, data):
        data[0].effective = 3
        data[1].effective = 1
        data[1].permitted = 1 << 8
        data[1].inheritable = 1 << 31
        return 0

    syscalls._capget = fake_capget

    assert syscalls.read_capability_sets() == (
        (1 << 32) | 3,
        1 << 40,
        1 << 63,
    )


def test_capability_clear_writes_both_v3_words_as_zero():
    syscalls = object.__new__(workload_identity._LinuxIdentitySyscalls)
    observed = {}

    def fake_capset(header, data):
        observed["version"] = header._obj.version
        observed["words"] = [
            (word.effective, word.permitted, word.inheritable)
            for word in data
        ]
        return 0

    syscalls._capset = fake_capset
    syscalls.clear_capability_sets()

    assert observed == {
        "version": workload_identity._LINUX_CAPABILITY_VERSION_3,
        "words": [(0, 0, 0), (0, 0, 0)],
    }
