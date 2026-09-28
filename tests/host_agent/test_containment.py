from __future__ import annotations

from pathlib import Path

import pytest

from ssh_over_mcp.host_agent.containment import (
    REQUIRED_CGROUP_V2_CONTROLLERS,
    ContainmentBackend,
    ContainmentHandle,
    ContainmentLimits,
    ContainmentRequest,
    ContainmentStats,
    probe_cgroup_v2,
)


class FakeHandle(ContainmentHandle):
    def __init__(self) -> None:
        self.attached: list[int] = []
        self.killed = False
        self.closed = False

    @property
    def scope_id(self) -> str:
        return "fake-scope"

    def attach(self, pid: int) -> None:
        self.attached.append(pid)

    def kill_all(self) -> None:
        self.killed = True

    def stats(self) -> ContainmentStats:
        return ContainmentStats(
            memory_current_bytes=123,
            pids_current=len(self.attached),
            cpu_usage_usec=456,
            populated=bool(self.attached),
        )

    def close(self) -> None:
        self.closed = True


class FakeBackend(ContainmentBackend):
    def __init__(self) -> None:
        self.requests: list[ContainmentRequest] = []
        self.handle = FakeHandle()

    @property
    def name(self) -> str:
        return "fake"

    def create(self, request: ContainmentRequest) -> ContainmentHandle:
        self.requests.append(request)
        return self.handle


def limits() -> ContainmentLimits:
    return ContainmentLimits(
        memory_max_bytes=512 * 1024 * 1024,
        pids_max=64,
        cpu_quota_us=100_000,
        cpu_period_us=100_000,
    )


def test_containment_request_and_handle_lifecycle():
    request = ContainmentRequest(
        request_id="req_12345678",
        limits=limits(),
    )
    backend = FakeBackend()

    with backend.create(request) as handle:
        handle.attach(1234)
        stats = handle.stats()

        assert handle.scope_id == "fake-scope"
        assert stats.pids_current == 1
        handle.kill_all()

    assert backend.requests == [request]
    assert backend.handle.attached == [1234]
    assert backend.handle.killed is True
    assert backend.handle.closed is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("memory_max_bytes", 0),
        ("pids_max", 0),
        ("cpu_quota_us", 0),
        ("cpu_period_us", 999),
        ("cpu_period_us", 1_000_001),
    ],
)
def test_invalid_containment_limits_are_rejected(field: str, value: int):
    values = {
        "memory_max_bytes": 512 * 1024 * 1024,
        "pids_max": 64,
        "cpu_quota_us": 100_000,
        "cpu_period_us": 100_000,
    }
    values[field] = value

    with pytest.raises(ValueError):
        ContainmentLimits(**values)


@pytest.mark.parametrize(
    "request_id",
    [
        "short",
        "../escape",
        "has/slash",
        "has space",
        "x" * 129,
    ],
)
def test_invalid_containment_request_id_is_rejected(request_id: str):
    with pytest.raises(ValueError):
        ContainmentRequest(request_id=request_id, limits=limits())


def test_probe_cgroup_v2_accepts_required_controllers(tmp_path: Path):
    (tmp_path / "cgroup.controllers").write_text(
        "cpuset cpu io memory hugetlb pids\n",
        encoding="ascii",
    )

    probe = probe_cgroup_v2(tmp_path)

    assert probe.unified is True
    assert probe.ready_for_containment is True
    assert REQUIRED_CGROUP_V2_CONTROLLERS.issubset(probe.controllers)
    assert probe.missing_required == frozenset()
    assert probe.reason is None


def test_probe_cgroup_v2_reports_missing_controller(tmp_path: Path):
    (tmp_path / "cgroup.controllers").write_text(
        "cpu memory\n",
        encoding="ascii",
    )

    probe = probe_cgroup_v2(tmp_path)

    assert probe.unified is True
    assert probe.ready_for_containment is False
    assert probe.missing_required == frozenset({"pids"})
    assert probe.reason is not None


def test_probe_cgroup_v2_fails_closed_without_unified_file(tmp_path: Path):
    probe = probe_cgroup_v2(tmp_path)

    assert probe.unified is False
    assert probe.ready_for_containment is False
    assert probe.controllers == frozenset()
    assert probe.missing_required == REQUIRED_CGROUP_V2_CONTROLLERS
    assert probe.reason is not None
