"""Portable supervisor OCI dispatch test; actual Linux pidfd is separately tested."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from ssh_over_mcp.host_agent import supervisor
from ssh_over_mcp.host_agent.containment import (
    ContainmentBackend,
    ContainmentError,
    ContainmentLimits,
    ContainmentRequest,
    ContainmentStats,
    ContainmentUnavailableError,
    PidfdContainmentHandle,
)
from ssh_over_mcp.host_agent.containment_manager_identity import (
    LinuxProcessIdentity,
    LinuxProcessIdentityPolicy,
)


class _Handle(PidfdContainmentHandle):
    def __init__(self, events: list[str], *, refuse: bool = False):
        self.events = events
        self.refuse = refuse
        self.received: int | None = None

    @property
    def scope_id(self) -> str:
        return "oci-test-only"

    def attach_pinned(self, pidfd: int) -> None:
        self.events.append("pidfd-attach")
        os.fstat(pidfd)
        self.received = pidfd
        if self.refuse == "unexpected":
            raise RuntimeError("unexpected adapter error")
        if self.refuse:
            raise ContainmentError("manager refused pinned child")

    def kill_all(self) -> None:
        self.events.append("kill_all")

    def stats(self) -> ContainmentStats:
        return ContainmentStats(populated=False)

    def close(self) -> None:
        self.events.append("close")


class _Backend(ContainmentBackend):
    def __init__(self, handle):
        self.handle = handle

    @property
    def name(self) -> str:
        return "oci-test-only"

    def create(self, request: ContainmentRequest) -> PidfdContainmentHandle:
        assert request.request_id == "req_12345678"
        return self.handle


def _request():
    return ContainmentRequest(
        request_id="req_12345678",
        limits=ContainmentLimits(
            memory_max_bytes=64 * 1024 * 1024,
            pids_max=8,
            cpu_quota_us=20_000,
            cpu_period_us=100_000,
        ),
    )


@pytest.mark.parametrize("case", ["accept", "deny", "unexpected", "pidfd_unavailable"])
def test_oci_parent_dispatch_preserves_pin_and_barrier_contract(monkeypatch, case):
    events: list[str] = []
    handle = _Handle(events, refuse="unexpected" if case == "unexpected" else case == "deny")
    backend = _Backend(handle)
    fake_pid = 54321
    monkeypatch.setattr(supervisor, "_validate_spawn_preconditions", lambda _prepared: None)

    def test_only_pipe():
        # Test fake parent-fork dispatch, not the production atomic pipe gate.
        r, w = os.pipe()
        os.set_inheritable(r, False)
        os.set_inheritable(w, False)
        return r, w

    monkeypatch.setattr(supervisor, "_pipe_cloexec", test_only_pipe)
    monkeypatch.setattr(supervisor.os, "fork", lambda: fake_pid, raising=False)
    monkeypatch.setattr(supervisor, "_release_start_barrier", lambda _fd: events.append("release"))
    monkeypatch.setattr(supervisor, "_reap_pid_bounded", lambda _pid: True)
    monkeypatch.setattr(supervisor.os, "kill", lambda _pid, _sig: events.append("kill"))

    read, write = os.pipe()
    pinned = []
    if case == "pidfd_unavailable":

        def failing_pin(_pid, _flags):
            events.append("pin-refused")
            raise OSError("no pidfd support")

        monkeypatch.setattr(supervisor.os, "pidfd_open", failing_pin, raising=False)
    else:

        def pin(_pid, _flags):
            events.append("pin")
            dupfd = os.dup(read)
            pinned.append(dupfd)
            return dupfd

        monkeypatch.setattr(supervisor.os, "pidfd_open", pin, raising=False)

    prepared = SimpleNamespace(request_id="req_12345678")
    policy = LinuxProcessIdentityPolicy(
        identity=LinuxProcessIdentity(uid=2103, gid=3103),
        supplementary_gids=frozenset(),
    )
    try:
        if case == "accept":
            result = supervisor.spawn_prepared_native_contained(
                prepared,
                backend,
                _request(),
                workload_identity_policy=policy,
            )
            assert result.pid == fake_pid
            result.close_pipes()
            result.close_containment()
            assert events[:3] == ["pin", "pidfd-attach", "release"]
            assert events[-1] == "close"
        else:
            with pytest.raises(
                supervisor.ChildSupervisorError, match="cannot attach contained child"
            ):
                supervisor.spawn_prepared_native_contained(
                    prepared,
                    backend,
                    _request(),
                    workload_identity_policy=policy,
                )
            assert "release" not in events
            assert events[-3:] == ["kill_all", "kill", "close"]
        for fd in pinned:
            with pytest.raises(OSError):
                os.fstat(fd)
        with pytest.raises(ContainmentUnavailableError, match="requires a pinned"):
            handle.attach(fake_pid)
    finally:
        os.close(read)
        os.close(write)


@pytest.mark.parametrize("failing_step", ["kill_all", "close"])
def test_oci_cleanup_continues_after_unexpected_backend_failure(monkeypatch, failing_step):
    """A broken OCI adapter cannot prevent direct child termination/reaping."""
    events: list[str] = []
    handle = _Handle(events)

    def fail_cleanup() -> None:
        events.append(failing_step)
        raise RuntimeError("unexpected OCI adapter failure")

    setattr(handle, failing_step, fail_cleanup)
    monkeypatch.setattr(supervisor.os, "kill", lambda _pid, _sig: events.append("kill"))

    def reap(_pid):
        events.append("reap")
        return True

    monkeypatch.setattr(supervisor, "_reap_pid_bounded", reap)
    barrier_read, barrier_write = os.pipe()
    child = supervisor.SpawnedChild(777, -1, -1, -1, containment=handle)
    try:
        with pytest.raises(
            supervisor.ChildSupervisorError, match="cannot clean failed contained child"
        ):
            supervisor._cleanup_failed_contained_spawn(
                pid=777,
                barrier_write=barrier_write,
                child=child,
                containment=handle,
            )
        assert events == ["kill_all", "kill", "reap", "close"]
        with pytest.raises(OSError):
            os.fstat(barrier_write)
    finally:
        os.close(barrier_read)
        try:
            os.close(barrier_write)
        except OSError:
            pass
