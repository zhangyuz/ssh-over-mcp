"""OCI-only manager child attach: no cgroup writer or privilege effects."""

from __future__ import annotations

import os
from dataclasses import replace

import pytest

from ssh_over_mcp.host_agent import oci_child_attach as attach
from ssh_over_mcp.host_agent.containment_manager_peer import LinuxPeerCredentialPolicy
from ssh_over_mcp.host_agent.oci_namespace_identity import (
    IdMapEntry,
    PinnedNamespaceIdentity,
)
from ssh_over_mcp.host_agent.oci_pidfd_handoff import OciPidfdHandoffRefused, PinnedOciChild
from ssh_over_mcp.host_agent.oci_source_migration import OciSourceDomain


def _policy() -> attach.OciChildAttachPolicy:
    return attach.OciChildAttachPolicy(
        domain=OciSourceDomain(
            "/som/node1",
            "/som/node1/admission",
            "/som/node1/host-agent-source",
        ),
        target_cgroup="/som/node1/workload/req-a",
        expected_child_uid_map=(IdMapEntry(0, 100000, 65536),),
        expected_child_gid_map=(IdMapEntry(0, 100000, 65536),),
    )


def _identity(pid: int, *, manager: bool) -> PinnedNamespaceIdentity:
    entry = (IdMapEntry(0, 100000, 65536),)
    return PinnedNamespaceIdentity(
        pid=pid,
        parent_pid=9,
        starttime=800,
        pidns=(4, 100),
        userns=(4, 201 if manager else 202),
        uid_map=entry,
        gid_map=entry,
    )


class _Stream:
    def __init__(self, response: bytes = b"A") -> None:
        self.sent: list[bytes] = []
        self.response = response

    def sendall(self, payload: bytes) -> None:
        self.sent.append(payload)

    def settimeout(self, _timeout: float) -> None:
        pass

    def recv(self, count: int) -> bytes:
        assert count == 1
        return self.response


class _ManagerPin:
    fd = 99

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass


def _mock_child(monkeypatch, *, uid_map=None, pidns=None):
    read, write = os.pipe()
    fd = os.dup(read)
    child = PinnedOciChild(fd=fd, pid=441, parent_pid=77, starttime=800)
    group = {"membership": _policy().domain.agent_source_cgroup, "birth": 800, "changed_ns": False}
    monkeypatch.setattr(attach, "receive_direct_child_pidfd", lambda *_a, **_k: child)
    monkeypatch.setattr(attach, "_self_pidfd", _ManagerPin)
    monkeypatch.setattr("ssh_over_mcp.host_agent.oci_pidfd_handoff._pidfd_pid", lambda _fd: 441)
    monkeypatch.setattr(
        "ssh_over_mcp.host_agent.oci_pidfd_handoff._proc_identity",
        lambda _pid: (77, group["birth"]),
    )
    monkeypatch.setattr(attach, "_current_cgroup", lambda _pid: group["membership"])

    def inspect(fd_arg):
        if fd_arg == 99:
            return _identity(42, manager=True)
        child_identity = _identity(441, manager=False)
        if uid_map is not None:
            child_identity = replace(child_identity, uid_map=uid_map)
        if pidns is not None:
            child_identity = replace(child_identity, pidns=pidns)
        if group["changed_ns"]:
            child_identity = replace(child_identity, userns=(4, 999))
        return child_identity

    monkeypatch.setattr(attach, "inspect_pinned_namespace_identity", inspect)
    return child, group, (fd, read, write)


def _close_mock_fds(fds):
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass


@pytest.mark.parametrize(
    "target",
    [
        "/som/node2/workload/req-a",
        "/som/node1/admission",
        "/som/node1/host-agent-source",
        "/som/node1/host-agent-source/workload/req-a",
        "/som/node1/admission/workload/req-a",
        "/som/node1/workload/../admission",
        "/som/node1",
    ],
)
def test_workload_target_cannot_escape_or_reuse_fixed_node_sources(target):
    original = _policy()
    with pytest.raises(ValueError):
        replace(original, target_cgroup=target)


def test_attach_ack_only_after_identity_scope_and_target_readback(monkeypatch):
    child, group, fds = _mock_child(monkeypatch)
    stream = _Stream()
    moved: list[int] = []

    def trusted_attach(receipt):
        assert receipt == child
        assert group["membership"] == _policy().domain.agent_source_cgroup
        moved.append(receipt.pid)
        group["membership"] = _policy().target_cgroup

    try:
        attach.handle_fixed_child_attach(
            stream,
            peer_policy=LinuxPeerCredentialPolicy(expected_uid=2103),
            policy=_policy(),
            trusted_attach=trusted_attach,
        )
        assert moved == [441]
        assert stream.sent == [b"A"]
        with pytest.raises(OSError):
            os.fstat(child.fd)
    finally:
        _close_mock_fds(fds)


@pytest.mark.parametrize(
    "failure",
    [
        "wrong_source",
        "wrong_target",
        "wrong_uidmap",
        "wrong_pidns",
        "changed_birth",
        "changed_ns_after_attach",
        "write_refused",
    ],
)
def test_attach_denies_unproven_identity_or_mutation(monkeypatch, failure):
    uid_map = (IdMapEntry(0, 200000, 65536),) if failure == "wrong_uidmap" else None
    pidns = (4, 301) if failure == "wrong_pidns" else None
    child, group, fds = _mock_child(monkeypatch, uid_map=uid_map, pidns=pidns)
    stream = _Stream()

    if failure == "wrong_source":
        group["membership"] = "/som/node2/host-agent-source"

    def move(_receipt):
        if failure == "wrong_target":
            group["membership"] = "/som/node2/workload/req-a"
        elif failure == "changed_birth":
            group["birth"] += 1
            group["membership"] = _policy().target_cgroup
        elif failure == "changed_ns_after_attach":
            group["changed_ns"] = True
            group["membership"] = _policy().target_cgroup
        elif failure == "write_refused":
            raise OSError("guest kernel denied delegated move")
        else:
            group["membership"] = _policy().target_cgroup

    try:
        with pytest.raises(OciPidfdHandoffRefused, match="attach refused"):
            attach.handle_fixed_child_attach(
                stream,
                peer_policy=LinuxPeerCredentialPolicy(expected_uid=2103),
                policy=_policy(),
                trusted_attach=move,
            )
        assert stream.sent == [b"N"]
        with pytest.raises(OSError):
            os.fstat(child.fd)
    finally:
        _close_mock_fds(fds)


def test_child_parent_refuses_invalid_ack_and_mismatched_readback(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(attach, "_require_connected_unix_stream", lambda _s: None)
    monkeypatch.setattr(
        attach,
        "authenticate_linux_unix_peer",
        lambda *_a, **_k: calls.append("peer"),
    )
    monkeypatch.setattr(attach, "send_pinned_child_pidfd", lambda *_a, **_k: calls.append("child"))
    monkeypatch.setattr(attach, "_pidfd_pid", lambda _fd: 441)
    monkeypatch.setattr(attach, "_current_cgroup", lambda _pid: "/som/node1/workload/wrong")
    arguments = {
        "pinned_child_fd": 42,
        "manager_peer_policy": LinuxPeerCredentialPolicy(expected_uid=2301),
        "expected_local_target_cgroup": _policy().target_cgroup,
    }
    with pytest.raises(OciPidfdHandoffRefused, match="readback"):
        attach.request_fixed_child_attach(_Stream(), **arguments)
    with pytest.raises(OciPidfdHandoffRefused, match="denied"):
        attach.request_fixed_child_attach(_Stream(b"N"), **arguments)
    assert calls == ["peer", "child", "peer", "child"]


def _client_plan():
    from ssh_over_mcp.host_agent.containment_manager_identity import (
        ContainmentServiceIdentityPlan,
        LinuxProcessIdentity,
    )

    return ContainmentServiceIdentityPlan(
        manager=LinuxProcessIdentity(uid=2204, gid=3204),
        host_agent=LinuxProcessIdentity(uid=2202, gid=3202),
        workload=LinuxProcessIdentity(uid=2203, gid=3203),
        manager_client_gid=3299,
    )


@pytest.mark.parametrize("case", ["ok", "connect_denied", "attach_denied"])
def test_oci_postdrop_attach_uses_one_owned_socket_and_fails_closed(monkeypatch, case):
    events = []
    plan = _client_plan()

    class ClientSocket:
        def set_inheritable(self, value):
            events.append(("cloexec", value))

        def settimeout(self, value):
            events.append(("timeout", value))

        def connect(self, path):
            events.append(("connect", path))
            if case == "connect_denied":
                raise OSError("untrusted socket")

        def close(self):
            events.append(("close",))

    sock = ClientSocket()
    monkeypatch.setattr(
        attach,
        "require_linux_process_identity",
        lambda policy: events.append(("identity", policy.identity.uid)),
        raising=False,
    )
    monkeypatch.setattr(attach.socket, "socket", lambda *args: sock)

    def request(received, **kwargs):
        assert received is sock
        events.append(("attach", kwargs["pinned_child_fd"]))
        assert kwargs["manager_peer_policy"] == plan.host_agent_connect_peer_policy()
        assert kwargs["expected_local_target_cgroup"] == "/som/node1/workload/req-a"
        if case == "attach_denied":
            raise OciPidfdHandoffRefused("manager rejected")

    monkeypatch.setattr(attach, "request_fixed_child_attach", request)
    if case == "ok":
        attach.request_fixed_child_attach_at_endpoint(
            "/run/som/node1/manager.sock",
            pinned_child_fd=47,
            identity_plan=plan,
            expected_local_target_cgroup="/som/node1/workload/req-a",
        )
        assert ("attach", 47) in events
    else:
        with pytest.raises(OciPidfdHandoffRefused):
            attach.request_fixed_child_attach_at_endpoint(
                "/run/som/node1/manager.sock",
                pinned_child_fd=47,
                identity_plan=plan,
                expected_local_target_cgroup="/som/node1/workload/req-a",
            )
        if case == "connect_denied":
            assert ("attach", 47) not in events
    assert events[0] == ("identity", 2202)
    assert events[-1] == ("close",)
    assert ("connect", "/run/som/node1/manager.sock") in events


def test_oci_postdrop_attach_refuses_bad_target_and_identity_before_socket(monkeypatch):
    from ssh_over_mcp.host_agent.containment_manager_identity import LinuxProcessIdentityError

    events = []
    monkeypatch.setattr(
        attach.socket,
        "socket",
        lambda *args: events.append("opened"),
    )

    with pytest.raises(ValueError):
        attach.request_fixed_child_attach_at_endpoint(
            "/run/som/node1/manager.sock",
            pinned_child_fd=47,
            identity_plan=_client_plan(),
            expected_local_target_cgroup="/som/node1/../node2",
        )
    assert events == []

    def deny(_policy):
        events.append("identity-denied")
        raise LinuxProcessIdentityError("wrong agent")

    monkeypatch.setattr(attach, "require_linux_process_identity", deny, raising=False)
    with pytest.raises(LinuxProcessIdentityError):
        attach.request_fixed_child_attach_at_endpoint(
            "/run/som/node1/manager.sock",
            pinned_child_fd=47,
            identity_plan=_client_plan(),
            expected_local_target_cgroup="/som/node1/workload/req-a",
        )
    assert events == ["identity-denied"]
