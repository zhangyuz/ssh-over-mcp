"""OCI manager source migration identity preflight — no cgroup writes."""

from __future__ import annotations

import os

import pytest

from ssh_over_mcp.host_agent import oci_source_migration as m
from ssh_over_mcp.host_agent.containment_manager_peer import LinuxPeerCredentialPolicy
from ssh_over_mcp.host_agent.oci_pidfd_handoff import OciPidfdHandoffRefused


def _domain() -> m.OciSourceDomain:
    return m.OciSourceDomain(
        delegated_root="/som-mode-a/node01",
        admission_cgroup="/som-mode-a/node01/admission",
        agent_source_cgroup="/som-mode-a/node01/host-agent-source",
    )


@pytest.mark.parametrize(
    "root,admission,source",
    [
        ("/", "/som-mode-a/node01/admission", "/som-mode-a/node01/host-agent-source"),
        (
            "/som-mode-a/node01",
            "/som-mode-a/node02/admission",
            "/som-mode-a/node01/host-agent-source",
        ),
        (
            "/som-mode-a/node01",
            "/som-mode-a/node01/admission",
            "/som-mode-a/node02/host-agent-source",
        ),
        (
            "/som-mode-a/node01",
            "/som-mode-a/node01/../node02",
            "/som-mode-a/node01/host-agent-source",
        ),
        ("/som-mode-a/node01", "/som-mode-a/node01/admission", "/som-mode-a/node01/admission"),
        ("/som-mode-a/node01", "/som-mode-a/node01/admission", "/som-mode-a/node01//source"),
        ("/som-mode-a/node01", "/som-mode-a/node01/admission", "/som-mode-a/node01/source\nchild"),
    ],
)
def test_fixed_domain_rejects_untrusted_or_cross_node_cgroup_paths(root, admission, source):
    with pytest.raises(ValueError):
        m.OciSourceDomain(root, admission, source)


def test_manager_inspects_self_pidfd_source_before_granting_immutable_receipt(monkeypatch):
    read_fd, write_fd = os.pipe()
    pinned = os.dup(read_fd)
    current = {"cgroup": "/som-mode-a/node01/admission", "birth": 881}
    monkeypatch.setattr(m, "receive_peer_self_pidfd", lambda *_args, **_kwargs: pinned)
    monkeypatch.setattr(m, "_pidfd_pid", lambda fd: 441 if fd == pinned else -1)
    monkeypatch.setattr(m, "_proc_identity", lambda pid: (77, current["birth"]))
    monkeypatch.setattr(m, "_current_cgroup", lambda pid: current["cgroup"])
    try:
        receipt = m.inspect_manager_source_self(
            object(),
            peer_policy=LinuxPeerCredentialPolicy(expected_uid=0),
            domain=_domain(),
        )
        assert receipt.pid == 441
        assert receipt.parent_pid == 77
        assert receipt.starttime == 881
        receipt.recheck_source()
        with pytest.raises(OciPidfdHandoffRefused, match="host-agent"):
            receipt.check_target_membership()
        current["cgroup"] = "/som-mode-a/node01/host-agent-source"
        receipt.check_target_membership()
        with pytest.raises(OciPidfdHandoffRefused, match="admission"):
            receipt.recheck_source()
        current["birth"] = 882
        with pytest.raises(OciPidfdHandoffRefused, match="identity changed"):
            receipt.check_target_membership()
    finally:
        os.close(pinned)
        os.close(read_fd)
        os.close(write_fd)


def test_source_identity_failure_closes_received_descriptor(monkeypatch):
    read_fd, write_fd = os.pipe()
    pinned = os.dup(read_fd)
    monkeypatch.setattr(m, "receive_peer_self_pidfd", lambda *_args, **_kwargs: pinned)
    monkeypatch.setattr(m, "_pidfd_pid", lambda _: 441)
    monkeypatch.setattr(m, "_proc_identity", lambda _: (77, 881))
    monkeypatch.setattr(m, "_current_cgroup", lambda _: "/som-mode-a/node02/admission")
    try:
        with pytest.raises(OciPidfdHandoffRefused, match="fixed admission"):
            m.inspect_manager_source_self(
                object(),
                peer_policy=LinuxPeerCredentialPolicy(expected_uid=0),
                domain=_domain(),
            )
        with pytest.raises(OSError):
            os.fstat(pinned)
    finally:
        try:
            os.close(pinned)
        except OSError:
            pass
        os.close(read_fd)
        os.close(write_fd)


def test_proc_cgroup_refuses_nonunified_or_untrusted_path(monkeypatch):
    import builtins
    import io

    real_open = builtins.open
    raw = {"bytes": b"0::/som-mode-a/node01/admission\n1:cpu:/other\n"}

    def fake_open(path, *args, **kwargs):
        if path == "/proc/441/cgroup":
            assert args == ("rb",)
            return io.BytesIO(raw["bytes"])
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)
    with pytest.raises(OciPidfdHandoffRefused, match="unified"):
        m._current_cgroup(441)
    raw["bytes"] = b"0::/som-mode-a/node01/../node02\n"
    with pytest.raises(OciPidfdHandoffRefused, match="unified"):
        m._current_cgroup(441)
    raw["bytes"] = b"0::/som-mode-a/node01/admission\r\n"
    with pytest.raises(OciPidfdHandoffRefused, match="unified"):
        m._current_cgroup(441)
    raw["bytes"] = b"0::/som-mode-a/node01/admission\n"
    assert m._current_cgroup(441) == "/som-mode-a/node01/admission"


class _ManagerStream:
    def __init__(self, response: bytes = b"A") -> None:
        self.sent: list[bytes] = []
        self.response = response
        self.timeout = None

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def recv(self, amount: int) -> bytes:
        assert amount == 1
        return self.response


def _source_receipt(monkeypatch):
    """Provide an owned fd and one pinned process in the manager namespace."""
    read_fd, write_fd = os.pipe()
    pinned = os.dup(read_fd)
    current = {"cgroup": "/som-mode-a/node01/admission", "birth": 5512}
    source = m.PinnedOciSource(pinned, 441, 77, 5512, _domain())
    monkeypatch.setattr(m, "inspect_manager_source_self", lambda *_a, **_k: source)
    monkeypatch.setattr(m, "_pidfd_pid", lambda _fd: 441)
    monkeypatch.setattr(m, "_proc_identity", lambda _pid: (77, current["birth"]))
    monkeypatch.setattr(m, "_current_cgroup", lambda _pid: current["cgroup"])
    return read_fd, write_fd, pinned, current


def test_fixed_move_acks_only_after_postwrite_same_process_membership(monkeypatch):
    read_fd, write_fd, pinned, current = _source_receipt(monkeypatch)
    stream = _ManagerStream()
    observed = []

    def move(receipt):
        assert receipt.pid == 441
        assert current["cgroup"] == _domain().admission_cgroup
        observed.append(receipt.pid)
        current["cgroup"] = _domain().agent_source_cgroup

    try:
        m.handle_fixed_source_move(
            stream,
            peer_policy=LinuxPeerCredentialPolicy(expected_uid=0),
            domain=_domain(),
            trusted_move=move,
        )
        assert observed == [441]
        assert stream.sent == [b"A"]
        assert stream.timeout == 2.0
        with pytest.raises(OSError):
            os.fstat(pinned)
    finally:
        for fd in (pinned, read_fd, write_fd):
            try:
                os.close(fd)
            except OSError:
                pass


@pytest.mark.parametrize("failure", ["no_move", "wrong_node", "changed_birth", "write_error"])
def test_fixed_move_refuses_without_ack_and_closes_fd(monkeypatch, failure):
    read_fd, write_fd, pinned, current = _source_receipt(monkeypatch)
    stream = _ManagerStream()

    def move(_receipt):
        if failure == "wrong_node":
            current["cgroup"] = "/som-mode-a/node02/host-agent-source"
        elif failure == "changed_birth":
            current["birth"] += 1
            current["cgroup"] = _domain().agent_source_cgroup
        elif failure == "write_error":
            raise OSError("guest cgroup delegation denied")

    try:
        with pytest.raises(OciPidfdHandoffRefused, match="migration refused"):
            m.handle_fixed_source_move(
                stream,
                peer_policy=LinuxPeerCredentialPolicy(expected_uid=0),
                domain=_domain(),
                trusted_move=move,
            )
        assert stream.sent == [b"N"]
        with pytest.raises(OSError):
            os.fstat(pinned)
    finally:
        for fd in (pinned, read_fd, write_fd):
            try:
                os.close(fd)
            except OSError:
                pass


def test_fixed_move_client_verifies_manager_peer_and_local_readback(monkeypatch):
    from ssh_over_mcp.host_agent import containment_manager_peer, oci_pidfd_handoff

    events = []
    monkeypatch.setattr(
        oci_pidfd_handoff,
        "_require_connected_unix_stream",
        lambda _sock: events.append("socket"),
    )
    monkeypatch.setattr(
        containment_manager_peer,
        "authenticate_linux_unix_peer",
        lambda *_a, **_k: events.append("authenticate"),
    )
    monkeypatch.setattr(
        oci_pidfd_handoff,
        "send_self_pidfd",
        lambda _sock: events.append("pidfd"),
    )
    monkeypatch.setattr(
        m,
        "_current_cgroup",
        lambda pid: "/som-mode-a/node01/host-agent-source",
    )
    stream = _ManagerStream()
    m.request_fixed_source_move(
        stream,
        manager_peer_policy=LinuxPeerCredentialPolicy(expected_uid=2204),
        expected_source_cgroup="/som-mode-a/node01/host-agent-source",
    )
    assert events == ["socket", "authenticate", "pidfd"]
    assert stream.timeout == 2.0
