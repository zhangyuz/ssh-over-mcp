"""Scoped manager cgroup-v2 source writer; no kernel/guest execution here."""

from __future__ import annotations

import errno

import pytest

from ssh_over_mcp.host_agent import oci_source_writer as writer
from ssh_over_mcp.host_agent.oci_pidfd_handoff import OciPidfdHandoffRefused
from ssh_over_mcp.host_agent.oci_source_migration import OciSourceDomain, PinnedOciSource


def _domain(node="node01"):
    return OciSourceDomain(
        delegated_root=f"/som-mode-a/{node}",
        admission_cgroup=f"/som-mode-a/{node}/admission",
        agent_source_cgroup=f"/som-mode-a/{node}/host-agent-source",
    )


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    root = tmp_path / "cgroup2"
    dest = root / "som-mode-a" / "node01" / "host-agent-source"
    dest.mkdir(parents=True)
    procs = dest / "cgroup.procs"
    procs.write_bytes(b"")
    sibling = root / "som-mode-a" / "node02" / "host-agent-source"
    sibling.mkdir(parents=True)
    (sibling / "cgroup.procs").write_bytes(b"")
    events = []
    monkeypatch.setattr(writer, "_CGROUP2_ROOT", str(root))
    monkeypatch.setattr(writer, "_require_cgroup2", lambda fd: events.append("fscheck"))
    monkeypatch.setattr(writer, "_mount_id", lambda fd: 41)
    monkeypatch.setattr(
        PinnedOciSource,
        "recheck_source",
        lambda self: events.append("precheck"),
    )
    monkeypatch.setattr(
        PinnedOciSource,
        "check_target_membership",
        lambda self: events.append("postcheck"),
    )
    return root, dest, procs, events


def _source(domain=None):
    return PinnedOciSource(-1, 441, 77, 882, domain if domain is not None else _domain())


def test_fixed_node_source_move_writes_only_selected_cgroup_and_rechecks(fixture):
    _root, _dest, procs, events = fixture
    writer.move_fixed_source(_source(), trusted_node="node01")
    assert procs.read_bytes() == b"441"
    assert events == [
        "precheck",
        "fscheck",
        "fscheck",
        "fscheck",
        "fscheck",
        "fscheck",
        "precheck",
        "postcheck",
    ]


def test_writer_refuses_arbitrary_target_and_other_node_without_any_write(fixture):
    root, _dest, procs, events = fixture
    bad = OciSourceDomain(
        delegated_root="/som-mode-a/node01",
        admission_cgroup="/som-mode-a/node01/admission",
        agent_source_cgroup="/som-mode-a/node01/sibling",
    )
    for src in (_source(bad), _source(_domain("node02")), object()):
        with pytest.raises(OciPidfdHandoffRefused):
            writer.move_fixed_source(src, trusted_node="node01")
    assert procs.read_bytes() == b""
    assert (root / "som-mode-a/node02/host-agent-source/cgroup.procs").read_bytes() == b""
    assert "postcheck" not in events


def test_writer_rejects_destination_symlink_before_mutating(fixture):
    _root, dest, _procs, events = fixture
    dest.rename(dest.parent / "other")
    dest.symlink_to(dest.parent / "other", target_is_directory=True)
    with pytest.raises(OciPidfdHandoffRefused, match="refused"):
        writer.move_fixed_source(_source(), trusted_node="node01")
    assert (dest.parent / "other" / "cgroup.procs").read_bytes() == b""
    assert "postcheck" not in events


@pytest.mark.parametrize("failure", ["before", "write", "short", "after"])
def test_migration_uncertainty_never_retries_or_reports_success(fixture, monkeypatch, failure):
    _root, _dest, procs, events = fixture
    calls = []
    if failure == "before":

        def reject_source(self):
            raise OciPidfdHandoffRefused("source changed")

        monkeypatch.setattr(PinnedOciSource, "recheck_source", reject_source)
    if failure == "after":

        def reject_target(self):
            events.append("postcheck")
            raise OciPidfdHandoffRefused("target unproven")

        monkeypatch.setattr(PinnedOciSource, "check_target_membership", reject_target)
    if failure in ("write", "short"):

        def fail_once(fd, buf):
            calls.append(bytes(buf))
            if failure == "write":
                raise OSError(errno.EIO, "unresolved effect")
            return len(buf) - 1

        monkeypatch.setattr(writer.os, "write", fail_once)
    with pytest.raises(OciPidfdHandoffRefused):
        writer.move_fixed_source(_source(), trusted_node="node01")
    if failure in ("write", "short"):
        assert calls == [b"441"]  # no retry even if outcome unknown
        assert procs.read_bytes() == b""
    assert "postcheck" not in events if failure != "after" else "postcheck" in events
    if failure == "before":
        assert procs.read_bytes() == b""


def test_non_cgroup2_mount_refuses_before_opening_target(fixture, monkeypatch):
    _root, _dest, procs, events = fixture

    def reject(_fd):
        raise OciPidfdHandoffRefused("not cgroup2")

    monkeypatch.setattr(writer, "_require_cgroup2", reject)
    with pytest.raises(OciPidfdHandoffRefused, match="not cgroup2"):
        writer.move_fixed_source(_source(), trusted_node="node01")
    assert procs.read_bytes() == b""
    assert events == ["precheck"]


def test_existing_pidfd_manager_handler_acks_only_after_fixed_writer(fixture, monkeypatch):
    from ssh_over_mcp.host_agent import oci_source_migration as migration
    from ssh_over_mcp.host_agent.containment_manager_peer import LinuxPeerCredentialPolicy

    _root, _dest, procs, events = fixture
    read_fd, write_fd = __import__("os").pipe()
    pinned_fd = __import__("os").dup(read_fd)
    source = PinnedOciSource(pinned_fd, 441, 77, 882, _domain())
    monkeypatch.setattr(migration, "inspect_manager_source_self", lambda *args, **kwargs: source)

    class Stream:
        def __init__(self):
            self.sent = []

        def sendall(self, value):
            events.append("ACK" if value == b"A" else "DENY")
            self.sent.append(value)

        def settimeout(self, _seconds):
            pass

    stream = Stream()
    try:
        writer.serve_fixed_node_source_once(
            stream,
            trusted_node="node01",
            domain=_domain(),
            peer_policy=LinuxPeerCredentialPolicy(expected_uid=0),
        )
        assert procs.read_bytes() == b"441"
        assert stream.sent == [b"A"]
        assert events[-2:] == ["postcheck", "ACK"]
        with pytest.raises(OSError):
            __import__("os").fstat(pinned_fd)
    finally:
        for fd in (pinned_fd, read_fd, write_fd):
            try:
                __import__("os").close(fd)
            except OSError:
                pass


@pytest.mark.parametrize("crossing_at", [3, 5])
def test_nested_cgroup_bind_mount_substitution_refused_before_write(
    fixture, monkeypatch, crossing_at
):
    _root, _dest, procs, events = fixture
    calls = 0

    def changed_mount(_fd):
        nonlocal calls
        calls += 1
        return 42 if calls == crossing_at else 41

    monkeypatch.setattr(writer, "_mount_id", changed_mount)
    with pytest.raises(OciPidfdHandoffRefused, match="substitution|destination"):
        writer.move_fixed_source(_source(), trusted_node="node01")
    assert procs.read_bytes() == b""
    assert "postcheck" not in events


def test_postwrite_unknown_is_typed_and_never_rolled_back(fixture, monkeypatch):
    _root, _dest, procs, events = fixture

    def refuse_readback(_self):
        events.append("postcheck")
        raise OciPidfdHandoffRefused("target became unknown")

    monkeypatch.setattr(PinnedOciSource, "check_target_membership", refuse_readback)
    with pytest.raises(writer.OciSourceOutcomeUnknown, match="do not retry"):
        writer.move_fixed_source(_source(), trusted_node="node01")
    assert procs.read_bytes() == b"441"
    assert events[-1] == "postcheck"


def test_postwrite_close_error_keeps_unknown_outcome(fixture, monkeypatch):
    import os

    _root, _dest, procs, events = fixture
    real_close = os.close

    def fail_after_real_close(fd):
        inode = os.fstat(fd).st_ino
        real_close(fd)
        if inode == procs.stat().st_ino:
            raise OSError(errno.EIO, "close uncertain")

    monkeypatch.setattr(writer.os, "close", fail_after_real_close)
    try:
        with pytest.raises(writer.OciSourceOutcomeUnknown, match="do not retry"):
            writer.move_fixed_source(_source(), trusted_node="node01")
    finally:
        monkeypatch.setattr(writer.os, "close", real_close)
    assert procs.read_bytes() == b"441"
    assert events[-1] == "postcheck"


def test_node02_requires_its_own_manager_identity_and_does_not_touch_node01(fixture):
    root, _dest, node01_procs, events = fixture
    writer.move_fixed_source(_source(_domain("node02")), trusted_node="node02")
    assert node01_procs.read_bytes() == b""
    assert (root / "som-mode-a/node02/host-agent-source/cgroup.procs").read_bytes() == b"441"
    assert events[-1] == "postcheck"
