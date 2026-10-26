"""Bounded one-slot OCI child cgroup writer tests (no actual cgroup writes)."""

from __future__ import annotations

import errno

import pytest

from ssh_over_mcp.host_agent import oci_child_writer as m
from ssh_over_mcp.host_agent.oci_pidfd_handoff import OciPidfdHandoffRefused, PinnedOciChild
from ssh_over_mcp.host_agent.oci_source_writer import OciSourceOutcomeUnknown


@pytest.fixture
def fake_kernel(tmp_path, monkeypatch):
    root = tmp_path / "cgroup2"
    for node in ("node01", "node02"):
        target = root / "som-mode-a" / node / "workload" / "mvp"
        target.mkdir(parents=True)
        (target / "cgroup.procs").write_bytes(b"")
    monkeypatch.setattr(m, "_CGROUP2_ROOT", str(root))
    monkeypatch.setattr(m, "_require_cgroup2", lambda fd: None)
    monkeypatch.setattr(m, "_mount_id", lambda fd: 99)
    events = []
    monkeypatch.setattr(
        PinnedOciChild,
        "recheck_identity",
        lambda self: events.append("pidfd-identity-check"),
    )
    monkeypatch.setattr(
        m,
        "_current_cgroup",
        lambda pid: "/som-mode-a/node01/workload/mvp",
    )
    return root, events


def _child():
    return PinnedOciChild(fd=70, pid=441, parent_pid=300, starttime=1234)


def test_single_fixed_child_attach_with_pre_and_post_pidfd_checks(fake_kernel):
    root, events = fake_kernel
    m.move_fixed_mvp_child(_child(), trusted_node="node01")
    assert (root / "som-mode-a/node01/workload/mvp/cgroup.procs").read_bytes() == b"441"
    assert (root / "som-mode-a/node02/workload/mvp/cgroup.procs").read_bytes() == b""
    assert events == ["pidfd-identity-check"] * 3


@pytest.mark.parametrize("node", ("../node02", "", "node03", "node01/../node02"))
def test_untrusted_manager_node_has_no_write(fake_kernel, node):
    root, events = fake_kernel
    with pytest.raises(OciPidfdHandoffRefused):
        m.move_fixed_mvp_child(_child(), trusted_node=node)
    assert (root / "som-mode-a/node01/workload/mvp/cgroup.procs").read_bytes() == b""
    assert events == []


def test_no_symlink_escape_from_fixed_workload(fake_kernel):
    root, events = fake_kernel
    node = root / "som-mode-a/node01"
    (node / "workload").rename(node / "workload-original")
    (node / "workload").symlink_to(node / "workload-original", target_is_directory=True)
    with pytest.raises(OciPidfdHandoffRefused):
        m.move_fixed_mvp_child(_child(), trusted_node="node01")
    assert (node / "workload-original/mvp/cgroup.procs").read_bytes() == b""
    assert len(events) == 1


def test_mount_substitution_before_write_refused(fake_kernel, monkeypatch):
    root, _ = fake_kernel
    calls = 0

    def mount_id(_fd):
        nonlocal calls
        calls += 1
        return 101 if calls == 4 else 99

    monkeypatch.setattr(m, "_mount_id", mount_id)
    with pytest.raises(OciPidfdHandoffRefused, match="submount"):
        m.move_fixed_mvp_child(_child(), trusted_node="node01")
    assert (root / "som-mode-a/node01/workload/mvp/cgroup.procs").read_bytes() == b""


def test_failed_postwrite_membership_is_unknown_no_retry(fake_kernel, monkeypatch):
    root, _ = fake_kernel
    monkeypatch.setattr(m, "_current_cgroup", lambda pid: "/som-mode-a/node02/workload/mvp")
    with pytest.raises(OciSourceOutcomeUnknown, match="do not retry"):
        m.move_fixed_mvp_child(_child(), trusted_node="node01")
    assert (root / "som-mode-a/node01/workload/mvp/cgroup.procs").read_bytes() == b"441"


def test_write_failure_is_unknown_single_attempt(fake_kernel, monkeypatch):
    root, _ = fake_kernel
    calls = []

    def fail_once(fd, payload):
        calls.append(payload)
        raise OSError(errno.EIO, "effect unknown")

    monkeypatch.setattr(m.os, "write", fail_once)
    with pytest.raises(OciSourceOutcomeUnknown, match="do not retry"):
        m.move_fixed_mvp_child(_child(), trusted_node="node01")
    assert calls == [b"441"]
    assert (root / "som-mode-a/node01/workload/mvp/cgroup.procs").read_bytes() == b""


def test_node02_target_is_isolated_from_node01(fake_kernel, monkeypatch):
    root, _events = fake_kernel
    monkeypatch.setattr(m, "_current_cgroup", lambda pid: "/som-mode-a/node02/workload/mvp")
    m.move_fixed_mvp_child(_child(), trusted_node="node02")
    assert (root / "som-mode-a/node02/workload/mvp/cgroup.procs").read_bytes() == b"441"
    assert (root / "som-mode-a/node01/workload/mvp/cgroup.procs").read_bytes() == b""
