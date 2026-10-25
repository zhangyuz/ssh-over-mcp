"""Nonprivileged, read-only namespace mapping and pinned identity gates."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from ssh_over_mcp.host_agent import oci_namespace_identity as m
from ssh_over_mcp.host_agent.oci_pidfd_handoff import OciPidfdHandoffRefused


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\n",
        b"0 1000 1\r\n",
        b"0 1000 1",
        b"0 1000 1\n\n",
        b"0 1000 0\n",
        b"0 1000 1\n2 1000 1\n",
        b"0 1000 3\n2 2000 1\n",
        b"0 4294967295 1\n",
        b"4294967295 0 1\n",
        b"0 -1 1\n",
        b"0 1 1 1\n",
        b"0 1 1\x00\n",
        b"0 1 1\x0b\n",
        b"0 1 1\x0c\n",
        b"0 1 1\nnot-a-map\n",
        b"0 1 1\n0 2 1\n",
    ],
)
def test_namespace_map_rejects_malformed_or_overlapping_bytes(raw):
    with pytest.raises(OciPidfdHandoffRefused):
        m.parse_id_map(raw)


def test_namespace_map_keeps_exact_unsigned_mapping_without_normalization():
    assert m.parse_id_map(b"         0     100000     65536\n") == (m.IdMapEntry(0, 100000, 65536),)
    assert m.parse_id_map(b"0 5000 1\n1 6000 1\n") == (
        m.IdMapEntry(0, 5000, 1),
        m.IdMapEntry(1, 6000, 1),
    )


def _identity(pid=441):
    entry = (m.IdMapEntry(0, 100000, 65536),)
    return m.PinnedNamespaceIdentity(
        pid=pid,
        parent_pid=77,
        starttime=400,
        pidns=(4, 100),
        userns=(4, 200),
        uid_map=entry,
        gid_map=entry,
    )


def test_oci_namespace_policy_requires_shared_pidns_and_distinct_userns():
    manager = _identity(10)
    peer = replace(_identity(11), userns=(4, 201))
    m.require_separate_userns_shared_pidns(manager, peer)
    with pytest.raises(OciPidfdHandoffRefused, match="share user"):
        m.require_separate_userns_shared_pidns(manager, _identity(11))
    with pytest.raises(OciPidfdHandoffRefused, match="PID namespaces differ"):
        m.require_separate_userns_shared_pidns(manager, replace(peer, pidns=(4, 101)))
    with pytest.raises(OciPidfdHandoffRefused, match="own OCI"):
        m.require_separate_userns_shared_pidns(manager, replace(peer, pid=10))


def test_pinned_namespace_reader_rechecks_birth_and_map_identity(monkeypatch):
    state = {"birth": 400, "uidmap": (m.IdMapEntry(0, 100000, 65536),)}
    monkeypatch.setattr(m, "_pidfd_pid", lambda _fd: 441)
    monkeypatch.setattr(m, "_proc_identity", lambda _pid: (77, state["birth"]))
    monkeypatch.setattr(
        m,
        "_namespace_inode",
        lambda _pid, kind: (4, 100 if kind == "pid" else 200),
    )
    monkeypatch.setattr(
        m,
        "_read_map",
        lambda _pid, name: (
            state["uidmap"] if name == "uid_map" else (m.IdMapEntry(0, 100000, 65536),)
        ),
    )
    assert m.inspect_pinned_namespace_identity(123).pid == 441
    state["birth"] += 1

    def change_birth(_pid):
        current = state["birth"]
        state["birth"] += 1
        return (77, current)

    monkeypatch.setattr(m, "_proc_identity", change_birth)
    with pytest.raises(OciPidfdHandoffRefused, match="changed"):
        m.inspect_pinned_namespace_identity(123)


def test_pinned_namespace_reader_rejects_changing_uid_map(monkeypatch):
    calls = {"uid": 0}
    monkeypatch.setattr(m, "_pidfd_pid", lambda _fd: 441)
    monkeypatch.setattr(m, "_proc_identity", lambda _pid: (77, 400))
    monkeypatch.setattr(m, "_namespace_inode", lambda _pid, kind: (4, 10 if kind == "pid" else 20))

    def read_map(_pid, name):
        if name == "uid_map":
            calls["uid"] += 1
            return (m.IdMapEntry(0, 100000 + calls["uid"], 1),)
        return (m.IdMapEntry(0, 200000, 1),)

    monkeypatch.setattr(m, "_read_map", read_map)
    with pytest.raises(OciPidfdHandoffRefused, match="mapping changed"):
        m.inspect_pinned_namespace_identity(123)


def test_namespace_reader_refuses_proc_link_missing(monkeypatch):
    def fail_stat(_path):
        raise FileNotFoundError("no proc namespace")

    monkeypatch.setattr(m.os, "stat", fail_stat)
    with pytest.raises(OciPidfdHandoffRefused, match="unavailable"):
        m._namespace_inode(441, "user")
    with pytest.raises(ValueError):
        m._namespace_inode(441, "mnt")


def test_parse_map_refuses_excessive_entries():
    with pytest.raises(OciPidfdHandoffRefused):
        m.parse_id_map(b"".join(f"{i} {i + 100000} 1\n".encode() for i in range(6)))


def test_namespace_inode_rejects_nonpositive_kernel_identifier(monkeypatch):
    monkeypatch.setattr(m.os, "stat", lambda _path: SimpleNamespace(st_dev=0, st_ino=12))
    with pytest.raises(OciPidfdHandoffRefused, match="invalid"):
        m._namespace_inode(441, "user")
