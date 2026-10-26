"""OCI root admission: trusted manager ACK must precede verified UID drop.

No process changes in tests: privilege operations and Unix socket are injected.
"""

from __future__ import annotations

import pytest

from ssh_over_mcp.host_agent import oci_launcher_admission as m


class _Ops:
    def __init__(self, events: list[str], *, bad_snapshot: bool = False) -> None:
        self.events = events
        self.bad_snapshot = bad_snapshot

    def effective_uid(self) -> int:
        return 0

    def set_keepcaps(self, flag: bool) -> None:
        self.events.append(f"keepcaps:{int(flag)}")

    def set_groups(self, groups: tuple[int, ...]) -> None:
        self.events.append(f"groups:{groups!r}")

    def set_res_gid(self, gid: int) -> None:
        self.events.append(f"gid:{gid}")

    def set_res_uid(self, uid: int) -> None:
        self.events.append(f"uid:{uid}")

    def set_capabilities(self, mask: int) -> None:
        self.events.append(f"caps:{mask}")

    def clear_ambient_capabilities(self) -> None:
        self.events.append("ambient-clear")

    def snapshot(self) -> m.OciAdmissionSnapshot:
        self.events.append("snapshot")
        return m.OciAdmissionSnapshot(
            uid=2202,
            euid=2202,
            suid=0 if self.bad_snapshot else 2202,
            gid=3202,
            egid=3202,
            sgid=3202,
            supplementary_gids=(3299,),
            cap_inheritable=0,
            cap_permitted=m.TRUSTED_AGENT_CAP_MASK,
            cap_effective=m.TRUSTED_AGENT_CAP_MASK,
            cap_ambient=0,
        )


class _Socket:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.closed = False

    def close(self) -> None:
        self.events.append("close-root-fd")
        self.closed = True


def _env() -> dict[str, str]:
    return {
        "SSH_ORIGINAL_COMMAND": "mcp-v1",
        "SUDO_USER": "ssh-over-mcp-e2e-host",
        "SUDO_UID": "2201",
        "SUDO_GID": "3201",
        "UNTRUSTED_INJECTION": "evil",
    }


def _run(monkeypatch: pytest.MonkeyPatch, *, manager_ok: bool = True, bad_snapshot: bool = False):
    events: list[str] = []
    socket = _Socket(events)
    ops = _Ops(events, bad_snapshot=bad_snapshot)
    fixed = m.OciLauncherDomain.for_node("node01")

    def connect(path: str):
        assert path == "/run/som/manager.sock"
        events.append("connect-root")
        return socket

    def manager_move(sock, *, manager_peer_policy, expected_source_cgroup):
        assert sock is socket and not sock.closed
        assert (manager_peer_policy.expected_uid, manager_peer_policy.expected_gid) == (2204, 3204)
        assert expected_source_cgroup == "/som-mode-a/node01/host-agent-source"
        events.append("manager-ACK" if manager_ok else "manager-DENY")
        if not manager_ok:
            raise m.OciAdmissionRefused("manager denied")

    monkeypatch.setattr(m, "request_fixed_source_move", manager_move)
    try:
        env = m.admit_oci_source_before_application(
            argv=(),
            env=_env(),
            domain=fixed,
            ops=ops,
            connect_manager=connect,
        )
    except m.OciAdmissionRefused:
        env = None
    return env, events, socket


def test_manager_ack_root_fd_closed_before_first_privilege_drop(monkeypatch) -> None:
    env, events, socket = _run(monkeypatch)
    assert socket.closed
    assert env is not None
    assert env == m.sanitized_oci_environment(_env())
    assert "UNTRUSTED_INJECTION" not in env
    assert events[:3] == ["connect-root", "manager-ACK", "close-root-fd"]
    assert events[3:9] == [
        "keepcaps:1",
        "groups:(3299,)",
        "gid:3202",
        "uid:2202",
        f"caps:{m.TRUSTED_AGENT_CAP_MASK}",
        "ambient-clear",
    ]
    assert events[-2:] == ["keepcaps:0", "snapshot"]


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("SSH_ORIGINAL_COMMAND", "sh"),
        ("SUDO_USER", "root"),
        ("SUDO_UID", "2202"),
        ("SUDO_GID", "3202"),
        ("SSH_TTY", "/dev/pts/1"),
    ],
)
def test_wrong_oci_origin_refused_before_connect(field, replacement) -> None:
    env = _env()
    env[field] = replacement
    with pytest.raises(m.OciAdmissionRefused):
        m.admit_oci_source_before_application(
            argv=(),
            env=env,
            domain=m.OciLauncherDomain.for_node("node01"),
            ops=_Ops([]),
            connect_manager=lambda _: pytest.fail("no connection allowed"),
        )


def test_argv_refused_before_connect() -> None:
    with pytest.raises(m.OciAdmissionRefused):
        m.admit_oci_source_before_application(
            argv=("--host", "node02"),
            env=_env(),
            domain=m.OciLauncherDomain.for_node("node01"),
            ops=_Ops([]),
            connect_manager=lambda _: pytest.fail("no connection allowed"),
        )


def test_manager_denied_no_privilege_drop_or_application(monkeypatch) -> None:
    env, events, socket = _run(monkeypatch, manager_ok=False)
    assert env is None
    assert socket.closed
    assert events == ["connect-root", "manager-DENY", "close-root-fd"]


def test_bad_post_drop_saved_uid_refused(monkeypatch) -> None:
    env, events, socket = _run(monkeypatch, bad_snapshot=True)
    assert env is None
    assert socket.closed
    assert events[-1] == "snapshot"


def test_reject_untrusted_node_selection() -> None:
    for value in ("node03", "../node01", "node01/../../node02", "", "node01\n", 1):
        with pytest.raises((ValueError, TypeError)):
            m.OciLauncherDomain.for_node(value)


def test_nonroot_launcher_refused_without_manager_call(monkeypatch) -> None:
    ops = _Ops([])
    monkeypatch.setattr(ops, "effective_uid", lambda: 2201)
    with pytest.raises(m.OciAdmissionRefused):
        m.admit_oci_source_before_application(
            argv=(),
            env=_env(),
            domain=m.OciLauncherDomain.for_node("node01"),
            ops=ops,
            connect_manager=lambda _: pytest.fail("no connection allowed"),
        )


def test_connect_error_refuses_before_drop() -> None:
    events: list[str] = []

    def unavailable(_path):
        events.append("connect")
        raise OSError("private manager absent")

    with pytest.raises(m.OciAdmissionRefused, match="manager handoff refused"):
        m.admit_oci_source_before_application(
            argv=(),
            env=_env(),
            domain=m.OciLauncherDomain.for_node("node02"),
            ops=_Ops(events),
            connect_manager=unavailable,
        )
    assert events == ["connect"]


def test_root_manager_fd_close_error_blocks_uid_transition(monkeypatch) -> None:
    events: list[str] = []

    class BadClose(_Socket):
        def close(self) -> None:
            super().close()
            raise OSError("fd close uncertain")

    def ok(_stream, *, manager_peer_policy, expected_source_cgroup):
        assert manager_peer_policy.expected_uid == 2204
        assert expected_source_cgroup.endswith("/node02/host-agent-source")
        events.append("manager-ACK")

    monkeypatch.setattr(m, "request_fixed_source_move", ok)
    with pytest.raises(m.OciAdmissionRefused, match="close root-phase"):
        m.admit_oci_source_before_application(
            argv=(),
            env=_env(),
            domain=m.OciLauncherDomain.for_node("node02"),
            ops=_Ops(events),
            connect_manager=lambda _path: BadClose(events),
        )
    assert events == ["manager-ACK", "close-root-fd"]


def test_forged_trusted_domain_cannot_select_another_cgroup() -> None:
    with pytest.raises(m.OciAdmissionRefused, match="untrusted OCI source domain"):
        m.admit_oci_source_before_application(
            argv=(),
            env=_env(),
            domain=m.OciLauncherDomain("node01", "/som-mode-a/node02/host-agent-source"),
            ops=_Ops([]),
            connect_manager=lambda _path: pytest.fail("no socket"),
        )
