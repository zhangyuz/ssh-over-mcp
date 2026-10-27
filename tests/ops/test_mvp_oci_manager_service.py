"""Source-only OCI manager entry + fixed UDS service tests.

All AF_UNIX, cgroup and privilege transitions are mocked; these do not
authorize Linux guest bootstrap, image admission or Docker start.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent import oci_manager_runtime as m
from ssh_over_mcp.host_agent.containment_manager_peer import LinuxPeerCredentials
from ssh_over_mcp.host_agent.oci_namespace_identity import IdMapEntry
from ssh_over_mcp.host_agent.oci_pidfd_handoff import OciPidfdHandoffRefused

ROOT = Path(__file__).resolve().parents[2]
ENTRY = ROOT / "ops/mvp/ssh-over-mcp-oci-manager.py"


class _Socket:
    def __init__(self, events):
        self.events = events

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.events.append("close-peer")


class _Listener:
    def __init__(self, events):
        self.events = events

    def __enter__(self):
        self.events.append("listen")
        return self

    def __exit__(self, *_args):
        self.events.append("close-listener")

    @property
    def fileno(self):
        return 3

    def accept(self):
        self.events.append("accept")
        return _Socket(self.events)


def _run(node="node01", *, requests=1, fail=False):
    events = []
    times = 0

    def identity(policy):
        assert (policy.identity.uid, policy.identity.gid) == (2204, 3204)
        assert policy.supplementary_gids == frozenset({3299})
        events.append("verify-identity")

    def listener_factory(policy):
        assert str(policy.path) == "/run/som/manager.sock"
        assert (policy.socket_uid, policy.socket_gid, policy.socket_mode) == (2204, 3299, 0o660)
        assert (policy.directory_uid, policy.directory_gid) == (2204, 3299)
        events.append("build-listener")
        return _Listener(events)

    def stop():
        return times >= requests

    def ready(_fd):
        return True

    def move(_sock, *, trusted_node, domain, peer_policy):
        nonlocal times
        assert trusted_node == node
        assert domain.delegated_root == f"/som-mode-a/{node}"
        assert domain.admission_cgroup.endswith(f"{node}/admission")
        assert domain.agent_source_cgroup.endswith(f"{node}/host-agent-source")
        assert (peer_policy.expected_uid, peer_policy.expected_gid) == (0, 0)
        events.append("move-or-refuse")
        times += 1
        if fail:
            raise OciPidfdHandoffRefused("guest kernel rejected")

    return events, identity, listener_factory, stop, ready, move


def test_manager_exposes_real_fixed_source_handler(monkeypatch):
    for node in ("node01", "node02"):
        e, ident, listener, stop, ready, move = _run(node, requests=2)
        monkeypatch.setattr(m, "serve_fixed_node_source_once", move)
        assert (
            m.serve_oci_source_manager(
                trusted_node=node,
                stop_requested=stop,
                identity_check=ident,
                listener_factory=listener,
                ready_to_accept=ready,
                peer_reader=lambda _sock: LinuxPeerCredentials(77, 0, 0),
            )
            == 2
        )
        assert e == [
            "verify-identity",
            "build-listener",
            "listen",
            "accept",
            "move-or-refuse",
            "close-peer",
            "accept",
            "move-or-refuse",
            "close-peer",
            "close-listener",
        ]


def test_failed_pidfd_move_exits_server_with_no_retry(monkeypatch):
    e, ident, listener, stop, ready, move = _run(fail=True)
    monkeypatch.setattr(m, "serve_fixed_node_source_once", move)
    with pytest.raises(m.OciManagerRuntimeRefused, match="inspect before restart"):
        m.serve_oci_source_manager(
            trusted_node="node01",
            stop_requested=stop,
            identity_check=ident,
            listener_factory=listener,
            ready_to_accept=ready,
            peer_reader=lambda _sock: LinuxPeerCredentials(77, 0, 0),
        )
    assert e.count("move-or-refuse") == 1
    assert e[-2:] == ["close-peer", "close-listener"]


@pytest.mark.parametrize("bad_node", ["node03", "", "../node01", "node01/../../node02"])
def test_untrusted_node_refused_before_creating_endpoint(bad_node):
    with pytest.raises(m.OciManagerRuntimeRefused):
        m.serve_oci_source_manager(
            trusted_node=bad_node,
            stop_requested=lambda: False,
            identity_check=lambda _policy: pytest.fail("identity checked"),
            listener_factory=lambda _policy: pytest.fail("untrusted socket"),
        )


def test_identity_failure_refuses_before_binding_endpoint():
    with pytest.raises(RuntimeError):
        m.serve_oci_source_manager(
            trusted_node="node01",
            stop_requested=lambda: False,
            identity_check=lambda _policy: (_ for _ in ()).throw(
                RuntimeError("wrong namespace identity")
            ),
            listener_factory=lambda _: pytest.fail("listener never binds"),
        )


def _load():
    spec = importlib.util.spec_from_file_location("som_oci_manager_test", ENTRY)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_entrypoint_rejects_user_arguments_before_touching_kernel(monkeypatch):
    entry = _load()
    monkeypatch.setattr(entry, "_kernel_unprivileged", lambda: pytest.fail("kernel check"))
    with pytest.raises(entry.OciManagerStartRefused, match="argv"):
        entry.main(argv=("--node", "node02"))


def test_manager_node_file_contents_cannot_be_client_selection(tmp_path, monkeypatch):
    entry = _load()
    node_file = tmp_path / "node-id"
    monkeypatch.setattr(entry, "NODE_ID_PATH", str(node_file))
    monkeypatch.setattr(entry, "_trusted_file", lambda _: None)
    from types import SimpleNamespace

    monkeypatch.setattr(
        entry.os,
        "fstat",
        lambda _fd: SimpleNamespace(st_uid=0, st_mode=node_file.stat().st_mode, st_nlink=1),
    )
    for raw, allowed in [
        (b"node01\n", True),
        (b"node02\n", True),
        (b"node03\n", False),
        (b"node01\nnode02\n", False),
        (b"node01\x00\n", False),
    ]:
        node_file.write_bytes(raw)
        if allowed:
            assert entry._node_id() == raw.decode().strip()
        else:
            with pytest.raises(entry.OciManagerStartRefused):
                entry._node_id()


@pytest.mark.parametrize(
    "nnp,bounding,accepted",
    [
        ("1", "0000000000000000", True),
        ("0", "0000000000000000", False),
        ("1", "0000000000000400", False),
    ],
)
def test_manager_kernel_nnp_and_zero_caps_proven_from_procfs(monkeypatch, nnp, bounding, accepted):
    import builtins
    import io

    entry = _load()
    monkeypatch.setattr(entry.sys, "platform", "linux")
    monkeypatch.setattr(entry.os, "geteuid", lambda: 2204)
    real_open = builtins.open
    raw = (
        f"NoNewPrivs:\t{nnp}\n"
        "CapInh:\t0000000000000000\n"
        "CapPrm:\t0000000000000000\n"
        "CapEff:\t0000000000000000\n"
        f"CapBnd:\t{bounding}\n"
        "CapAmb:\t0000000000000000\n"
    )

    def fake_open(name, *args, **kwargs):
        if name == "/proc/self/status":
            return io.StringIO(raw)
        return real_open(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)
    if accepted:
        entry._kernel_unprivileged()
    else:
        with pytest.raises(entry.OciManagerStartRefused):
            entry._kernel_unprivileged()
    source = ENTRY.read_text()
    assert "sys.path.insert(0, SOURCE_PATH)" in source
    assert "sys.path.insert(1, SITE_PACKAGES)" not in source
    assert "docker.sock" not in source


def test_manager_rejects_untrusted_bytecode_before_import(tmp_path, monkeypatch):
    entry = _load()
    target = tmp_path / "src"
    (target / "ssh_over_mcp" / "host_agent").mkdir(parents=True)
    monkeypatch.setattr(entry, "SOURCE_PATH", str(target))
    entry._refuse_source_bytecode()
    (target / "ssh_over_mcp" / "__pycache__").mkdir()
    with pytest.raises(entry.OciManagerStartRefused, match="bytecode"):
        entry._refuse_source_bytecode()
    (target / "ssh_over_mcp" / "__pycache__").rmdir()
    (target / "ssh_over_mcp" / "host_agent" / "hidden.pyc").write_bytes(b"unknown")
    with pytest.raises(entry.OciManagerStartRefused, match="bytecode"):
        entry._refuse_source_bytecode()


def test_manager_guest_entry_is_not_wired_into_ssh_candidate() -> None:
    docker = (ROOT / "deploy/ssh-target/Dockerfile.review-candidate").read_text()
    assert "ssh-over-mcp-oci-manager.py" not in docker
    assert 'ENTRYPOINT ["/usr/local/libexec/ssh-over-mcp-image-hold"]' in docker
    assert (
        "Dockerfile.review-candidate"
        not in (ROOT / "deploy/compose/compose.dev-ssh.yaml").read_text()
    )


def _one_child_service(
    monkeypatch, *, node="node01", identity=(2202, 3202), maps=True, reject=False
):
    events: list[str] = []
    calls = 0
    e, ident, listener, _stop, _ready, _move = _run(node, requests=1)

    def child(_sock, *, peer_policy, policy, trusted_attach):
        nonlocal calls
        calls += 1
        assert (peer_policy.expected_uid, peer_policy.expected_gid) == (2202, 3202)
        assert policy.target_cgroup == f"/som-mode-a/{node}/workload/mvp"
        assert policy.expected_child_uid_map == (IdMapEntry(0, 100000, 65536),)
        assert policy.expected_child_gid_map == (IdMapEntry(0, 100000, 65536),)
        if reject:
            raise OciPidfdHandoffRefused("attach refused")
        events.append("child-ACK")

    monkeypatch.setattr(m, "handle_fixed_child_attach", child)
    kw = {
        "trusted_node": node,
        "stop_requested": lambda: calls >= 1,
        "identity_check": ident,
        "listener_factory": listener,
        "ready_to_accept": lambda _fd: True,
        "peer_reader": lambda _sock: LinuxPeerCredentials(77, *identity),
    }
    if maps:
        kw.update(
            expected_child_uid_map=(IdMapEntry(0, 100000, 65536),),
            expected_child_gid_map=(IdMapEntry(0, 100000, 65536),),
        )
    return kw, e, events, lambda: calls


def test_postdrop_agent_routes_only_to_fixed_mvp_child_handler(monkeypatch):
    for node in ("node01", "node02"):
        kw, actions, child_actions, calls = _one_child_service(monkeypatch, node=node)
        assert m.serve_oci_source_manager(**kw) == 1
        assert calls() == 1
        assert child_actions == ["child-ACK"]
        assert actions[-2:] == ["close-peer", "close-listener"]


def test_child_attach_disabled_without_trusted_maps_is_fatal(monkeypatch):
    kw, actions, child_actions, calls = _one_child_service(monkeypatch, maps=False)
    with pytest.raises(m.OciManagerRuntimeRefused):
        m.serve_oci_source_manager(**kw)
    assert calls() == 0 and not child_actions
    assert actions[-2:] == ["close-peer", "close-listener"]


def test_wrong_agent_peer_refused_even_when_trusted_maps_present(monkeypatch):
    kw, actions, child_actions, calls = _one_child_service(monkeypatch, identity=(2202, 0))
    with pytest.raises(m.OciManagerRuntimeRefused):
        m.serve_oci_source_manager(**kw)
    assert calls() == 0 and not child_actions
    assert actions[-2:] == ["close-peer", "close-listener"]


def test_child_attach_failure_terminates_manager_without_retry(monkeypatch):
    kw, actions, _child_actions, calls = _one_child_service(monkeypatch, reject=True)
    with pytest.raises(m.OciManagerRuntimeRefused, match="inspect before restart"):
        m.serve_oci_source_manager(**kw)
    assert calls() == 1
    assert actions[-2:] == ["close-peer", "close-listener"]


def test_partial_child_userns_map_provision_refused_before_socket():
    _e, ident, _listener, _stop, ready, _move = _run()
    with pytest.raises(m.OciManagerRuntimeRefused, match="both trusted"):
        m.serve_oci_source_manager(
            trusted_node="node01",
            stop_requested=lambda: False,
            identity_check=ident,
            listener_factory=lambda _: pytest.fail("no listener"),
            ready_to_accept=ready,
            expected_child_uid_map=(IdMapEntry(0, 100000, 65536),),
        )


def test_second_child_attach_is_refused_and_scope_not_reused(monkeypatch):
    actions, identity, factory, _stop, _ready, _move = _run(requests=2)
    connections = []
    attached = []

    def read_peer(_sock):
        connections.append("agent")
        return LinuxPeerCredentials(77, 2202, 3202)

    def child(_sock, **kwargs):
        attached.append(kwargs["policy"].target_cgroup)

    monkeypatch.setattr(m, "handle_fixed_child_attach", child)
    with pytest.raises(m.OciManagerRuntimeRefused):
        m.serve_oci_source_manager(
            trusted_node="node01",
            stop_requested=lambda: len(connections) >= 3,
            identity_check=identity,
            listener_factory=factory,
            ready_to_accept=lambda _fd: True,
            peer_reader=read_peer,
            expected_child_uid_map=(IdMapEntry(0, 100000, 65536),),
            expected_child_gid_map=(IdMapEntry(0, 100000, 65536),),
        )
    assert len(connections) == 2
    assert attached == ["/som-mode-a/node01/workload/mvp"]
    assert actions[-2:] == ["close-peer", "close-listener"]


def test_root_owned_guest_namespace_maps_feed_actual_manager_service(monkeypatch):
    import signal

    entry = _load()
    monkeypatch.setattr(entry, "_kernel_unprivileged", lambda: None)
    checked = []
    monkeypatch.setattr(entry, "_trusted_file", lambda path: checked.append(path))
    monkeypatch.setattr(entry, "_node_id", lambda: "node01")
    monkeypatch.setattr(entry, "_refuse_source_bytecode", lambda: None)
    monkeypatch.setattr(
        entry,
        "_root_owned_map_bytes",
        lambda path: b"0 100000 65536\n",
    )
    monkeypatch.setattr(signal, "signal", lambda *_args: None)
    recorded = []

    def fake_service(**kwargs):
        recorded.append(kwargs)

    monkeypatch.setattr(m, "serve_oci_source_manager", fake_service)
    old_path = list(entry.sys.path)
    old_bytecode = entry.sys.dont_write_bytecode
    try:
        assert entry.main(argv=()) == 0
    finally:
        entry.sys.path[:] = old_path
        entry.sys.dont_write_bytecode = old_bytecode

    assert len(recorded) == 1
    assert recorded[0]["trusted_node"] == "node01"
    assert recorded[0]["expected_child_uid_map"] == (IdMapEntry(0, 100000, 65536),)
    assert recorded[0]["expected_child_gid_map"] == (IdMapEntry(0, 100000, 65536),)
    assert any(path.endswith("/oci_child_writer.py") for path in checked)
    assert any(path.endswith("/oci_child_attach.py") for path in checked)


@pytest.mark.parametrize("raw", [b"", b"x" * 4097])
def test_guest_map_file_empty_or_oversized_refused(tmp_path, monkeypatch, raw):
    from types import SimpleNamespace

    entry = _load()
    path = tmp_path / "child-map"
    path.write_bytes(raw)
    monkeypatch.setattr(entry, "CHILD_UID_MAP_PATH", str(path))
    monkeypatch.setattr(entry, "_trusted_file", lambda _path: None)
    monkeypatch.setattr(
        entry.os,
        "fstat",
        lambda _fd: SimpleNamespace(st_uid=0, st_mode=path.stat().st_mode, st_nlink=1),
    )
    with pytest.raises(entry.OciManagerStartRefused):
        entry._root_owned_map_bytes(str(path))


def test_untrusted_guest_map_filename_rejected_before_open():
    entry = _load()
    with pytest.raises(entry.OciManagerStartRefused, match="path"):
        entry._root_owned_map_bytes("/tmp/attacker-influenced-map")


def test_agent_dispatch_calls_fixed_node_child_writer_no_client_destination(monkeypatch):
    kw, _actions, _child_actions, _calls = _one_child_service(monkeypatch, node="node02")
    invoked = []

    def child(_sock, *, policy, trusted_attach, **_kwargs):
        assert policy.target_cgroup == "/som-mode-a/node02/workload/mvp"
        trusted_attach("pinned-child")

    def writer(child, *, trusted_node):
        invoked.append((child, trusted_node))

    monkeypatch.setattr(m, "handle_fixed_child_attach", child)
    monkeypatch.setattr(m, "move_fixed_mvp_child", writer)
    observed = 0

    def read_peer(_sock):
        nonlocal observed
        observed += 1
        return LinuxPeerCredentials(77, 2202, 3202)

    kw["peer_reader"] = read_peer
    kw["stop_requested"] = lambda: observed >= 1
    assert m.serve_oci_source_manager(**kw) == 1
    assert invoked == [("pinned-child", "node02")]
