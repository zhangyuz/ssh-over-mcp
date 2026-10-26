"""Source-only OCI manager entry + fixed UDS service tests.

All AF_UNIX, cgroup and privilege transitions are mocked; these do not
authorize Linux guest bootstrap, image admission or Docker start.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from ssh_over_mcp.host_agent import oci_manager_runtime as m
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
    assert "sys.path.insert(1, SITE_PACKAGES)" in source
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
