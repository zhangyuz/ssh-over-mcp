"""Real fixed-path OCI launcher entry; all privileged syscalls mocked.

No Docker/VM, root, host cgroup or credential changes in this test.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ENTRY = ROOT / "ops/mvp/ssh-over-mcp-oci-launcher.py"


def _load():
    spec = importlib.util.spec_from_file_location("som_oci_launcher_entry_test", ENTRY)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_candidate_image_uses_exact_oci_launcher_not_managed_launcher() -> None:
    image = (ROOT / "deploy/ssh-target/Dockerfile.review-candidate").read_text()
    ssh = (ROOT / "deploy/ssh-target/sshd_config.review-candidate").read_text()
    sudo = (ROOT / "deploy/ssh-target/sudoers.review-candidate").read_text()
    expected = "/usr/local/libexec/ssh-over-mcp-oci-launcher.py"
    assert f"COPY ops/mvp/ssh-over-mcp-oci-launcher.py {expected}" in image
    assert "COPY deploy/ssh-target/sshd_config.review-candidate" in image
    assert "COPY deploy/ssh-target/sudoers.review-candidate" in image
    assert f"ForceCommand /usr/bin/sudo -n /usr/bin/python3 -I -S {expected}" in ssh
    assert f"NOPASSWD: /usr/bin/python3 -I -S {expected}" in sudo
    assert "ssh-over-mcp-host-agent-launcher.py" not in image
    assert "ssh-over-mcp-host-agent-launcher.py" not in ssh
    assert "ssh-over-mcp-host-agent-launcher.py" not in sudo
    assert 'env_keep += "SSH_ORIGINAL_COMMAND"' in sudo
    assert 'ENTRYPOINT ["/usr/local/libexec/ssh-over-mcp-image-hold"]' in image
    assert "exit 78" in (ROOT / "deploy/ssh-target/entrypoint.review-hold").read_text()


def test_node_identity_is_exact_root_owned_regular_file(tmp_path: Path) -> None:
    # root ownership/parent immutability needs Linux image; pure content
    # parser is tested on macOS and Linux.
    module = _load()
    assert module.parse_node_id(b"node01\n") == "node01"
    assert module.parse_node_id(b"node02\n") == "node02"
    for raw in (
        b"node01",
        b"node03\n",
        b"node01\nnode02\n",
        b"node01\x00\n",
        b"../node02\n",
        b"node01\r\n",
        b"",
    ):
        with pytest.raises(module.OciLauncherFailure):
            module.parse_node_id(raw)


def test_entrypoint_only_imports_application_after_manager_ack_and_uid_drop(monkeypatch) -> None:
    module = _load()
    calls: list[str] = []

    class FakeOps:
        def effective_uid(self):
            return 0

        def set_keepcaps(self, flag):
            calls.append(f"keep:{flag}")

        def set_groups(self, value):
            calls.append("groups")

        def set_res_gid(self, value):
            calls.append("gid")

        def set_res_uid(self, value):
            calls.append("uid")

        def set_capabilities(self, mask):
            calls.append("caps")

        def clear_ambient_capabilities(self):
            calls.append("ambient")

        def snapshot(self):
            from ssh_over_mcp.host_agent.oci_launcher_admission import (
                TRUSTED_AGENT_CAP_MASK,
                OciAdmissionSnapshot,
            )

            calls.append("snapshot")
            return OciAdmissionSnapshot(
                2202,
                2202,
                2202,
                3202,
                3202,
                3202,
                (3299,),
                0,
                TRUSTED_AGENT_CAP_MASK,
                TRUSTED_AGENT_CAP_MASK,
                0,
            )

    class Sock:
        def close(self):
            calls.append("close-root-sock")

    def manager_move(_sock, **_):
        calls.append("ACK")

    from ssh_over_mcp.host_agent import oci_launcher_admission as admission

    monkeypatch.setattr(admission, "request_fixed_source_move", manager_move)

    def application():
        assert calls[:2] == ["ACK", "close-root-sock"]
        assert calls.index("uid") < calls.index("snapshot")
        calls.append("application")
        return 0

    original_env = os.environ.copy()
    try:
        assert (
            module.run(
                argv=(),
                env={
                    "SSH_ORIGINAL_COMMAND": "mcp-v1",
                    "SUDO_USER": "ssh-over-mcp-e2e-host",
                    "SUDO_UID": "2201",
                    "SUDO_GID": "3201",
                },
                node_loader=lambda: "node01",
                ops_factory=lambda: FakeOps(),
                connector=lambda _: Sock(),
                application=application,
            )
            == 0
        )
    finally:
        os.environ.clear()
        os.environ.update(original_env)
    assert calls[-1] == "application"


@pytest.mark.parametrize("case", ["bad-command", "bad-node", "bad-manager", "bad-argv"])
def test_entrypoint_fails_closed_without_importing_application(monkeypatch, case):
    module = _load()
    env = {
        "SSH_ORIGINAL_COMMAND": "mcp-v1",
        "SUDO_USER": "ssh-over-mcp-e2e-host",
        "SUDO_UID": "2201",
        "SUDO_GID": "3201",
    }
    if case == "bad-command":
        env["SSH_ORIGINAL_COMMAND"] = "sh"

    def refuse_manager(_):
        raise OSError("manager unavailable")

    node = "node03" if case == "bad-node" else "node01"
    with pytest.raises(module.OciLauncherFailure):
        module.run(
            argv=("--run",) if case == "bad-argv" else (),
            env=env,
            node_loader=lambda: node,
            ops_factory=lambda: (
                pytest.fail("must not construct privileged ops before gate")
                if case in ("bad-command", "bad-node", "bad-argv")
                else type("Ops", (), {"effective_uid": lambda self: 0})()
            ),
            connector=refuse_manager,
            application=lambda: pytest.fail("application must not run"),
        )


def test_pre_drop_bytecode_cache_is_refused(tmp_path: Path, monkeypatch) -> None:
    module = _load()
    src = tmp_path / "src"
    (src / "ssh_over_mcp" / "host_agent").mkdir(parents=True)
    monkeypatch.setattr(module, "SOURCE_PATH", str(src))
    module._refuse_source_bytecode()
    (src / "ssh_over_mcp" / "__pycache__").mkdir()
    with pytest.raises(module.OciLauncherFailure, match="bytecode"):
        module._refuse_source_bytecode()
    (src / "ssh_over_mcp" / "__pycache__").rmdir()
    (src / "ssh_over_mcp" / "host_agent" / "injected.pyc").write_bytes(b"evil")
    with pytest.raises(module.OciLauncherFailure, match="bytecode"):
        module._refuse_source_bytecode()


def test_node_id_file_path_constant_and_no_untrusted_cli_selector() -> None:
    module = _load()
    assert module.NODE_ID_PATH == "/etc/ssh-over-mcp/node-id"
    assert module.SOURCE_PATH == "/opt/ssh-over-mcp-e2e/workspace/src"
    assert "DOCKER_HOST" not in ENTRY.read_text()
