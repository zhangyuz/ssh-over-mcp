"""Optional real, unprivileged OpenSSH-to-Host-Agent FS smoke on Linux.

Never accesses host Docker/VM, sudo, cgroups, network beyond 127.0.0.1, or
persistent credentials. This is NOT a hardened OCI/Mode A acceptance test.
"""

from __future__ import annotations

import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path

import pytest

from ssh_over_mcp.ssh.protocol import (
    FsMkdirEnvelope,
    FsReadEnvelope,
    FsStatEnvelope,
    FsWriteEnvelope,
    encode_request,
)

ROOT = Path(__file__).resolve().parents[2]
REVIEW = ROOT / "deploy/ssh-target/sshd_config.fs-only-review-candidate"

_AGENT = """import os
import sys
from pathlib import Path
from ssh_over_mcp.host_agent.cli import run
from ssh_over_mcp.host_agent.policy import HostFilesystemProfilePolicy, load_host_policy

if os.environ.get("SSH_ORIGINAL_COMMAND") != "mcp-v1" or os.environ.get("SSH_TTY"):
    raise SystemExit(78)
if os.geteuid() != {uid} or os.getegid() != {gid}:
    raise SystemExit(78)
if sys.platform != "linux" or "NoNewPrivs:\\t1" not in Path("/proc/self/status").read_text():
    raise SystemExit(78)
policy = load_host_policy(Path({policy!r}), require_root_owner=False)
policy = policy.model_copy(update={{"filesystem": {{"rw-operator": HostFilesystemProfilePolicy(
    stat_roots=({data!r},), read_roots=({data!r},),
    mkdir_roots=({data!r},), write_create_roots=({data!r},),
    max_read_bytes=4096, max_write_bytes=4096
)}}}})
raise SystemExit(run(env={{"SSH_ORIGINAL_COMMAND": "mcp-v1"}},
    stdin=sys.stdin.buffer, stdout=sys.stdout.buffer, stderr=sys.stderr,
    execution_stderr=sys.stderr.buffer, policy=policy))
"""


def _keygen(path: Path) -> None:
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)],
        check=True,
        capture_output=True,
        timeout=10,
    )
    path.chmod(0o600)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _one_node(node: Path, user: str, uid: int, gid: int):
    node.mkdir(mode=0o700)
    data = node / "data"
    data.mkdir(mode=0o700)
    hostkey, client = node / "hostkey", node / "client"
    _keygen(hostkey)
    _keygen(client)
    (node / "authorized_keys").write_text(client.with_suffix(".pub").read_text())
    (node / "authorized_keys").chmod(0o600)
    (data / "existing.bin").write_bytes(node.name.encode() + b"\\x00")

    agent = node / "agent.py"
    policy = ROOT / "deploy/ssh-target/host-policy.review-candidate.yaml"
    agent.write_text(_AGENT.format(uid=uid, gid=gid, data=str(data), policy=str(policy)))
    agent.chmod(0o500)
    port = _free_port()
    (node / "known_hosts").write_text(
        f"[127.0.0.1]:{port} {hostkey.with_suffix('.pub').read_text().strip()}\\n"
    )
    config = REVIEW.read_text()
    replacements = {
        "Port 2222": f"Port {port}\\nListenAddress 127.0.0.1",
        "/etc/ssh/hostkeys/ssh_host_ed25519_key": str(hostkey),
        "/etc/ssh/authorized_keys/%u": str(node / "authorized_keys"),
        "ssh-over-mcp-e2e-host": user,
        "/usr/bin/python3 -I -S /usr/local/libexec/ssh-over-mcp-fs-only-launcher.py": f"{sys.executable} {agent}",
    }
    for original, replacement in replacements.items():
        assert config.count(original) == 1
        config = config.replace(original, replacement)
    config += f"\\nPidFile {node / 'sshd.pid'}\\n"
    conf = node / "sshd.conf"
    conf.write_text(config)
    verify = subprocess.run(
        ["/usr/sbin/sshd", "-G", "-f", str(conf)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert verify.returncode == 0, verify.stderr
    return conf, client, port, data, node / "known_hosts"


def _rpc(
    client: Path, known_hosts: Path, port: int, user: str, envelope, body=b"", command="mcp-v1"
):
    return subprocess.run(
        [
            "ssh",
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "CheckHostIP=no",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ConnectTimeout=3",
            "-o",
            "ConnectionAttempts=1",
            "-i",
            str(client),
            "-p",
            str(port),
            f"{user}@127.0.0.1",
            command,
        ],
        input=encode_request(envelope, body),
        capture_output=True,
        check=False,
        timeout=18,
    )


def test_rootless_openssh_template_and_typed_agent_fixture_are_closed():
    import ast

    source = REVIEW.read_text()
    assert "Port 2222" in source.splitlines()
    assert "AuthenticationMethods publickey" in source
    assert "DisableForwarding yes" in source
    assert "PermitTTY no" in source
    assert "StrictModes yes" in source
    assert "UsePAM no" in source
    assert "UsePrivilegeSeparation no" not in source
    assert "/usr/bin/sudo" not in source
    ast.parse(_AGENT.format(uid=2201, gid=3201, policy="/tmp/p", data="/tmp/d"))


@pytest.mark.skipif(sys.platform != "linux", reason="requires real Linux OpenSSH")
def test_two_real_rootless_openssh_sessions_fs_create_read_and_isolation(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("must run as an unprivileged CI identity")
    if not all(shutil.which(x) for x in ("ssh", "ssh-keygen", "setpriv")):
        pytest.skip("requires OpenSSH client and setpriv")
    if not Path("/usr/sbin/sshd").is_file():
        pytest.skip("OpenSSH server not preinstalled; do not install as CI root")

    identity = pwd.getpwuid(os.getuid())
    assert identity.pw_shell.startswith("/")
    user, uid, gid = identity.pw_name, os.getuid(), os.getgid()
    with ExitStack() as stack:
        nodes = []
        for alias in ("node01", "node02"):
            conf, key, port, data, known = _one_node(tmp_path / alias, user, uid, gid)
            proc = subprocess.Popen(
                ["setpriv", "--no-new-privs", "/usr/sbin/sshd", "-D", "-e", "-f", str(conf)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            stack.callback(
                lambda p=proc: (p.terminate(), p.wait(timeout=4)) if p.poll() is None else None
            )
            ready = False
            for _ in range(40):
                if proc.poll() is not None:
                    break
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        ready = True
                        break
                except OSError:
                    time.sleep(0.1)
            assert ready, "unprivileged OpenSSH did not accept loopback connections"
            nodes.append((key, known, port, data))

        for i, (key, known, port, data) in enumerate(nodes):
            directory = data / "mvp"
            file = directory / "probe.bin"
            payload = f"node-{i}-ssh".encode() + b"\\x00"
            base = f"rootless_node_{i}"

            def call(envelope, body=b"", key=key, known=known, port=port):
                return _rpc(key, known, port, user, envelope, body)

            mkdir = call(
                FsMkdirEnvelope(
                    request_id=base + "_mkdir", profile="rw-operator", path=str(directory)
                )
            )
            assert mkdir.returncode == 0, mkdir.stderr[-450:]
            write = call(
                FsWriteEnvelope(
                    request_id=base + "_write",
                    profile="rw-operator",
                    path=str(file),
                    content_length=len(payload),
                ),
                payload,
            )
            assert write.returncode == 0, write.stderr[-450:]
            stat = call(
                FsStatEnvelope(request_id=base + "_stat", profile="rw-operator", path=str(file))
            )
            assert stat.returncode == 0 and json.loads(stat.stdout)["size"] == len(payload), (
                stat.stderr[-450:]
            )
            read = call(
                FsReadEnvelope(
                    request_id=base + "_read", profile="rw-operator", path=str(file), max_bytes=4096
                )
            )
            assert read.returncode == 0 and read.stdout == payload, read.stderr[-450:]
            repeat = call(
                FsWriteEnvelope(
                    request_id=base + "_repeat",
                    profile="rw-operator",
                    path=str(file),
                    content_length=4,
                ),
                b"evil",
            )
            assert repeat.returncode != 0 and file.read_bytes() == payload
            foreign = nodes[1 - i][3] / "mvp" / "probe.bin"
            cross = call(
                FsReadEnvelope(
                    request_id=base + "_cross",
                    profile="rw-operator",
                    path=str(foreign),
                    max_bytes=4096,
                )
            )
            assert cross.returncode != 0
            bad = _rpc(
                key,
                known,
                port,
                user,
                FsStatEnvelope(request_id=base + "_badcmd", profile="rw-operator", path=str(file)),
                command="unexpected-command",
            )
            assert bad.returncode != 0
            other_known = nodes[1 - i][1]
            wrong_host = _rpc(
                key,
                other_known,
                port,
                user,
                FsStatEnvelope(
                    request_id=base + "_wronghost", profile="rw-operator", path=str(file)
                ),
            )
            assert wrong_host.returncode != 0
