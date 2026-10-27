"""Test-only real OpenSSH FS/OCI admission on disposable GitHub-hosted Ubuntu.

No external container network, no host-published ports, no production keys,
no persistent host/VM state. NOT a private-userns or no-NIC VM acceptance.
"""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

IMAGE = "som-mvp-fs-privsep:local"
SSH_CAPS = ("SETUID", "SETGID", "SETPCAP", "SYS_CHROOT")


def run(args: list[str], *, stdin: bytes | None = None, timeout: int = 22, ok: bool = True):
    proc = subprocess.run(args, input=stdin, capture_output=True, timeout=timeout, check=False)
    if ok and proc.returncode:
        raise AssertionError(
            (args[0], proc.returncode, proc.stderr[-800:].decode(errors="replace"))
        )
    return proc


def frame(operation: str, ident: str, path: str, body: bytes = b"", **extra: object) -> bytes:
    envelope = dict(
        version=1, request_id=ident, profile="rw-operator", operation=operation, path=path, **extra
    )
    raw = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    return b"SMCP\x00\x01" + struct.pack(">I", len(raw)) + raw + body


def prepare(node: Path, name: str) -> tuple[Path, Path, Path]:
    keys = node / "hostkeys"
    auth = node / "authorized_keys"
    keys.mkdir(parents=True, mode=0o755)
    auth.mkdir(mode=0o755)
    keys.chmod(0o755)
    auth.chmod(0o755)
    host = keys / "ssh_host_ed25519_key"
    client = node / "client"
    for key in (host, client):
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
    authorized = auth / "ssh-over-mcp-e2e-host"
    authorized.write_bytes(client.with_suffix(".pub").read_bytes())
    authorized.chmod(0o644)
    # OpenSSH StrictModes checks *container* root ownership. Under Docker
    # userns-remap, container root maps to a subordinate, nonzero HOST uid.
    # CI alone supplies that exact mapped uid; no host daemon is modified.
    mapped_root = os.getenv("SOM342_REMAPPED_ROOT_UID")
    root_owner = (
        f"{int(mapped_root)}:{int(os.getenv('SOM342_REMAPPED_ROOT_GID', '0'))}"
        if mapped_root
        else "root:root"
    )
    if mapped_root:
        assert int(mapped_root) >= 65536
    run(["sudo", "-n", "chown", root_owner, str(keys), str(auth), str(authorized)])
    run(["sudo", "-n", "chown", root_owner, str(host)])
    run(["sudo", "-n", "chmod", "0600", str(host)])
    known = node / "known_hosts"
    known.write_text(f"[127.0.0.1]:2222 {host.with_suffix('.pub').read_text().strip()}\n")
    return host, client, known


def start_node(name: str, work: Path, running: list[str]) -> tuple[str, Path, Path]:
    _host, client, known = prepare(work, name)
    args = [
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        *[argument for cap in SSH_CAPS for argument in ("--cap-add", cap)],
        "--read-only",
        "--tmpfs",
        "/run:rw,noexec,nosuid,nodev,mode=0755,size=8m",
        "--tmpfs",
        "/run/sshd:rw,noexec,nosuid,nodev,mode=0755,size=2m",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,mode=1777,size=8m",
        "--tmpfs",
        "/srv/data:rw,noexec,nosuid,nodev,uid=2201,gid=3201,mode=0700,size=8m",
        "--mount",
        f"type=bind,src={work / 'hostkeys'},dst=/etc/ssh/hostkeys,readonly",
        "--mount",
        f"type=bind,src={work / 'authorized_keys'},dst=/etc/ssh/authorized_keys,readonly",
        "--entrypoint",
        "/usr/sbin/sshd",
        IMAGE,
        "-D",
        "-e",
    ]
    output = run(args, timeout=40).stdout.decode().strip()
    assert output and len(output) >= 12
    running.append(name)
    details = json.loads(run(["docker", "inspect", name]).stdout)[0]
    hostconfig = details["HostConfig"]
    assert hostconfig["NetworkMode"] == "none"
    if os.getenv("SOM342_REMAPPED_ROOT_UID"):
        security = json.loads(
            run(["docker", "info", "--format", "{{json .SecurityOptions}}"]).stdout
        )
        assert any("userns" in entry for entry in security)
        assert hostconfig["UsernsMode"] != "host"
    assert hostconfig["Privileged"] is False
    assert hostconfig["ReadonlyRootfs"] is True
    assert set(hostconfig["CapDrop"]) == {"ALL"}
    assert {c.removeprefix("CAP_") for c in hostconfig["CapAdd"]} == set(SSH_CAPS)
    assert not hostconfig["Binds"]
    assert all(not bindings for bindings in details["NetworkSettings"]["Ports"].values())
    # docker cp refuses a read-only OCI rootfs even for tmpfs destinations.
    # Use stdin to populate only the independently mounted /tmp tmpfs.
    for src, target, mode in ((client, "client", "0600"), (known, "known_hosts", "0644")):
        run(
            [
                "docker",
                "exec",
                "-i",
                "-u",
                "0:0",
                name,
                "/bin/sh",
                "-c",
                f"umask 077; cat > /tmp/{target}; chmod {mode} /tmp/{target}",
            ],
            stdin=src.read_bytes(),
        )
    for _ in range(40):
        state = json.loads(run(["docker", "inspect", name]).stdout)[0]["State"]
        if not state["Running"]:
            break
        probe = run(
            ["docker", "exec", "-u", "0:0", name, "/usr/sbin/sshd", "-t"], timeout=6, ok=False
        )
        if probe.returncode == 0:
            return name, client, known
        time.sleep(0.1)
    raise AssertionError(
        ("OCI sshd not admitted", name, run(["docker", "logs", name], ok=False).stderr[-600:])
    )


def call(name: str, envelope: bytes, command: str = "mcp-v1") -> subprocess.CompletedProcess[bytes]:
    args = [
        "docker",
        "exec",
        "-i",
        "-u",
        "0:0",
        name,
        "/usr/bin/ssh",
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
        "UserKnownHostsFile=/tmp/known_hosts",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "ConnectTimeout=3",
        "-o",
        "ConnectionAttempts=1",
        "-i",
        "/tmp/client",
        "-p",
        "2222",
        "ssh-over-mcp-e2e-host@127.0.0.1",
        command,
    ]
    return run(args, stdin=envelope, timeout=25, ok=False)


def check_node(name: str, index: int) -> None:
    base = f"/srv/data/mvp-node-{index}"
    dest = f"{base}/probe.bin"
    payload = f"oci-openssh-fs-node-{index}\x00".encode()
    token = f"oci_node_{index}_"
    mkdir = call(name, frame("fs_mkdir", token + "mkdir", base))
    assert mkdir.returncode == 0, ("mkdir", mkdir.returncode, mkdir.stderr[-450:])
    write = call(
        name, frame("fs_write", token + "write", dest, payload, content_length=len(payload))
    )
    assert write.returncode == 0, ("write", write.returncode, write.stderr[-450:])
    read = call(name, frame("fs_read", token + "read", dest, max_bytes=4096))
    assert read.returncode == 0 and read.stdout == payload, (
        "read",
        read.returncode,
        read.stderr[-450:],
    )
    stat = call(name, frame("fs_stat", token + "stat", dest))
    assert stat.returncode == 0 and json.loads(stat.stdout)["size"] == len(payload)
    overwrite = call(name, frame("fs_write", token + "overwrite", dest, b"evil", content_length=4))
    assert overwrite.returncode == 69, ("create-only negative", overwrite.returncode)
    deny = call(
        name,
        frame(
            "fs_read", token + "denied", "/etc/ssh/hostkeys/ssh_host_ed25519_key", max_bytes=4096
        ),
    )
    assert deny.returncode == 77, ("hostkey policy negative", deny.returncode)
    command = call(name, frame("fs_stat", token + "cmd", dest), command="not-mcp-v1")
    assert command.returncode != 0, "ForceCommand command validation did not refuse"
    logs = run(["docker", "logs", name], ok=False).stderr.decode(errors="replace")
    assert "Accepted publickey for ssh-over-mcp-e2e-host" in logs, logs[-750:]


def main() -> None:
    assert sys.platform == "linux" and os.geteuid() != 0
    assert os.getenv("GITHUB_ACTIONS") == "true"
    assert os.getenv("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.getenv("RUNNER_OS") == "Linux"
    assert os.getenv("RUNNER_TEMP")
    assert os.getenv("GITHUB_EVENT_NAME") == "pull_request"
    assert shutil.which("docker") and shutil.which("ssh-keygen")
    detail = json.loads(run(["docker", "image", "inspect", IMAGE]).stdout)[0]
    assert detail["Config"]["Entrypoint"] == ["/usr/local/libexec/ssh-over-mcp-image-hold"]
    running: list[str] = []
    with tempfile.TemporaryDirectory(prefix="som342-oci-", dir=os.environ["RUNNER_TEMP"]) as tmp:
        work = Path(tmp)
        try:
            nodes: dict[int, tuple[str, Path]] = {}
            for i in (1, 2):
                name = f"som342-oci-node{i}-{uuid.uuid4().hex[:6]}"
                _name, _client, known = start_node(name, work / name, running)
                nodes[i] = (name, known)
                try:
                    check_node(name, i)
                except AssertionError as exc:
                    logs = run(["docker", "logs", name], ok=False).stderr
                    raise AssertionError((exc.args, logs[-1700:].decode(errors="replace"))) from exc

            # Both nodes are still running with network=none, separate tmpfs
            # /srv/data and independent SSH host keys. A sibling path isn't
            # available even though each has the same policy prefix.
            for i in (1, 2):
                name, known = nodes[i]
                _, foreign_known = nodes[3 - i]
                cross = call(
                    name,
                    frame(
                        "fs_read",
                        f"oci_node_{i}_cross",
                        f"/srv/data/mvp-node-{3 - i}/probe.bin",
                        max_bytes=4096,
                    ),
                )
                assert cross.returncode != 0 and cross.stdout == b""

                # Deliberately substitute the sibling's host fingerprint.
                # OpenSSH must refuse the connection, then recover once its
                # exact pinned host key is restored.
                wrong_pinned_host = foreign_known.read_bytes()
                run(
                    [
                        "docker",
                        "exec",
                        "-i",
                        "-u",
                        "0:0",
                        name,
                        "/bin/sh",
                        "-c",
                        "umask 077; cat > /tmp/known_hosts; chmod 0644 /tmp/known_hosts",
                    ],
                    stdin=wrong_pinned_host,
                )
                denied = call(name, frame("fs_stat", f"oci_node_{i}_bad_hostkey", "/srv/data"))
                assert denied.returncode != 0 and b"Host key verification failed" in denied.stderr
                run(
                    [
                        "docker",
                        "exec",
                        "-i",
                        "-u",
                        "0:0",
                        name,
                        "/bin/sh",
                        "-c",
                        "umask 077; cat > /tmp/known_hosts; chmod 0644 /tmp/known_hosts",
                    ],
                    stdin=known.read_bytes(),
                )
                verified = call(name, frame("fs_stat", f"oci_node_{i}_restored_key", "/srv/data"))
                assert verified.returncode == 0, verified.stderr[-500:]
            print("MODE_A_OPENSSH_OCI_TWO_NODE_FS_ONLY_HOSTED_PASS")
            print("HOSTED_DISPOSABLE=true NETWORK_NONE=true USERNS_PRIVATE_PROVEN=false")
            print("SIGNED_IMAGE=false NO_NIC_VM_PROVEN=false DEPLOYED=false")
        finally:
            for name in reversed(running):
                run(["docker", "rm", "-f", name], timeout=15, ok=False)
            # Remove ONLY the two known fixture directories on this disposable
            # GitHub runner (not any parent or shared host path).
            for node in work.iterdir():
                for name in ("hostkeys", "authorized_keys"):
                    fixture = node / name
                    if fixture.is_dir() and not fixture.is_symlink():
                        run(["sudo", "-n", "rm", "-rf", "--", str(fixture)], timeout=5, ok=False)


if __name__ == "__main__":
    main()
