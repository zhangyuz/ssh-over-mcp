"""Test-only real OpenSSH FS/OCI admission on disposable GitHub-hosted Ubuntu.

No external container network, no host-published ports, no production keys,
no persistent host/VM state. NOT a private-userns or no-NIC VM acceptance.
"""

from __future__ import annotations

import base64
import hashlib
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

IMAGE = "som-mvp-fs-native-review:local"
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


def prepare_v5_test_trust(
    work: Path,
    host: str,
    *,
    central_policy_sha256: str = "a" * 64,
    signer_key: bytes | None = None,
) -> list[str]:
    """Generate per-node test-only root-owned v5 HMAC verifier + immutable policy.

    These are disposable CI credentials. No production key is imported;
    never print them or package them in image/CI artifacts.
    """
    assert host in {"node01", "node02"}
    assert len(central_policy_sha256) == 64 and all(
        char in "0123456789abcdef" for char in central_policy_sha256
    )
    assert signer_key is None or (type(signer_key) is bytes and len(signer_key) == 32)
    public_line = (work / "hostkeys" / "ssh_host_ed25519_key.pub").read_text().split()
    assert len(public_line) >= 2 and public_line[0] == "ssh-ed25519"
    hostkey_digest = hashlib.sha256(base64.b64decode(public_line[1], validate=True)).hexdigest()
    trust = work / "v5-trust"
    trust.mkdir(mode=0o755)
    policy = {
        "version": 5,
        "enabled": True,
        "host": host,
        "host_key_sha256": hostkey_digest,
        "signer_key_path": "/etc/ssh-over-mcp/v5/signer.key",
        "nonce_db_path": "/var/lib/som-pr347-nonce/nonces.sqlite",
        "visibility": {
            "version": 5,
            "enabled": True,
            "host": host,
            "profile": "rw-operator",
            "policy_epoch": 11,
            "central_policy_sha256": central_policy_sha256,
            "operations": {
                "fs_list": {"allow_roots": ["/srv/data"], "deny_subtrees": []},
                "fs_search": {"allow_roots": ["/srv/data"], "deny_subtrees": []},
            },
        },
    }
    (trust / "host-visibility.json").write_text(
        json.dumps(policy, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    (trust / "signer.key").write_bytes(
        os.urandom(32) if signer_key is None else signer_key
    )
    # Host runner root is trusted only inside disposable GitHub-hosted CI;
    # group 3201 is the fixed unprivileged FS-only Host Agent's read identity.
    run(["sudo", "-n", "chown", "-R", "0:3201", str(trust)])
    run(["sudo", "-n", "chmod", "0755", str(trust)])
    for file in (trust / "host-visibility.json", trust / "signer.key"):
        run(["sudo", "-n", "chmod", "0440", str(file)])
    return [
        "--mount",
        f"type=bind,src={trust},dst=/etc/ssh-over-mcp/v5,readonly",
        "--tmpfs",
        "/var/lib/som-pr347-nonce:rw,nosuid,nodev,noexec,uid=2201,gid=3201,mode=0700,size=4m",
    ]


def start_node(
    name: str,
    work: Path,
    running: list[str],
    *,
    network: str = "none",
    alias: str | None = None,
    image: str = IMAGE,
    use_default_entrypoint: bool = False,
    v5_host_id: str | None = None,
    v5_policy_sha256: str = "a" * 64,
    v5_signer_key: bytes | None = None,
    prepared_keys: bool = False,
) -> tuple[str, Path, Path]:
    if use_default_entrypoint:
        assert image == "som-mvp-fs-online-pilot-review:local"
    if prepared_keys:
        assert (work / "hostkeys" / "ssh_host_ed25519_key").is_file()
        client, known = work / "client", work / "known_hosts"
        assert client.is_file() and known.is_file()
    else:
        _host, client, known = prepare(work, name)
    v5_mounts = (
        prepare_v5_test_trust(
            work, v5_host_id,
            central_policy_sha256=v5_policy_sha256,
            signer_key=v5_signer_key,
        )
        if v5_host_id is not None else []
    )
    # The immutable native no-sudo review files are baked into IMAGE.
    # No per-container code or sshd configuration mounts are accepted.
    args = [
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "--network",
        network,
        *([] if alias is None else ["--network-alias", alias]),
        "--cap-drop",
        "ALL",
        *[argument for cap in SSH_CAPS for argument in ("--cap-add", cap)],
        "--security-opt",
        "no-new-privileges:true",
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
        *v5_mounts,
        *([] if use_default_entrypoint else ["--entrypoint", "/usr/sbin/sshd"]),
        image,
        *([] if use_default_entrypoint else ["-D", "-e"]),
    ]
    output = run(args, timeout=40).stdout.decode().strip()
    assert output and len(output) >= 12
    running.append(name)
    details = json.loads(run(["docker", "inspect", name]).stdout)[0]
    hostconfig = details["HostConfig"]
    assert hostconfig["NetworkMode"] == network
    if os.getenv("SOM342_REMAPPED_ROOT_UID"):
        security = json.loads(
            run(["docker", "info", "--format", "{{json .SecurityOptions}}"]).stdout
        )
        assert any("userns" in entry for entry in security)
        assert hostconfig["UsernsMode"] != "host"
        uid_map = run(
            ["docker", "exec", "-u", "0:0", name, "cat", "/proc/self/uid_map"]
        ).stdout.decode()
        gid_map = run(
            ["docker", "exec", "-u", "0:0", name, "cat", "/proc/self/gid_map"]
        ).stdout.decode()
        assert uid_map.split()[0:2] == ["0", os.environ["SOM342_REMAPPED_ROOT_UID"]]
        assert gid_map.split()[0:2] == ["0", os.environ["SOM342_REMAPPED_ROOT_GID"]]
    assert hostconfig["Privileged"] is False
    assert hostconfig["ReadonlyRootfs"] is True
    assert set(hostconfig["CapDrop"]) == {"ALL"}
    assert {c.removeprefix("CAP_") for c in hostconfig["CapAdd"]} == set(SSH_CAPS)
    assert hostconfig["SecurityOpt"] == ["no-new-privileges:true"]
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

    # The preceding probes used the stock ssh CLI. Verify the *real product*
    # AsyncSSH connection pool, explicit pinned host key, typed SMCP protocol
    # and transport byte collection against this actual OpenSSH container.
    project_client = (
        Path(__file__).with_name("mode_a_hosted_project_transport_smoke.py").read_bytes()
    )
    project_result = run(
        [
            "docker",
            "exec",
            "-i",
            "-u",
            "0:0",
            name,
            "/opt/ssh-over-mcp-e2e/venv/bin/python",
            "-",
            str(index),
        ],
        stdin=project_client,
        timeout=35,
        ok=False,
    )
    marker = f"PROJECT_ASYNCSSH_TRANSPORT_TYPED_FS_NODE_{index}_PASS".encode()
    assert project_result.returncode == 0 and marker in project_result.stdout, (
        project_result.returncode,
        project_result.stderr[-900:],
        project_result.stdout[-250:],
    )


def prove_central_mcp_ledger(
    work: Path,
    running: list[str],
    networks: list[str],
    *,
    node_image: str = IMAGE,
    default_node_entrypoint: bool = False,
) -> None:
    """Two test-only node-local bridges, central MCP+Ledger over real SSH.

    This proves node-to-node isolation, NOT directional node-to-MCP egress
    firewall rules or production Compose startup.
    Previously verified per-node network=none tests run separately.
    """
    # Run the same central MCP/Ledger proof against either the historical
    # STOP78 test image with explicit test-only entrypoint, or the DISTINCT
    # runnable pilot image using its exact baked default sshd entrypoint.
    if default_node_entrypoint:
        assert node_image == "som-mvp-fs-online-pilot-review:local"
    else:
        assert node_image == IMAGE
    # Separate per-node internal bridges: the control can reach both nodes,
    # while neither node is attached to the other node's SSH network.
    node_networks: list[str] = []
    node_names: list[str] = []
    prepared: list[tuple[Path, Path]] = []
    for index in (1, 2):
        network = f"som342-node{index}-{uuid.uuid4().hex[:8]}"
        run(["docker", "network", "create", "--internal", "--driver", "bridge", network])
        networks.append(network)
        desc = json.loads(run(["docker", "network", "inspect", network]).stdout)[0]
        assert desc["Internal"] is True and desc["Driver"] == "bridge"
        node_networks.append(network)
        name = f"som342-mcp-node{index}-{uuid.uuid4().hex[:5]}"
        _, client, _ = start_node(
            name,
            work / name,
            running,
            network=network,
            alias=f"node{index:02}",
            image=node_image,
            use_default_entrypoint=default_node_entrypoint,
        )
        node_names.append(name)
        prepared.append((client, work / name / "hostkeys" / "ssh_host_ed25519_key.pub"))

    # Prove real TCP reachability is denied across node networks by IP, not
    # merely by absent Docker DNS names. No SSH bytes or keys in this probe.
    for source, peer, peer_network in (
        (node_names[0], node_names[1], node_networks[1]),
        (node_names[1], node_names[0], node_networks[0]),
    ):
        peer_details = json.loads(run(["docker", "inspect", peer]).stdout)[0]
        target_ip = peer_details["NetworkSettings"]["Networks"][peer_network]["IPAddress"]
        assert target_ip and target_ip != "127.0.0.1"
        probe = run(
            [
                "docker",
                "exec",
                "-u",
                "2201:3201",
                source,
                "/opt/ssh-over-mcp-e2e/venv/bin/python",
                "-c",
                (
                    "import socket,sys; s=socket.socket(); s.settimeout(1);"
                    "rc=s.connect_ex((sys.argv[1],2222)); s.close();"
                    "sys.exit(0 if rc!=0 else 31)"
                ),
                target_ip,
            ],
            timeout=8,
            ok=False,
        )
        assert probe.returncode == 0, ("node reached sibling isolated SSH address", source, peer)
    print("HOSTED_TWO_NODE_CROSS_NETWORK_SSH_DENIED_PASS", flush=True)

    control = f"som342-mcp-control-{uuid.uuid4().hex[:6]}"
    run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            control,
            "--network",
            node_networks[0],
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--read-only",
            "--user",
            "2201:3201",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,uid=2201,gid=3201,mode=1777,size=16m",
            "--entrypoint",
            "/bin/sleep",
            IMAGE,
            "120",
        ],
        timeout=35,
    )
    running.append(control)
    run(["docker", "network", "connect", node_networks[1], control])
    control_info = json.loads(run(["docker", "inspect", control]).stdout)[0]
    assert set(control_info["NetworkSettings"]["Networks"]) == set(node_networks)
    # Both host aliases must be routable from the control plane, not from
    # each other; only SSH from the control is required for this probe.
    for index in (1, 2):
        candidate = run(
            [
                "docker",
                "exec",
                "-u",
                "2201:3201",
                control,
                "/opt/ssh-over-mcp-e2e/venv/bin/python",
                "-c",
                "import socket,sys; s=socket.create_connection((sys.argv[1],2222),3); s.close()",
                f"node{index:02}",
            ],
            timeout=8,
            ok=False,
        )
        assert candidate.returncode == 0, ("control cannot access SSH node", index)
    print("HOSTED_CONTROL_TO_TWO_ISOLATED_SSH_NODES_PASS", flush=True)
    assert control_info["HostConfig"]["Privileged"] is False
    assert control_info["HostConfig"]["ReadonlyRootfs"] is True
    assert control_info["HostConfig"]["CapDrop"] == ["ALL"]
    assert control_info["HostConfig"]["SecurityOpt"] == ["no-new-privileges:true"]
    assert control_info["HostConfig"]["NetworkMode"] == node_networks[0]
    # First prove a separate origin-only listener rejects both SSH nodes
    # WITHOUT any netns firewall, then retain the stronger stateful ACL proof.
    from mode_a_hosted_origin_bind_probe import prove as prove_origin_only_bind

    origin_ip = prove_origin_only_bind(control, node_names, node_networks, networks, run)
    control_node_ips = [
        control_info["NetworkSettings"]["Networks"][net]["IPAddress"] for net in node_networks
    ]
    from mode_a_hosted_directional_acl import prove as prove_directional_acl

    prove_directional_acl(control, node_names, node_networks, run)
    for index, (client, hostkey) in enumerate(prepared, 1):
        for label, content, mode in (
            (f"client{index}", client.read_bytes(), "0600"),
            (f"hostkey{index}.pub", hostkey.read_bytes(), "0644"),
        ):
            run(
                [
                    "docker",
                    "exec",
                    "-i",
                    "-u",
                    "2201:3201",
                    control,
                    "/bin/sh",
                    "-c",
                    f"umask 077; cat > /tmp/{label}; chmod {mode} /tmp/{label}",
                ],
                stdin=content,
            )
    controller = Path(__file__).with_name("mode_a_hosted_control_ledger_smoke.py").read_bytes()
    result = run(
        [
            "docker",
            "exec",
            "-i",
            "-u",
            "2201:3201",
            control,
            "/opt/ssh-over-mcp-e2e/venv/bin/python",
            "-",
            origin_ip,
            *control_node_ips,
        ],
        stdin=controller,
        timeout=65,
        ok=False,
    )
    if result.returncode:
        raise AssertionError(
            (
                "central MCP/Ledger two-node proof",
                result.returncode,
                result.stderr[-4000:],
                result.stdout[-650:],
            )
        )
    assert b"REAL_MCP_HTTP_ORIGIN_INTERFACE_ONLY_PASS" in result.stdout
    assert b"CENTRAL_MCP_LEDGER_TWO_OPENSSH_NODES_TEST_ONLY_PASS" in result.stdout
    assert b"CENTRAL_MCP_LEDGER_ONCE_ONLY_REAL_SSH_node01_PASS" in result.stdout
    assert b"CENTRAL_MCP_LEDGER_ONCE_ONLY_REAL_SSH_node02_PASS" in result.stdout
    print("CENTRAL_MCP_LEDGER_TWO_OPENSSH_NODES_TEST_ONLY_PASS", flush=True)
    print("NATIVE_FOUR_ZERO_LIMITED_CAPBND_TEST_ONLY=true", flush=True)
    print("FS_LAUNCHER_FIVE_ZERO_RELEASE_CONTRACT_UNCHANGED=true", flush=True)
    print("NODE_TO_NODE_TCP_DENIAL_PROVEN=true", flush=True)
    print("HOSTED_DIRECTIONAL_NETNS_ACL_TEST_ONLY_PASS=true", flush=True)
    print("NETWORK_DIRECTIONAL_ACL_PROVEN=false SIGNED_MEDIA=false DEPLOYED=false")


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
    networks: list[str] = []
    with tempfile.TemporaryDirectory(prefix="som342-oci-", dir=os.environ["RUNNER_TEMP"]) as tmp:
        work = Path(tmp)
        try:
            nodes: dict[int, tuple[str, Path]] = {}
            for i in (1, 2):
                name = f"som342-oci-node{i}-{uuid.uuid4().hex[:6]}"
                # Same baked review image in normal and userns Engines.
                _name, _client, known = start_node(name, work / name, running)
                nodes[i] = (name, known)
                if i == 1:
                    # Independent NO-SUDO review feasibility probe. Never
                    # changes the production ForceCommand/STOP78; an unproved
                    # kernel boundary cannot be counted as release approval.
                    from mode_a_native_login_probe import check as check_native_login

                    check_native_login(name, known)
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
            # No shared network is used for the preceding isolation proof.
            # Separate *test-only* internal bridge exercises the real central
            # MCP HTTP+Ledger control plane against two different SSH nodes.
            # Prove the full central one-use Ledger operation in the
            # dedicated remapped Engine too; never substitute local SSH-only
            # probes for a real control-plane operation.
            prove_central_mcp_ledger(work, running, networks)
            if os.getenv("SOM342_REMAPPED_ROOT_UID"):
                print("USERNS_REMAPPED_NATIVE_NO_SUDO_TWO_REAL_FS_NODES_PASS", flush=True)
                print("USERNS_REMAPPED_CENTRAL_LEDGER_TWO_NODE_TEST_ONLY_PASS", flush=True)
            print("MODE_A_OPENSSH_OCI_TWO_NODE_FS_ONLY_HOSTED_PASS")
            print("HOSTED_DISPOSABLE=true NETWORK_NONE=true USERNS_PRIVATE_PROVEN=false")
            print("SIGNED_IMAGE=false NO_NIC_VM_PROVEN=false DEPLOYED=false")
        finally:
            for name in reversed(running):
                run(["docker", "rm", "-f", name], timeout=15, ok=False)
            for network in reversed(networks):
                run(["docker", "network", "rm", network], timeout=15, ok=False)
            # Remove ONLY the two known fixture directories on this disposable
            # GitHub runner (not any parent or shared host path).
            for node in work.iterdir():
                for name in ("hostkeys", "authorized_keys"):
                    fixture = node / name
                    if fixture.is_dir() and not fixture.is_symlink():
                        run(["sudo", "-n", "rm", "-rf", "--", str(fixture)], timeout=5, ok=False)


if __name__ == "__main__":
    main()
