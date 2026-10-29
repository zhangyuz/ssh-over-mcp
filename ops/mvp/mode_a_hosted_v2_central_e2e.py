"""Disposable fs_list v2 real MCP HTTP -> Ledger -> central v5 signer -> two OpenSSH v2."""

import json
import os
import secrets
import sys
import tempfile
import uuid
from pathlib import Path

from mode_a_hosted_oci_fs_smoke import IMAGE, prepare, run, start_node


def main():
    assert sys.platform == "linux" and os.geteuid() != 0
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.environ.get("GITHUB_EVENT_NAME") == "pull_request"
    running, networks = [], []
    with tempfile.TemporaryDirectory(
        prefix="som-fslist-central-", dir=os.environ["RUNNER_TEMP"]
    ) as tmp:
        work = Path(tmp)
        try:
            for i in (1, 2):
                prepare(work / f"node{i:02}", f"node{i:02}")
            pubkeys = [
                (work / f"node{i:02}" / "hostkeys" / "ssh_host_ed25519_key.pub").read_text().strip()
                for i in (1, 2)
            ]
            # Derive the exact digest with the product PolicyEngine, not a copied hash algorithm.
            digest_program = """
import json,sys
sys.path.insert(0,"/opt/ssh-over-mcp-e2e/workspace/src")
from ssh_over_mcp.inventory.models import Inventory
from ssh_over_mcp.policy.models import PolicyDocument
from ssh_over_mcp.policy.engine import PolicyEngine
keys=json.load(sys.stdin)
hosts={f"node{i:02}":{"address":f"node{i:02}","port":2222,
 "ssh_user":"ssh-over-mcp-e2e-host","credential_ref":f"client{i}",
 "host_key":" ".join(key.split()[:2]),"allowed_roles":["rw-operator"]}
 for i,key in enumerate(keys,1)}
policy={"version":1,"default":"deny","roles":{"rw-operator":{}},
 "risk":{"approval_required":["medium","high","critical"]},
 "rules":[
 {"id":"v2.list.allow","effect":"allow","roles":["rw-operator"],
  "hosts":["node01","node02"],"tools":["fs_list"],"paths":["/srv/data","/srv/data/**"]},
 {"id":"v2.list.deny","effect":"deny","roles":["rw-operator"],
  "hosts":["node01","node02"],"tools":["fs_list"],
  "paths":["/srv/data/secret","/srv/data/secret/**"]}]}
engine=PolicyEngine(inventory=Inventory.model_validate({"hosts":hosts}),
 policy=PolicyDocument.model_validate(policy))
print(engine.policy_version[7:])
"""
            digest = (
                run(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "-i",
                        "--network",
                        "none",
                        "--entrypoint",
                        "/opt/ssh-over-mcp-e2e/venv/bin/python",
                        IMAGE,
                        "-c",
                        digest_program,
                    ],
                    stdin=json.dumps(pubkeys).encode(),
                    timeout=30,
                )
                .stdout.decode()
                .strip()
            )
            assert len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)
            signer_keys = {f"node{i:02}": secrets.token_bytes(32) for i in (1, 2)}
            assert signer_keys["node01"] != signer_keys["node02"]
            node_names = []
            for i in (1, 2):
                network = f"som-fslist-net{i}-{uuid.uuid4().hex[:7]}"
                run(["docker", "network", "create", "--internal", network])
                networks.append(network)
                name = f"som-fslist-ssh{i}-{uuid.uuid4().hex[:7]}"
                start_node(
                    name,
                    work / f"node{i:02}",
                    running,
                    network=network,
                    alias=f"node{i:02}",
                    v5_host_id=f"node{i:02}",
                    v5_policy_sha256=digest,
                    v5_signer_key=signer_keys[f"node{i:02}"],
                    prepared_keys=True,
                )
                node_names.append(name)
                run(
                    [
                        "docker",
                        "exec",
                        "-u",
                        "2201:3201",
                        name,
                        "/bin/sh",
                        "-c",
                        (
                            "printf 'public data' > /srv/data/public.txt; mkdir /srv/data/secret; "
                            "printf 'classified' > /srv/data/secret/password"
                        ),
                    ]
                )
            control = f"som-fslist-control-{uuid.uuid4().hex[:7]}"
            run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--rm",
                    "--name",
                    control,
                    "--network",
                    networks[0],
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
                    "180",
                ]
            )
            running.append(control)
            run(["docker", "network", "connect", networks[1], control])
            origin_net = f"som-fslist-origin-{uuid.uuid4().hex[:7]}"
            run(["docker", "network", "create", "--internal", origin_net])
            networks.append(origin_net)
            run(["docker", "network", "connect", origin_net, control])
            details = json.loads(run(["docker", "inspect", control]).stdout)[0]
            origin_ip = details["NetworkSettings"]["Networks"][origin_net]["IPAddress"]
            ips = [details["NetworkSettings"]["Networks"][net]["IPAddress"] for net in networks[:2]]
            for i in (1, 2):
                files = [
                    (f"client{i}", (work / f"node{i:02}" / "client").read_bytes(), "0600"),
                    (
                        f"hostkey{i}.pub",
                        (
                            work / f"node{i:02}" / "hostkeys" / "ssh_host_ed25519_key.pub"
                        ).read_bytes(),
                        "0644",
                    ),
                    (f"v5-signer-node{i:02}", signer_keys[f"node{i:02}"], "0600"),
                ]
                for label, data, mode in files:
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
                        stdin=data,
                    )
            script = Path(__file__).with_name("mode_a_hosted_control_ledger_smoke.py").read_bytes()
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
                    *ips,
                    "--v2",
                ],
                stdin=script,
                timeout=100,
                ok=False,
            )
            assert result.returncode == 0, (
                result.returncode,
                result.stderr[-3500:],
                result.stdout[-1200:],
            )
            for node in ("node01", "node02"):
                assert f"CENTRAL_MCP_LEDGER_REAL_OPENSSH_V2_{node}_PASS".encode() in result.stdout
            assert b"CENTRAL_MCP_LEDGER_TWO_OPENSSH_V2_TEST_ONLY_PASS" in result.stdout
            print("FS_LIST_V2_REAL_CENTRAL_MCP_LEDGER_TWO_OPENSSH_E2E_PASS", flush=True)
        finally:
            for name in reversed(running):
                run(["docker", "rm", "-f", name], timeout=20, ok=False)
            for net in reversed(networks):
                run(["docker", "network", "rm", net], timeout=20, ok=False)
            run(
                ["sudo", "-n", "chown", "-R", f"{os.geteuid()}:{os.getegid()}", str(work)], ok=False
            )


if __name__ == "__main__":
    main()
