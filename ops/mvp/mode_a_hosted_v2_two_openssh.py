"""fs_list v2: disposable two-node *real* OpenSSH SMCP v2 Docker proof.

Exclusively github-hosted Ubuntu, never production/Yuz.local Docker. The
signed request in this test is constructed inside each disposable container:
this does NOT assert central MCP/Ledger/VisibilityAuthority integration.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import uuid
from pathlib import Path

from mode_a_hosted_oci_fs_smoke import IMAGE, run, start_node


def main() -> None:
    assert sys.platform == "linux" and os.geteuid() != 0
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.environ.get("GITHUB_EVENT_NAME") == "pull_request"
    assert os.environ.get("RUNNER_TEMP")
    detail = json.loads(run(["docker", "image", "inspect", IMAGE]).stdout)[0]
    assert detail["Config"]["Entrypoint"] == ["/usr/local/libexec/ssh-over-mcp-image-hold"]
    workbase = Path(os.environ["RUNNER_TEMP"])
    running: list[str] = []
    with tempfile.TemporaryDirectory(prefix="som-fslist-v2-", dir=workbase) as owned:
        work = Path(owned)
        try:
            keys = []
            probe = Path(__file__).with_name("mode_a_hosted_v2_client_probe.py").read_bytes()
            for i in (1, 2):
                host = f"node{i:02d}"
                name = f"som-fslist-v2-{host}-{uuid.uuid4().hex[:8]}"
                _node, _client, known = start_node(
                    name,
                    work / host,
                    running,
                    network="none",
                    v5_host_id=host,
                )
                keys.append(known.read_bytes())
                # Even if a certificate is valid, Docker must expose no port,
                # and the Host Agent verifier is NOT a container-writable path.
                info = json.loads(run(["docker", "inspect", name]).stdout)[0]
                assert info["HostConfig"]["NetworkMode"] == "none"
                assert info["HostConfig"]["ReadonlyRootfs"] is True
                assert not any(info["NetworkSettings"]["Ports"].values())
                trust = [m for m in info["Mounts"] if m["Destination"] == "/etc/ssh-over-mcp/v5"]
                assert len(trust) == 1 and trust[0]["RW"] is False
                tmpfs = info["HostConfig"]["Tmpfs"]
                assert "/var/lib/som-fslist-v2-nonce" in tmpfs
                prefill = run(
                    [
                        "docker",
                        "exec",
                        "-u",
                        "2201:3201",
                        name,
                        "/bin/sh",
                        "-c",
                        (
                            "printf 'public data' > /srv/data/public.txt && "
                            "mkdir /srv/data/secret && "
                            "printf 'classified' > /srv/data/secret/password"
                        ),
                    ],
                    timeout=10,
                )
                assert prefill.returncode == 0
                result = run(
                    [
                        "docker",
                        "exec",
                        "-i",
                        "-u",
                        "0:0",
                        name,
                        "/opt/ssh-over-mcp-e2e/venv/bin/python",
                        "-",
                        str(i),
                    ],
                    stdin=probe,
                    timeout=100,
                    ok=False,
                )
                markers = [
                    f"REAL_OPENSSH_SMCP_V2_FS_LIST_{host}_PASS".encode(),
                    f"REAL_OPENSSH_SMCP_V2_DENIAL_REPLAY_DOWNGRADE_{host}_PASS".encode(),
                ]
                assert result.returncode == 0 and all(m in result.stdout for m in markers), (
                    "v2 actual OpenSSH failed",
                    host,
                    result.returncode,
                    result.stderr[-850:],
                    result.stdout[-350:],
                )
                print(f"CI_FS_LIST_V2_REAL_TWO_OPENSSH_{host}_PASS", flush=True)
            assert len(set(keys)) == 2, "independent SSH host identities required"
            print("CI_FS_LIST_V2_REAL_TWO_OPENSSH_DISTINCT_KEYS_PASS", flush=True)
        finally:
            for name in reversed(running):
                run(["docker", "rm", "-f", name], timeout=20, ok=False)
            # Only this unique, owned throwaway CI directory is restored for
            # automatic tmp cleanup. Never touch shared users, images or volumes.
            run(
                [
                    "sudo",
                    "-n",
                    "chown",
                    "-R",
                    f"{os.geteuid()}:{os.getegid()}",
                    str(work),
                ],
                timeout=20,
                ok=False,
            )


if __name__ == "__main__":
    main()
    from mode_a_hosted_v2_central_e2e import main as prove_central_v2
    prove_central_v2()
