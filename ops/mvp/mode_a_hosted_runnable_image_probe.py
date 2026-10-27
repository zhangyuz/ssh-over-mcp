"""Test the default startup of a separate runnable candidate, CI only.

No published ports, --network none, no production keys, no archive export.
The original STOP78 image and all historical release gates stay unchanged.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import uuid
from pathlib import Path

from mode_a_hosted_oci_fs_smoke import check_node, prove_central_mcp_ledger, run, start_node

IMAGE = "som-mvp-fs-online-pilot-review:local"


def main() -> None:
    assert sys.platform == "linux" and os.geteuid() != 0
    assert os.getenv("GITHUB_ACTIONS") == "true"
    assert os.getenv("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.getenv("GITHUB_EVENT_NAME") == "pull_request"
    assert os.getenv("RUNNER_TEMP")
    config = json.loads(
        run(["docker", "image", "inspect", IMAGE, "--format", "{{json .Config}}"]).stdout
    )
    assert config["Entrypoint"] == ["/usr/sbin/sshd"]
    assert config["Cmd"] == ["-D", "-e"]
    running: list[str] = []
    networks: list[str] = []
    with tempfile.TemporaryDirectory(
        prefix="som342-online-pilot-proof-", dir=os.environ["RUNNER_TEMP"]
    ) as tmp:
        work = Path(tmp)
        name = f"som342-online-pilot-{uuid.uuid4().hex[:8]}"
        try:
            start_node(name, work / name, running, image=IMAGE, use_default_entrypoint=True)
            observed = json.loads(run(["docker", "inspect", name]).stdout)[0]
            assert observed["Config"]["Entrypoint"] == ["/usr/sbin/sshd"]
            assert observed["Config"]["Cmd"] == ["-D", "-e"]
            assert observed["HostConfig"]["NetworkMode"] == "none"
            assert not any(observed["NetworkSettings"]["Ports"].values())
            check_node(name, 1)
            print("HOSTED_ONLINE_PILOT_DEFAULT_SSHD_FS_PASS", flush=True)
            # Use the SAME baked default-boot image for both networked SSH
            # nodes; the real central MCP HTTP + persistent Ledger sends
            # independently approved once-only FS mutations to both.
            prove_central_mcp_ledger(
                work,
                running,
                networks,
                node_image=IMAGE,
                default_node_entrypoint=True,
            )
            print("HOSTED_ONLINE_PILOT_DEFAULT_SSHD_TWO_NODE_MCP_LEDGER_PASS", flush=True)
            print("TEST_ONLY=true IMAGE_RELEASE_ATTESTED=false DEPLOYED=false", flush=True)
        finally:
            for current in reversed(running):
                run(["docker", "rm", "-f", current], ok=False)
            for network in reversed(networks):
                run(["docker", "network", "rm", network], ok=False)
            # Clean only fixture-owned directories in the temp work root.
            # Normal and userns-remapped root ownership may differ on host.
            for node in work.iterdir():
                for directory in ("hostkeys", "authorized_keys"):
                    target = node / directory
                    if target.is_dir() and not target.is_symlink():
                        run(["sudo", "-n", "rm", "-rf", "--", str(target)], ok=False)


if __name__ == "__main__":
    main()
