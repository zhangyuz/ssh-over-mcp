"""Disposable CI-only origin-interface bind proof. No host firewall or guest changes."""

from __future__ import annotations

import json
import os
import time
import uuid
from collections.abc import Callable
from typing import Any

IMAGE = "som-mvp-fs-native-review:local"
PYTHON = "/opt/ssh-over-mcp-e2e/venv/bin/python"

# Accept one ingress connection on disposable port 18000, not MCP port 8000.
# Keeping ports distinct avoids a just-closed TCP listener affecting MCP bind.
# The listener runs inside disposable control OCI, as unprivileged UID2201.
LISTENER = (
    "import socket,sys,pathlib;"
    "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
    "s.bind((sys.argv[1],18000));s.listen(5);"
    "pathlib.Path('/tmp/som342-origin-ready').write_text('1');"
    "s.settimeout(30);c,_=s.accept();c.sendall(b'ORIGIN_OK');c.close();s.close();"
    "pathlib.Path('/tmp/som342-origin-done').write_text('1')"
)
NEGATIVE = (
    "import socket,sys;s=socket.socket();s.settimeout(1);"
    "rc=s.connect_ex((sys.argv[1],18000));s.close();"
    "sys.exit(0 if rc!=0 else 35)"
)
POSITIVE = (
    "import socket,sys;s=socket.create_connection((sys.argv[1],18000),3);"
    "reply=s.recv(16);s.close();sys.exit(0 if reply==b'ORIGIN_OK' else 36)"
)


def prove(
    control: str,
    nodes: list[str],
    node_networks: list[str],
    networks: list[str],
    run: Callable[..., Any],
) -> str:
    assert os.getenv("GITHUB_ACTIONS") == "true"
    assert os.getenv("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.getenv("GITHUB_EVENT_NAME") == "pull_request"
    assert len(nodes) == len(node_networks) == 2
    assert control.startswith("som342-mcp-control-")
    assert all(node.startswith("som342-mcp-node") for node in nodes)

    origin = "som342-origin-" + uuid.uuid4().hex[:8]
    run(["docker", "network", "create", "--internal", "--driver", "bridge", origin])
    networks.append(origin)
    run(["docker", "network", "connect", origin, control])
    detail = json.loads(run(["docker", "inspect", control]).stdout)[0]
    end = detail["NetworkSettings"]["Networks"]
    assert set(end) == {*node_networks, origin}
    address = end[origin]["IPAddress"]
    assert address and address != "127.0.0.1"
    assert all(end[n]["IPAddress"] != address for n in node_networks)
    # An image may EXPOSE 2222 without any published host binding.
    assert all(not bindings for bindings in detail["NetworkSettings"]["Ports"].values())

    run(["docker", "exec", "-d", "-u", "2201:3201", control, PYTHON, "-c", LISTENER, address])
    for _ in range(60):
        ready = run(
            [
                "docker",
                "exec",
                "-u",
                "2201:3201",
                control,
                "test",
                "-f",
                "/tmp/som342-origin-ready",
            ],
            ok=False,
        )
        if ready.returncode == 0:
            break
        time.sleep(0.1)
    else:
        raise AssertionError("origin-only listener never started")

    # Before ANY iptables rule, both nodes must be unable to connect to
    # either the node-facing interface or the origin-only listening address.
    for node, network in zip(nodes, node_networks, strict=True):
        for target in (end[network]["IPAddress"], address):
            result = run(
                ["docker", "exec", "-u", "2201:3201", node, PYTHON, "-c", NEGATIVE, target],
                timeout=8,
                ok=False,
            )
            assert result.returncode == 0, ("reverse MCP reachability", node, network, target)

    # The real ingress network must be able to reach that same listener.
    run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            origin,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--read-only",
            "--user",
            "2201:3201",
            "--entrypoint",
            PYTHON,
            IMAGE,
            "-c",
            POSITIVE,
            address,
        ],
        timeout=20,
    )
    for _ in range(60):
        done = run(
            ["docker", "exec", "-u", "2201:3201", control, "test", "-f", "/tmp/som342-origin-done"],
            ok=False,
        )
        if done.returncode == 0:
            break
        time.sleep(0.1)
    else:
        raise AssertionError("origin-only listener did not close")
    print("HOSTED_ORIGIN_BIND_ONLY_TWO_NODE_REVERSE_TCP18000_DENIED_PASS", flush=True)
    return address
