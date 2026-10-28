"""Disposable CI proof: node-originated NEW TCP/8000 is denied, SSH still works.

Installs INPUT rules only inside a short-lived control-container network namespace,
never the runner host namespace or Yuz.local. Does not authorize production ACL.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from collections.abc import Callable
from typing import Any

Run = Callable[..., Any]
PORT = "8000"
CONNECT = (
    "import socket,sys; s=socket.socket(); s.settimeout(1);"
    "rc=s.connect_ex((sys.argv[1],8000)); s.close();"
    "sys.exit(0 if rc==0 else 41)"
)
LISTENER = (
    "import socket,pathlib; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
    "s.bind(('0.0.0.0',8000)); s.listen(32);"
    # Exactly four intentional positive connects: readiness, both SSH nodes,
    # and the final control loopback probe. Do not leave a port-8000 daemon.
    "\nfor _ in range(4):\n c,_=s.accept(); c.close()"
    "\ns.close();pathlib.Path('/tmp/som342-acl-done').write_text('1')"
)


def prove(control: str, nodes: list[str], networks: list[str], run: Run) -> None:
    assert os.getenv("GITHUB_ACTIONS") == "true"
    assert os.getenv("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.getenv("GITHUB_EVENT_NAME") == "pull_request"
    assert control.startswith("som342-mcp-control-")
    assert len(nodes) == len(networks) == 2 and all(
        name.startswith("som342-mcp-node") for name in nodes
    )
    nsenter, iptables = shutil.which("nsenter"), shutil.which("iptables")
    assert nsenter and iptables, "host netns inspection utilities are required"

    details = json.loads(run(["docker", "inspect", control]).stdout)[0]
    assert details["State"]["Running"] is True
    pid = details["State"]["Pid"]
    assert type(pid) is int and pid > 1
    endpoints: list[tuple[str, str, str]] = []
    for node, network in zip(nodes, networks, strict=True):
        node_details = json.loads(run(["docker", "inspect", node]).stdout)[0]
        source = node_details["NetworkSettings"]["Networks"][network]["IPAddress"]
        target = details["NetworkSettings"]["Networks"][network]["IPAddress"]
        assert source and target and source != target
        endpoints.append((node, source, target))

    # A real, deliberately open listener makes the negative test meaningful:
    # prior to applying our rule, BOTH SSH nodes must successfully connect.
    run(
        [
            "docker",
            "exec",
            "-d",
            "-u",
            "2201:3201",
            control,
            "/opt/ssh-over-mcp-e2e/venv/bin/python",
            "-c",
            LISTENER,
        ]
    )
    for _ in range(35):
        ready = run(
            [
                "docker",
                "exec",
                "-u",
                "2201:3201",
                control,
                "/opt/ssh-over-mcp-e2e/venv/bin/python",
                "-c",
                CONNECT,
                "127.0.0.1",
            ],
            timeout=8,
            ok=False,
        )
        if ready.returncode == 0:
            break
        time.sleep(0.1)
    else:
        raise AssertionError("MCP-port test listener never became reachable")

    for node, _, target in endpoints:
        assert (
            run(
                [
                    "docker",
                    "exec",
                    "-u",
                    "2201:3201",
                    node,
                    "/opt/ssh-over-mcp-e2e/venv/bin/python",
                    "-c",
                    CONNECT,
                    target,
                ],
                timeout=8,
                ok=False,
            ).returncode
            == 0
        ), "pre-policy node->control not reachable"

    for _, source, target in endpoints:
        run(
            [
                "sudo",
                "-n",
                nsenter,
                "--target",
                str(pid),
                "--net",
                iptables,
                "-w",
                "2",
                "-I",
                "INPUT",
                "1",
                "-s",
                source,
                "-d",
                target,
                "-p",
                "tcp",
                "--dport",
                PORT,
                "-m",
                "conntrack",
                "--ctstate",
                "NEW",
                "-j",
                "REJECT",
            ],
            timeout=10,
        )

    for node, _, target in endpoints:
        assert (
            run(
                [
                    "docker",
                    "exec",
                    "-u",
                    "2201:3201",
                    node,
                    "/opt/ssh-over-mcp-e2e/venv/bin/python",
                    "-c",
                    CONNECT,
                    target,
                ],
                timeout=8,
                ok=False,
            ).returncode
            != 0
        ), "NEW TCP/8000 reached control despite ACL"
    assert (
        run(
            [
                "docker",
                "exec",
                "-u",
                "2201:3201",
                control,
                "/opt/ssh-over-mcp-e2e/venv/bin/python",
                "-c",
                CONNECT,
                "127.0.0.1",
            ],
            timeout=8,
            ok=False,
        ).returncode
        == 0
    )
    # The test listener must shut down before the REAL MCP binds TCP/8000.
    for _ in range(35):
        done = run(
            ["docker", "exec", "-u", "2201:3201", control, "test", "-f", "/tmp/som342-acl-done"],
            ok=False,
        )
        if done.returncode == 0:
            break
        time.sleep(0.1)
    else:
        raise AssertionError("disposable ACL listener did not exit")
    print("HOSTED_NODE_TO_CONTROL_TCP8000_NEW_DENIED_BOTH_PASS", flush=True)
    print("DIRECTIONAL_ACL_DISPOSABLE_CONTROL_NETNS_ONLY=true", flush=True)
