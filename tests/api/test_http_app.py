from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import pytest
import uvicorn
from mcp import Client
from starlette.testclient import TestClient

from ssh_over_mcp.api.app import build_application
from ssh_over_mcp.api.errors import PrincipalConfigurationError
from ssh_over_mcp.api.runtime import MCPRuntimeSettings
from ssh_over_mcp.api.service import MCPService

_CONFIG = """
inventory:
  hosts:
    host-a:
      address: 10.0.0.1
      port: 22
      ssh_user: secret-user
      credential_ref: secret://host-a
      host_key: secret-host-key
      labels: [secret-label]
      allowed_roles: [developer]
policy:
  version: 1
  default: deny
  roles:
    developer: {}
  rules: []
"""


def write_config(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(_CONFIG, encoding="utf-8")
    return path


def settings(tmp_path: Path, *, profile: str = "developer") -> MCPRuntimeSettings:
    return MCPRuntimeSettings(
        config_path=write_config(tmp_path),
        profile=profile,
        port=8000,
    )


def test_health_and_readiness_are_plain_http_routes(tmp_path: Path) -> None:
    app = build_application(settings(tmp_path))

    with TestClient(app) as client:
        health = client.get("/healthz")
        ready = client.get("/readyz")

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert ready.status_code == 200
    assert ready.json() == {"status": "ready"}

    route_paths = {getattr(route, "path", None) for route in app.routes}
    assert {"/mcp", "/healthz", "/readyz"} <= route_paths


def test_unknown_static_profile_fails_application_construction(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        PrincipalConfigurationError,
        match="configured principal profile is invalid",
    ):
        build_application(settings(tmp_path, profile="missing"))


def test_health_and_readiness_do_not_execute_domain_operations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("lifecycle endpoint must not call MCP service")

    monkeypatch.setattr(MCPService, "list_hosts", forbidden)
    monkeypatch.setattr(MCPService, "get_host", forbidden)
    monkeypatch.setattr(MCPService, "explain_policy", forbidden)

    app = build_application(settings(tmp_path))

    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/readyz").status_code == 200


@pytest.mark.asyncio
async def test_streamable_http_round_trip_at_mcp_path(
    tmp_path: Path,
) -> None:
    app = build_application(settings(tmp_path))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    port = sock.getsockname()[1]

    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
        )
    )
    task = asyncio.create_task(server.serve(sockets=[sock]))

    try:
        for _ in range(500):
            if server.started:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("uvicorn did not start")

        async with Client(f"http://127.0.0.1:{port}/mcp") as client:
            listed = await client.list_tools()
            result = await client.call_tool("hosts_list", {})

        assert {tool.name for tool in listed.tools} == {
            "hosts_list",
            "host_info",
            "policy_explain",
        }
        assert result.is_error is False
        assert result.structured_content == {
            "hosts": [
                {
                    "alias": "host-a",
                    "labels": [],
                    "capabilities": [],
                }
            ]
        }
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, timeout=5)
        sock.close()
