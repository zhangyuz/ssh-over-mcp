from __future__ import annotations

from pathlib import Path

from ssh_over_mcp.api import main as api_main
from ssh_over_mcp.api.runtime import MCPRuntimeSettings


def test_main_passes_validated_bind_host_to_uvicorn(monkeypatch) -> None:
    settings = MCPRuntimeSettings(
        config_path=Path("/etc/ssh-over-mcp/config.yaml"),
        credential_map_path=Path("/etc/ssh-over-mcp/credentials.yaml"),
        profile="developer",
        ledger_socket_path=Path("/run/ssh-over-mcp/ledger-exec.sock"),
        ledger_server_uid=2104,
        ledger_server_gid=3104,
        bind_host="0.0.0.0",
        origin_bearer_token_file=Path("/run/secrets/origin-bearer"),
        port=9123,
    )
    application = object()
    calls: list[tuple[object, str, int]] = []

    monkeypatch.setattr(api_main, "load_runtime_settings", lambda _env: settings)
    monkeypatch.setattr(api_main, "build_application", lambda value: application)
    monkeypatch.setattr(
        api_main.uvicorn,
        "run",
        lambda app, *, host, port: calls.append((app, host, port)),
    )

    api_main.main()

    assert calls == [(application, "0.0.0.0", 9123)]
