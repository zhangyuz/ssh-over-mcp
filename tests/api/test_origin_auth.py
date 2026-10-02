from __future__ import annotations

import json
import os
import traceback
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from ssh_over_mcp.api.app import build_application
from ssh_over_mcp.api.errors import RuntimeConfigurationError
from ssh_over_mcp.api.origin_auth import (
    OriginBearerAuthMiddleware,
    load_origin_bearer_token,
)
from ssh_over_mcp.api.runtime import MCPRuntimeSettings
from ssh_over_mcp.api.service import MCPService
from ssh_over_mcp.approvals.client import LedgerClientError

_TOKEN = b"SUPERSECRET_ORIGIN_MARKER_6A"
_CONFIG = """
inventory:
  hosts:
    host-a:
      address: 10.0.0.1
      port: 22
      ssh_user: test-user
      credential_ref: secret://host-a
      host_key: test-host-key
      allowed_roles: [developer]
policy:
  version: 1
  default: deny
  roles:
    developer: {}
  rules: []
"""
def _write_app_files(tmp_path: Path) -> tuple[Path, Path]:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(_CONFIG, encoding="utf-8")
    key_path = tmp_path / "host-a.key"
    key_path.write_text("test-key-material", encoding="utf-8")
    credential_map_path = tmp_path / "credentials.yaml"
    credential_map_path.write_text(
        "credentials:\n"
        f'  "secret://host-a": "{key_path}"\n',
        encoding="utf-8",
    )
    return config_path, credential_map_path


def _settings(tmp_path: Path, token_file: Path) -> MCPRuntimeSettings:
    config_path, credential_map_path = _write_app_files(tmp_path)
    return MCPRuntimeSettings(
        config_path=config_path,
        credential_map_path=credential_map_path,
        profile="developer",
        ledger_socket_path=tmp_path / "ledger-exec.sock",
        ledger_server_uid=os.getuid(),
        ledger_server_gid=os.getgid(),
        origin_bearer_token_file=token_file,
        port=8000,
    )


def _write_token(tmp_path: Path, token: bytes = _TOKEN) -> Path:
    path = tmp_path / "origin-bearer"
    path.write_bytes(token)
    return path
class ReadyLedgerClient:
    async def ping(self) -> None:
        return None

    async def append_audit(self, event) -> str:
        return f"evt_{event.request_id}"


class FailingLedgerClient:
    async def ping(self) -> None:
        raise LedgerClientError("SUPERSECRET ledger transport detail")


def test_load_origin_bearer_token_accepts_visible_ascii(tmp_path: Path) -> None:
    token = b"A9-._~" + (b"Z" * (4096 - 6))
    path = _write_token(tmp_path, token)

    assert load_origin_bearer_token(path) == token


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"A" * 4097,
        _TOKEN + b"\r",
        _TOKEN + b"\n",
        _TOKEN + b"\x00",
        _TOKEN + b" ",
        _TOKEN + b"\x1f",
        _TOKEN + b"\x7f",
    ],
)
def test_load_origin_bearer_token_rejects_invalid_token_file_bytes(
    tmp_path: Path,
    payload: bytes,
) -> None:
    path = _write_token(tmp_path, payload)

    with pytest.raises(RuntimeConfigurationError) as exc_info:
        load_origin_bearer_token(path)

    assert str(exc_info.value) == "runtime configuration is invalid"
    assert _TOKEN.decode() not in str(exc_info.value)
def test_load_origin_bearer_token_rejects_directory(tmp_path: Path) -> None:
    path = tmp_path / "origin-bearer"
    path.mkdir()

    with pytest.raises(RuntimeConfigurationError, match="^runtime configuration is invalid$"):
        load_origin_bearer_token(path)


def test_load_origin_bearer_token_rejects_symlink(tmp_path: Path) -> None:
    target = _write_token(tmp_path)
    path = tmp_path / "origin-bearer-link"
    path.symlink_to(target)

    with pytest.raises(RuntimeConfigurationError, match="^runtime configuration is invalid$"):
        load_origin_bearer_token(path)


def test_load_origin_bearer_token_rejects_fifo(tmp_path: Path) -> None:
    path = tmp_path / "origin-bearer-fifo"
    os.mkfifo(path)

    with pytest.raises(RuntimeConfigurationError, match="^runtime configuration is invalid$"):
        load_origin_bearer_token(path)


def test_load_origin_bearer_token_failure_is_secret_safe(tmp_path: Path) -> None:
    path = _write_token(tmp_path, _TOKEN + b"\n")

    try:
        load_origin_bearer_token(path)
    except RuntimeConfigurationError as exc:
        rendered = traceback.format_exc()
        assert str(exc) == "runtime configuration is invalid"
        assert _TOKEN.decode() not in str(exc)
        assert _TOKEN.decode() not in rendered
    else:
        raise AssertionError("invalid token file must fail closed")
async def _ok_app(scope, receive, send) -> None:
    assert scope["type"] == "http"
    await send({"type": "http.response.start", "status": 204, "headers": []})
    await send({"type": "http.response.body", "body": b""})


async def _asgi_request(
    app,
    *,
    path: str = "/mcp",
    headers: list[tuple[bytes, bytes]] | None = None,
) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    sent: list[dict[str, object]] = []
    delivered = False

    async def receive() -> dict[str, object]:
        nonlocal delivered
        if delivered:
            return {"type": "http.disconnect"}
        delivered = True
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": headers or [],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8000),
    }
    await app(scope, receive, send)
    start = next(item for item in sent if item["type"] == "http.response.start")
    body = b"".join(
        item.get("body", b"")
        for item in sent
        if item["type"] == "http.response.body"
    )
    return int(start["status"]), list(start["headers"]), body
def _header_map(headers: list[tuple[bytes, bytes]]) -> dict[bytes, bytes]:
    return {name.lower(): value for name, value in headers}


@pytest.mark.asyncio
async def test_origin_auth_accepts_exact_bearer_case_insensitive_scheme() -> None:
    app = OriginBearerAuthMiddleware(_ok_app, token=_TOKEN)

    status, _headers, _body = await _asgi_request(
        app,
        headers=[(b"authorization", b"bEaReR " + _TOKEN)],
    )

    assert status == 204


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers",
    [
        [],
        [(b"authorization", b"Bearer WRONGSECRET")],
        [(b"authorization", b"Basic " + _TOKEN)],
        [(b"authorization", b"Bearer ")],
        [(b"authorization", b"Bearer  " + _TOKEN)],
        [(b"authorization", b"Bearer\t" + _TOKEN)],
        [(b"authorization", b"Bearer \xff")],
        [
            (b"authorization", b"Bearer " + _TOKEN),
            (b"authorization", b"Bearer " + _TOKEN),
        ],
    ],
)
async def test_origin_auth_rejects_invalid_authorization_uniformly(
    headers: list[tuple[bytes, bytes]],
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = OriginBearerAuthMiddleware(_ok_app, token=_TOKEN)

    status, response_headers, body = await _asgi_request(app, headers=headers)

    assert status == 401
    assert json.loads(body) == {"error": "origin authentication failed"}
    assert _header_map(response_headers)[b"www-authenticate"] == b"Bearer"
    assert _TOKEN not in body
    assert _TOKEN.decode() not in caplog.text
    assert b"WRONGSECRET" not in body
@pytest.mark.asyncio
async def test_origin_auth_only_protects_mcp_path_namespace() -> None:
    app = OriginBearerAuthMiddleware(_ok_app, token=_TOKEN)

    mcp_slash, _headers, _body = await _asgi_request(app, path="/mcp/")
    similar, _headers, _body = await _asgi_request(app, path="/mcpfoo")

    assert mcp_slash == 401
    assert similar == 204


def test_origin_auth_precedes_mcp_body_limit(
    tmp_path: Path,
) -> None:
    token_file = _write_token(tmp_path)
    app = build_application(_settings(tmp_path, token_file))
    oversized_body = b"x" * ((128 * 1024) + 1)

    with TestClient(app) as client:
        rejected = client.post(
            "/mcp",
            content=oversized_body,
            headers={
                "content-type": "application/json",
                "host": "127.0.0.1:8000",
            },
        )
        authenticated = client.post(
            "/mcp",
            content=oversized_body,
            headers={
                "authorization": "Bearer " + _TOKEN.decode(),
                "content-type": "application/json",
                "host": "127.0.0.1:8000",
            },
        )

    assert rejected.status_code == 401
    assert rejected.json() == {"error": "origin authentication failed"}
    assert authenticated.status_code == 413
@pytest.mark.parametrize(
    ("ledger_factory", "expected_ready"),
    [
        (ReadyLedgerClient, 200),
        (FailingLedgerClient, 503),
    ],
)
def test_origin_auth_leaves_health_and_readiness_credential_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ledger_factory,
    expected_ready: int,
) -> None:
    token_file = _write_token(tmp_path)
    monkeypatch.setattr(
        "ssh_over_mcp.api.app.build_ledger_client",
        lambda _settings: ledger_factory(),
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("health/readiness must not execute MCP domain operations")

    monkeypatch.setattr(MCPService, "list_hosts", forbidden)
    monkeypatch.setattr(MCPService, "get_host", forbidden)
    monkeypatch.setattr(MCPService, "explain_policy", forbidden)

    app = build_application(_settings(tmp_path, token_file))

    with TestClient(app) as client:
        health = client.get("/healthz")
        ready = client.get("/readyz")

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert ready.status_code == expected_ready
    assert _TOKEN.decode() not in health.text
    assert _TOKEN.decode() not in ready.text


def test_application_middleware_repr_redacts_origin_bearer(tmp_path: Path) -> None:
    token_file = _write_token(tmp_path)
    app = build_application(_settings(tmp_path, token_file))

    rendered = repr(app.user_middleware)

    assert _TOKEN.decode() not in rendered
    assert "<origin bearer redacted>" in rendered
