from __future__ import annotations

from collections.abc import Callable
from contextlib import asynccontextmanager

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from ssh_over_mcp.approvals.client import LedgerClientError
from ssh_over_mcp.approvals.transport import LedgerTransportError
from ssh_over_mcp.config.loader import load_config
from ssh_over_mcp.policy.engine import PolicyEngine
from ssh_over_mcp.ssh.filesystem_list_v2 import VisibilityAuthority

from .ledger_runtime import build_ledger_client
from .origin_auth import (
    OriginBearerAuthMiddleware,
    load_origin_bearer_token,
    redact_origin_bearer_token,
)
from .principal import StaticPrincipalProvider
from .runtime import MCPRuntimeSettings
from .server import build_mcp_server
from .service import MCPService
from .ssh_runtime import build_ssh_runtime, load_credential_map

MAX_MCP_HTTP_REQUEST_BYTES = 128 * 1024


def build_application(
    settings: MCPRuntimeSettings,
    *,
    visibility_authority_factory: Callable[[PolicyEngine], VisibilityAuthority] | None = None,
    enable_fs_list: bool = False,
) -> ASGIApp:
    bundle = load_config(settings.config_path)
    policy = PolicyEngine(
        inventory=bundle.inventory,
        policy=bundle.policy,
    )
    if type(enable_fs_list) is not bool or (
        enable_fs_list and visibility_authority_factory is None
    ):
        raise ValueError("trusted visibility authority required for fs_list")
    visibility_authority = (
        visibility_authority_factory(policy)
        if visibility_authority_factory is not None
        else None
    )
    if visibility_authority is not None and visibility_authority.engine is not policy:
        raise ValueError("visibility authority must share the active policy engine")
    principal_provider = StaticPrincipalProvider(
        profile=settings.profile,
        policy=bundle.policy,
    )
    credential_map = load_credential_map(settings.credential_map_path)
    ledger_client = build_ledger_client(settings)
    ssh_runtime = build_ssh_runtime(
        inventory=bundle.inventory,
        policy=policy,
        credential_map=credential_map,
        ledger=ledger_client,
        visibility_authority=visibility_authority,
    )
    service = MCPService(
        inventory=bundle.inventory,
        policy=policy,
        approval_client=ledger_client,
        ssh_executor=ssh_runtime.executor,
        ssh_filesystem=ssh_runtime.filesystem,
    )
    mcp = build_mcp_server(
        service=service,
        principal_provider=principal_provider,
        audit=ssh_runtime.audit,
        enable_fs_list=enable_fs_list,
    )

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @mcp.custom_route("/readyz", methods=["GET"])
    async def readyz(_request: Request) -> JSONResponse:
        try:
            await ledger_client.ping()
        except (LedgerClientError, LedgerTransportError):
            return JSONResponse(
                {"status": "not_ready"},
                status_code=503,
            )
        return JSONResponse({"status": "ready"})

    app = mcp.streamable_http_app(
        stateless_http=True,
        json_response=True,
        max_request_body_size=MAX_MCP_HTTP_REQUEST_BYTES,
        host=settings.bind_host,
    )
    mcp_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application):
        async with mcp_lifespan(application):
            try:
                yield
            finally:
                await ssh_runtime.connections.close()

    app.router.lifespan_context = lifespan
    if settings.origin_bearer_token_file is not None:
        token = load_origin_bearer_token(settings.origin_bearer_token_file)
        app.add_middleware(
            OriginBearerAuthMiddleware,
            token=redact_origin_bearer_token(token),
        )
    return app
