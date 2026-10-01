from __future__ import annotations

from contextlib import asynccontextmanager

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from ssh_over_mcp.config.loader import load_config
from ssh_over_mcp.policy.engine import PolicyEngine

from .principal import StaticPrincipalProvider
from .runtime import MCPRuntimeSettings
from .server import build_mcp_server
from .service import MCPService
from .ssh_runtime import build_ssh_runtime, load_credential_map

MAX_MCP_HTTP_REQUEST_BYTES = 128 * 1024


def build_application(
    settings: MCPRuntimeSettings,
) -> ASGIApp:
    bundle = load_config(settings.config_path)
    policy = PolicyEngine(
        inventory=bundle.inventory,
        policy=bundle.policy,
    )
    principal_provider = StaticPrincipalProvider(
        profile=settings.profile,
        policy=bundle.policy,
    )
    credential_map = load_credential_map(settings.credential_map_path)
    ssh_runtime = build_ssh_runtime(
        inventory=bundle.inventory,
        policy=policy,
        credential_map=credential_map,
    )
    service = MCPService(
        inventory=bundle.inventory,
        policy=policy,
        ssh_executor=ssh_runtime.executor,
    )
    mcp = build_mcp_server(
        service=service,
        principal_provider=principal_provider,
    )

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @mcp.custom_route("/readyz", methods=["GET"])
    async def readyz(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ready"})

    app = mcp.streamable_http_app(
        stateless_http=True,
        json_response=True,
        max_request_body_size=MAX_MCP_HTTP_REQUEST_BYTES,
        host="127.0.0.1",
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
    return app
