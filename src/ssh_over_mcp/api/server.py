from __future__ import annotations

from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .errors import ApiError
from .models import (
    ExplainableTool,
    HostsListResult,
    HostSummary,
    PolicyExplainRequest,
    PolicyExplainResult,
)
from .principal import PrincipalProvider
from .service import MCPService

_READ_ONLY_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True,
    open_world_hint=False,
)


class StrictMCPServer(MCPServer):
    """MCPServer which fails closed on undeclared top-level tool arguments."""

    async def list_tools(self):
        tools = await super().list_tools()
        for tool in tools:
            tool.input_schema = {
                **tool.input_schema,
                "additionalProperties": False,
            }
        return tools

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        context=None,
    ):
        tool = next(
            (
                candidate
                for candidate in await self.list_tools()
                if candidate.name == name
            ),
            None,
        )
        if tool is not None:
            allowed = set(
                tool.input_schema.get("properties", {})
            )
            if set(arguments).difference(allowed):
                raise ToolError("unexpected tool argument")
        return await super().call_tool(name, arguments, context)


def build_mcp_server(
    *,
    service: MCPService,
    principal_provider: PrincipalProvider,
) -> MCPServer:
    mcp = StrictMCPServer("ssh-over-mcp")

    @mcp.tool(
        annotations=_READ_ONLY_ANNOTATIONS,
    )
    def hosts_list() -> HostsListResult:
        """List hosts visible to the server-owned principal."""

        try:
            return service.list_hosts(
                principal_provider.get_principal()
            )
        except ApiError as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(
        annotations=_READ_ONLY_ANNOTATIONS,
    )
    def host_info(alias: str) -> HostSummary:
        """Return public metadata for one visible host alias."""

        try:
            return service.get_host(
                principal_provider.get_principal(),
                alias,
            )
        except ApiError as exc:
            raise ToolError(str(exc)) from exc

    @mcp.tool(
        annotations=_READ_ONLY_ANNOTATIONS,
    )
    def policy_explain(
        host: str,
        tool: ExplainableTool,
        executable: str | None = None,
        args: tuple[str, ...] = (),
        cwd: str | None = None,
        path: str | None = None,
        env: dict[str, str] | None = None,
        privilege: str = "user",
    ) -> PolicyExplainResult:
        """Explain central policy without executing the request."""

        try:
            return service.explain_policy(
                principal_provider.get_principal(),
                PolicyExplainRequest(
                    host=host,
                    tool=tool,
                    executable=executable,
                    args=args,
                    cwd=cwd,
                    path=path,
                    env={} if env is None else env,
                    privilege=privilege,
                ),
            )
        except ApiError as exc:
            raise ToolError(str(exc)) from exc

    return mcp
