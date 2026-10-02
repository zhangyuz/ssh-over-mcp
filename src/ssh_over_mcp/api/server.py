from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import ValidationError

from ssh_over_mcp.audit.models import AuditEventType
from ssh_over_mcp.audit.recorder import (
    AuditPersistenceFailure,
    AuditRecorder,
)

from .context import OperationContext, new_request_id
from .errors import ApiError
from .models import (
    ExplainableTool,
    FsMkdirRequest,
    FsMkdirResult,
    FsReadRequest,
    FsReadResult,
    FsStatRequest,
    FsStatResult,
    FsWriteRequest,
    FsWriteResult,
    HostsListResult,
    HostSummary,
    MCPHostAlias,
    PolicyExplainRequest,
    PolicyExplainResult,
    SSHExecRequest,
    SSHExecResult,
)
from .principal import PrincipalProvider
from .service import MCPService

_READ_ONLY_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True,
    open_world_hint=False,
)
_EXEC_ANNOTATIONS = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=True,
    idempotent_hint=False,
    open_world_hint=False,
)
_CREATE_ONLY_ANNOTATIONS = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=False,
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
        try:
            return await super().call_tool(name, arguments, context)
        except ToolError as exc:
            if isinstance(exc.__cause__, ValidationError):
                raise ToolError("invalid tool input") from None
            raise


def build_mcp_server(
    *,
    service: MCPService,
    principal_provider: PrincipalProvider,
    audit: AuditRecorder,
) -> MCPServer:
    mcp = StrictMCPServer("ssh-over-mcp")

    def operation_context() -> OperationContext:
        return OperationContext(
            request_id=new_request_id(),
            principal=principal_provider.get_principal(),
            received_at=datetime.now(UTC),
        )

    async def record_request_received(
        context: OperationContext,
        *,
        tool: str,
        host: str | None = None,
    ) -> None:
        try:
            await audit.request_received(
                context,
                tool=tool,
                host=host,
            )
        except AuditPersistenceFailure:
            raise ToolError("audit persistence failed") from None

    async def record_discovery_outcome(
        event_type: AuditEventType,
        context: OperationContext,
        *,
        tool: str,
        host: str | None = None,
    ) -> None:
        try:
            await audit.simple_event(
                event_type,
                context=context,
                tool=tool,
                host=host,
            )
        except AuditPersistenceFailure:
            raise ToolError("audit persistence failed") from None

    @mcp.tool(
        annotations=_READ_ONLY_ANNOTATIONS,
    )
    async def hosts_list() -> HostsListResult:
        """List hosts visible to the server-owned principal."""

        context = operation_context()
        await record_request_received(
            context,
            tool="hosts_list",
        )
        try:
            result = service.list_hosts(context)
        except ApiError as exc:
            await record_discovery_outcome(
                AuditEventType.EXECUTION_FAILED,
                context,
                tool="hosts_list",
            )
            raise ToolError(str(exc)) from exc

        await record_discovery_outcome(
            AuditEventType.EXECUTION_COMPLETED,
            context,
            tool="hosts_list",
        )
        return result

    @mcp.tool(
        annotations=_READ_ONLY_ANNOTATIONS,
    )
    async def host_info(alias: MCPHostAlias) -> HostSummary:
        """Return public metadata for one visible host alias."""

        context = operation_context()
        await record_request_received(
            context,
            tool="host_info",
            host=alias,
        )
        try:
            result = service.get_host(context, alias)
        except ApiError as exc:
            await record_discovery_outcome(
                AuditEventType.EXECUTION_FAILED,
                context,
                tool="host_info",
                host=alias,
            )
            raise ToolError(str(exc)) from exc

        await record_discovery_outcome(
            AuditEventType.EXECUTION_COMPLETED,
            context,
            tool="host_info",
            host=alias,
        )
        return result

    @mcp.tool(
        annotations=_READ_ONLY_ANNOTATIONS,
    )
    async def policy_explain(
        host: MCPHostAlias,
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
            request = PolicyExplainRequest(
                host=host,
                tool=tool,
                executable=executable,
                args=args,
                cwd=cwd,
                path=path,
                env={} if env is None else env,
                privilege=privilege,
            )
        except ValidationError:
            raise ToolError("invalid tool input") from None

        context = operation_context()
        await record_request_received(
            context,
            tool="policy_explain",
            host=host,
        )
        try:
            result = service.explain_policy(context, request)
        except ApiError as exc:
            await record_discovery_outcome(
                AuditEventType.EXECUTION_FAILED,
                context,
                tool="policy_explain",
                host=host,
            )
            raise ToolError(str(exc)) from exc

        await record_discovery_outcome(
            AuditEventType.EXECUTION_COMPLETED,
            context,
            tool="policy_explain",
            host=host,
        )
        return result

    @mcp.tool(
        annotations=_EXEC_ANNOTATIONS,
    )
    async def ssh_exec(
        host: MCPHostAlias,
        executable: str,
        args: tuple[str, ...] = (),
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        stdin: str = "",
        timeout_seconds: float | None = None,
    ) -> SSHExecResult:
        """Execute one policy-gated structured SSH command."""

        try:
            request = SSHExecRequest(
                host=host,
                executable=executable,
                args=args,
                cwd=cwd,
                env={} if env is None else env,
                stdin=stdin,
                timeout_seconds=timeout_seconds,
            )
        except ValidationError:
            raise ToolError("invalid tool input") from None

        context = operation_context()
        await record_request_received(
            context,
            tool="ssh_exec",
            host=host,
        )
        try:
            return await service.ssh_exec(context, request)
        except ApiError as exc:
            raise ToolError(str(exc)) from None

    @mcp.tool(
        annotations=_READ_ONLY_ANNOTATIONS,
    )
    async def fs_stat(
        host: MCPHostAlias,
        path: str,
    ) -> FsStatResult:
        """Return policy-gated metadata for one remote filesystem object."""

        try:
            request = FsStatRequest(host=host, path=path)
        except ValidationError:
            raise ToolError("invalid tool input") from None

        context = operation_context()
        await record_request_received(
            context,
            tool="fs_stat",
            host=host,
        )
        try:
            return await service.fs_stat(context, request)
        except ApiError as exc:
            raise ToolError(str(exc)) from None

    @mcp.tool(
        annotations=_READ_ONLY_ANNOTATIONS,
    )
    async def fs_read(
        host: MCPHostAlias,
        path: str,
        max_bytes: int,
    ) -> FsReadResult:
        """Read one bounded remote regular file without shell fallback."""

        try:
            request = FsReadRequest(
                host=host,
                path=path,
                max_bytes=max_bytes,
            )
        except ValidationError:
            raise ToolError("invalid tool input") from None

        context = operation_context()
        await record_request_received(
            context,
            tool="fs_read",
            host=host,
        )
        try:
            return await service.fs_read(context, request)
        except ApiError as exc:
            raise ToolError(str(exc)) from None

    @mcp.tool(
        annotations=_CREATE_ONLY_ANNOTATIONS,
    )
    async def fs_mkdir(
        host: MCPHostAlias,
        path: str,
    ) -> FsMkdirResult:
        """Create one policy-gated remote directory at an absent path."""

        try:
            request = FsMkdirRequest(host=host, path=path)
        except ValidationError:
            raise ToolError("invalid tool input") from None

        context = operation_context()
        await record_request_received(
            context,
            tool="fs_mkdir",
            host=host,
        )
        try:
            return await service.fs_mkdir(context, request)
        except ApiError as exc:
            raise ToolError(str(exc)) from None

    @mcp.tool(
        annotations=_CREATE_ONLY_ANNOTATIONS,
    )
    async def fs_write(
        host: MCPHostAlias,
        path: str,
        data_base64: str,
    ) -> FsWriteResult:
        """Create one absent remote regular file from bounded base64 bytes."""

        try:
            request = FsWriteRequest(
                host=host,
                path=path,
                data_base64=data_base64,
            )
        except ValidationError:
            raise ToolError("invalid tool input") from None

        context = operation_context()
        await record_request_received(
            context,
            tool="fs_write",
            host=host,
        )
        try:
            return await service.fs_write(context, request)
        except ApiError as exc:
            raise ToolError(str(exc)) from None

    return mcp
