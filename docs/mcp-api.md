# MCP API

## Principles

- Prefer typed capabilities over a single generic shell tool.
- Keep `ssh_exec` for general structured command execution.
- Keep `ssh_shell` as a distinct privileged capability.
- Tool arguments identify logical hosts and resources; credentials remain server-side.
- Tool results are bounded and structured.

## Initial tool surface

### Discovery

#### `hosts_list`
Returns hosts visible to the current profile, including safe labels and capabilities.

#### `host_info`
Returns non-secret inventory and runtime information for one allowed host.

#### `policy_explain`
Explains an allow/deny/approval decision for a hypothetical normalized operation without executing it.

### Command execution

#### `ssh_exec`

Structured command execution.

Conceptual input:

```json
{
  "host": "dev01",
  "executable": "/usr/bin/git",
  "args": ["status", "--short"],
  "cwd": "/srv/projects/app",
  "env": {},
  "stdin": null,
  "timeout_seconds": 60
}
```

Requirements:

- MUST NOT use a shell to interpret `executable` or `args`;
- executable and arguments are policy-evaluated separately;
- `cwd` is policy-evaluated;
- environment is allowlisted;
- timeout and output bounds are enforced;
- remote host agent independently validates the structured request.

#### `ssh_shell`

Raw command-string execution. Separate capability; disabled by default; intended for explicitly authorized administrative/break-glass access.

A structured-command denial MUST NOT fall back to this tool.

### Filesystem

- `fs_list`
- `fs_stat`
- `fs_read`
- `fs_write`
- `fs_mkdir`
- `fs_move`
- `fs_delete`
- `fs_search`

Typed filesystem tools provide better audit semantics and path policy than equivalent shell commands. Their presence does not replace OS permissions.

Remote filesystem enforcement MUST NOT rely on a normalized path string alone.
After policy allows a path, the host boundary must independently pin path
components without following symlinks before touching the object. Paths are
absolute, lexically canonical, and hard-bounded to the Linux 4096-byte pathname
limit. Read-only operations are bounded and structured; they do not invoke
shell commands or PATH lookup.

The first host-agent filesystem slice supports only regular files and
directories for stat, and regular files for read. The final object is first
pinned and classified with an `O_PATH` descriptor; a read-capable descriptor is
opened only after the pinned inode is proven regular. Symlinks and special
objects (FIFO, socket, block/character device) therefore fail closed before a
data-capable open. File reads have a hard
64 MiB ceiling in addition to the caller/server policy bound.

Host-local read-only filesystem policy is profile-scoped. Each profile may have
separate canonical `stat_roots` and `read_roots`; read-enabled profiles also
require a strict server-owned `max_read_bytes` ceiling. Authorization is
lexical-only and does not resolve or open the requested path. The descriptor-
pinned primitive still performs the actual object access and independently
rejects symlinks/special objects. A sibling prefix such as `/srv/app2` is not
inside `/srv/app`.

These primitives and policy are not yet exposed as an SMCP operation or MCP
tool.

### Processes

- `process_list`
- `process_signal`

Signal permissions are policy-controlled by process identity/scope where feasible.

### Services

- `service_status`
- `service_action`

`service_action` accepts a service identifier and an enumerated action such as `start`, `stop`, `restart`, or `reload`. It is preferred over arbitrary `systemctl` invocation when managing production services.

### Logs and metrics

- `logs_read`
- `host_metrics`

### Approval / elevation

- `request_elevation`
- `approval_status`

These tools create or inspect approval requests. They do not themselves grant privilege without a trusted approval path.

### Audit

- `audit_query`

Read-only and restricted to profiles permitted to inspect audit events.

## MCP transport

The remote MCP server uses Streamable HTTP at `/mcp`. The implementation SHOULD track the current MCP stable SDK/specification and SHOULD support stateless requests when available. Protocol negotiation/compatibility is handled at the transport layer rather than by business policy.

## Annotations

Tools SHOULD accurately declare read-only, destructive, and open-world semantics where supported by the MCP SDK/client ecosystem. These annotations improve client behavior but are not authorization controls.

## Error model

Errors should distinguish:

- invalid request/schema;
- host not visible;
- policy denied;
- approval required;
- SSH transport failure;
- host-key failure;
- remote policy denied;
- timeout;
- output truncated;
- execution failure.

Do not return secret values in error details.
