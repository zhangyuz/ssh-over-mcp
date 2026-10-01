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
Implemented in the first Phase 4 slice. Returns only logical aliases visible to
the server-owned principal. Existing inventory labels are not yet classified as
public, so labels and capabilities are returned as empty lists.

#### `host_info`
Implemented in the first Phase 4 slice. Returns the same alias-only public
identity for one visible host. Unknown and role-hidden aliases produce the same
public not-visible error. This slice does not open SSH or probe host runtime
state.

#### `policy_explain`
Implemented in the first Phase 4 slice. Evaluates a hypothetical central-policy
request without execution or SSH access. The trusted profile is injected by the
server, hidden hosts fail before policy evaluation, and the result exposes only
the sanitized decision/reason/risk, caller-originated normalized
executable/cwd/path, approval requirement, and policy version. Matched rule IDs,
effective roles, capabilities, credentials, host keys, configured roots, and
environment values are not returned. Policy-explain request metadata is capped at
64 KiB, with explicit bounds on path-like fields, argv, environment entries,
and privilege text.

### Command execution

#### `ssh_exec`

Implemented as the first side-effecting Phase 4 MCP adapter. It delegates to
the existing policy-gated `SSHExecutor`; the MCP layer does not implement a
second SSH or execution path.

Input:

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
- the trusted profile is injected by the server and is never a tool argument;
- only logical inventory aliases are accepted; SSH address/user/port,
  credential reference, host key, request ID, and output/stdin ceilings are
  not client-selectable;
- host visibility is checked before execution;
- executable, arguments, cwd, and environment are evaluated by the existing
  central policy path before network access;
- client `timeout_seconds` may only tighten the server-owned executor default;
- stdin is UTF-8 text at the MCP boundary and is checked against the
  server-owned byte ceiling after encoding;
- stdout/stderr remain bounded by the executor and are returned losslessly as
  `stdout_base64` / `stderr_base64`;
- policy denial, approval-required, credential, host-key, transport, protocol,
  and unexpected executor/library failures are mapped to stable public errors
  without raw secret-bearing exception detail;
- nonzero remote exit status, local collection timeout, and output truncation
  remain structured result fields rather than shell-style fallback behavior;
- application shutdown closes the pooled SSH connection manager;
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

The host agent now exposes typed SMCP v1 `fs_stat` and `fs_read`
operations using the same bounded metadata frame as `exec`. Filesystem
requests are metadata-only: any trailing application stdin is a protocol error
and object access does not begin. `fs_stat` returns compact JSON metadata on
stdout; `fs_read` returns raw file bytes. Host-policy denial and filesystem
access failure return generic SSH-visible errors without policy-root or inode
details.

These are host-agent wire operations only. The MCP `fs_stat` and `fs_read`
adapters remain future Phase 4 slices; they are not registered by the initial
discovery/explanation server.

The host agent also exposes create-only `fs_mkdir` as a typed SMCP v1
operation. Its request is metadata-only and contains only request ID, profile,
operation, and path. Mode, owner, recursive, and overwrite fields are not part
of the schema and extra metadata is rejected. The host agent applies the
profile-scoped `mkdir_roots` policy and rejects any trailing request body before
calling the one-level create-only directory primitive. Success returns status 0
with no stdout body. Policy denial and primitive failure remain generic. This is
not yet an MCP `fs_mkdir` tool.

The host agent also exposes create-only `fs_write` as typed SMCP v1. Metadata
contains request ID, profile, operation, path, and one strict non-negative
`content_length`; overwrite, append, mode, and owner semantics are absent and
extra fields are rejected. The raw request body must match the declared length
exactly. Host-local write-create policy is evaluated before body read, and the
create-only primitive is not called until the complete authorized body and EOF
have been observed. Success returns status 0 with empty stdout. Pre-publication
failures use the generic filesystem failure. If publication committed but the
parent-directory fsync fails, status 74 plus a fixed host-owned diagnostic means
durability is uncertain and the caller MUST NOT blindly retry. This is not yet
an MCP `fs_write` tool.

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

The first Phase 4 server uses the official MCP Python SDK v2 and exposes
Streamable HTTP at `/mcp` with stateless JSON responses. Until verified OAuth
identity is added, the packaged server binds only to `127.0.0.1` and uses one
operator-configured static principal profile from `SSH_OVER_MCP_PROFILE`.
Clients cannot override that profile through tool arguments, query parameters,
or arbitrary request metadata.

Local liveness/readiness are ordinary HTTP endpoints:

- `GET /healthz` -> `{"status":"ok"}`;
- `GET /readyz` -> `{"status":"ready"}`.

They are not MCP tools and they do not probe inventory hosts or establish SSH
sessions. Runtime configuration uses required `SSH_OVER_MCP_CONFIG`,
`SSH_OVER_MCP_CREDENTIAL_MAP`, and `SSH_OVER_MCP_PROFILE`, plus optional
`SSH_OVER_MCP_PORT` (default 8000).

The credential-map file is operator-owned YAML or JSON. It contains only
logical inventory credential references mapped to absolute paths of already
mounted private-key files, for example:

```yaml
credentials:
  "secret://ssh/dev01": "/run/secrets/ssh/dev01"
```

Private-key bytes are never stored in this map. Startup fails closed if the
file shape is invalid, a mapped path is not an existing absolute file, or any
inventory credential reference lacks a mapping. Startup composes the existing
`FileCredentialProvider -> SSHConnectionManager -> SSHExecutor` chain but does
not resolve a credential or open SSH. The MCP registry in this slice remains
only `hosts_list`, `host_info`, and `policy_explain`; `ssh_exec` is still
a later separately reviewed adapter.

The Streamable HTTP endpoint rejects request bodies larger than 128 KiB before
MCP parsing. OAuth/claim-to-profile mapping remains a later Cloudflare-phase
concern.

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
