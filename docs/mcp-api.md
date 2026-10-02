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

Implemented in Phase 4 as the first side-effecting MCP adapter. It delegates to
the existing policy-gated `SSHExecutor`; the MCP layer does not implement a
second execution path.

Input:

```json
{
  "host": "dev01",
  "executable": "/usr/bin/git",
  "args": ["status", "--short"],
  "cwd": "/srv/projects/app",
  "env": {},
  "stdin": "",
  "timeout_seconds": 30
}
```

The server injects the trusted profile and fixed `privilege="user"`. Clients
cannot provide profile, SSH address/port/user, credential reference, host key,
request ID, privilege, output limit, or stdin limit.

Requirements and bounds:

- MUST NOT use a shell to interpret `executable` or `args`;
- executable, argv, cwd, and environment are evaluated by central policy before
  any SSH connection is acquired;
- policy denial and approval-required outcomes do not reach the network path;
- `stdin` is UTF-8 text with a 64 KiB MCP hard ceiling;
- `timeout_seconds` is optional, positive, no greater than 60 seconds, and may
  only tighten the active server-owned executor timeout;
- the client cannot widen the executor's server-owned stdin/output limits;
- the host agent independently validates the structured SMCP request;
- structured denial never falls back to `ssh_shell`.

Successful tool results contain server-generated `request_id`, logical host
alias, exit status/signal, duration, local collection `timed_out` /
`truncated` flags, and lossless `stdout_base64` / `stderr_base64` fields.
Arbitrary binary remote output is never guessed or lossy-decoded as UTF-8.

Policy denial, approval-required, credential, host-key, transport, and
unexpected execution-boundary failures are mapped to stable public errors.
Raw policy reasons, credential references, host keys, library exception text,
and other secret-bearing internal details are not returned.

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

The Phase 4 MCP `fs_stat` and `fs_read` adapters are now implemented.
Both accept only a logical host alias plus a bounded path; `fs_read` additionally
requires one strict positive `max_bytes` value capped at 1 MiB by the MCP
surface. The trusted profile and fixed user privilege are injected server-side.
Host visibility and central policy are evaluated before the shared structured
SSH transport can acquire a connection. The central normalized path is the only
path placed in the typed SMCP envelope, and the host agent independently applies
its profile-scoped path policy and descriptor-pinned object checks.

`fs_stat` returns server-generated request ID, host alias, normalized path,
kind, size, mode, uid, gid, and mtime_ns. `fs_read` returns the request ID,
host alias, normalized path, and lossless `data_base64`. A file larger than
the requested bound is rejected rather than truncated. Remote policy denial,
timeout, control-plane output overflow, malformed remote responses, credential,
host-key, and transport failures are mapped to stable public errors without
returning raw remote stderr or internal exception detail.

The host agent also exposes create-only `fs_mkdir` as a typed SMCP v1
operation. Its request is metadata-only and contains only request ID, profile,
operation, and path. Mode, owner, recursive, parents, and overwrite fields are
not part of the schema and extra metadata is rejected. The host agent applies
the profile-scoped `mkdir_roots` policy and rejects any trailing request body
before calling the one-level create-only directory primitive. The parent must
already exist, the final entry must be absent, and the server-owned maximum mode
is `0700`.

The Phase 4 MCP `fs_mkdir` adapter is now implemented. MCP input contains only
logical host alias and bounded path; the trusted profile and fixed user
privilege are injected server-side. Host visibility and central policy complete
before the structured SSH transport can acquire a connection, and only the
central normalized path enters `FsMkdirEnvelope`.

A clean remote status 77 is a definite host-policy denial. A channel-open
failure is also a definite pre-request transport failure. Once the request may
have been sent, however, timeout, collection/output failure, nonzero status other
than clean policy denial, malformed success output, or other foreign transport
failure is returned as `filesystem mutation outcome uncertain; do not retry
blindly`. This conservative classification is required because the directory
may already have been created even if its success response was lost.

The host agent also exposes create-only `fs_write` as typed SMCP v1. Metadata
contains request ID, profile, operation, path, and one strict non-negative
`content_length`; overwrite, append, mode, and owner semantics are absent and
extra fields are rejected. The raw request body must match the declared length
exactly. Host-local write-create policy is evaluated before body read, and the
create-only primitive is not called until the complete authorized body and EOF
have been observed. Success returns status 0 with empty stdout. Pre-publication
failures use the generic filesystem failure. If publication committed but the
parent-directory fsync fails, status 74 plus a fixed host-owned diagnostic means
durability is uncertain and the caller MUST NOT blindly retry.

The Phase 4 MCP `fs_write` adapter is now implemented. MCP input contains only
logical host alias, bounded path, and canonical strict `data_base64`. The MCP
surface caps decoded content at 64 KiB so a maximum-size request remains inside
the existing 128 KiB Streamable HTTP request-body limit; that outer cap does not
replace the host-agent profile-specific `write_create_roots` and
`max_write_bytes` checks. `content_length` is derived server-side from decoded
bytes and cannot be supplied by the caller.

Only the centrally normalized path and server-derived content length enter
`FsWriteEnvelope`; the exact decoded bytes are the SMCP body. The existing
host-agent primitive remains create-if-absent, publishes an unnamed `O_TMPFILE`
only after full write and file fsync, uses maximum mode `0600`, and fsyncs the
parent directory after publication. Overwrite, append, caller-selected mode/
owner, move, and delete remain unavailable.

A clean remote status 74 maps to the distinct public outcome
`filesystem write committed; durability uncertain; do not retry blindly`.
A clean status 77 remains a definite host-policy denial. Any local timeout,
truncation, signal ambiguity, status 69, lost acknowledgement, or other
post-send transport/collection failure maps to generic mutation-outcome-
uncertain with the same do-not-retry-blindly rule. Definite credential,
host-key, connection, and channel-open failures remain pre-request transport
errors.

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
- `GET /readyz` -> `{"status":"ready"}` only when the authenticated local
  Security Ledger execution endpoint answers its bounded ping; ledger failure
  returns HTTP 503 with `{"status":"not_ready"}`.

They are not MCP tools and they do not probe inventory hosts or establish SSH
sessions. Runtime configuration uses required `SSH_OVER_MCP_CONFIG`,
`SSH_OVER_MCP_CREDENTIAL_MAP`, `SSH_OVER_MCP_PROFILE`,
`SSH_OVER_MCP_LEDGER_EXEC_SOCKET_PATH`,
`SSH_OVER_MCP_LEDGER_SERVICE_UID`, and
`SSH_OVER_MCP_LEDGER_SERVICE_GID`, plus optional
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
`FileCredentialProvider -> SSHConnectionManager` boundary plus one shared
`StructuredSSHTransport`; `SSHExecutor` consumes that transport after central
policy allows execution. Composition does not resolve a credential or open SSH.
Application shutdown closes the pooled SSH connection manager after the MCP SDK
lifespan exits.

The registered MCP surface is now `hosts_list`, `host_info`,
`policy_explain`, `ssh_exec`, `fs_stat`, `fs_read`, `fs_mkdir`, and
`fs_write`.
Health/readiness remain ordinary HTTP routes and do not appear in the MCP tool
registry.

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
- filesystem mutation outcome uncertain / do not retry blindly;
- filesystem write committed / durability uncertain / do not retry blindly;
- required audit persistence failure;
- post-attempt audit persistence outcome uncertain / do not retry blindly;
- execution failure.

Do not return secret values in error details.
