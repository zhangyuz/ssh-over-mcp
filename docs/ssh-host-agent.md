# Remote SSH host agent

## Purpose

The host agent is the second enforcement boundary. It prevents a compromised or misconfigured control plane from converting a dedicated MCP SSH credential into an unrestricted shell credential.

## OpenSSH entry point

A dedicated account should be configured with an authorized key or SSH certificate principal that forces the host agent, for example:

```text
restrict,command="/usr/local/libexec/ssh-over-mcp-host-agent" ssh-ed25519 AAAA...
```

Equivalent `sshd_config` `Match User` / `ForceCommand` configuration may be used.

## Required SSH restrictions

Unless a capability explicitly needs otherwise:

- no agent forwarding;
- no local/remote TCP forwarding;
- no X11 forwarding;
- no tunnel device forwarding;
- no user-controlled SSH environment;
- no PTY for structured operations;
- no arbitrary `.ssh/rc` behavior.

The Phase 2 client additionally disables ambient SSH configuration, ssh-agent authentication, password authentication, keyboard-interactive authentication, host-based authentication, GSS authentication/key exchange, PTY allocation, X11 forwarding, and SSH environment forwarding for structured operations.

## Host-key validation

The control plane connects to the server-owned inventory address while validating the host key against the inventory alias.

For each connection it constructs an in-memory `known_hosts` entry:

```text
<inventory-alias> <key-type> <base64-public-key>
```

and connects with that alias as the host-key lookup name. Unknown, malformed, or changed host keys fail closed.

Host aliases are restricted to letters, digits, `.`, `_`, and `-` so they cannot inject `known_hosts` patterns.

## Phase 2 host-agent wire protocol

Structured execution uses a fixed SSH exec command:

```text
mcp-v1
```

The executable, argv, cwd, environment, resource limits, and stdin are **not** embedded into that SSH command string.

Instead, stdin on the SSH channel contains:

```text
+----------------------+-----------------------------------------------+
| field                | encoding                                      |
+----------------------+-----------------------------------------------+
| magic                | 6 bytes: 53 4d 43 50 00 01 ("SMCP" + v1)      |
| metadata length      | 4-byte unsigned big-endian integer            |
| metadata             | UTF-8 JSON ExecEnvelope                       |
| application stdin    | remaining bytes                               |
+----------------------+-----------------------------------------------+
```

Metadata is limited to 64 KiB. The envelope defines bounded stdin, output, and execution time limits.

Conceptual metadata:

```json
{
  "version": 1,
  "request_id": "req_01...",
  "operation": "exec",
  "profile": "developer",
  "executable": "/usr/bin/git",
  "argv": ["status", "--short"],
  "cwd": "/srv/projects/app",
  "env": {},
  "limits": {
    "timeout_seconds": 60,
    "max_output_bytes": 1048576,
    "max_stdin_bytes": 1048576
  }
}
```

This framing has two important properties:

1. executable/argv/environment values are not shell-parsed by the SSH client path;
2. sensitive environment values are not placed in `SSH_ORIGINAL_COMMAND`.

The host agent MUST validate the fixed protocol command and parse the frame from stdin.

## Execution

Structured command execution MUST use an `execve`-equivalent path with a concrete executable and argv. The host agent MUST NOT turn structured execution into `sh -c`.

The central control plane MUST obtain an allow decision before opening the SSH connection for an operation.

## Resource handling

The Phase 2 client:

- shares one configured output-byte budget across stdout and stderr;
- closes the SSH channel when the output budget is exceeded;
- applies a wall-clock timeout;
- aborts the remote channel on caller cancellation;
- never requests a PTY for structured execution.

The remote host agent in Phase 3 MUST enforce its own limits independently. Client-side limits are not a substitute for server-side resource enforcement.

## Host-local policy

The host agent maintains a second policy boundary on each managed host. The default policy path is:

```text
/etc/ssh-over-mcp/host-policy.yaml
```

The policy file MUST be opened without following symlinks, MUST be a regular file, MUST be root-owned in production, and MUST NOT be group- or world-writable. The implementation bounds the policy file size and rejects duplicate YAML keys.

Phase 3c uses host-policy schema version 2. Each command policy binds:

- an exact requested executable path;
- an expected canonical filesystem realpath;
- one or more token-based argv rules (`exact` or non-empty `prefix`);
- canonical allowed cwd roots, or an explicit no-cwd allowance;
- whether the resolved executable must be root-owned;
- whether group/world-writable executables may be accepted.

Global host policy also constrains:

- exact allowed server-side profiles;
- allowed environment-variable names;
- hard-denied loader/runtime environment variables;
- maximum execution timeout requested by the control plane;
- maximum output budget requested by the control plane;
- maximum stdin budget requested by the control plane.

The host agent MUST apply metadata/resource checks before reading application stdin. A client cannot increase host limits by declaring larger limits in the request.

Executable authorization resolves the requested path and requires it to match the configured canonical target. The target MUST be a regular executable file and is root-owned/non-group-world-writable by default. Working directories are resolved with symlinks and MUST remain beneath an explicitly configured canonical root.

`exact` argv rules are the safer default. A `prefix` rule authorizes every trailing token after the configured prefix and MUST only be used when that wider argument surface is intentionally acceptable; it does not interpret shell syntax or constrain command-specific path/helper semantics.

Authorization results may carry canonical executable/cwd paths for the next stage, but Phase 3c still performs no process execution. Phase 3d MUST close the authorization-to-exec TOCTOU window using an fd-pinned or equivalently race-resistant execution mechanism before enabling commands.

The central policy may be more expressive, but the host-local policy should preserve critical invariants if the central layer is bypassed.

## OS account model

Prefer separate accounts for materially different privilege levels, for example:

- `mcp-observer`;
- `mcp-developer`;
- `mcp-operator`.

Avoid a permanently available root SSH account for normal operations.

## Privileged helper

A root helper may expose narrow operations such as:

```text
service.restart(webapp.service)
package.install(approved-package)
host.reboot()
```

It MUST validate its own input and MUST NOT expose a generic command string. If `sudoers` is used, permit only fixed helper binaries/arguments rather than `NOPASSWD: ALL`.

## Sandboxing

Where available, commands can be launched via systemd transient units, namespaces, cgroups, seccomp, AppArmor/SELinux, or containers. Development commands that execute repository code SHOULD receive stronger filesystem/network confinement than simple inspection commands.
