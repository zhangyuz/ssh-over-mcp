# Remote SSH host agent

## Purpose

The host agent is the second enforcement boundary. It prevents a compromised or misconfigured control plane from converting a dedicated MCP SSH key into an unrestricted shell credential.

## OpenSSH entry point

A dedicated account should be configured with an authorized key or SSH certificate principal that forces the host agent, for example conceptually:

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

## Host-agent protocol

The control plane sends a versioned structured envelope over the forced command channel. Example conceptual payload:

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
  "timeout_seconds": 60
}
```

The transport encoding MUST avoid shell interpretation. The host agent parses and validates the envelope before execution.

## Execution

Structured command execution should use an `execve`-equivalent path with a concrete executable and argv. The host agent MUST NOT turn structured execution into `sh -c`.

## Host-local policy

The host agent maintains a local policy profile sufficient to constrain:

- allowed account/profile;
- allowed filesystem roots;
- allowed executable classes/paths where practical;
- privilege helper calls;
- PTY/forwarding behavior;
- resource limits.

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
