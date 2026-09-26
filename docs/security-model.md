# Security model

## Core invariants

1. **Default deny.** An operation without an explicit matching allow rule is denied.
2. **Deny overrides allow.** Any applicable deny rule terminates evaluation as denied.
3. **The model is not an authorization principal.** Roles, target credentials, and policy profiles are resolved server-side.
4. **Host inventory is authoritative.** Agents select a host alias only; they do not provide arbitrary IPs, usernames, keys, or host-key policy.
5. **SSH host keys are pinned or CA-validated.** Changed or unknown keys fail closed.
6. **Structured execution is the normal command path.** Raw shell is separately authorized.
7. **Filesystem policy is not the final boundary.** OS ownership, ACLs, namespaces, MAC policy, and dedicated users remain authoritative when arbitrary code execution is allowed.
8. **Privilege is explicit.** Root-equivalent operations use narrowly scoped helpers or time-limited break-glass access.
9. **No generic normal-role root path.** `NOPASSWD: ALL`, unrestricted `sudo`, Docker socket access, host namespace escape, and equivalent capabilities are prohibited for ordinary roles.
10. **All decisions are auditable.** Allow, deny, approval-required, execution start, and execution completion are logged with stable request IDs.
11. **Secrets are never model-facing.** SSH private keys, service tokens, origin credentials, and secret environment variables are not returned by tools or stored in tool descriptions.
12. **Policy changes are versioned.** Audit events record the policy version/hash used for the decision.

## Defense layers

```text
Cloudflare identity / service token
              |
MCP origin authentication
              |
role + host + capability policy
              |
command / path / env policy
              |
risk + approval
              |
SSH host-key validation
              |
remote ForceCommand agent
              |
remote local policy
              |
Linux user / ACL / sudo / sandbox
```

A layer may reduce risk from another layer failing; no single upper layer is treated as sufficient for root safety.

## Allowlist and denylist semantics

Allowlists define supported capability. Denylists block known-dangerous or contextually forbidden subsets. A denylist by itself is never sufficient because many programs can emulate shell or filesystem behavior.

Examples of shell-equivalent or code-execution-capable programs include interpreters, shells, editors with command escapes, build systems, package managers, container runtimes, and utilities that invoke external helpers. Policy MUST classify by capability rather than by command name reputation.

## Raw shell

`ssh_shell` MAY exist to satisfy the general remote-control goal, but:

- it is disabled in normal profiles;
- it MUST require an explicit role/capability;
- production use SHOULD require a short-lived approval;
- it MUST be fully audited;
- it MUST NOT bypass the remote OS account's restrictions;
- denial of a structured command MUST NOT automatically retry through raw shell.

## SSH requirements

- password authentication SHOULD be disabled for MCP service accounts;
- host key verification MUST be enabled;
- agent forwarding MUST be disabled by default;
- remote port forwarding and local forwarding MUST be disabled unless a specific capability requires them;
- PTY allocation SHOULD be disabled by default and enabled only for an explicitly authorized interactive session;
- SSH user environment injection MUST remain disabled unless narrowly constrained.

## Resource controls

Every execution path SHOULD support:

- wall-clock timeout;
- output byte limit;
- stdin byte limit;
- process/resource limits where available;
- cancellation;
- concurrency limits per identity/profile/host;
- rate limiting.

## Secret handling

Secret material should be provided from a secret manager, mounted file, short-lived SSH certificate flow, or equivalent protected runtime source. Long-lived private keys SHOULD NOT be embedded in repository configuration.
