# Development roadmap

## Phase 0 — specification baseline

Status: **complete**

Deliverables:

- source-of-truth docs;
- ADR baseline;
- repository skeleton;
- threat model;
- initial tool and policy schemas.

Exit criteria: security invariants and API semantics are reviewable before implementation.

## Phase 1 — policy core

Status: **complete; merged to main**

Implemented:

- typed configuration loader;
- host inventory schema;
- role/capability schema;
- allow/deny evaluator;
- command capability classification;
- filesystem path normalization helpers;
- risk classification;
- deterministic policy-explain output.

Tests:

- deny overrides allow;
- no-match denies;
- inheritance does not widen denied capability;
- host alias cannot escape inventory;
- executable canonicalization;
- environment allowlist;
- path traversal/symlink cases.

## Phase 2 — SSH execution core

Status: **complete; merged to main**

Implemented:

- AsyncSSH-based client transport;
- pinned host-key validation via inventory alias;
- no ambient SSH config/agent/password/GSS fallback;
- credential-provider abstraction;
- structured binary-framed remote envelope;
- fixed `mcp-v1` SSH command;
- no PTY / X11 / SSH environment forwarding for structured execution;
- bounded stdin and combined stdout/stderr;
- timeouts and cancellation cleanup;
- connection pooling with age limit;
- per-host session concurrency limit;
- policy decision before network access.

## Phase 3 — remote host agent

Status: **Phase 3a parser implemented on phase-3a-host-agent-parser; review/merge pending**

### Phase 3a — ForceCommand protocol entry

Implemented:

- installable `ssh-over-mcp-host-agent` entrypoint;
- exact `SSH_ORIGINAL_COMMAND=mcp-v1` validation;
- PTY rejection;
- bounded streaming SMCP v1 frame parser;
- metadata and stdin limits enforced before execution;
- fail-closed parse-only behavior: valid requests are not executed yet.

### Remaining Phase 3 work


- ForceCommand executable;
- streaming Phase 2 protocol parser;
- host-local policy;
- structured exec without shell interpretation;
- filesystem operations;
- resource controls;
- optional privileged helper protocol.

Adversarial tests include malformed envelopes, command injection, env injection, PTY/forwarding attempts, and bypass through alternate executables.

## Phase 4 — MCP surface

Implement Streamable HTTP MCP server and tools documented in `mcp-api.md`. Include health/readiness endpoints outside the MCP tool surface.

## Phase 5 — audit and approvals

Implement request IDs, policy hashes, structured audit sinks, approval store, approval request hashing, expiration, and single-use behavior.

## Phase 6 — Cloudflare reference deployment

Provide:

- container image;
- Docker Compose reference;
- no-public-port private networking pattern;
- Cloudflare Tunnel route instructions;
- MCP Portal + Managed OAuth instructions;
- service-token instructions;
- Gateway logging/DLP guidance.

## Phase 7 — hardening

- systemd sandbox reference profiles;
- AppArmor/SELinux guidance;
- egress policy examples;
- SSH CA support;
- secret-manager integration;
- fuzz/property testing of policy and host-agent protocol;
- security review checklist.

## Definition of done for v1

A v1 release must demonstrate:

1. at least two roles with materially different permissions;
2. multiple inventory-managed hosts;
3. structured exec and typed filesystem/service operations;
4. raw shell disabled for normal roles and approval-gated for admin;
5. pinned host-key failure behavior;
6. remote ForceCommand enforcement;
7. deny-overrides-allow policy tests;
8. audit trail for allow/deny/execution/approval;
9. private Cloudflare Portal deployment without public origin port;
10. adversarial tests for common policy bypasses.
