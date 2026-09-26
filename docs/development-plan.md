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

Status: **Through Phase 3d2b2b1 merged; Phase 3d2b2b2a implemented on phase-3d2b2b2a-containment-contract; review/merge pending**

### Phase 3a — ForceCommand protocol entry

Implemented:

- installable `ssh-over-mcp-host-agent` entrypoint;
- exact `SSH_ORIGINAL_COMMAND=mcp-v1` validation;
- PTY rejection;
- bounded streaming SMCP v1 frame parser;
- metadata and stdin limits enforced before execution;
- fail-closed parse-only behavior: valid requests are not executed yet.

### Phase 3b — host-local request gate

Implemented:

- root-owned, no-symlink host-policy loader;
- duplicate-key and size validation;
- exact profile allowlist;
- exact executable allowlist;
- environment allowlist plus hard-denied loader variables;
- host-side timeout/output/stdin ceilings;
- metadata authorization before application-stdin read;
- fail-closed behavior after authorization; still no process execution.

### Phase 3c — canonical command authorization

Implemented:

- host-policy schema version 2 with per-command rules;
- exact/prefix argv token authorization;
- requested executable → expected realpath pinning;
- regular-file and execute-bit checks;
- root ownership and group/world-write controls;
- canonical cwd-root confinement;
- symlink retarget and cwd escape rejection;
- NUL-bearing argv/cwd/environment rejection;
- canonical resolved paths returned for the future execution stage;
- fail-closed behavior; still no process execution.

### Phase 3d1 — fd-pinned execution preparation

Implemented:

- authorization-time executable device+inode+ctime and cwd device+inode identities;
- host authorization repeated immediately before fd preparation;
- canonical executable opened with `O_NOFOLLOW|O_CLOEXEC`;
- canonical cwd opened as a directory fd with `O_NOFOLLOW|O_CLOEXEC`;
- fd identity revalidation using `fstat()`;
- executable ownership/writeability/setuid/setgid/capability revalidation on the pinned object;
- ELF/shebang/other format classification;
- fd-based `os.execve()` capability detection;
- deterministic descriptor cleanup;
- fail-closed behavior; still no process execution.

### Phase 3d2a — native fd-based exec primitive

Implemented:

- native ELF-only execution gate;
- fd-based `os.execve()` requirement;
- pinned cwd requirement; no ambient cwd inheritance;
- final executable identity revalidation using device+inode+ctime;
- final cwd identity revalidation using device+inode;
- explicit argv construction;
- explicit request environment only; no ambient `os.environ`;
- `fchdir(cwd_fd)` followed by `execve(executable_fd, ...)`;
- no shell or PATH lookup;
- disposable-child real exec smoke test;
- primitive remains disconnected from the ForceCommand CLI;
- signal/fd/stdio/rlimit process-state sanitation explicitly deferred to the child supervisor.

### Phase 3d2b1 — forked child supervisor skeleton

Implemented:

- parent-side native exec spec validation before fork;
- atomic close-on-exec stdin/stdout/stderr pipes;
- disposable child created with `fork()`;
- independent child session/process group via `setsid()`;
- child signal mask cleared and catchable signals reset;
- `umask 077`;
- core dumps disabled;
- child stdio installed with `dup2()`;
- unrelated child descriptors closed before exec;
- generic child exec failure message with fixed exit code 125;
- parent-side PID/pipe handle with deterministic pipe cleanup and wait;
- real `cat` integration coverage;
- supervisor remains disconnected from the ForceCommand CLI.

### Phase 3d2b2a — bounded parent execution loop

Implemented:

- nonblocking selector-based stdin/stdout/stderr loop;
- pre-spawn stdin byte-limit enforcement;
- wall-clock timeout;
- shared stdout+stderr output byte budget;
- exact capture truncation at the combined budget;
- SIGTERM process-group termination;
- SIGKILL escalation after grace;
- cleanup deadline and direct-child reap;
- structured execution result with timeout/output flags and duration;
- tests for cat round-trip, sleep timeout, yes output overflow, stderr capture and pre-setsid signal fallback;
- runner remains disconnected from the ForceCommand CLI.

### Phase 3d2b2b1 — host-local child rlimits

Implemented:

- host-policy schema version 3;
- required server-owned child resource ceilings;
- CPU-time limit via `RLIMIT_CPU`;
- address-space limit via `RLIMIT_AS`;
- process-count limit via `RLIMIT_NPROC`;
- regular-file-size limit via `RLIMIT_FSIZE`;
- open-file limit via `RLIMIT_NOFILE`;
- prepared commands carry their host-local child limits;
- effective limits clamp to stricter inherited hard limits;
- rlimit setup failures remain generic child exit 125;
- rlimits explicitly documented as defense-in-depth, not descendant containment.

### Phase 3d2b2b2a — descendant-containment contract

Implemented:

- backend-neutral `ContainmentBackend` and per-request `ContainmentHandle`;
- explicit finite `memory_max_bytes`, `pids_max`, `cpu_quota_us`, and `cpu_period_us`;
- attach / recursive kill-all / accounting / cleanup lifecycle;
- read-only cgroup-v2 probe;
- required `cpu`, `memory`, and `pids` controller detection;
- invalid request identifiers and non-positive/absurd limit values fail closed;
- no default/no-op backend and no supervisor integration yet.

### Remaining Phase 3 work

- Phase 3d2b2b2b: concrete cgroup-v2 backend plus fork-start barrier;
- Phase 3d2b2b2c: cgroup descendant-kill and resource-limit integration tests;
- Phase 3d2c: wire supervised native execution into the ForceCommand CLI only after containment is enforced;
- typed filesystem operations;
- execution-time resource enforcement;
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
