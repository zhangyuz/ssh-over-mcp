# Phase 7A Local E2E Foundation Design

- Status: Design approved; implementation not started
- Date: 2026-10-02
- Base: `a00c36f4260efa52d722222319ac78756f2b5562`

## 1. Purpose

Phase 7A establishes a real local end-to-end product safety net before additional OS, credential, and policy hardening is layered on top of the Phase 6 reference deployment.

The goal is not to add a new product capability. The goal is to prove that the existing product works through its real security boundaries from MCP ingress to managed-host execution, and that failure paths fail closed without bypassing those boundaries.

The project development methodology is also made normative in this phase so future work follows the same review/test/CI discipline independent of chat/session memory.

## 2. Core development principle

The project adopts this normative principle:

> **小步快跑，持续迭代，关注质量、安全、一致性。**

This means:
- ship small, independently reviewable slices;
- continuously convert uncertainty and review findings into evidence;
- treat quality, security, and consistency as completion constraints;
- never weaken a security invariant merely to keep velocity high.

The full normative workflow lives in `docs/development-methodology.md`.

## 3. Scope

Phase 7A includes:
- a complete local product E2E fixture;
- real OpenSSH `sshd`;
- real pinned host-key verification;
- real ForceCommand routing into `ssh-over-mcp-host-agent`;
- authenticated host-agent → containment-manager IPC;
- real delegated cgroup-v2 containment;
- real one-way workload identity drop;
- real Security Ledger approval/audit paths;
- real filesystem and structured-exec behavior;
- full cleanup verification;
- a dedicated high-security E2E workflow/trust model;
- methodology persistence and documentation linkage.

Phase 7A does not include:
- live Cloudflare account mutation;
- systemd sandbox/AppArmor/SELinux hardening itself;
- egress policy implementation;
- SSH CA implementation;
- secret-manager implementation;
- broad fuzz/property testing.

Those remain later Phase 7 slices and must regress against the 7A E2E safety net.
## 4. Why E2E-first

The repository already has strong isolated evidence for:
- MCP control-plane behavior;
- approvals and audit;
- SSH host-agent ForceCommand execution;
- authenticated containment-manager IPC;
- delegated cgroup-v2;
- workload UID/GID drop;
- container/Compose/Cloudflare reference deployment.

Without a product-level E2E path, later hardening can still fail by breaking the integration between these independently verified components.

Phase 7 therefore begins with E2E rather than adding more hardening surfaces first.

Alternatives rejected:
1. OS-hardening first — defers integration risk until after more boundaries change.
2. Credential-hardening first — expands identity/secret surface before a full product safety net exists.
3. Privileged all-in-one container E2E — convenient but does not prove the intended host privilege separation.

## 5. Local E2E architecture

The authoritative local E2E path is:

```text
E2E client
   |
   | MCP Streamable HTTP + origin bearer
   v
ssh-over-mcp MCP origin
   |
   +---- Security Ledger
   |
   | pinned-host-key SSH
   v
real OpenSSH sshd
   |
   | ForceCommand
   v
ssh-over-mcp-host-agent
   |
   | authenticated Unix socket
   v
containment manager
   |
   | delegated cgroup-v2
   v
workload identity
   |
   v
native executable / typed filesystem operation
```

This is a real Linux fixture. Mocks may support focused lower-level tests but do not count as the 7A completion E2E.

## 6. Security domains

### 6.1 Bootstrap authority

Root is used only by operator-owned fixture infrastructure to prepare trusted host state:
- fixture users/groups;
- sshd configuration and host key;
- root-owned host policy/config;
- delegated cgroup hierarchy;
- test filesystem ownership;
- narrowly scoped runtime directories.

Root is not part of normal request execution.

### 6.2 MCP/control plane

The MCP process keeps the existing Phase 5/6 authority model:
- server-owned inventory/profile;
- no caller-selected host address/user/key/profile;
- no Ledger admin authority;
- no raw model-visible secrets;
- central policy/approval/audit remain authoritative before execution.

### 6.3 Host agent

The host agent:
- is reached only through real sshd ForceCommand;
- uses the existing authenticated manager client;
- does not own writable cgroup authority;
- keeps the existing capability/identity constraints required for the verified child identity transition.

### 6.4 Containment manager

The containment manager:
- owns only typed containment-management authority;
- is authenticated over the existing Unix-socket peer contract;
- does not receive SSH credentials, MCP credentials, or application policy authority;
- does not spawn arbitrary commands.

### 6.5 Workload

The workload must be verified from the real kernel to have:
- configured workload UID/GID;
- no supplementary groups;
- zero effective/permitted/inheritable capabilities;
- zero ambient capabilities;
- `no_new_privs=1`;
- expected cgroup membership;
- no manager socket;
- no cgroup-management authority.
## 7. Start-barrier and fail-closed execution

The workload must not execute until containment attachment succeeds.

Required ordering:
1. trusted child/stdio/rlimit setup;
2. child waits behind existing start barrier;
3. manager authenticates request and attaches child to the request cgroup;
4. parent verifies successful attachment;
5. parent releases barrier;
6. child performs the verified identity/capability transition;
7. native exec occurs.

Any failure before barrier release must produce no workload execution side effect.

Containment attachment failure must never be “recovered” by running outside the cgroup.

## 8. E2E test matrix

The first E2E matrix covers complete mainline behavior and high-value failure paths.

### 8.1 Discovery
- `host_list`;
- `host_info`;
- only server-owned inventory is visible.

### 8.2 Allowed execution
An allowed `ssh_exec` request must traverse:
MCP → central authorization → SSH → real sshd → ForceCommand → host-agent → containment manager → native executable.

The test verifies stdout, exit status, workload identity, and audit lifecycle.

### 8.3 Central deny
A central DENY must:
- occur before remote workload execution;
- produce no remote side effect;
- produce the authoritative denial audit event.

### 8.4 Host-local deny
A request that central policy allows but host-local policy denies may cross the SSH boundary, but:
- no workload exec may occur;
- no typed mutation may occur.

### 8.5 Approval lifecycle
The E2E flow must prove:
1. first request becomes approval-required and does not execute;
2. MCP cannot grant/deny;
3. operator/admin boundary grants via `approvalctl`;
4. exact retry consumes the binding once;
5. replay fails;
6. changed binding fails.

### 8.6 Filesystem operations
Real managed-host filesystem tests include:
- `fs_stat`;
- `fs_read`;
- create-only `fs_mkdir`;
- create-only `fs_write`;
- existing destination rejection;
- no overwrite on replay/error.

### 8.7 Host-key mismatch
Changing the expected host-key trust material must fail closed before remote command execution.

### 8.8 Ledger outage
When the Security Ledger is unavailable:
- readiness reflects failure;
- authorization/execution cannot silently bypass Ledger;
- no mutation side effect occurs.

### 8.9 Containment failure
A forced attachment/containment failure must prove the child never crosses the start barrier.

### 8.10 Workload identity
The E2E run records real kernel evidence for UID/GID/groups/caps/`NoNewPrivs`/cgroup membership.

### 8.11 Audit and secret retention
Audit must contain the expected request/decision/approval/execution lifecycle while excluding:
- SSH private key material;
- origin bearer;
- Ledger HMAC;
- Cloudflare credentials;
- raw sensitive request body;
- other model-invisible secrets.

### 8.12 Multi-profile separation
Two materially different static-profile deployments must prove different permissions while requests cannot select or override the profile.
## 9. Error semantics

E2E validates where an error occurs, not merely that an error occurs.

Normative rule:

```text
reject as early as possible
+ fail closed
+ preserve authoritative audit semantics
+ do not expose lower-level secret/internal detail
+ never convert uncertainty into success
```

Examples:
- invalid origin credential → rejected at HTTP boundary;
- central deny → no SSH execution;
- approval-required → no workload execution;
- host-key mismatch → remote host is not trusted;
- host-local deny → no workload exec;
- containment attach failure → no barrier release;
- Ledger unavailable → no execute-first/audit-later behavior;
- durability-uncertain mutation → explicit uncertainty remains visible and is not automatically retried.

## 10. Fixture lifecycle

Each E2E run must:
1. validate exact trusted commit and fixture helper integrity;
2. reject unknown stale privileged state;
3. create disposable test identities/keys/cgroups/data;
4. start sshd, manager, Ledger, and origin;
5. execute the E2E matrix;
6. collect security evidence;
7. teardown all disposable state;
8. verify teardown.

Cleanup verification includes:
- no fixture sshd process;
- no manager process;
- no workload process;
- no leftover delegated/request cgroup;
- no Unix socket;
- no temporary SSH private key;
- no temporary origin credential;
- no temporary Ledger DB/HMAC material;
- no test filesystem state that the fixture contract marks disposable;
- no temporary fixture identities when fixture design uses per-run identities.

Business assertions passing with cleanup failure is an E2E failure.

Unknown stale privileged state causes fail-closed startup rather than silent repair.

## 11. CI and E2E gate model

### 11.1 Level 1 — ordinary PR validation

The normal self-hosted Linux x86 runner remains non-root and unprivileged.

It runs:
- unit;
- static contract;
- integration;
- adversarial/security;
- full pytest;
- supported Python versions;
- lint/compile verification.

Do not add Docker socket, broad sudo, host PID namespace, writable cgroup authority, or equivalent root escape to this runner.

### 11.2 Level 2 — deployment/container validation

Changes to image/Compose/container identity/mount/secret/network behavior additionally run the existing authorized Docker-host probes.

### 11.3 Level 3 — full Linux E2E

Full E2E is required before merge for changes affecting:
- SSH runtime/transport;
- policy/authorization;
- approvals/Ledger;
- credential handling;
- host-agent;
- containment;
- filesystem mutation semantics;
- audit;
- workload identity;
- systemd/AppArmor/SELinux;
- egress controls;
- SSH CA;
- secret-manager integration;
- the E2E fixture itself.

Phase closure and release-candidate work always requires full E2E.

Docs-only changes that do not change these boundaries do not require the expensive E2E gate.

## 12. High-privilege workflow trust model

The existing `ssh-over-mcp-cgroup-live` pattern is extended rather than weakening ordinary CI.

Operator-owned infrastructure outside the checkout owns:
- root helper;
- root-owned helper config;
- narrowly scoped sudo rule;
- helper hash/integrity expectation;
- delegated-cgroup/sshd/bootstrap authority.

The GitHub runner remains:
- non-root;
- zero capabilities;
- no Docker socket;
- no generic root shell.

The helper accepts only the reviewed fixed operation. Workflow/user input cannot inject arbitrary paths, UIDs, commands, sudo arguments, or helper flags.

The E2E request is bound to an exact trusted 40-hex commit.

This architecture makes full E2E required evidence without granting unchecked PR code generic root authority.
## 13. Implementation slicing

Phase 7A is split into four independently reviewable slices.

### 7A1 — E2E fixture foundation
Build only:
- fixture identities/configuration;
- real sshd + ForceCommand;
- manager socket;
- delegated cgroup;
- deterministic bootstrap/teardown;
- exact-commit/helper integrity checks.

The completion focus is fixture privilege separation and cleanup.

### 7A2 — Happy-path product E2E
Connect:
MCP HTTP → policy/Ledger → SSH → sshd → host-agent → containment → workload → audit.

Cover discovery, allowed exec, typed filesystem operations, audit, and kernel workload identity.

### 7A3 — Adversarial/fail-closed E2E
Add:
- central deny;
- host-local deny;
- approval grant/retry/replay;
- host-key mismatch;
- existing destination;
- Ledger outage;
- containment failure;
- secret non-retention;
- no-side-effect-before-authoritative-gate checks.

### 7A4 — Workflow gate and methodology persistence
Stabilize the dedicated E2E workflow/gating rules and ensure the normative methodology is linked from repository agent/source-of-truth entrypoints.

## 14. Development methodology persistence

`docs/development-methodology.md` is the normative method.

`AGENTS.md` must require agents to read and follow it before making behavior changes.

`docs/README.md` must include it in the source-of-truth hierarchy.

The methodology preserves:
- small slices;
- RED → minimal GREEN;
- targeted/full verification;
- security review;
- exact-head PR CI;
- fresh final review;
- exact merge-main CI;
- cleanup;
- written rulings;
- escalation to live/E2E when the boundary warrants it.

## 15. Cloudflare boundary

Phase 7A does not claim a real Cloudflare SaaS E2E.

The complete local E2E boundary starts at the MCP origin HTTP boundary and ends at real managed-host execution/filesystem/audit/approval behavior.

Existing Phase 6 Cloudflare connector/Portal/Access/Gateway tests and guidance remain valid.

A future live Cloudflare sandbox/account E2E requires explicit operator approval and separate design because it mutates external account state.

## 16. Definition of Done

Phase 7A is complete only when:
1. real sshd and ForceCommand are used;
2. pinned SSH host-key trust is verified;
3. real Security Ledger is used;
4. approval admin authority is separate;
5. authenticated containment manager is used;
6. real delegated cgroup-v2 is used;
7. workload identity/capability state is kernel-verified;
8. allowed MCP → workload execution succeeds end to end;
9. typed filesystem create-only semantics are proven end to end;
10. central deny has zero execution side effect;
11. host-local deny has zero workload exec;
12. approval replay fails closed;
13. host-key mismatch fails closed;
14. Ledger outage fails closed;
15. containment failure never releases the child to exec;
16. secrets are absent from model-visible output/audit/log evidence;
17. cleanup verification passes;
18. exact-head dedicated E2E evidence exists for required changes;
19. ordinary CI security posture is not weakened;
20. development methodology is normative and linked from repository entrypoints;
21. final review has no remaining Critical/Important finding;
22. exact PR-head and merge-main CI gates pass;
23. merged worktrees/branches and disposable fixture state are cleaned.

## 17. Later Phase 7 slices

After 7A:
- 7B: systemd sandbox, AppArmor/SELinux, and egress hardening;
- 7C: SSH CA and secret-manager integration;
- 7D: property/fuzz testing, security checklist, and Phase 7 final review.

Every later hardening slice regresses against the 7A E2E safety net.
