# Phase 7A Local E2E Foundation Design

- Status: Tasks 1–7 implemented and verified; Phase 7A4 closure in progress
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
   | ForceCommand → fixed no-argument sudo target
   v
root-owned capability launcher
   |
   | immediately drop to host-agent UID/GID
   | retain only CAP_SETUID + CAP_SETGID
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

Root is used by operator-owned fixture infrastructure to prepare trusted host state:
- fixture users/groups;
- sshd configuration and host key;
- root-owned host policy/config;
- delegated cgroup hierarchy;
- test filesystem ownership;
- narrowly scoped runtime directories.

Normal request execution has exactly one additional bounded root transition: the fixed host-agent capability launcher begins as root only long enough to validate its invocation context and establish the final non-root host-agent identity/capability state. No repository/application module may be imported or executed while that launcher still has UID 0 or broader capabilities.

### 6.2 MCP/control plane

The MCP process keeps the existing Phase 5/6 authority model:
- server-owned inventory/profile;
- no caller-selected host address/user/key/profile;
- no Ledger admin authority;
- no raw model-visible secrets;
- central policy/approval/audit remain authoritative before execution.

### 6.3 Host-agent capability launcher

Real sshd cannot directly provide the non-root ForceCommand process with the two Linux capabilities required by ADR 0005. Phase 7A therefore adds one fixed operator-installed launcher boundary.

The launcher contract is:
- ForceCommand invokes exactly one fixed no-argument sudo target;
- the installed launcher is root-owned and not writable by the SSH account;
- the sudo rule authorizes only that exact launcher command and no arguments;
- the launcher rejects any argv;
- before application import it validates the fixed SSH context (`SSH_ORIGINAL_COMMAND=mcp-v1`, no PTY);
- it sanitizes/ignores caller-controlled Python/import environment before application import;
- while still root, it moves only the current ForceCommand session into the fixed `host-agent-source` cgroup beneath the delegated root and verifies residency; the sshd master remains outside the delegated subtree;
- it sets the exact host-agent supplementary group set;
- it drops real/effective/saved GID and UID to the configured non-root host-agent identity;
- it retains only `CAP_SETUID` and `CAP_SETGID` in effective/permitted sets;
- it has zero inheritable/ambient capabilities and no `CAP_KILL`, `CAP_SYS_ADMIN`, or generic privilege;
- it verifies the resulting identity/capability state;
- only after that verification may it import/run `ssh_over_mcp.host_agent.cli`.

The launcher source may live in the repository for review, but the executable copy used by the trusted fixture is installed outside the checkout and is operator-owned. The E2E workflow verifies the installed artifact integrity before use.

### 6.4 Host agent

The host agent:
- is reached only through real sshd ForceCommand and the fixed capability launcher;
- is non-root before any `ssh_over_mcp` application module is imported;
- begins application execution with exactly `CAP_SETUID` and `CAP_SETGID` in effective/permitted sets and no other capabilities;
- uses the existing authenticated manager client;
- does not own writable cgroup authority;
- starts application execution inside the fixed `host-agent-source` cgroup so the non-root manager can lawfully migrate forked children into request scopes without owning the host/system cgroup hierarchy;
- keeps the existing capability/identity constraints required for the verified child identity transition.

### 6.5 Containment manager

The containment manager:
- owns only typed containment-management authority;
- is authenticated over the existing Unix-socket peer contract;
- does not receive SSH credentials, MCP credentials, or application policy authority;
- does not spawn arbitrary commands.

### 6.6 Workload

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
MCP → central authorization → SSH → real sshd → ForceCommand → fixed capability launcher → non-root host-agent → containment manager → native executable.

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

Each Level-3 E2E run has an outer persistent-host lifecycle and an inner disposable-guest lifecycle.

### 10.1 Persistent orchestrator lifecycle

The trusted orchestrator must:
1. run only trusted-main workflow/orchestration code under a dedicated non-admin account;
2. validate the requested target as an exact 40-hex commit;
3. fail closed on stale QEMU/provider artifacts or processes from an earlier run;
4. fetch the target into a temporary bare Git repository without checking out its worktree on the host;
5. create a Git bundle containing the exact target commit;
6. build a hash-verified Python 3.14 linux/amd64 wheelhouse from the trusted-main `requirements/runtime.lock`;
7. construct read-only cloud-init seed and payload media containing trusted bootstrap data, trusted-main read-only guest harness, exact target bundle, expected commit, runtime lock, and wheelhouse;
8. start a fresh pinned Ubuntu 26.04 x86_64 QEMU/HVF guest with `-nic none`, no host mounts/shares, no monitor, and serial-only result output;
9. never pass GitHub tokens, production credentials, unrelated host secrets, host sockets, or host network devices into the guest;
10. collect a commit-bound result through a host-bounded 2 MiB serial stream after QEMU exits;
11. remove overlay/media/log/bare-repository/bundle/wheelhouse state in a `finally` path and verify no stale provider process/artifact remains.

Unknown pre-existing provider state causes fail-closed startup rather than silent reuse or deletion.

### 10.2 Disposable guest lifecycle

Inside the fresh guest, the E2E must:
1. clone/checkout the transferred bundle and verify HEAD equals the requested target commit;
2. create disposable test identities/keys/cgroups/data;
3. install the exact target launcher at the fixed root-owned guest path;
4. start sshd and the containment manager;
5. start test-local Ledger/origin components as the non-root probe identity where applicable;
6. execute the E2E matrix;
7. collect security evidence;
8. teardown all disposable in-guest state;
9. verify teardown before guest destruction.

In-guest cleanup verification includes:
- no fixture sshd process;
- no manager process;
- no workload process;
- no leftover delegated/request cgroup;
- no Unix socket;
- no temporary SSH private key;
- no temporary origin credential;
- no temporary Ledger DB/HMAC material;
- no disposable test filesystem state;
- no unexpected fixture process/identity residue.

Business assertions passing with in-guest cleanup failure is an E2E failure. Guest destruction is an additional outer containment requirement, not a substitute for these assertions.

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

## 12. Disposable-guest workflow trust model

The existing ordinary CI and historical `ssh-over-mcp-cgroup-live` contract remain unchanged. Full product E2E adds a separate orchestration boundary rather than upgrading either runner with more privilege.

The reference persistent orchestrator is:
- a dedicated native macOS x86 account such as `gha-e2e-orchestrator`;
- non-admin/non-root with no passwordless sudo;
- a self-hosted runner used only by the trusted-main manual E2E workflow;
- QEMU 11.1.2 using HVF on Intel macOS with Hypervisor support;
- no target-commit checkout or execution on the persistent host.

The trusted guest image is Ubuntu 26.04 x86_64 server cloud image dated 2026-07-20 with SHA-256 `117816726abbdefc5ef3e38902e81a76f1c76c3610e709999d0885f9d5d9b477`.

The guest has **no virtual network device** (`-nic none`), no host filesystem mount/share, no QEMU monitor, no Docker socket, and no production secret. The target commit is transferred only inside a read-only payload image as a Git bundle produced from a host-side bare repository. The root gate and orchestrator come from the already-merged trusted-main checkout on the same read-only payload. As ADR 0008 specifies, target manager/probe/support/application code and the launcher under test come from the exact target checkout and run only inside the guest after the fixed non-root handoff. The target cannot supply or modify the root gate or orchestrator used to certify itself. Runtime wheels are prepared on the host from the trusted-main hash-locked runtime requirements and installed offline inside the guest. The GitHub token used to fetch the bundle remains on the orchestrator and is never copied into the guest. The target bundle is capped at 256 MiB, the guest virtual disk at 8 GiB, the serial stream at 2 MiB, and orchestration requires at least 16 GiB host free space.

The capability-bearing target checkout may become root inside the disposable guest. That is explicitly accepted by ADR 0006/0008 because the VM has no target-controlled network or host-filesystem/device path and receives only test-scoped state. It may not gain authority over the persistent orchestrator.

The real sshd path inside the guest remains:

```text
sshd
→ ForceCommand exact sudo target
→ fixed capability launcher
→ non-root host-agent with CAP_SETUID/CAP_SETGID only
→ authenticated containment manager
→ delegated cgroup-v2
→ zero-capability workload
```

The capability launcher must still prove that `ssh_over_mcp` application code is not imported while the launcher itself is root; the disposable VM does not weaken the production-representative inner boundary.

The root guest gate/orchestrator is trusted test authority and must already be merged to `main` before evaluating a later target commit. An unmerged target PR cannot modify the gate/orchestrator used to certify itself; trusted-authority changes and target-fixture changes are separate review/merge slices.

The E2E request is bound to an exact target commit through all of:
- trusted workflow `commit_sha` input;
- bare-repository fetch result;
- bundle target ref;
- guest checkout `git rev-parse HEAD`;
- guest expected-commit value.

The workflow run's GitHub `headSha` identifies the trusted-main workflow revision and is not the tested-commit identity.

After every run QEMU must exit and the disposable overlay, seed/payload media, temporary bundle/repository, and wheelhouse must be removed. Stale provider state before a run requires operator inspection rather than silent reuse.

## 13. Implementation slicing

Phase 7A is split into four independently reviewable slices.

### 7A1 — E2E fixture foundation

7A1 is intentionally split at the trust boundary:
- **7A1-trusted-gate:** merge the host orchestrator/root guest gate/provider contracts first; this slice does not use its own unmerged gate as Level-3 evidence.
- **7A1-target-fixture:** add the target manager/probe/support/launcher behavior and validate that exact PR head using the already-merged trusted-main gate.

Build only:
- trusted native-macOS QEMU/HVF orchestrator and pinned no-network guest definition;
- exact-commit bare-Git → bundle transfer with no host target checkout;
- fixture identities/configuration;
- real sshd + ForceCommand;
- fixed no-argument capability launcher and exact sudo contract;
- verified non-root host-agent startup with only `CAP_SETUID`/`CAP_SETGID`;
- manager socket;
- delegated cgroup;
- deterministic in-guest bootstrap/teardown;
- whole-guest destruction verification;
- exact-commit/provider integrity checks.

The completion focus is fixture privilege separation and cleanup.

### 7A2 — Happy-path product E2E
Connect:
MCP HTTP → policy/Ledger → SSH → sshd → capability launcher → non-root host-agent → containment → workload → audit.

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
2. the fixed capability launcher is root-owned, no-argument, exact-sudo authorized, integrity-checked, and enters application code only after reaching the exact non-root host-agent identity with only `CAP_SETUID`/`CAP_SETGID`;
3. pinned SSH host-key trust is verified;
4. real Security Ledger is used;
5. approval admin authority is separate;
6. authenticated containment manager is used;
7. real delegated cgroup-v2 is used;
8. workload identity/capability state is kernel-verified;
9. allowed MCP → workload execution succeeds end to end;
10. typed filesystem create-only semantics are proven end to end;
11. central deny has zero execution side effect;
12. host-local deny has zero workload exec;
13. approval replay fails closed;
14. host-key mismatch fails closed;
15. Ledger outage fails closed;
16. containment failure never releases the child to exec;
17. secrets are absent from model-visible output/audit/log evidence;
18. in-guest cleanup verification passes;
19. capability-bearing target checkout executes only inside a fresh disposable Linux VM, never on the persistent orchestrator;
20. the guest receives no virtual network device, host filesystem mount/share, GitHub token, production credential, unrelated host secret, or target-controlled host socket/device;
21. exact-target E2E evidence exists and whole-guest destruction is verified after every run;
22. ordinary CI security posture is not weakened;
23. development methodology is normative and linked from repository entrypoints;
24. final review has no remaining Critical/Important finding and exact PR-head/merge-main ordinary CI gates pass;
25. merged worktrees/branches, host-side bundle/wheelhouse/overlay/media/log state, QEMU process, and disposable in-guest fixture state are cleaned.

## 17. Later Phase 7 slices

After 7A:
- 7B: systemd sandbox, AppArmor/SELinux, and egress hardening;
- 7C: SSH CA and secret-manager integration;
- 7D: property/fuzz testing, security checklist, and Phase 7 final review.

Every later hardening slice regresses against the 7A E2E safety net.

## 18. Phase 7A evidence matrix

Level-3 E2E is required for changes affecting SSH, authorization,
approvals/Ledger, credentials, host-agent, containment, filesystem mutation,
audit, workload identity, OS hardening, egress, SSH CA, secret-manager
integration, or the E2E fixture. Phase closure and release candidates always
require full E2E. Ordinary CI stays unprivileged on its separate self-hosted
Linux runner; it receives no Docker socket or privileged fixture access.

The following evidence maps all 25 approved DoD criteria to executable checks.
The current verified baseline is PR #119 merge `d373598e7d0b5371765354a9ba89bf93f822828f`.
Phase 7A4 exact-head gates and cleanup remain pending; Phase 7A is not closed.

| # | Criterion | Executable evidence | Current evidence |
| --- | --- | --- | --- |
| 1 | Real sshd/ForceCommand | `tests/live/local_e2e_support.py` | Five-fixture guest PASS |
| 2 | Root launcher drops before application import | `tests/ops/test_host_agent_capability_launcher_contract.py` | Static/order checks plus real guest execution PASS |
| 3 | Pinned host key | `tests/live/local_e2e_support.py` | Wrong-key Task 6 fails before ForceCommand |
| 4 | Real Security Ledger | `tests/live/local_e2e_support.py` | Independent sealed audit DBs verify committed decisions |
| 5 | Separate approval admin authority | `tests/live/test_local_e2e.py` | Real production CLI subprocess; no MCP mutation tool |
| 6 | Authenticated containment manager | `tests/ops/test_live_e2e_gate_contract.py` | Fixed manager/host peer identities and real guest PASS |
| 7 | Delegated cgroup-v2 | `tests/live/local_e2e_support.py` | Real request scope membership and absence checks PASS |
| 8 | Kernel workload identity/capabilities | `tests/live/local_e2e_support.py` | UID/GID/groups/caps/NoNewPrivs and cgroup state PASS |
| 9 | Allowed MCP execution | `scripts/run-live-local-e2e-probe.py` | Real MCP → Ledger → SSH → workload PASS |
| 10 | Typed create-only filesystem behavior | `tests/live/local_e2e_support.py` | Write/mkdir/no-overwrite and profile separation PASS |
| 11 | Central denial before execution | `tests/live/local_e2e_support.py` | Sealed policy_denied; no SSH/marker/execution_started |
| 12 | Host-local denial before workload | `tests/live/local_e2e_support.py` | Real SSH; fixed exit 77; marker unchanged |
| 13 | Approval replay denied | `tests/live/local_e2e_support.py` | CLI grant/consume; replay needs a new approval |
| 14 | Host-key mismatch fail closed | `tests/live/local_e2e_support.py` | Pinned mismatch; generic error; no ForceCommand/marker |
| 15 | Ledger outage fail closed | `tests/live/local_e2e_support.py` | Health 200/readiness 503; no SSH or side effect |
| 16 | Containment outage prevents exec | `tests/live/local_e2e_support.py` | Final fixed STOP_MANAGER; generic exit 69; no request cgroup |
| 17 | No secret retention | `tests/live/local_e2e_support.py` | Client/audit/log/storage scans include Task 7 sentinels |
| 18 | In-guest cleanup | `tests/ops/test_live_e2e_gate_contract.py` | Trusted gate cleanup after target execution PASS |
| 19 | Target code only in disposable VM | `tests/ops/test_live_e2e_orchestrator_contract.py` | Bare-fetch/bundle; no persistent-host target worktree |
| 20 | No guest network/share/token/host channel | `tests/ops/test_live_e2e_orchestrator_contract.py` | Pinned QEMU -nic none, fixed devices/media, token exclusion |
| 21 | Exact commit and whole-guest destruction | `scripts/run-live-local-e2e-orchestrator.py` | Exact head/merge E2E; provider-state absence PASS |
| 22 | Ordinary runner posture unchanged | `tests/ops/test_live_e2e_orchestrator_contract.py` | Self-hosted unprivileged Linux; no Docker socket |
| 23 | Normative methodology linked | `tests/ops/test_phase7a_closure_evidence.py` | Trigger guidance consistency; repository entrypoints link method |
| 24 | Clean final review and ordinary CI | `tests/ops/test_phase7a_closure_evidence.py` | PR119 exact-head independent review and both CI runs PASS; 7A4 pending |
| 25 | Branches/processes/artifacts cleaned | `tests/ops/test_live_e2e_orchestrator_contract.py` | PR119 cleanup PASS; Phase 7A4 final cleanup pending |

### 18.1 Exact Task 7 acceptance evidence

- PR head `da23e044442d2d922bea11afa4c5c49cd117259e`: ordinary Python 3.13/3.14 [CI 37396007211](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/37396007211) PASS; trusted-main [Level-3 37396022348](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/37396022348) PASS, including provider-state absence and checkout cleanup.
- Exact merge `d373598e7d0b5371765354a9ba89bf93f822828f`: ordinary [CI 37396564506](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/37396564506) PASS; trusted-main [Level-3 37396581780](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/37396581780) PASS with cleanup.
- Fresh independent review of the exact PR head found no Critical, Important, or actionable Minor finding.
- After merge-main verification, 19 clean Phase 7A3 worktrees, 20 local branches, and 38 remote target/diagnostic branches were removed. Main matched origin at the exact merge SHA; no Phase 7A3 remote branches remained.

Ruling: earlier Task 6 unit/contract evidence did not certify live execution because the probe omitted its fixture call. PR #119 permanently wires the fixed five-fixture order; only subsequent passing full-matrix runs count for Task 6 and Task 7 acceptance. Sealed Ledger audit inspection replaces unreliable concurrent harness reads without weakening audit assertions.

Ruling: the guest installs trusted runtime dependencies offline and runs target source through a fixed source path. It does not install target console scripts. Task 7 therefore invokes the real `ssh-over-mcp-approvalctl` entry point as `python -m ssh_over_mcp.approvals.cli`, with the fixed target source path and bytecode disabled. Admin peer authentication and grant semantics are unchanged; approval mutation remains outside MCP.

### 18.2 Carried authority and deployment regression

Phase 7A4 regresses the existing suites under `tests/approvals/`, `tests/api/`, `tests/policy/`, `tests/ssh/`, and `tests/host_agent/` in full ordinary Linux CI. These cover single-use binding, principal isolation, durable audit, pre-network authorization, host identity, credential secrecy, privilege transition, attach-before-exec, and filesystem uncertainty/create-only semantics.

Phase 6 deployment checks remain `tests/ops/test_container_reproducibility_contract.py`, `tests/ops/test_compose_contract.py`, `tests/ops/test_cloudflare_connector_contract.py`, and the live reproducible-image/container/Compose/connector probes. The connector uses only a fake token and does not provision a Cloudflare account. Fresh Phase 7A4 Mac x86 deployment reruns passed: two independent no-cache builds were bit-reproducible; 14 container/Compose/fake-token connector tests passed. The tested image ID was `sha256:725c672918a0635d44336b1792f465eb2382e2e79cfa83279d605130b4c02b0e`. No live account provisioning was performed. Whole-phase review identified lifecycle integrity gaps; separate authority PR #120 merged as `76fdd4fee08f28b85b97c151617988120a7ae855` after exact-head ordinary CI and clean independent review. Its exact merge-main [CI 37397940466](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/37397940466) and [Level-3 37397957958](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/37397957958) passed, including provider-state absence and checkout cleanup. This already-merged authority now certifies the separate target/evidence slice. No closure claim is made here.


### 18.3 Whole-phase review findings and sequencing

Whole-phase review found missing markerless-QEMU detection and launcher copy
integrity checking. Separate authority PR #120 addresses those documented
invariants with RED/GREEN contracts and has merged at
`76fdd4fee08f28b85b97c151617988120a7ae855`; the target/evidence PR does not modify
its certifying gate. Exact-head [ordinary CI 37397679558](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/37397679558) and independent review passed before authority merge.
Exact authority merge-main [CI 37397940466](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/37397940466) and [Level-3 37397957958](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/37397957958) passed before target certification.

The trusted gate owns fixture lifecycle, exact commit binding, and cleanup.
Reviewed target probe/support owns product assertions and the gate checks its
exit status. Lifecycle success alone cannot prove product coverage: fixed
five-fixture contracts and independent review remain required. Accepted
guest-root-equivalent target authority means read-only guest harness storage
is not a hardware tamperproof boundary. ADR 0008's independent outer boundary
is the no-network/no-host-share VM and its destruction.

The target transcript scan now decodes stdout/stderr/filesystem base64 fields
on structured and JSON-text surfaces before comparing secret sentinels.
Malformed binary encoding fails closed. Seven focused RED/GREEN regressions
cover the formerly missed encoded-output surface; product secret handling is
unchanged.
