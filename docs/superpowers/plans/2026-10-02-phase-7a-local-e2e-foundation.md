# Phase 7A Local E2E Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish a production-representative local Linux E2E safety net from authenticated MCP ingress through real SSH/ForceCommand/containment to workload/filesystem/audit behavior without weakening ordinary CI.

**Architecture:** A dedicated non-admin native macOS x86 orchestrator executes only trusted-main orchestration code. It fetches the exact target commit into a temporary bare Git repository, creates a bundle, starts a fresh pinned Ubuntu 26.04 Lima `vz` guest with no host mounts, copies the bundle into that guest, and runs all root/capability-bearing target code only inside the VM. Real guest sshd ForceCommand reaches one fixed root-owned capability launcher which drops to the non-root host-agent identity with only `CAP_SETUID`/`CAP_SETGID` before importing application code. In-guest cleanup is verified and the entire guest is destroyed after every run.

**Tech Stack:** macOS x86_64, Lima 2.2.0 / Virtualization.framework (`vz`), pinned Ubuntu 26.04 x86_64 cloud image, Python 3.13/3.14, OpenSSH, sudo, Linux capabilities via `prctl/capset`, cgroup v2, AsyncSSH, MCP Python SDK v2 Streamable HTTP, Security Ledger Unix sockets/SQLite, pytest, GitHub Actions self-hosted runners.

**Spec:** `docs/superpowers/specs/2026-10-02-phase-7a-local-e2e-foundation-design.md`

## Global Constraints

- Implementation MUST include the approved design commits `fff4527` and `2df40b9` or their merged descendants plus the disposable-guest ADR/spec correction recorded during Task 1.
- Core method: **小步快跑，持续迭代，关注质量、安全、一致性。**
- Ordinary CI remains `[self-hosted, linux, x64, ssh-over-mcp-mac-x86]`; never add a GitHub-hosted fallback or Docker socket.
- Preserve the existing `ssh-over-mcp-cgroup-live` contract unchanged; it is not upgraded or reused as a persistent target-code host.
- Full E2E uses a separate native macOS x86 orchestrator account/label: `gha-e2e-orchestrator` on `[self-hosted, macOS, X64, ssh-over-mcp-e2e-orchestrator]`.
- The orchestrator account is non-admin/non-root, has no passwordless sudo, and executes only the trusted-main workflow/orchestration script.
- The target commit MUST NOT be checked out or executed as a host worktree. The orchestrator fetches it into a temporary bare Git repository and creates a bundle.
- Fixed Lima provider: version `2.2.0`, driver `vz`, architecture `x86_64`, fixed instance name `ssh-over-mcp-e2e`, serialized workflow concurrency.
- Fixed guest image: Ubuntu 26.04 x86_64 server cloud image dated `2026-07-20`, digest `sha256:117816726abbdefc5ef3e38902e81a76f1c76c3610e709999d0885f9d5d9b477`.
- Guest starts with no host filesystem mounts, no Docker socket, and no product port-forward dependency. GitHub tokens and production/host secrets MUST NOT enter the guest.
- If the fixed Lima instance exists before a run, fail closed for operator inspection; never silently reuse/delete unknown pre-existing guest state.
- The trusted orchestrator creates a root-owned guest expected-commit file from the workflow `commit_sha`; guest checkout HEAD must equal that exact value.
- Fixed in-guest probe identity: `2204:3204`; manager `2201:3201`; host agent/SSH account `2202:3202`; workload `2203:3203`; manager-client supplementary GID `3299`.
- Fixed SSH account name: `ssh-over-mcp-e2e-host`; fixed probe account name: `ssh-over-mcp-e2e-probe`.
- Fixed loopback sshd port inside guest: `22222`; fail if occupied rather than choosing a caller-controlled port.
- Fixed guest workspace: `/opt/ssh-over-mcp-e2e/workspace`; Python environment: `/opt/ssh-over-mcp-e2e/venv`; cgroup root: `/sys/fs/cgroup/ssh-over-mcp-e2e`.
- Fixed launcher source/install path: `ops/live-e2e/ssh-over-mcp-host-agent-launcher.py` → `/usr/local/libexec/ssh-over-mcp-host-agent-launcher.py` inside the guest.
- ForceCommand sudo invocation is exactly `/usr/bin/python3 -I -S /usr/local/libexec/ssh-over-mcp-host-agent-launcher.py`; no launcher arguments are permitted.
- No `ssh_over_mcp` application module may be imported/executed while the launcher itself has UID 0 or capabilities broader than the final host-agent set.
- Final host-agent application state is non-root `2202:3202`, supplementary groups exactly `{3299}`, effective/permitted capabilities exactly `CAP_SETGID|CAP_SETUID`, inheritable/ambient capabilities zero.
- Workload state remains UID/GID `2203:3203`, no supplementary groups, zero effective/permitted/inheritable/ambient capabilities, `NoNewPrivs=1`.
- Capability-bearing target code may obtain root-equivalent authority only inside the disposable guest. Whole-guest destruction is mandatory even when in-guest cleanup passes.
- No live Cloudflare account mutation is part of Phase 7A.
- Every E2E-sensitive PR after trusted workflow bootstrap requires exact-target full E2E before merge; every merge/phase-closure candidate requires merge-main E2E too.

## PR / Slice Sequence

1. **7A1-bootstrap PR — Tasks 1–2:** land launcher source, disposable-guest orchestrator/config, guest gate source, trusted-main manual workflow, and static/security tests. This PR does not claim target-commit live E2E success because its workflow definition is not trusted-main until merge.
2. Operator provisions only the dedicated native macOS `gha-e2e-orchestrator` account/runner; no root helper/sudo policy is installed on the persistent host.
3. **7A1-live PR — Task 3:** prove real sshd → launcher → host-agent → manager → cgroup → workload inside a fresh disposable guest for the exact PR head using the already-trusted workflow from main.
4. **7A2 PR — Tasks 4–5:** happy-path MCP/Ledger/SSH/filesystem/audit/multi-profile E2E in fresh guests.
5. **7A3 PR — Tasks 6–7:** adversarial/fail-closed E2E in fresh guests.
6. **7A4 PR — Tasks 8–9:** gate documentation, whole-phase review, exact-target/merge-main E2E closure, cleanup.

The bootstrap ordering is intentional: an unmerged PR cannot modify the host-side workflow/orchestrator used as its own privileged-test authority. Once the bootstrap PR is merged, the trusted-main orchestrator may transfer and execute later exact target commits only inside disposable guests.

## Review Focus

1. **Python/import code executing while launcher is still root.** Task 1 tests the launcher under AST/order instrumentation and requires `-I -S`, environment sanitation, privilege verification, and delayed application import.
2. **ForceCommand/sudo environment loss or spoofing.** Tasks 1–3 test exact `SSH_ORIGINAL_COMMAND=mcp-v1`, no PTY, expected `SUDO_USER/UID/GID`, exact sudo command, and successful real sshd invocation.
3. **Capability-bearing target code escaping a persistent fixture or stale guest being reused.** Tasks 2–3 prove target worktrees never execute on the host, host mounts/tokens are absent from the guest, pre-existing fixed-name guests fail closed, deliberate probe failure still verifies in-guest cleanup, and the entire VM is deleted afterward.
4. **A test-control path turning into a generic root RPC.** Task 7 allows only one fixed control message, `STOP_MANAGER\n`, over an inherited socketpair; any other bytes fail the run and no paths/commands/IDs are accepted.
5. **Full E2E passing while a lower security boundary is bypassed.** Tasks 4–7 assert real origin auth, Ledger authorization/audit, pinned host key, sshd logs, host-local policy, launcher state, manager peer auth, cgroup membership, workload identity, and side-effect counters together.

---

## File Map

- Create `ops/live-e2e/ssh-over-mcp-host-agent-launcher.py` — standalone stdlib-only root-to-host-agent capability handoff.
- Create `ops/live-e2e/ssh-over-mcp-live-e2e-gate` — disposable-guest root fixture lifecycle owner.
- Create `ops/live-e2e/lima-ubuntu-26.04.yaml` — pinned no-host-mount guest definition.
- Create `ops/live-e2e/README.md` — orchestrator/guest provisioning contract; no persistent-host root installer.
- Create `scripts/run-live-local-e2e-orchestrator.py` — trusted-main Mac host bare-Git/bundle/Lima lifecycle controller.
- Create `.github/workflows/live-local-e2e.yml` — trusted-main, manual exact-target E2E workflow.
- Create `tests/ops/test_host_agent_capability_launcher_contract.py` — launcher static/order/security contract.
- Create `tests/ops/test_live_e2e_orchestrator_contract.py` — persistent-host isolation/provider/workflow contract.
- Create `tests/ops/test_live_e2e_gate_contract.py` — in-guest root-gate contract.
- Create `scripts/run-live-local-e2e-manager.py` — non-root containment-manager service process.
- Create `scripts/run-live-local-e2e-probe.py` — non-root exact-checkout E2E test launcher/metadata emitter.
- Create `tests/live/local_e2e_support.py` — typed fixture metadata plus real Ledger/MCP HTTP harness.
- Create `tests/live/test_local_e2e.py` — product-level happy/adversarial E2E matrix.
- Modify `tests/live/README.md` — dedicated full-E2E commands/evidence.
- Modify `docs/self-hosted-runner.md` — dedicated native macOS orchestrator and disposable-guest trust contract.
- Modify `docs/development-methodology.md` only if implementation reveals a missing normative gate; do not weaken approved rules.
- Modify `docs/development-plan.md` and Phase 7A spec only when exact evidence permits status advancement.
---

### Task 1: Implement the fixed host-agent capability launcher

**Slice:** 7A1-bootstrap

**Files:**
- Create: `ops/live-e2e/ssh-over-mcp-host-agent-launcher.py`
- Create: `tests/ops/test_host_agent_capability_launcher_contract.py`
- Modify: `ops/live-e2e/README.md` (created in this task with launcher installation contract)

**Interfaces:**
- Fixed invocation: `/usr/bin/python3 -I -S /usr/local/libexec/ssh-over-mcp-host-agent-launcher.py`
- `main(argv: Sequence[str] | None = None) -> int`
- Internal transition function: `_drop_and_verify(ops: _PrivilegeOps) -> None`
- Internal context function: `_validated_environment(argv: Sequence[str], env: Mapping[str, str]) -> dict[str, str]`
- Internal application entry: `_run_application() -> int`; this is the only function allowed to import `ssh_over_mcp`.
- Fixed application source after privilege drop: `/opt/ssh-over-mcp-e2e/workspace/src`.

- [ ] **Step 1: Write RED launcher contract tests**

Tests must assert:
- reviewed launcher file exists;
- top-level AST contains no import whose module begins with `ssh_over_mcp`;
- `_run_application` is the only scope containing that import;
- constants pin host UID/GID `2202:3202`, manager-client GID `3299`, workspace path, and expected cap mask bits 6/7 only;
- wrong argv, missing/wrong `SSH_ORIGINAL_COMMAND`, any `SSH_TTY`, wrong `SUDO_USER`, wrong `SUDO_UID/GID` reject before transition/application;
- sanitized environment contains only fixed safe values plus exact `SSH_ORIGINAL_COMMAND=mcp-v1` and excludes `PYTHONPATH`, `PYTHONHOME`, `LD_*`, user-controlled locale/module values;
- fake privilege ops prove ordering: validate → sanitize → keepcaps → groups/GID/UID drop → exact capset → keepcaps off → read-back verify → application import;
- any read-back mismatch prevents application entry.

Run the focused test and require RED because the launcher does not yet exist.

- [ ] **Step 2: Implement the standalone launcher with stdlib only before the drop**

Use `ctypes` for `prctl(PR_SET_KEEPCAPS)`, `capset` Linux capability v3, and read-back from `/proc/self/status` plus `os.getresuid/getresgid/getgroups`.

Before application import:
- EUID must be 0;
- reject every argv;
- require exact sshd/sudo context;
- replace `os.environ` with the sanitized mapping;
- set supplementary groups to exactly `[3299]`;
- set real/effective/saved GID to `3202`, UID to `2202`;
- set effective/permitted mask to only bits 6 and 7;
- require inheritable and ambient zero;
- verify all real/effective/saved IDs/groups/capability sets.

Only then prepend the fixed checkout `src` path and fixed root-owned E2E venv site-packages path to `sys.path`, import `ssh_over_mcp.host_agent.cli`, and call `main()`.

Do not use `subprocess`, shell execution, caller-supplied paths, or dynamic module names.

- [ ] **Step 3: Run launcher focused tests, Ruff, compile, diff check**

Expected: launcher contract GREEN and ordinary tests remain privilege-free.

- [ ] **Step 4: Document the exact operator sudo/sshd handoff**

`ops/live-e2e/README.md` must specify:
- root-owned non-symlink launcher install;
- exact interpreter/launcher command;
- dedicated SSH account only;
- environment preservation limited to the sshd-provided `SSH_ORIGINAL_COMMAND` / `SSH_TTY` needed for validation;
- no `SETENV` or arbitrary sudo command;
- application packages are imported only after the drop;
- no repository root-install script is provided.

- [ ] **Step 5: Commit**

```bash
git add ops/live-e2e/ssh-over-mcp-host-agent-launcher.py \
        ops/live-e2e/README.md \
        tests/ops/test_host_agent_capability_launcher_contract.py
git commit -m "Ops: add fixed host-agent capability launcher"
```

---

### Task 2: Add the trusted disposable-guest orchestrator and guest gate bootstrap

**Slice:** 7A1-bootstrap

**Files:**
- Create: `ops/live-e2e/lima-ubuntu-26.04.yaml`
- Create: `ops/live-e2e/ssh-over-mcp-live-e2e-gate`
- Create: `scripts/run-live-local-e2e-orchestrator.py`
- Create: `tests/ops/test_live_e2e_orchestrator_contract.py`
- Create: `tests/ops/test_live_e2e_gate_contract.py`
- Create: `.github/workflows/live-local-e2e.yml`
- Modify: `ops/live-e2e/README.md`
- Modify: `docs/self-hosted-runner.md`

**Interfaces:**
- Host orchestrator account: `gha-e2e-orchestrator`, native macOS x86, non-admin/non-root, no sudo.
- Workflow label: `[self-hosted, macOS, X64, ssh-over-mcp-e2e-orchestrator]`.
- Orchestrator accepts exactly one target 40-hex commit and no target-controlled path/command input.
- Fixed Lima instance: `ssh-over-mcp-e2e`; provider Lima `2.2.0`, `vz`, x86_64.
- Guest image is dated Ubuntu 26.04 server image with digest `sha256:117816726abbdefc5ef3e38902e81a76f1c76c3610e709999d0885f9d5d9b477`.
- Guest has no host mounts; target source crosses the boundary only as a Git bundle.
- Host target fetch occurs in a temporary bare Git repository; no target worktree is checked out on the host.
- GitHub token is host-only and is excluded from guest command environments.
- Guest workspace: `/opt/ssh-over-mcp-e2e/workspace`; expected-commit config: `/etc/ssh-over-mcp/live-e2e-gate.conf`.
- Guest gate executes as root inside the disposable VM only and owns guest identities/sshd/sudo/cgroup/test lifecycle.
- Host orchestrator always destroys the VM it created and verifies absence even when the guest gate fails.

- [ ] **Step 1: Write RED host-orchestrator/provider trust-contract tests**

Require:
- Lima config pins the dated Ubuntu 26.04 x86_64 image + digest and `vmType: vz` / `arch: x86_64`;
- no Lima mounts/host-path exposure and no product port-forward entry;
- orchestrator validates exact 40-hex target SHA;
- orchestrator checks `limactl version 2.2.0`, `kern.hv_support=1`, and fixed instance absence before creation;
- target repository is initialized/fetched as bare and never checked out on the host;
- bundle is created from a local ref whose object ID is re-read and equals target SHA;
- host-side commands use argument arrays, never `shell=True` or interpolated shell command strings;
- target bundle is the only target-controlled payload copied into the guest;
- host workflow token/credential variables are explicitly excluded from guest command environments;
- `limactl start` uses trusted-main config with fixed instance name and no mounts;
- guest checkout HEAD is queried by trusted orchestrator and compared to target SHA before guest gate invocation;
- cleanup is in `finally`: delete only the instance created by this run, verify absent, remove bare repo/bundle;
- a pre-existing fixed-name instance causes hard failure and is not auto-deleted;
- ordinary `.github/workflows/ci.yml` remains unchanged.

Run focused tests and require RED.

- [ ] **Step 2: Implement the pinned Lima guest definition**

Pin:
- `https://cloud-images.ubuntu.com/releases/resolute/release-20260720/ubuntu-26.04-server-cloudimg-amd64.img`;
- exact SHA-256 above;
- `arch: x86_64`;
- `vmType: vz`;
- fixed CPU/memory/disk;
- `mounts: []`;
- containerd disabled;
- no product port-forward declarations.

The orchestrator additionally uses Lima plain/no-mount mode. Lima's internal control SSH is orchestration infrastructure, not a product test port-forward.

- [ ] **Step 3: Implement the trusted-main Mac orchestrator**

The script:
1. validates its one target SHA;
2. verifies provider/version/HV support and fixed guest absence;
3. creates one private temporary host directory under the orchestrator account;
4. initializes a bare Git repository, fetches exact target using host-only read credentials, creates/re-verifies a local target ref, and creates a Git bundle;
5. starts the fresh guest from trusted-main Lima config;
6. performs trusted guest bootstrap for git, openssh-server, sudo, Python/venv, and test prerequisites;
7. copies the bundle into the guest with `limactl copy`;
8. clones/checks out inside `/opt/ssh-over-mcp-e2e/workspace` and verifies guest HEAD equals target SHA;
9. writes exact target SHA to root-owned guest config;
10. invokes `sudo /usr/bin/python3 /opt/ssh-over-mcp-e2e/workspace/ops/live-e2e/ssh-over-mcp-live-e2e-gate` inside the VM;
11. captures bounded output/evidence;
12. in `finally`, deletes the created VM, verifies absence, and removes host temp state.

No GitHub token is copied into the guest. Do not mount host repository/home into the guest.

- [ ] **Step 4: Write RED/implement the in-guest root gate static contract**

The gate is stdlib-only at root and accepts no CLI arguments. It reads exactly one `EXPECTED_COMMIT=<40hex>` from guest root-owned config and verifies canonical guest workspace HEAD/clean tree before fixture setup.

Static tests require fixed guest paths/UIDs/GIDs/port, strict stale-state rejection, `finally` cleanup, no Docker calls, and no caller-selected path/identity/command/capability input.

It may create guest-local users/groups/sudoers/launcher because ADR 0006 makes the whole VM disposable; this authority must never move to the persistent Mac orchestrator.

- [ ] **Step 5: Implement the manual trusted-main workflow**

Workflow requirements:
- `workflow_dispatch` only with one required full `commit_sha` input;
- `permissions: contents: read`;
- `[self-hosted, macOS, X64, ssh-over-mcp-e2e-orchestrator]`;
- concurrency serializes the fixed Lima instance and does not cancel a running E2E;
- checkout trusted-main workflow/orchestrator only with pinned `actions/checkout`, no persisted credentials;
- validate runner is macOS x86_64, non-root/non-admin, Lima 2.2.0, HV support enabled;
- run only trusted-main `scripts/run-live-local-e2e-orchestrator.py <commit_sha>` for the target;
- post-step verify fixed Lima instance is absent.

The workflow run `headSha` proves trusted-main orchestrator revision, not target identity.

- [ ] **Step 6: Document orchestrator provisioning**

Document dedicated non-admin Mac account/home permissions, native runner registration, no sudo requirement, Lima 2.2.0/HV prerequisite, guest image digest, host-only read token behavior, no host mounts, and fixed-name stale-instance handling.

- [ ] **Step 7: Run static/full ordinary verification and commit bootstrap PR**

Run launcher/orchestrator/gate/workflow contract tests, full ordinary pytest, Ruff, compileall, diff check. No live target-commit E2E claim yet.

Commit:
```bash
git add ops/live-e2e scripts/run-live-local-e2e-orchestrator.py         .github/workflows/live-local-e2e.yml tests/ops         docs/self-hosted-runner.md
git commit -m "Ops: bootstrap disposable full-E2E guest"
```

Fresh review must have no Critical/Important finding. Merge only after exact PR-head ordinary CI and exact merge-main ordinary CI.

**External provisioning gate:** after merge, provision/register only the dedicated non-admin native Mac orchestrator runner. Do not give it sudo and do not reuse the ordinary Docker runner as a VM host-control surface.

---

### Task 3: Prove the real sshd/launcher/containment fixture end to end

**Slice:** 7A1-live

**Files:**
- Create: `scripts/run-live-local-e2e-manager.py`
- Create: `scripts/run-live-local-e2e-probe.py`
- Create: `tests/live/local_e2e_support.py`
- Create: `tests/live/test_local_e2e.py`
- Modify: `tests/live/README.md`
- Modify: `docs/self-hosted-runner.md`

**Interfaces:**
- `LocalE2EFixture.from_env() -> LocalE2EFixture` parses only operator-provided fixed metadata and verifies paths/IDs/port.
- Manager script consumes fixed env values from the disposable-guest gate and creates `CgroupV2Backend` + `ContainmentManagerDispatcher` + `ContainmentManagerService.serve_forever()`.
- Probe script validates exact commit/clean checkout, emits one bounded JSON metadata record, then runs only `tests/live/test_local_e2e.py` with `SSH_OVER_MCP_RUN_LIVE_LOCAL_E2E=1`.
- Initial live test uses production `SSHConnectionManager` + `StructuredSSHTransport`, not raw shell SSH.

- [ ] **Step 1: Write RED fixture/preflight tests**

Add tests for:
- required fixture env and exact numeric IDs;
- loopback host/port and canonical absolute paths;
- exact private-key/host-key file ownership/mode expected from the guest gate;
- manager socket owner/group/mode;
- direct structured SSH execution of the fixed workload-state command.

The live test asserts returned state:
- UID/GID all `2203:3203`;
- groups empty;
- CapInh/Prm/Eff/Amb all zero;
- `NoNewPrivs=1`;
- cgroup path is beneath the dedicated request scope;
- no inherited manager socket.

Before implementation/static fixture setup, run locally without opt-in and verify skip; the dedicated gate is the RED/GREEN authority for the real path.

- [ ] **Step 2: Implement non-root manager runner**

The manager runner:
- validates it is manager `2201:3201` with supplementary `3299`, zero capabilities, NNP=1;
- constructs the exact `ContainmentServiceIdentityPlan`;
- verifies it runs outside the delegated root;
- creates backend/dispatcher/service on the operator-owned endpoint;
- handles SIGTERM only as a stop predicate;
- on exit cleans every managed request scope and restores controller state;
- never creates users/cgroups/root directories itself.

- [ ] **Step 3: Implement exact-checkout probe launcher**

The probe:
- verifies `SSH_OVER_MCP_LIVE_EXPECTED_COMMIT`, HEAD, and clean worktree;
- verifies current process is the guest probe identity `2204:3204` with zero capabilities and no supplementary groups;
- validates fixture metadata;
- runs the fixed pytest file with bounded timeout;
- accepts no CLI-selected path/identity/test expression.

- [ ] **Step 4: Implement the real SSH fixture test**

Use the operator-generated private key and exact host key to construct production SSH inventory/credentials and an `ExecEnvelope` for the fixed state script. Run through `StructuredSSHTransport`.

Assert:
- actual sshd authentication succeeded;
- ForceCommand ignores the client's command except exact `mcp-v1` context;
- launcher self-verification permitted application entry;
- host-agent authenticated the real manager;
- request cgroup exists during execution and is removed afterward;
- output contains the exact workload kernel state above.

- [ ] **Step 5: Add deliberate failure cleanup proof**

Run a fixed test case which exits nonzero after the first real request. The guest gate must still remove sshd/manager processes, keys, sockets, host policy, runtime data, and cgroup root. The trusted orchestrator must then destroy the VM and verify absence. A second workflow run starts from a new guest. Record both in-guest cleanup and guest destruction as live evidence.

- [ ] **Step 6: Run exact-head full E2E through the trusted-main workflow**

Operator dispatches the workflow definition from trusted `main` with the exact 7A1-live PR head (for example `gh workflow run live-local-e2e.yml --ref main -f commit_sha=<PR_HEAD_SHA>`). The trusted orchestrator itself writes that SHA into the fresh guest's root-owned expected-commit config.

Require:
- the workflow run itself is anchored to trusted `main`; its GitHub run `headSha` is **not** used as the tested-commit identity;
- workflow input, host bare-fetch object ID, bundle target ref, guest `git rev-parse HEAD`, and guest root-owned `EXPECTED_COMMIT` all equal the requested PR head SHA;
- fixture test GREEN;
- in-guest cleanup assertions GREEN and trusted host orchestrator confirms the Lima instance is deleted.

- [ ] **Step 7: Commit / PR / merge-main gate**

```bash
git add scripts/run-live-local-e2e-manager.py scripts/run-live-local-e2e-probe.py \
        tests/live/local_e2e_support.py tests/live/test_local_e2e.py \
        tests/live/README.md docs/self-hosted-runner.md
git commit -m "Test: prove real local SSH containment E2E"
```

Require exact PR-head ordinary CI + full E2E, fresh review, merge, then exact merge-main ordinary CI + full E2E before starting 7A2.

---

### Task 4: Add real MCP origin/Ledger discovery and execution E2E

**Slice:** 7A2

**Files:**
- Modify: `tests/live/local_e2e_support.py`
- Modify: `tests/live/test_local_e2e.py`

**Interfaces:**
- `LocalMCPHarness` async context manager owns test-local Security Ledger service/thread, temp DB/HMAC/sockets, config/credential/origin-token files, uvicorn server, and MCP client transport.
- `LocalMCPHarness.client(profile: str, policy_variant: str = "normal")` exposes an MCP `Client` constructed with `streamable_http_client(..., http_client=httpx2.AsyncClient(headers={"Authorization": "Bearer ..." }))`.
- Central inventory always uses alias `e2e-host`, loopback:22222, server-owned SSH user, logical credential ref, exact operator-generated host key.
- No application startup path resolves the SSH key or opens SSH before a tool request.

- [ ] **Step 1: Write RED MCP-origin happy-path tests**

Cover:
- wrong/missing bearer rejected at origin middleware;
- correct bearer can initialize MCP and list tools;
- `hosts_list` and `host_info` return only server-owned alias/labels/capabilities and do not expose address, SSH user, key path, host-key material;
- allowed `ssh_exec` state request succeeds through the complete path and returns expected stdout/exit status.

- [ ] **Step 2: Implement the test-local Ledger/MCP harness**

Reuse production `SecurityLedgerService`, `MCPRuntimeSettings`, `build_application`, uvicorn, file credential provider, and MCP Streamable HTTP transport.

Ledger uses separate execution/admin Unix socket paths. MCP receives only the execution path/settings. The test harness/admin side retains the admin path for later approval tests.

- [ ] **Step 3: Prove full workload state through MCP**

Parse the state command stdout returned by `ssh_exec` and assert the same UID/GID/groups/caps/NNP/cgroup/no-manager-fd state proven in Task 3.

Also assert the request ID is the control-plane generated `req_<32hex>` form and no caller field can select profile/host address/SSH user/credential.

- [ ] **Step 4: Verify audit lifecycle**

Query the test-owned Ledger SQLite database read-only and assert the successful request contains at least:
`request_received → policy_allowed → execution_started → execution_completed`
for one request ID, with expected profile/host/tool and bounded byte/status metadata.

- [ ] **Step 5: Run focused E2E, full ordinary regression, exact-head dedicated E2E**

Commit:
```bash
git add tests/live/local_e2e_support.py tests/live/test_local_e2e.py
git commit -m "Test: exercise MCP to workload execution E2E"
```

---

### Task 5: Add filesystem, audit-retention, and static multi-profile E2E

**Slice:** 7A2

**Files:**
- Modify: `ops/live-e2e/ssh-over-mcp-live-e2e-gate`
- Modify: `tests/ops/test_live_e2e_gate_contract.py`
- Modify: `tests/live/local_e2e_support.py`
- Modify: `tests/live/test_local_e2e.py`

**Interfaces:**
- Root helper prepares fixed host-owned `/opt/ssh-over-mcp-e2e/fs-data` with one seed file and empty create directory.
- Host policy has `developer` stat/read/mkdir/write-create roots and `readonly` stat/read roots only.
- Two MCP harness instances select server-owned profile `developer` vs `readonly`; tool arguments never carry a trusted profile override.

- [ ] **Step 1: Write RED typed-filesystem E2E tests**

Developer profile:
- `fs_stat` seed file metadata;
- `fs_read` exact seed bytes;
- `fs_mkdir` creates one new directory;
- replay of same mkdir fails and existing directory remains;
- `fs_write` creates one file with exact bytes;
- `fs_read` returns those bytes;
- second write to same path fails and original bytes remain.

- [ ] **Step 2: Add root-helper filesystem fixture and policy**

The disposable-guest gate creates only fixed fixture paths and ownership. Do not permit test input to select roots/modes/owners.

Update static gate tests to pin the paths and cleanup behavior.

- [ ] **Step 3: Write/implement multi-profile E2E**

Start a second MCP harness with static `readonly` profile:
- read succeeds;
- mutation is denied;
- adding a `profile=developer` extra tool argument is rejected by the MCP schema rather than switching authority;
- the developer deployment remains unaffected.

- [ ] **Step 4: Verify filesystem audit and secret retention**

For read/mkdir/write requests assert execution audit events exist.

Seed unique sentinels for origin bearer, SSH credential filename/content fragment, application stdin/env/argv sensitive values where applicable. Scan tool results/errors plus test-owned Ledger DB rows and application log captures; none may contain raw secret bytes. Safe fingerprints/counts are allowed.

- [ ] **Step 5: Full 7A2 slice gate**

Run all Task 4–5 focused/live tests, full Linux ordinary suite, exact-head E2E workflow, fresh review.

Commit:
```bash
git add ops/live-e2e/ssh-over-mcp-live-e2e-gate \
        tests/ops/test_live_e2e_gate_contract.py \
        tests/live/local_e2e_support.py tests/live/test_local_e2e.py
git commit -m "Test: cover filesystem and profile E2E"
```

Merge 7A2 only after exact PR-head ordinary CI + E2E; require exact merge-main ordinary CI + E2E before 7A3.
---

### Task 6: Add origin, central-policy, host-policy, and host-key fail-closed E2E

**Slice:** 7A3

**Files:**
- Modify: `ops/live-e2e/ssh-over-mcp-live-e2e-gate`
- Modify: `tests/live/local_e2e_support.py`
- Modify: `tests/live/test_local_e2e.py`

**Interfaces:**
- The guest gate exposes an sshd log file readable by the guest probe identity `2204:3204` but not writable by it.
- Harness can build central policy variants: `normal`, `central_deny`, `remote_deny`, `wrong_host_key`.
- Fixed workload marker remains the remote-execution side-effect counter.

- [ ] **Step 1: Write RED origin-auth early-rejection test**

Snapshot sshd log size and marker state. Send missing/wrong origin bearer. Assert HTTP rejection, no Ledger execution event, sshd log unchanged, marker unchanged, secret not echoed.

- [ ] **Step 2: Write RED central-deny E2E**

Central policy denies the fixed state execution. Assert:
- tool returns central-policy denial;
- audit contains `policy_denied`;
- no `execution_started`;
- sshd log unchanged;
- marker unchanged.

This E2E evidence combines with existing integration tests which directly assert `SSHConnectionManager.get_connection` is never called after central deny.

- [ ] **Step 3: Write RED host-local deny E2E**

Central policy allows fixed `/usr/bin/false`, but host policy intentionally contains no command rule for it.

Assert:
- SSH session occurs (sshd log grows);
- host-agent reports generic remote-policy denial;
- audit contains `remote_policy_denied`;
- no workload marker mutation.

- [ ] **Step 4: Write RED pinned-host-key mismatch E2E**

Use a syntactically valid wrong Ed25519 host key in server-owned inventory.

Assert:
- request fails before ForceCommand/workload execution;
- audit contains `host_key_failure`;
- no marker mutation;
- error does not disclose expected/observed raw key material.

- [ ] **Step 5: Implement only harness/fixture support needed for these cases**

Do not add a bypass/test-only production hook. Fault variants live in test config or fixed operator fixture state.

- [ ] **Step 6: Verify/commit**

Run focused cases, full ordinary suite, exact-head E2E.

```bash
git add ops/live-e2e/ssh-over-mcp-live-e2e-gate \
        tests/live/local_e2e_support.py tests/live/test_local_e2e.py
git commit -m "Test: validate fail-closed policy and host trust E2E"
```

---

### Task 7: Add approval, Ledger outage, containment failure, replay, and cleanup E2E

**Slice:** 7A3

**Files:**
- Modify: `ops/live-e2e/ssh-over-mcp-live-e2e-gate`
- Modify: `tests/ops/test_live_e2e_gate_contract.py`
- Modify: `tests/live/local_e2e_support.py`
- Modify: `tests/live/test_local_e2e.py`

**Interfaces:**
- Fixed approval workload command appends one byte to `/opt/ssh-over-mcp-e2e/workload-data/approval-marker`; host policy exact argv only.
- Approval policy variant marks that command `process_control` (MEDIUM) and configures MEDIUM as approval-required.
- Admin grant uses the real `ssh-over-mcp-approvalctl grant <approval_id>` command with only admin-socket/service UID/GID environment.
- Optional inherited test-control socket allows exactly one request string: `STOP_MANAGER\n`; guest gate parent responds `OK\n` after bounded manager termination. Every other message is fatal.

- [ ] **Step 1: Write RED approval lifecycle E2E**

Assert:
1. first marker request returns approval-required;
2. marker size remains zero and sshd log does not grow;
3. MCP tool surface contains no grant/deny method;
4. real `ssh-over-mcp-approvalctl grant` over admin socket changes state to granted;
5. exact retry succeeds and marker size becomes one;
6. approval state becomes consumed;
7. same approval replay fails and marker stays size one;
8. changed argv/binding with old approval does not execute and produces a distinct pending approval.

- [ ] **Step 2: Write RED Ledger outage E2E**

Stop the test-local Ledger after app readiness:
- `/healthz` remains healthy;
- `/readyz` becomes 503/not_ready;
- new execution/mutation request fails;
- no SSH/workload marker side effect.

Do not add an execute-first/audit-later fallback.

- [ ] **Step 3: Add the fixed manager-stop control channel**

Root gate creates a socketpair before forking the probe. Probe receives only the child FD number in operator-controlled env.

Protocol accepts exactly `STOP_MANAGER\n`; no arguments or second command. Root parent terminates/reaps only its known manager PID and returns `OK\n`. Unknown bytes fail the gate.

Static tests prove this is not a path/command/UID root RPC.

- [ ] **Step 4: Write containment-unavailable E2E as the final execution test**

After all other cases, request `STOP_MANAGER`, wait for `OK`, then call the fixed state execution.

Assert:
- host-agent fails generically;
- no workload marker/state script side effect;
- no request cgroup is left;
- no internal manager/socket exception leaks through MCP.

No manager restart is needed because this is the final execution case in the probe.

- [ ] **Step 5: Final secret-retention scan**

Scan:
- all captured MCP tool text/structured results;
- test-local Ledger database text/blob fields;
- uvicorn/application captured logs;
- readable sshd log.

Assert absence of raw origin bearer, SSH private key bytes, Ledger HMAC bytes, approval marker sensitive test values, and any deliberately seeded stdin/env/argv secret.

- [ ] **Step 6: Deliberate failure cleanup regression**

Force one assertion/probe failure after sshd+manager are active and require root gate post-cleanup verification. Then run a normal probe again to prove stale state was not preserved.

- [ ] **Step 7: Full 7A3 review/merge gates**

Run targeted adversarial suite, full ordinary suite, exact PR-head E2E, fresh review. No Critical/Important finding may remain.

Commit:
```bash
git add ops/live-e2e/ssh-over-mcp-live-e2e-gate \
        tests/ops/test_live_e2e_gate_contract.py \
        tests/live/local_e2e_support.py tests/live/test_local_e2e.py
git commit -m "Test: add adversarial full-product E2E"
```

Merge only after exact PR-head ordinary CI + E2E; require exact merge-main ordinary CI + E2E before 7A4.

---

### Task 8: Stabilize E2E gate policy, documentation, and evidence contracts

**Slice:** 7A4

**Files:**
- Modify: `.github/workflows/live-local-e2e.yml`
- Modify: `tests/ops/test_live_e2e_gate_contract.py`
- Modify: `tests/live/README.md`
- Modify: `docs/self-hosted-runner.md`
- Modify: `docs/development-methodology.md` only if the implemented behavior requires clarification without weakening it.
- Modify: `docs/development-plan.md`
- Modify: `docs/superpowers/specs/2026-10-02-phase-7a-local-e2e-foundation-design.md`
- Create: `tests/ops/test_phase7a_closure_evidence.py`

**Interfaces:**
- Level-3 trigger list must match the approved methodology/spec.
- Trusted workflow remains manual from main with exact requested commit.
- Closure docs may say “implementation complete” only after all 25 DoD criteria have executable/live evidence; “closed” remains post-merge exact-head E2E/CI + cleanup state.

- [ ] **Step 1: Write RED gate-policy consistency tests**

Assert methodology/spec/runner docs agree that Level 3 is required for SSH, authorization, approvals/Ledger, credentials, host-agent, containment, filesystem mutation, audit, workload identity, OS hardening, egress, SSH CA, secret manager, E2E fixture, phase closure, and release candidates.

Assert ordinary CI remains unprivileged and separate.

- [ ] **Step 2: Build the 25-criterion Phase 7A evidence matrix**

For each DoD item record exact source invariant + static/integration/live test. Do not mark external exact-head PR/merge gates green before they occur.

Include carried Phase 5/6 authority/secret/deployment regression suites in the final review matrix.

- [ ] **Step 3: Update operator/live documentation from actual implementation**

Document exact orchestrator label/account, Lima/provider version, pinned Ubuntu image digest, guest/kernel evidence, fixed identities/port, launcher digest, test counts, in-guest cleanup result, whole-VM destruction result, and operator provisioning procedure. Never document secrets.

- [ ] **Step 4: Run full regression matrix before changing status**

Ordinary Linux:
```bash
python -m ruff check src tests
python -m compileall -q src tests
python -m pytest -q
```

Authorized Mac x86 Docker host:
- reproducible image;
- container image;
- Phase 6B Compose;
- Phase 6C connector.

Disposable Ubuntu 26.04 x86 E2E:
- full local E2E exact branch head inside a fresh Lima guest;
- no host mounts/token/production secrets enter the guest;
- in-guest cleanup and whole-guest destruction both pass;
- existing delegated-cgroup proof is rerun only if its contract is touched.

- [ ] **Step 5: Mark Phase 7A implementation complete, not closed**

Only after Step 4 and whole-phase review are clean, update spec/development plan to “implementation complete; post-merge exact-head gates pending”.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/live-local-e2e.yml tests/ops \
        tests/live/README.md docs/self-hosted-runner.md \
        docs/development-methodology.md docs/development-plan.md \
        docs/superpowers/specs/2026-10-02-phase-7a-local-e2e-foundation-design.md
git commit -m "Docs: record Phase 7A E2E evidence"
```

---

### Task 9: Whole-Phase-7A review, exact-head closure, and cleanup

**Slice:** 7A4

**Files:**
- Modify only concrete defect regressions/fixes found by review.
- Post-merge closure record may modify the Phase 7A spec/development plan if external evidence cannot truthfully be recorded before merge.

**Interfaces:**
- Produces authoritative Phase 7A closure on main.
- No new capability is allowed in this task.

- [ ] **Step 1: Fresh whole-Phase-7A adversarial review**

Review from Phase 6 closure `a00c36f...` through exact 7A4 head against:
- 25 Phase 7A DoD criteria;
- Phase 5 security invariants;
- Phase 6 deployment/credential boundaries;
- ADR 0005/0006/0007;
- no application code while launcher root;
- no generic sudo/root RPC;
- no caller-selected identities/paths/profile/credential;
- attach-before-exec;
- approval single-use/binding;
- create-only filesystem semantics;
- secret retention;
- stale state/cleanup;
- workflow trust/commit binding.

Every Critical/Important finding gets root-cause analysis, focused RED, smallest fix, targeted GREEN, full regression, and fresh review.

- [ ] **Step 2: Exact PR-head preflight**

Require clean worktree and rerun:
- full ordinary Linux suite;
- applicable Mac x86 live deployment probes;
- full dedicated E2E against exact head;
- existing live delegated-cgroup proof if touched;
- `git diff --check`.

Record exact SHA/run IDs.

- [ ] **Step 3: PR exact-head CI/E2E and final review**

Push PR. Require:
- ordinary self-hosted Python 3.13 + 3.14 CI run `headSha` exactly equals the PR head and succeeds;
- trusted-main manual full E2E is dispatched with `commit_sha` equal to that PR head, and the workflow proves bare-fetch ID, bundle ref, guest checkout HEAD, and guest expected-commit all equal that value;
- no independent/author review ambiguity: use independent reviewer if available, otherwise explicitly record fresh author self-review;
- no remaining Critical/Important finding.

- [ ] **Step 4: Squash merge and require exact merge-main evidence**

After merge:
- fetch/fast-forward local main;
- record exact merge-main SHA;
- require ordinary CI `push` run headSha exactly equals merge-main SHA and succeeds on Python 3.13/3.14;
- dispatch trusted-main full E2E with `commit_sha=<merge-main SHA>`; require bare-fetch/bundle/guest-checkout/guest-config equality, in-guest cleanup, whole-VM destruction, and success;
- if Phase 7A closure docs still say pending, land one tiny docs/test closure-record PR exactly as Phase 6 did, with its own CI gates.

- [ ] **Step 5: Cleanup**

Audit before deleting. Remove only merged/superseded Phase 7A worktrees/branches, prune refs, and verify:
- root `main == origin/main`;
- clean worktree;
- no obsolete Phase 7A local/remote branches;
- no persistent-host Lima instance named `ssh-over-mcp-e2e`;
- no host-side temporary bare repository/bundle;
- no obsolete E2E guest state;
- the dedicated non-admin orchestrator account/runner remains only because it is intentional trusted infrastructure.

## Phase 7A Completion Gate

Phase 7A is closed only when all 25 DoD criteria have current evidence, ordinary CI security posture is unchanged, exact PR-head and merge-main ordinary CI succeed, exact-target PR-head and merge-main full E2E succeed through the trusted-main workflow, capability-bearing target code ran only inside fresh disposable guests, in-guest cleanup and whole-VM destruction succeeded, the final review has no Critical/Important finding, code/tests/docs/roadmap agree, and repository/host temporary state is clean.
