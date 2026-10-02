# Phase 7A Local E2E Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish a production-representative local Linux E2E safety net from authenticated MCP ingress through real SSH/ForceCommand/containment to workload/filesystem/audit behavior without weakening ordinary CI.

**Architecture:** A dedicated non-root `gha-e2e` self-hosted runner invokes one operator-installed root gate. The root gate verifies an exact trusted commit, prepares disposable sshd/cgroup/runtime state, starts the containment manager under its non-root identity, and forks the repository E2E probe only after dropping that probe to the non-root runner identity. Real sshd ForceCommand reaches one fixed root-owned capability launcher which drops to the non-root host-agent identity with only `CAP_SETUID`/`CAP_SETGID` before importing application code.

**Tech Stack:** Python 3.13/3.14, OpenSSH, sudo, Linux capabilities via `prctl/capset`, cgroup v2, AsyncSSH, MCP Python SDK v2 Streamable HTTP, Security Ledger Unix sockets/SQLite, pytest, GitHub Actions self-hosted Linux x86.

**Spec:** `docs/superpowers/specs/2026-10-02-phase-7a-local-e2e-foundation-design.md`

## Global Constraints

- Implementation MUST include the approved design commits `fff4527` and `2df40b9` or their merged descendants.
- Core method: **小步快跑，持续迭代，关注质量、安全、一致性。**
- Ordinary CI remains `[self-hosted, linux, x64, ssh-over-mcp-mac-x86]`; never add a GitHub-hosted fallback or Docker socket.
- Full E2E uses a separate runner account and label: `gha-e2e` on `[self-hosted, linux, x64, ssh-over-mcp-e2e-live]`.
- Preserve the existing `ssh-over-mcp-cgroup-live` runner and its one-sudo-command contract unchanged.
- The `gha-e2e` runner itself is non-root, has zero effective capabilities, no Docker socket, and exactly one passwordless sudo command: `/usr/local/libexec/ssh-over-mcp-live-e2e-gate`.
- The E2E root gate accepts no arguments and reads only `EXPECTED_COMMIT=<40-hex>` from root-owned mode-0600 `/etc/ssh-over-mcp/live-e2e-gate.conf`.
- Fixed fixture identities: manager `2201:3201`, host agent/SSH account `2202:3202`, workload `2203:3203`, manager-client supplementary GID `3299`.
- Fixed SSH account name: `ssh-over-mcp-e2e-host`; fixed runner account name: `gha-e2e`.
- Fixed loopback sshd port: `22222`; fail if occupied rather than choosing a caller-controlled port.
- Fixed fixture root: `/opt/ssh-over-mcp-e2e`; fixed root-owned Python environment: `/opt/ssh-over-mcp-e2e/venv`; fixed cgroup root: `/sys/fs/cgroup/ssh-over-mcp-e2e`.
- Fixed launcher source/install path: `ops/live-e2e/ssh-over-mcp-host-agent-launcher.py` → `/usr/local/libexec/ssh-over-mcp-host-agent-launcher.py`.
- ForceCommand sudo invocation is exactly `/usr/bin/python3 -I -S /usr/local/libexec/ssh-over-mcp-host-agent-launcher.py`; no launcher arguments are permitted.
- No `ssh_over_mcp`/checkout application module may be imported or executed while the launcher has UID 0 or capabilities broader than the final host-agent set.
- Final host-agent application state is non-root `2202:3202`, supplementary groups exactly `{3299}`, effective/permitted capabilities exactly `CAP_SETGID|CAP_SETUID`, inheritable/ambient capabilities zero.
- Workload state remains UID/GID `2203:3203`, no supplementary groups, zero effective/permitted/inheritable/ambient capabilities, `NoNewPrivs=1`.
- The root E2E gate may execute checked-out repository code only in children after dropping those children to a configured non-root identity.
- Root/operator helpers, sudo rules, accounts, and installed launcher are infrastructure outside the checkout. Repository code MUST NOT install or rewrite sudoers as part of a test.
- Unknown stale fixture state is a hard failure. Cleanup failure makes the E2E run fail.
- No live Cloudflare account mutation is part of Phase 7A.
- Every E2E-sensitive PR after workflow bootstrap requires exact-head full E2E evidence before merge; every merge/phase-closure candidate requires merge-main E2E evidence too.

## PR / Slice Sequence

1. **7A1-bootstrap PR — Tasks 1–2:** land the reviewed launcher/gate source and trusted manual workflow definition with static/security tests. This PR does not claim live E2E success.
2. Operator provisions `gha-e2e`, fixed accounts/groups, root-owned Python environment, installed gate/launcher, and exact sudo policies from the merged reviewed artifacts.
3. **7A1-live PR — Task 3:** prove real sshd → launcher → host-agent → manager → cgroup → workload on the exact PR head using the already-trusted workflow from main.
4. **7A2 PR — Tasks 4–5:** happy-path MCP/Ledger/SSH/filesystem/audit/multi-profile E2E.
5. **7A3 PR — Tasks 6–7:** adversarial/fail-closed E2E.
6. **7A4 PR — Tasks 8–9:** gate documentation, whole-phase review, exact-head/merge-main E2E closure, cleanup.

The bootstrap ordering is intentional: an unmerged PR must not be able to modify the workflow definition that invokes root infrastructure and then use that modified definition as its own security evidence.

## Review Focus

1. **Python/import code executing while launcher is still root.** Task 1 tests the launcher under AST/order instrumentation and requires `-I -S`, environment sanitation, privilege verification, and delayed application import.
2. **ForceCommand/sudo environment loss or spoofing.** Tasks 1–3 test exact `SSH_ORIGINAL_COMMAND=mcp-v1`, no PTY, expected `SUDO_USER/UID/GID`, exact sudo command, and successful real sshd invocation.
3. **Stale privileged fixture state or failed teardown being silently reused.** Tasks 2–3 test fail-closed stale-state detection and deliberate probe failure with verified process/socket/cgroup/key/data cleanup.
4. **A test-control path turning into a generic root RPC.** Task 7 allows only one fixed control message, `STOP_MANAGER\n`, over an inherited socketpair; any other bytes fail the run and no paths/commands/IDs are accepted.
5. **Full E2E passing while a lower security boundary is bypassed.** Tasks 4–7 assert real origin auth, Ledger authorization/audit, pinned host key, sshd logs, host-local policy, launcher state, manager peer auth, cgroup membership, workload identity, and side-effect counters together.

---

## File Map

- Create `ops/live-e2e/ssh-over-mcp-host-agent-launcher.py` — standalone stdlib-only root-to-host-agent capability handoff.
- Create `ops/live-e2e/ssh-over-mcp-live-e2e-gate` — operator-installed root fixture lifecycle owner.
- Create `ops/live-e2e/README.md` — operator provisioning contract; no root installer script.
- Create `.github/workflows/live-local-e2e.yml` — trusted-main, manual exact-commit E2E workflow.
- Create `tests/ops/test_host_agent_capability_launcher_contract.py` — launcher static/order/security contract.
- Create `tests/ops/test_live_e2e_gate_contract.py` — root-gate/workflow static trust contract.
- Create `scripts/run-live-local-e2e-manager.py` — non-root containment-manager service process.
- Create `scripts/run-live-local-e2e-probe.py` — non-root exact-checkout E2E test launcher/metadata emitter.
- Create `tests/live/local_e2e_support.py` — typed fixture metadata plus real Ledger/MCP HTTP harness.
- Create `tests/live/test_local_e2e.py` — product-level happy/adversarial E2E matrix.
- Modify `tests/live/README.md` — dedicated full-E2E commands/evidence.
- Modify `docs/self-hosted-runner.md` — `gha-e2e` runner/operator trust contract.
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
- Fixed application source after privilege drop: `/home/gha-e2e/actions-runner/_work/ssh-over-mcp/ssh-over-mcp/src`.

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

### Task 2: Add the operator-owned E2E gate and trusted workflow bootstrap

**Slice:** 7A1-bootstrap

**Files:**
- Create: `ops/live-e2e/ssh-over-mcp-live-e2e-gate`
- Create: `tests/ops/test_live_e2e_gate_contract.py`
- Create: `.github/workflows/live-local-e2e.yml`
- Modify: `ops/live-e2e/README.md`
- Modify: `docs/self-hosted-runner.md`

**Interfaces:**
- Installed root helper: `/usr/local/libexec/ssh-over-mcp-live-e2e-gate`; accepts no arguments.
- Root config: `/etc/ssh-over-mcp/live-e2e-gate.conf`; exactly one `EXPECTED_COMMIT=<40-hex>` line.
- Workspace: `/home/gha-e2e/actions-runner/_work/ssh-over-mcp/ssh-over-mcp`.
- Runtime: `/opt/ssh-over-mcp-e2e`.
- Cgroup root: `/sys/fs/cgroup/ssh-over-mcp-e2e`.
- sshd: `127.0.0.1:22222`.
- Root helper invokes repository probe only in a forked child after switching that child to the actual `gha-e2e` UID/GID/groups.
- Root helper starts repository manager script only after switching that child to manager `2201:3201`, supplementary group `3299`, zero capabilities, `NoNewPrivs=1`.
- Root helper owns final teardown on every exit.

- [ ] **Step 1: Write RED static trust-contract tests**

Require:
- helper no-argument contract and fixed install/config/workspace/runtime/cgroup/port/identity constants;
- helper source imports no `ssh_over_mcp` application module while root;
- no `shell=True`, no command built from workflow/user input, no Docker calls, no arbitrary sudo;
- config parser accepts exactly one full 40-hex `EXPECTED_COMMIT`;
- helper validates canonical clean workspace HEAD exactly equals operator commit;
- helper refuses existing runtime/cgroup/sshd PID/socket/key state;
- checked-out probe exec is preceded by irreversible drop to `gha-e2e`;
- checked-out manager script exec is preceded by exact manager identity + zero caps + NNP;
- root parent remains outside delegated cgroup;
- helper cleanup is in `finally` and refuses unknown cgroup children rather than recursively deleting arbitrary state;
- helper never calls `cgroup.kill` on the delegated root;
- workflow is `workflow_dispatch` only, uses full commit input, dispatches from trusted main, has `contents: read`, fixed E2E runner label, and exactly one root helper invocation;
- ordinary `.github/workflows/ci.yml` remains unchanged in runner privilege/sockets.

Run focused tests and require RED.

- [ ] **Step 2: Implement root fixture preparation**

The operator gate must:
- verify root-owned helper/config/runtime parent and installed launcher owner/mode/hash;
- verify `gha-e2e` has exactly one NOPASSWD sudo command (the E2E gate);
- verify `ssh-over-mcp-e2e-host` has only the exact Python `-I -S` launcher sudo command;
- verify fixed manager/host/workload accounts/groups map to the approved numeric IDs;
- generate disposable Ed25519 sshd host key and client key under runtime;
- create root-owned authorized_keys and sshd config with loopback-only port 22222, no password/KbdInteractive/PAM forwarding/X11/tunnel/TTY/user environment, and exact ForceCommand;
- create root-owned `/etc/ssh-over-mcp/host-policy.yaml` only if absent; record its inode; stale/unexpected existing file fails closed and cleanup removes it only if the same inode is still present;
- create manager endpoint directory and delegated cgroup root with only the approved ownership surfaces;
- create host-owned filesystem fixture directories and workload-owned marker directory;
- create root-owned fixed workload state/marker Python scripts used only as exact argv to root-owned `/usr/bin/python3`;
- start manager and sshd as fixed child processes;
- run two fixed fixture cycles: first an operator-selected cleanup-proof phase in which the non-root probe intentionally exits with the one expected sentinel status, then a normal full phase; each cycle gets a fresh runtime/cgroup/sshd/manager fixture and full teardown verification;
- fork the non-root repo probe child in each cycle;
- wait boundedly, preserve/validate the phase-specific probe exit status, then cleanup/reap all fixture state before the next cycle or final return.

- [ ] **Step 3: Implement the manual trusted-main workflow**

Workflow requirements:
- label: `[self-hosted, linux, x64, ssh-over-mcp-e2e-live]`;
- verify runner non-root, zero CapEff, no Docker socket;
- verify helper/launcher/interpreter/runtime/config ownership/mode and literal SHA-256 values;
- verify runner sudo list contains exactly the E2E root helper;
- validate input as exact 40-hex;
- checkout that exact commit with pinned `actions/checkout`, no persisted credentials, clean tree;
- verify HEAD and clean status;
- invoke only `sudo -n /usr/local/libexec/ssh-over-mcp-live-e2e-gate`;
- post-step assert runtime PID/socket/cgroup fixture paths are absent.

Compute helper/launcher SHA-256 from their finalized source and pin the exact values in the workflow; tests recompute them from repository source.

- [ ] **Step 4: Document operator provisioning without an installer**

Document permanent fixture accounts/groups, root-owned Python environment, exact sudo rules, helper/launcher copy paths/modes/hashes, and runner registration label. Explicitly state that operator provisioning is out-of-band trusted infrastructure and repository tests do not install sudoers/users.

- [ ] **Step 5: Run static/full ordinary verification**

Run launcher/gate/workflow contract tests, full ordinary pytest, Ruff, compileall, and diff check. No live success claim yet.

- [ ] **Step 6: Commit and complete the 7A1-bootstrap PR**

```bash
git add ops/live-e2e .github/workflows/live-local-e2e.yml \
        tests/ops/test_host_agent_capability_launcher_contract.py \
        tests/ops/test_live_e2e_gate_contract.py \
        docs/self-hosted-runner.md
git commit -m "Ops: bootstrap trusted full-E2E gate"
```

Fresh review must have no Critical/Important finding. Merge only after exact PR-head ordinary CI and exact merge-main ordinary CI.

**External provisioning gate:** after merge, stop if the dedicated operator fixture is not provisioned. Do not weaken the ordinary runner or reuse the existing `gha-live` sudo contract as a shortcut.
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
- Manager script consumes fixed env values from root helper and creates `CgroupV2Backend` + `ContainmentManagerDispatcher` + `ContainmentManagerService.serve_forever()`.
- Probe script validates exact commit/clean checkout, emits one bounded JSON metadata record, then runs only `tests/live/test_local_e2e.py` with `SSH_OVER_MCP_RUN_LIVE_LOCAL_E2E=1`.
- Initial live test uses production `SSHConnectionManager` + `StructuredSSHTransport`, not raw shell SSH.

- [ ] **Step 1: Write RED fixture/preflight tests**

Add tests for:
- required fixture env and exact numeric IDs;
- loopback host/port and canonical absolute paths;
- exact private-key/host-key file ownership/mode expected from operator helper;
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
- verifies current process is the non-root `gha-e2e` account with zero capabilities;
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

Run a fixed test case which exits nonzero after the first real request. The operator gate must still remove sshd/manager processes, keys, sockets, host policy, runtime data, and cgroup root. A second run must start from clean state. Record this as live evidence.

- [ ] **Step 6: Run exact-head full E2E through the trusted-main workflow**

Operator updates root-owned `EXPECTED_COMMIT` to the exact 7A1-live PR head, then dispatches the workflow definition from trusted `main` (for example `gh workflow run live-local-e2e.yml --ref main -f commit_sha=<PR_HEAD_SHA>`) with the same 40-hex SHA.

Require:
- the workflow run itself is anchored to trusted `main`; its GitHub run `headSha` is **not** used as the tested-commit identity;
- workflow input, checkout verification output, checked-out `git rev-parse HEAD`, and root-owned `EXPECTED_COMMIT` all equal the requested PR head SHA;
- fixture test GREEN;
- post-cleanup assertions GREEN.

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

The root helper creates only fixed fixture paths and ownership. Do not permit test input to select roots/modes/owners.

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
- Root helper exposes an sshd log file readable by `gha-e2e` but not writable by it.
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
- Optional inherited test-control socket allows exactly one request string: `STOP_MANAGER\n`; root helper responds `OK\n` after bounded manager termination. Every other message is fatal.

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
- Closure docs may say “implementation complete” only after all 24 DoD criteria have executable/live evidence; “closed” remains post-merge exact-head E2E/CI + cleanup state.

- [ ] **Step 1: Write RED gate-policy consistency tests**

Assert methodology/spec/runner docs agree that Level 3 is required for SSH, authorization, approvals/Ledger, credentials, host-agent, containment, filesystem mutation, audit, workload identity, OS hardening, egress, SSH CA, secret manager, E2E fixture, phase closure, and release candidates.

Assert ordinary CI remains unprivileged and separate.

- [ ] **Step 2: Build the 24-criterion Phase 7A evidence matrix**

For each DoD item record exact source invariant + static/integration/live test. Do not mark external exact-head PR/merge gates green before they occur.

Include carried Phase 5/6 authority/secret/deployment regression suites in the final review matrix.

- [ ] **Step 3: Update operator/live documentation from actual implementation**

Document exact runner label/account, helper/launcher digests, Ubuntu/kernel evidence, fixed identities/port, test counts, cleanup result, and operator config procedure. Never document secrets.

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

Dedicated Ubuntu x86 E2E:
- full local E2E exact branch head;
- existing delegated-cgroup gate remains independently green.

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
- 24 Phase 7A DoD criteria;
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
- trusted-main manual full E2E is dispatched with `commit_sha` equal to that PR head, and the workflow proves the checked-out/tested SHA plus operator `EXPECTED_COMMIT` equal that value;
- no independent/author review ambiguity: use independent reviewer if available, otherwise explicitly record fresh author self-review;
- no remaining Critical/Important finding.

- [ ] **Step 4: Squash merge and require exact merge-main evidence**

After merge:
- fetch/fast-forward local main;
- record exact merge-main SHA;
- require ordinary CI `push` run headSha exactly equals merge-main SHA and succeeds on Python 3.13/3.14;
- operator pins E2E config to that exact merge-main SHA and dispatches trusted-main full E2E with `commit_sha=<merge-main SHA>`; require checkout/config equality and success;
- if Phase 7A closure docs still say pending, land one tiny docs/test closure-record PR exactly as Phase 6 did, with its own CI gates.

- [ ] **Step 5: Cleanup**

Audit before deleting. Remove only merged/superseded Phase 7A worktrees/branches, prune refs, and verify:
- root `main == origin/main`;
- clean worktree;
- no obsolete Phase 7A local/remote branches;
- no fixture sshd/manager/workload process;
- no fixture socket/runtime key/host-policy residue;
- no `/sys/fs/cgroup/ssh-over-mcp-e2e`;
- operator permanent accounts/helpers remain only because they are intentional trusted infrastructure.

## Phase 7A Completion Gate

Phase 7A is closed only when all 24 DoD criteria have current evidence, ordinary CI security posture is unchanged, exact PR-head and merge-main ordinary CI succeed, exact PR-head and merge-main full E2E succeed through the trusted-main workflow, the final review has no Critical/Important finding, code/tests/docs/roadmap agree, and repository plus disposable fixture cleanup is clean.
