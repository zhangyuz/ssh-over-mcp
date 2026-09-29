# Live Delegated Cgroup Validation Implementation Plan

Date: 2026-09-29

**Goal:** Implement Phase `3d2b2b2c3` as a dedicated Linux-only live proof that the production manager/client/start-barrier/workload composition enforces request cgroup limits, recursively kills descendants, and prevents workload self-migration.

**Spec:** `docs/superpowers/specs/2026-09-29-live-delegated-cgroup-validation-design.md`

## Global constraints

- Generic GitHub-hosted CI and the existing hardened Docker runner remain unchanged and receive no writable cgroup access.
- Accepted live evidence requires Linux cgroup v2 and an operator-provided, disposable delegated root.
- The delegated root is absolute, canonical, empty of member processes, and exposes `cpu`, `memory`, and `pids` to child cgroups.
- The containment-manager process itself remains outside the delegated root; the delegated root is an internal node used only to create source/request/sentinel child scopes.
- The operator creates one dedicated host-agent source cgroup directly below the delegated root and places the host-agent process there before bootstrap authority is dropped. Execution children inherit that membership before the manager moves them to sibling request scopes.
- Manager, host-agent, and workload UIDs are distinct.
- Only the manager identity may write the delegated cgroup subtree.
- Host agent keeps the existing narrow identity-transition authority and does not gain `CAP_KILL` or `CAP_SYS_ADMIN`.
- Any privileged bootstrap authority is confined to fixture setup/cleanup and is not retained by the manager, host-agent, or workload processes whose state is being asserted.
- Workload receives no supplementary groups and no capabilities.
- The manager protocol remains create / attach / kill / stats / close only.
- No live-only execution path may bypass the production start barrier, workload transition, or pinned native ELF exec path.
- Every process wait, protocol round trip, cgroup-empty wait, and cleanup action is bounded.
- ForceCommand execution remains disabled throughout this phase.

## Review focus

Every review must explicitly check:

- no generic-runner privilege widening;
- no manager process placed inside the delegated root or tested principal retaining bootstrap/root authority;
- no manager write authority above the delegated root and no attempt to use `CLONE_INTO_CGROUP` to bypass cgroup-v2 placement rules;
- source and request scopes share the delegated root as their nearest common ancestor for manager-authorized migration;
- no Docker socket or `--privileged` requirement;
- no model-controlled cgroup path;
- no manager scope capability in argv/env/log output;
- no manager control FD in the workload;
- no fallback that treats direct PID/process-group kill as evidence for recursive containment;
- no self-migration test which passes merely because the target path is absent;
- no resource test capable of creating host-wide memory/PID pressure;
- no cleanup path which writes `cgroup.kill` at the delegated root.

---

### Task 1: Add opt-in live fixture preflight

**Files:**
- Create: `tests/live/test_delegated_cgroup.py`
- Modify: `tests/live/README.md`

Add an opt-in marker:

```text
SSH_OVER_MCP_RUN_LIVE_CGROUP=1
```

Require the operator to provide the delegated root and one direct-child host-agent source cgroup through dedicated test configuration values. Do not search the host for writable cgroup paths.

Preflight must verify:

1. Linux and unified cgroup v2;
2. delegated root is absolute, canonical, and exists;
3. `cpu`, `memory`, and `pids` are present in `cgroup.controllers`;
4. delegated-root `cgroup.procs` is empty before child-controller enablement;
5. required controller delegation can be enabled/read back;
6. host-agent source cgroup is an existing direct child of the delegated root;
7. source directory and source `cgroup.procs` are manager-writable but not group/other writable and carry no access ACL;
8. manager identity can create and remove a disposable child scope;
9. host-agent and workload identities do not have direct write authority to delegated-root/source membership/control files.

Generic pytest skips this module unless the opt-in flag is set. When the flag is set, failed fixture preconditions are hard failures, not skips.

**Verify:**

```bash
python -m pytest -q tests/live/test_delegated_cgroup.py -k preflight
python -m pytest -q
```

The first command should skip outside the dedicated fixture and the ordinary suite must remain unchanged.

---

### Task 2: Add a narrow native cgroup workload probe

**Files:**
- Create: `tests/live/cgroup_workload_probe.c`
- Modify: `tests/live/README.md`

Build a small native ELF helper with fixed subcommands for test-only behavior. It may:

- report PID/UID/GID and current unified-cgroup membership;
- attempt one write of its own PID to a harness-supplied root/sibling membership file;
- create a bounded descendant tree;
- perform bounded CPU saturation;
- perform bounded memory allocation;
- perform bounded fork attempts.

It MUST NOT execute arbitrary commands, open arbitrary operator-selected control files beyond the specific fixture paths supplied by the harness, or accept shell text.

Compile with warnings-as-errors in the dedicated fixture setup.

**Verify:**

- compiler warnings are zero;
- helper reports deterministic machine-readable records;
- malformed action arguments fail closed.

---

### Task 3: Prove real backend creation, attachment, and finite limits

**Files:**
- Modify: `tests/live/test_delegated_cgroup.py`

Use the real `CgroupV2Backend` against the delegated root.

The operator/delegator supplies one disposable stopped process already placed in the configured host-agent source cgroup. The manager must not create this first in-subtree process from outside the delegation boundary.

For separate disposable request scopes, prove:

- source cgroup is a direct child of the configured root and the supplied source PID is actually resident there;
- scope is created only below the configured root;
- `memory.max`, `pids.max`, and `cpu.max` equal the requested finite values;
- the manager can attach the stopped source PID from the source child cgroup to a sibling request scope through real `cgroup.procs`;
- kernel membership confirms the PID is in the request scope before release;
- stats read real `memory.current`, `pids.current`, `cpu.stat`, and `cgroup.events`;
- the manager can move the stopped fixture PID back to the source cgroup for bounded cleanup;
- the now-empty request scope is removable.

The source PID is operator-owned fixture state. The manager does not need permission to signal it, and the test must not gain `CAP_KILL` merely for cleanup.

This task validates the manager-side primitive only. It does not yet claim full privilege separation.

---

### Task 4: Prove production manager/client/barrier composition and migration denial

**Files:**
- Modify: `tests/live/test_delegated_cgroup.py`
- Create: `scripts/run-live-delegated-cgroup-probe.py`

Compose the already-implemented production boundaries:

1. manager identity + real `CgroupV2Backend`;
2. host-agent process already placed by the operator in the dedicated source child cgroup;
3. secure Unix endpoint and manager service;
4. authenticated `connect_authenticated_containment_manager()`;
5. `ContainmentManagerClient` as the bounded runner backend;
6. execution child inheriting source-cgroup membership at fork;
7. existing start barrier while the manager moves the child source -> sibling request scope;
8. real workload UID/GID transition;
9. pinned native ELF execution of the cgroup probe.

The fixture must also prove that the manager process remains outside the delegated root, that the host-agent begins with only the already-approved identity-transition authority (`CAP_SETUID`/`CAP_SETGID`, no `CAP_KILL`/`CAP_SYS_ADMIN`), and that neither manager nor workload retains bootstrap capabilities.

The first machine-readable record emitted by the executed native ELF must report membership in the expected request scope. That observation is the live evidence that manager-confirmed attach and start-barrier release happened before workload exec; a later membership check alone is insufficient.

Create a sibling sentinel scope before the workload executes.

The workload attempts to write its PID to:

- delegated-root `cgroup.procs`;
- sibling-scope `cgroup.procs`.

Both targets must exist and be manager-writable. Both workload writes must fail with `EACCES` or `EPERM`, and kernel membership must still show the original request scope.

Also prove the workload has:

- no manager-client supplementary group;
- no effective/permitted/inheritable/ambient capabilities;
- no open manager control descriptor;
- no manager opaque scope capability in argv or environment.

Any successful migration fails the live gate.

---

### Task 5: Prove PID and CPU enforcement

**Files:**
- Modify: `tests/live/test_delegated_cgroup.py`

Use separate request scopes.

**PID proof:**
- configure a small finite `pids.max`;
- make bounded fork attempts;
- require kernel refusal before the scope exceeds the limit;
- sample `pids.current` and prove it never exceeds the configured ceiling;
- clean all descendants through manager-authoritative containment.

**CPU proof:**
- configure a restrictive finite `cpu.max`;
- run bounded CPU saturation;
- compare `cpu.stat` before/after;
- require `nr_throttled` to increase and require `throttled_usec` to be present and nondecreasing;
- keep wall-clock duration bounded.

Do not infer enforcement only from limit-file read-back.

---

### Task 6: Prove memory enforcement without host pressure

**Files:**
- Modify: `tests/live/test_delegated_cgroup.py`

Use an isolated request scope with a deliberately small `memory.max`.

The native helper allocates memory in bounded increments beyond that ceiling. Require request-scope `memory.events` evidence: the `oom` and/or `oom_kill` counter must increase from its baseline, and the workload must terminate or report allocation failure consistently with that kernel event. Limit-file read-back or process death alone is insufficient.

Requirements:

- use a small ceiling and hard upper allocation bound;
- record before/after request-scope memory accounting;
- unrelated sentinel scope remains healthy;
- host-wide OOM or unrelated termination fails the test;
- cleanup remains bounded.

If reliable kernel attribution cannot be achieved on the target runner, do not weaken the assertion; fix the fixture.

---

### Task 7: Prove recursive descendant kill and sibling survival

**Files:**
- Modify: `tests/live/test_delegated_cgroup.py`

The workload creates a bounded process tree with descendants that remain alive.

Then:

1. retain pidfds for reported descendants when available, or record PID plus `/proc/<pid>/stat` start time as a stable process identity;
2. invoke the existing manager `kill_all()`;
3. prove the recorded descendant identities are gone without confusing PID reuse for survival;
4. require `cgroup.events populated 0` before deadline as the authoritative scope-empty signal;
5. prove the sibling sentinel remains alive;
6. close/remove the empty request scope.

Do not use process-group SIGKILL as the passing evidence. Direct signaling may remain defense-in-depth, but the proof must be attributable to request-scope `cgroup.kill`.

---

### Task 8: Add dedicated Linux runner/operator entrypoint

**Files:**
- Create: `.github/workflows/live-cgroup-security.yml`
- Modify: `scripts/run-live-delegated-cgroup-probe.py`
- Modify: `docs/self-hosted-runner.md`
- Modify: `tests/live/README.md`

The accepted workflow is manual/trusted and uses a separate custom label such as:

```text
[self-hosted, linux, ssh-over-mcp-cgroup-live]
```

It must:

- execute only on a disposable, isolated Linux fixture with no production secrets or host credentials;
- have users/groups, the delegated subtree, the direct-child host-agent source cgroup, and initial host-agent/source-process placement prepared by the operator outside the checked-out test code, so the job does not gain a generic root setup path;
- execute only with the pre-delegated disposable subtree intended for this proof;
- expose no Docker socket to the job;
- not require `--privileged`;
- pass only server/operator-controlled fixture paths and identity configuration;
- run the dedicated live gate on one exact commit;
- clean request scopes after success/failure;
- record fixture/kernel/cgroup metadata needed to audit the result without dumping unrelated host state.

Do not modify `self-hosted-security.yml` to grant additional cgroup authority.

---

### Task 9: Full review and phase closure

**Files:**
- Modify: `docs/development-plan.md`
- Modify: `docs/ssh-host-agent.md`
- Modify: `remote/host_agent/README.md`
- Modify: `docs/self-hosted-runner.md` as needed

Only after exact-head live evidence passes:

- run full ordinary Python 3.13 and 3.14 Ruff/compile/pytest gates;
- rerun the dedicated live cgroup suite;
- review the complete phase diff for privilege widening, manager-protocol growth, cgroup path injection, inherited descriptors/capabilities, migration bypass, cleanup scope, and accidental ForceCommand wiring;
- record the exact commit SHA and fixture description;
- mark Phase `3d2b2b2c3` implemented;
- advance the roadmap to Phase `3d2c`.

Expected final state: the repository has live evidence for request-level cgroup escape resistance and resource enforcement, while ForceCommand execution remains disabled until the next phase.
