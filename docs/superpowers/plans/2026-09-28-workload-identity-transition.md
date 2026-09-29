# Workload Identity Transition Implementation Plan

> **For agentic workers:** Implement task-by-task with a Review -> Fix -> Verify gate after every task. Do not merge an implementation increment while any security review issue or required validation remains unresolved.

**Goal:** Implement Phase `3d2b2b2c2b2b3`: every supervised native workload crosses an irreversible Linux host-agent -> workload UID/GID boundary after containment release and before native exec, with `no_new_privs=1`, no supplementary groups, no active/ambient capabilities, no saved host-agent identity, and bounded containment-authoritative cleanup when the parent loses signal permission.

**Architecture:** Add one Linux-specific workload-identity primitive behind a private syscall boundary, then make the supervisor require an explicit workload identity policy before every child exec. Keep the containment start barrier authoritative. Update the bounded runner so expected cross-UID `EPERM` on direct/process-group signaling immediately escalates to the existing containment kill path without adding `CAP_KILL`. Validate the real transition in a dedicated disposable Linux capability probe; generic CI stays unprivileged.

**Tech Stack:** Python 3.13+, Linux credential syscalls via stdlib `os` plus a narrow `ctypes` libc boundary, pytest, existing containment/supervisor abstractions, Docker/self-hosted Linux validation.

**Spec:** `docs/superpowers/specs/2026-09-28-workload-identity-transition-design.md`

**ADR:** `docs/decisions/0005-workload-identity-drop.md`

## Global Constraints

- The host-agent source identity is non-root and coherent: real/effective/saved UID are equal; real/effective/saved GID are equal.
- The workload target UID/GID are non-root, are not the all-ones reserved sentinel, and the target UID differs from the verified source UID.
- The workload policy must have an actually empty supplementary-group set for this transition.
- `PR_SET_NO_NEW_PRIVS=1` is set before UID/GID mutation.
- Ambient capabilities are cleared before identity mutation.
- Supplementary groups are cleared before `setresgid`.
- `setresgid(target, target, target)` precedes `setresuid(target, target, target)`.
- Effective/permitted/inheritable capability sets are explicitly cleared after UID transition and then read back.
- Filesystem UID/GID are verified explicitly.
- The post-drop kernel group list must be literally empty; do not reuse the general validator's primary-GID normalization as proof.
- The existing pinned cwd/executable revalidation remains after the identity transition and immediately before exec.
- No production API gains a bypass flag, optional workload policy, current-identity fallback, or no-op transition mode.
- The parent does not gain `CAP_KILL`, does not switch identity to signal the child, and does not regain authority through a manager protocol expansion.
- Generic CI/self-hosted Docker validation remains unprivileged. Real `CAP_SETUID`/`CAP_SETGID` exercise belongs only to the dedicated live probe.
- ForceCommand execution remains disabled after this phase.

## Review Focus

- Linux capability ABI coverage is complete for all capabilities reported by the running kernel; unknown/unsupported ranges fail closed.
- Source credentials and target policy are validated before the first mutating syscall.
- `no_new_privs` and ambient clear happen before group/ID transition.
- A failed `setresgid` prevents `setresuid`; a failed `setresuid` prevents capability clear/exec.
- Capability read-back cannot silently truncate the upper 32 bits.
- FSUID/FSGID verification is read-only from the transition's perspective and cannot accidentally change credentials.
- A supplementary group equal to the workload primary GID still fails the stronger empty-group contract.
- Supervisor tests prove: barrier release -> trusted child setup/rlimits -> identity transition -> pinned native exec.
- Timeout/output-limit `EPERM` is treated as expected cross-UID loss of signal permission only when containment-authoritative cleanup succeeds.
- Successful containment kill is not converted into a false failure because defense-in-depth direct/process-group `SIGKILL` also returns `EPERM`.
- `ESRCH` is treated only as a race with process exit, never as proof that the containment scope is empty.
- The live probe proves the parent identity/capability state is unchanged while only the child crosses the boundary.

---

### Task 1: Linux Workload Identity Transition Primitive

**Files:**
- Create: `src/ssh_over_mcp/host_agent/workload_identity.py`
- Create: `tests/host_agent/test_workload_identity.py`

**Interfaces:**
- Consumes:
  - `LinuxProcessIdentityPolicy`
  - Linux `getresuid/getresgid/getgroups`
  - Linux `setgroups/setresgid/setresuid`
  - `prctl(PR_SET_NO_NEW_PRIVS)` and `prctl(PR_GET_NO_NEW_PRIVS)`
  - `prctl(PR_CAP_AMBIENT_CLEAR_ALL)`
  - `capget/capset`
  - explicit FSUID/FSGID read-back
- Produces:
  - `class WorkloadIdentityTransitionError(RuntimeError)`
  - `WorkloadIdentityTransitionSnapshot` matching the accepted design: `identity: LinuxProcessIdentitySnapshot`, `filesystem_uid`, `filesystem_gid`, `no_new_privs`, `effective_capabilities`, `permitted_capabilities`, and `inheritable_capabilities`
  - `transition_to_workload_identity(policy: LinuxProcessIdentityPolicy) -> WorkloadIdentityTransitionSnapshot`

Use a private module-level syscall adapter/seam for tests. Do **not** add a public dependency-injection parameter to `transition_to_workload_identity`.

- [ ] **Step 1: Write validation-order unit tests**

Add focused tests for:

```python
def test_missing_required_linux_api_fails_before_mutation(...): ...
def test_root_or_mixed_source_identity_fails_before_mutation(...): ...
def test_root_or_reserved_target_id_fails_before_mutation(...): ...
def test_nonempty_workload_supplementary_groups_fail_before_mutation(...): ...
def test_target_uid_equal_to_source_uid_fails_before_mutation(...): ...
```

Assert no mutating syscall is attempted in every precondition failure.

- [ ] **Step 2: Write exact transition-order tests**

Pin the success sequence:

```text
read source credentials
read/validate capability ABI range
set no_new_privs
clear ambient capabilities
setgroups([])
setresgid(target, target, target)
setresuid(target, target, target)
read FSUID/FSGID
capset(all zero)
read credentials/groups/capabilities/no_new_privs
verify exact post-drop state
```

The test should compare a recorded operation list, not merely assert that calls happened.

- [ ] **Step 3: Write failure-cutoff tests**

Cover:

- `PR_SET_NO_NEW_PRIVS` failure -> no group/ID change;
- ambient clear failure -> no group/ID change;
- `setgroups([])` failure -> no GID/UID change;
- `setresgid` failure -> no UID change;
- `setresuid` failure -> no capset or success return;
- capset failure -> transition fails;
- saved UID/GID mismatch -> fail;
- FSUID/FSGID mismatch -> fail;
- any residual supplementary group, including target primary GID -> fail;
- nonzero effective/permitted/inheritable capability bit -> fail;
- `no_new_privs` read-back not equal to one -> fail;
- unsupported/truncated capability ABI/range -> fail.

- [ ] **Step 4: Implement the minimal Linux syscall boundary**

Use narrow private wrappers around libc/Linux calls. Requirements:

- fail closed if Linux-only operations are unavailable;
- use capability ABI v3 data wide enough for capabilities 0..63;
- read `/proc/sys/kernel/cap_last_cap` or an equivalent authoritative kernel value and reject a capability range the implementation cannot represent completely;
- clear both 32-bit capability words for effective/permitted/inheritable sets;
- use a genuinely read-only FSUID/FSGID observation mechanism from the transition's perspective; prefer parsing the four-ID `Uid:` / `Gid:` fields from `/proc/self/status` rather than probing through `setfsuid` / `setfsgid`;
- translate syscall failures into the transition error without exposing partially-successful state as success.

- [ ] **Step 5: Verify Task 1**

Run:

```bash
python -m pytest -q tests/host_agent/test_workload_identity.py
python -m compileall -q src/ssh_over_mcp/host_agent/workload_identity.py tests/host_agent/test_workload_identity.py
```

Expected: PASS without requiring runner capabilities or changing the test process identity.

- [ ] **Step 6: Commit Task 1**

```bash
git add src/ssh_over_mcp/host_agent/workload_identity.py tests/host_agent/test_workload_identity.py
git commit -m "feat: add verified workload identity transition"
```

---

### Task 2: Make Workload Identity Mandatory in the Supervisor

**Files:**
- Modify: `src/ssh_over_mcp/host_agent/supervisor.py`
- Modify: `tests/host_agent/test_supervisor.py`
- Modify: `src/ssh_over_mcp/host_agent/__init__.py` only if a stable public type/error export is required

**Interfaces:**
- Consumes Task 1 `transition_to_workload_identity`
- Adds a required `workload_identity_policy: LinuxProcessIdentityPolicy` to child-spawn paths that can reach native exec
- Keeps the test seam private by monkeypatching the supervisor module's imported transition symbol before `fork()`

- [ ] **Step 1: Write API fail-closed tests**

Prove there is no production path that reaches native exec without an explicit workload policy.

Tests should fail before implementation if the new required argument is absent.

- [ ] **Step 2: Write child ordering tests**

Prove:

```text
containment attach succeeds
parent releases start barrier
child sets session/signal/umask/core/stdio/fd/rlimits
child transition_to_workload_identity(policy)
child exec_prepared_native_in_child(prepared)
```

Use pre-fork monkeypatching so generic CI does not require `CAP_SETUID`/`CAP_SETGID`.

- [ ] **Step 3: Write transition-failure test**

If the identity transition raises:

- native exec helper is never called;
- child exits through the existing generic fail-closed child status;
- parent supervision semantics remain unchanged.

- [ ] **Step 4: Implement mandatory supervisor integration**

Pass the workload policy through the contained-spawn path and into the released child. Call the transition only after trusted pre-exec setup/rlimits and before `exec_prepared_native_in_child()`.

Do not:

- add a nullable policy;
- infer current identity;
- add a skip/bypass flag;
- change the containment manager protocol;
- move pinned executable/cwd validation ahead of the transition.

- [ ] **Step 5: Verify Task 2**

Run:

```bash
python -m pytest -q   tests/host_agent/test_workload_identity.py   tests/host_agent/test_supervisor.py   tests/host_agent/test_execute.py   tests/host_agent/test_prepare.py
```

Expected: PASS in the ordinary unprivileged environment.

- [ ] **Step 6: Commit Task 2**

```bash
git add src/ssh_over_mcp/host_agent/supervisor.py tests/host_agent/test_supervisor.py src/ssh_over_mcp/host_agent/__init__.py
git commit -m "feat: require workload identity before native exec"
```

---

### Task 3: Preserve Bounded Runner Semantics After Cross-UID Signal Denial

**Files:**
- Modify: `src/ssh_over_mcp/host_agent/run.py`
- Modify: `tests/host_agent/test_run.py`

**Interfaces:**
- `run_prepared_native(..., workload_identity_policy: LinuxProcessIdentityPolicy, ...)`
- Existing `ContainmentHandle.kill_all()` remains the authoritative hard-kill mechanism

- [ ] **Step 1: Add required workload-policy propagation tests**

Assert `run_prepared_native` passes the exact workload policy to `spawn_prepared_native_contained`.

No optional/fallback workload policy is allowed.

- [ ] **Step 2: Add timeout `EPERM` regression**

Simulate process-group/direct `SIGTERM` raising `PermissionError(errno.EPERM)`.

Expected:

1. timeout flag becomes true;
2. no grace-period wait is required before escalation;
3. containment `kill_all()` is attempted immediately;
4. output pipes are boundedly drained/closed;
5. child is reaped;
6. containment becomes empty and is closed;
7. result still reports `timed_out=True`.

- [ ] **Step 3: Add output-limit `EPERM` regression**

Same authority loss, but preserve `output_exceeded=True`.

- [ ] **Step 4: Add error-boundary regressions**

Cover:

- successful containment kill + defense-in-depth `SIGKILL` `EPERM` -> no false failure;
- containment kill failure -> `BoundedExecutionError`;
- non-`EPERM` graceful signal error -> `BoundedExecutionError`;
- `ESRCH` signal race -> continue to containment accounting; never infer empty scope;
- direct child exited but scope still populated -> containment kill still happens;
- cleanup failure may override the original result only under the existing bounded-cleanup failure contract.

- [ ] **Step 5: Implement minimal signaling classification**

Refactor the existing signal helper/termination transition so expected `EPERM` is distinguishable from other failures.

Do not catch every `OSError` as equivalent. Keep containment kill authoritative and existing process-group/direct signaling defense-in-depth only.

- [ ] **Step 6: Verify Task 3**

Run:

```bash
python -m pytest -q tests/host_agent/test_run.py tests/host_agent/test_supervisor.py
```

Repeat the timeout/output-limit boundary cases multiple times to detect timing regressions.

- [ ] **Step 7: Commit Task 3**

```bash
git add src/ssh_over_mcp/host_agent/run.py tests/host_agent/test_run.py
git commit -m "fix: handle cross-uid signal denial through containment"
```

---

### Task 4: Dedicated Live Linux Capability-Transition Validation

**Files:**
- Create one dedicated live probe under `scripts/` or `tests/live/`
- Create/modify a dedicated workflow or operator script for the probe
- Do not modify the generic self-hosted runner to grant identity-changing capabilities

**Live fixture identities:**

Use four distinct numeric IDs:

- host-agent UID;
- host-agent primary GID;
- workload UID/workload primary GID;
- manager-client supplementary GID.

The host-agent and workload primary GIDs must also be distinct for this probe.

- [ ] **Step 1: Build the disposable capability fixture**

Launch the actual probe process as a **non-root** UID with only:

```text
CAP_SETUID
CAP_SETGID
```

in the effective/permitted capability sets, plus the manager-client supplementary group.

The parent must not have `CAP_KILL`.

A root container/bootstrap process may be used only to construct the disposable fixture and then drop into the non-root host-agent process before the probe assertions begin.

- [ ] **Step 2: Exercise the real transition**

The live test must prove before native exec:

- source process is non-root;
- pre-transition `no_new_privs` is exactly `0`, then the transition changes it to `1`;
- only `CAP_SETUID`/`CAP_SETGID` are active;
- transition reaches the distinct workload UID/GID;
- real/effective/saved UID/GID all match workload;
- FSUID/FSGID match workload;
- supplementary groups are empty;
- effective/permitted/inheritable capabilities are zero;
- ambient capabilities are empty;
- `no_new_privs=1`.

- [ ] **Step 3: Prove irreversibility**

After the drop, assert:

- restoring host-agent UID fails;
- restoring host-agent GID fails;
- restoring manager-client supplementary group fails.

- [ ] **Step 4: Prove state after native ELF exec**

Run the existing pinned **native ELF** exec path into a small probe executable and report the same identity/capability/`no_new_privs` state from the executed image.

A script/interpreter fixture is not sufficient for this gate; the probe must exercise the repository's native fd-based ELF exec path so interpreter behavior cannot mask the credential boundary.

- [ ] **Step 5: Prove parent remained unchanged and cannot signal**

Synchronize parent/child so the child is alive after dropping identity.

Assert:

- parent credentials/capabilities before and after are identical;
- parent `kill(child_pid, 0)` fails with `EPERM`, not `ESRCH`;
- only the child changed identity;
- disposable cleanup remains bounded.

- [ ] **Step 6: Verify the live probe is isolated from generic validation**

The ordinary full suite must still pass without `CAP_SETUID`/`CAP_SETGID`.

Document the exact dedicated command/workflow required for the live proof.

- [ ] **Step 7: Commit Task 4**

```bash
git add <live-probe-files>
git commit -m "test: validate live workload identity transition"
```

---

### Task 5: Source-of-Truth Docs and Full Verification

**Files:**
- Modify: `src/ssh_over_mcp/host_agent/__init__.py` if public exports are intentionally added
- Modify: `docs/ssh-host-agent.md`
- Modify: `docs/development-plan.md`
- Modify: `remote/host_agent/README.md`
- Test all files touched in Tasks 1-4

- [ ] **Step 1: Update host-agent security boundary documentation**

Document:

- non-root host-agent capability requirement: `CAP_SETUID` + `CAP_SETGID` only for this boundary;
- child transition ordering;
- literal empty supplementary-group requirement;
- `no_new_privs`, capability clear/read-back, FSUID/FSGID verification;
- expected parent signal `EPERM` after drop and containment-authoritative hard cleanup;
- containment manager API unchanged;
- ForceCommand still disabled.

- [ ] **Step 2: Advance the roadmap**

Update `docs/development-plan.md`:

- mark Phase `3d2b2b2c2b2b3` implemented only after the live proof passes;
- next phase becomes `3d2b2b2c2c`: authenticated containment-manager client integration through the existing start barrier and bounded runner.

Update `remote/host_agent/README.md` with the same operator-visible boundary.

- [ ] **Step 3: Run static/focused verification**

```bash
python -m compileall -q src tests
python -m pytest -q   tests/host_agent/test_workload_identity.py   tests/host_agent/test_supervisor.py   tests/host_agent/test_run.py
```

Run Ruff/format checks configured by the repository.

- [ ] **Step 4: Run the full ordinary suite on supported Python versions**

Required:

```text
Python 3.13 full suite: PASS
Python 3.14 full suite: PASS
generic runner effective capabilities: unchanged/unprivileged
```

- [ ] **Step 5: Run the dedicated live capability-transition proof**

Required: PASS on the exact implementation head SHA.

Do not substitute mocked unit tests for this gate.

- [ ] **Step 6: Review the complete implementation diff**

Review specifically for:

- privilege widening;
- capability ABI truncation;
- ordering regressions;
- bypass/optional policy paths;
- descriptor inheritance changes;
- signal-error misclassification;
- manager protocol changes;
- ForceCommand accidentally enabled;
- docs claiming validation not actually observed.

Fix every issue found, rerun the affected verification, then re-review.

- [ ] **Step 7: Open/merge implementation PR only after all gates pass**

PR summary must include:

- exact implementation head SHA;
- ordinary Python 3.13/3.14 validation results;
- dedicated live probe result;
- cross-UID `EPERM` regressions;
- confirmation that parent has no `CAP_KILL`;
- confirmation that manager protocol and ForceCommand boundary are unchanged.

After merge, begin Phase `3d2b2b2c2c` as the next small increment.
