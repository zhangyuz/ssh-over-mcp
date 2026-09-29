# Workload Identity Transition Design

Date: 2026-09-28

Status: accepted for implementation planning (2026-09-28)

## 1. Purpose

This design defines Phase `3d2b2b2c2b2b3`: the irreversible Linux identity transition performed by the forked execution child before native `execve`.

The intended outcome is that every structured workload starts under the dedicated workload UID/GID, with:

- real, effective, and saved UID all equal to the configured workload UID;
- real, effective, and saved GID all equal to the configured workload GID;
- filesystem UID/GID equal to the configured workload UID/GID;
- no supplementary groups;
- no effective, permitted, inheritable, or ambient capabilities;
- Linux `no_new_privs=1`;
- no retained saved identity which can restore the host-agent identity;
- existing pinned executable/cwd revalidation still performed after the drop and immediately before exec.

The containment manager remains a narrow containment service and does not gain command-execution authority.

## 2. Context

The repository already defines three distinct OS identities:

- containment manager;
- host agent;
- untrusted workload.

The host-agent and workload UIDs are required to be distinct and non-root. The workload process policy has no supplementary groups.

The current forked child performs trusted pre-exec setup and then calls `exec_prepared_native_in_child()`, but it still runs with the host-agent identity. This leaves the workload in the same OS identity domain as the process which is permitted to authenticate to the containment manager.

ADR 0004 requires the workload privilege domain to remain separate from containment-management authority. The service identity contract defines the target workload UID/GID, but does not yet perform the transition.

Linux requires `CAP_SETUID` to set arbitrary real/effective/saved UIDs and `CAP_SETGID` to set arbitrary real/effective/saved GIDs and supplementary groups. The host-agent therefore needs narrowly scoped identity-transition authority even though it remains a non-root process.

## 3. Architectural decision

The host-agent process remains non-root and owns only the narrow authority needed to create the forked child and transition that child to the dedicated workload identity.

The deployment grants the host-agent process:

- `CAP_SETUID`;
- `CAP_SETGID`;

and no broader capability solely for workload identity transition.

After `fork()`, only the child consumes this authority for the transition. The child then removes all effective, permitted, inheritable, and ambient capability state before executing workload code.

The containment manager does not perform the identity transition and does not spawn or exec workloads.

This decision is recorded separately in ADR 0005.

## 4. Alternatives considered

### 4.1 Selected: forked child performs its own one-way drop

The host-agent child performs the transition after the existing containment start barrier is released and before native exec.

Advantages:

- smallest new trust surface;
- no new privileged IPC protocol;
- preserves the existing parent/fork/start-barrier architecture;
- preserves the containment manager's narrow typed protocol;
- makes the final privilege state directly verifiable in the child immediately before exec.

Cost:

- the host-agent service must hold `CAP_SETUID` and `CAP_SETGID`;
- the child transition code becomes a security-sensitive Linux primitive.

### 4.2 Deferred: dedicated identity-switch helper

A separate privileged helper could perform UID/GID transition.

This reduces host-agent capability possession, but requires another authenticated local IPC protocol and another privileged lifecycle component. It is not justified for this increment.

### 4.3 Rejected: containment manager spawns the workload

This would combine containment-management authority and generic process execution in one component, expanding ADR 0004's narrow `create/attach/kill/stats/close` boundary. It is rejected.

## 5. Scope

### 5.1 In scope

This phase implements:

1. a Linux workload-identity transition primitive;
2. explicit `no_new_privs` enforcement;
3. supplementary-group removal;
4. real/effective/saved GID transition;
5. real/effective/saved UID transition;
6. clearing effective, permitted, and inheritable capability sets;
7. clearing ambient capabilities;
8. post-transition read-back verification including filesystem UID/GID;
9. supervisor integration before native exec;
10. fail-closed child behavior if any transition or verification step fails;
11. tests which lock transition ordering and failure semantics;
12. source-of-truth documentation updates.

### 5.2 Explicit non-goals

This phase does not:

- give the containment manager execution authority;
- add a generic privileged helper;
- wire the ForceCommand CLI to execute workloads;
- integrate the manager client into the bounded runner;
- add live cgroup self-migration validation;
- add systemd unit files;
- add root SSH or a root host-agent process;
- add `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, `CAP_SETPCAP`, or other broad capabilities;
- empty the Linux capability bounding set from inside the child;
- implement privileged/break-glass execution;
- weaken the default denial of setuid/setgid or file-capability executables.

## 6. Parent process privilege contract

The production host-agent process remains non-root.

For this phase, deployment is expected to grant only the capability authority required for the child identity transition:

```text
CAP_SETUID
CAP_SETGID
```

The host-agent may also hold the already-defined manager-client supplementary group needed to authenticate to the containment-manager socket.

The workload identity MUST remain a different UID from the host-agent identity.

The host-agent process MUST NOT be made root merely to make the transition work.

The implementation must not require `CAP_SETPCAP` or `CAP_SYS_ADMIN`.

`CAP_SETUID` and `CAP_SETGID` are not kernel-restricted to the configured workload IDs. A compromised host agent can change credentials to other identities within its user namespace, including privileged identities. The host agent is therefore a privileged trusted component despite having a nonzero UID. The workload must not control its code, imports, configuration, or target-identity selection. The post-drop guarantee protects against workload code; it does not contain compromise of the capability-bearing host agent. `no_new_privs` does not remove capabilities or prohibit credential-changing syscalls while the process still holds the necessary authority.

A future deployment-hardening increment may add startup verification of the host-agent's exact capability bounding/permitted/effective sets. This phase's normative security boundary is the verified post-drop child state.

## 7. Child transition ordering

The existing parent/child start barrier remains authoritative:

```text
parent forks child
  -> child blocks on start barrier
  -> containment manager confirms request-scope attachment
  -> parent releases child
  -> child performs trusted pre-exec setup
  -> child performs irreversible workload identity transition
  -> child revalidates pinned cwd/executable
  -> child execve(fd, argv, env)
```

No untrusted workload code executes before containment attachment or before the identity transition.

Before any transition syscall, the helper MUST read the source real/effective/saved UID and GID. Each source triple must be internally equal and nonzero; an unavailable read, mixed source identity, or root source fails before mutation. This enforces the non-root source contract without expanding this phase into exact parent capability-set validation.

The helper MUST reject a workload policy whose target UID or GID is root or the reserved all-ones UID/GID sentinel, whose supplementary-group set is non-empty, or whose target UID equals that verified source UID. The workload transition is never a no-op identity path. The target policy is trusted server-side input derived from the service identity plan, not a model-supplied UID/GID.

Within the released child, the required order is:

1. create the child session and reset signals;
2. apply restrictive umask/core settings;
3. duplicate stdio;
4. close unrelated descriptors;
5. apply child rlimits;
6. set Linux `no_new_privs=1`;
7. clear ambient capabilities;
8. clear supplementary groups with `setgroups([])`;
9. call `setresgid(workload_gid, workload_gid, workload_gid)`;
10. call `setresuid(workload_uid, workload_uid, workload_uid)`;
11. verify that Linux filesystem UID/GID are synchronized to the workload UID/GID;
12. clear effective, permitted, and inheritable capabilities with `capset`;
13. verify the complete post-drop identity contract;
14. call the existing native execution primitive, which revalidates the pinned cwd/executable immediately before `execve`.

Identity transition happens after trusted rlimit/FD setup so those operations can complete using the host-agent's trusted pre-exec authority, but before any workload-selected executable begins.

## 8. no_new_privs

The child MUST set `PR_SET_NO_NEW_PRIVS=1` before changing identity.

The setting is irreversible for the process and preserved across `execve`.

This guarantees that the workload cannot gain privilege through the exec transition, including through:

- set-user-ID mode bits;
- set-group-ID mode bits;
- file capabilities.

The repository may continue to deny such executable metadata at policy/preparation layers. `no_new_privs` is an independent execution-time boundary rather than a replacement for those checks.

A future privileged/break-glass path must be a separate design. The normal structured workload path does not disable `no_new_privs`.

## 9. Capability handling

The child MUST NOT rely on implicit Linux capability changes caused by UID transitions.

This is especially important because the production transition is from one
nonzero UID to a different nonzero UID. Linux's automatic capability-clearing
rules are primarily tied to transitions involving UID 0; this nonroot-to-
nonroot transition does not provide the security invariant we need. The child
therefore explicitly clears and verifies its own capability sets.

The implementation explicitly:

1. clears ambient capabilities before the UID/GID transition;
2. transitions GID/UID while `CAP_SETGID` / `CAP_SETUID` are still usable;
3. writes zero effective, permitted, and inheritable capability sets after the transition;
4. reads the capability sets back and requires them to be zero.

The capability bounding set is not required to be empty in this phase.

Reason:

- emptying the bounding set would require additional capability-management authority such as `CAP_SETPCAP`, widening the host-agent privilege surface;
- a bounding-set bit is not itself an active capability;
- the child has `no_new_privs=1`, zero effective/permitted/inheritable sets, and no ambient capabilities, so `execve` cannot reacquire privilege.

Production deployment SHOULD constrain the host-agent's capability bounding set to the minimum required capability set.

## 10. Post-drop verification

The transition is successful only if all read-back checks pass.

Required input constraints:

```text
workload UID != 0
workload GID != 0
workload UID != current host-agent UID
configured supplementary groups == empty
```

Required identity state:

```text
real UID      == workload UID
effective UID == workload UID
saved UID     == workload UID

real GID      == workload GID
effective GID == workload GID
saved GID     == workload GID

filesystem UID == workload UID
filesystem GID == workload GID

supplementary groups == empty
```

Supplementary-group verification MUST require an actually empty kernel-reported group list. Reusing `require_linux_process_identity()` alone is insufficient: that existing general-purpose validator normalizes away a duplicate primary GID. This transition's stronger empty-list contract must reject even a remaining supplementary entry equal to the workload primary GID.

Linux `setresuid()` and `setresgid()` always synchronize the filesystem IDs to the resulting effective IDs. The implementation nevertheless treats FSUID/FSGID as explicit post-drop invariants because Linux filesystem permission checks use those IDs.

Required privilege state:

```text
no_new_privs == 1

effective capabilities   == 0
permitted capabilities   == 0
inheritable capabilities == 0
ambient capabilities     == 0
```

Ambient capability emptiness may be established by the kernel invariant after explicitly clearing ambient capabilities and verifying permitted/inheritable sets are zero.

Verification MUST happen before entering `exec_prepared_native_in_child()`.

No transition step may be treated as best effort.

## 11. Linux API boundary

The transition is Linux-specific and fail-closed.

Expected kernel/libc primitives include:

- `setgroups`;
- `setresgid`;
- `setresuid`;
- `prctl(PR_SET_NO_NEW_PRIVS)`;
- `prctl(PR_GET_NO_NEW_PRIVS)`;
- `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)`;
- `capset`;
- `capget`;
- Linux FSUID/FSGID read-back using the established `setfsuid(-1)` / `setfsgid(-1)` query pattern or an equivalent kernel-backed method.

If a required primitive is unavailable, returns an error, or produces a state which fails read-back verification, the child MUST NOT call `execve`.

The implementation must check all syscall/libc return values. Capability handling must not silently truncate kernel capability state: if the running kernel exposes a capability ABI/range the implementation cannot represent and verify completely, the transition fails closed.

## 12. Component boundary

Add a focused module:

```text
src/ssh_over_mcp/host_agent/workload_identity.py
```

Conceptual API:

```python
class WorkloadIdentityTransitionError(RuntimeError):
    ...

@dataclass(frozen=True, slots=True)
class WorkloadIdentityTransitionSnapshot:
    identity: LinuxProcessIdentitySnapshot
    filesystem_uid: int
    filesystem_gid: int
    no_new_privs: bool
    effective_capabilities: int
    permitted_capabilities: int
    inheritable_capabilities: int
    ambient_capabilities_empty: bool

def transition_to_workload_identity(
    policy: LinuxProcessIdentityPolicy,
) -> WorkloadIdentityTransitionSnapshot:
    ...
```

The returned snapshot records the verified post-drop identity and privilege state. The existing `LinuxProcessIdentitySnapshot` alone is intentionally insufficient because it does not include filesystem IDs, capability state, or `no_new_privs`.

The module owns only Linux identity/capability transition logic. It does not:

- fork;
- attach cgroups;
- manipulate stdio;
- select executables;
- execute commands;
- talk to the containment manager.

The supervisor remains responsible for child lifecycle and ordering.

## 13. Supervisor integration

The execution APIs must receive an explicit workload identity policy.

The child path MUST NOT silently default to the current host-agent identity.

Conceptually:

```python
run_prepared_native(
    ...,
    workload_identity_policy=policy,
)

spawn_prepared_native(
    ...,
    workload_identity_policy=policy,
)

spawn_prepared_native_contained(
    ...,
    workload_identity_policy=policy,
)
```

The bounded runner must propagate the policy through the contained spawn and barrier entry into the shared child setup. The existing uncontained spawn primitive remains an internal/test primitive and must perform the same identity transition; it is not a production alternative to mandatory containment.

The exact naming may change during implementation planning, but an explicit identity input is normative.

Inside the forked child:

```text
trusted setup
  -> transition_to_workload_identity(policy)
  -> exec_prepared_native_in_child(prepared)
```

If transition fails, the existing child failure boundary emits only the existing generic child-exec failure message and exits with the existing failure code. Sensitive syscall or capability details are not exposed to the workload protocol.

### 13.1 Supervision after the UID change

The parent-child relationship does not grant signal permission across different UIDs. With only `CAP_SETUID` and `CAP_SETGID`, the unchanged host-agent parent cannot assume that `killpg()` or its direct-PID fallback can send `SIGTERM` to the dropped workload. The current `_signal_process_group()` raises `BoundedExecutionError` when the direct fallback receives `EPERM`; leaving this unchanged would turn an ordinary timeout or output-limit event into a supervision error.

For timeout and output-limit termination:

1. retain the existing result flag and close stdin;
2. attempt the existing bounded graceful signal path;
3. if permission denial prevents graceful delivery, immediately invoke the existing containment-authoritative hard-kill path and start its cleanup deadline; do not wait a grace period for a signal which was not delivered;
4. retain bounded output draining, child reaping, populated-scope verification, and scope close;
5. return the original timeout/output-limit result only when containment cleanup succeeds.

`EPERM` must be distinguishable from other signal failures. Do not broadly suppress `BoundedExecutionError`. Unexpected signaling errors and failed containment kill/accounting/reap/close retain their existing failure semantics. A successful containment kill must not become a false failure merely because the defense-in-depth direct/process-group `SIGKILL` also lacks permission. `ESRCH` remains a process-exit race, not proof that the containment scope is empty.

Do not add `CAP_KILL`, switch the parent UID to signal a workload, retain the host-agent saved UID in the child, or extend the manager protocol with a generic signal/exec operation. Pre-release spawn-failure cleanup still operates on a child which has not changed identity. This phase uses the existing `ContainmentBackend` abstraction; production manager-client wiring and live cgroup validation remain follow-on phases.

## 14. Failure semantics

The following are fatal to the child before exec:

- missing required Linux credential APIs;
- invalid, root, or mixed source credentials;
- root/reserved-sentinel workload UID/GID, non-empty workload supplementary groups, or no-op workload UID;
- failure to set `no_new_privs`;
- failure to clear ambient capabilities;
- failure to clear supplementary groups;
- failure of `setresgid`;
- failure of `setresuid`;
- failure to clear capability sets;
- any UID/GID read-back mismatch;
- any filesystem UID/GID mismatch;
- any saved-ID mismatch;
- any supplementary-group residue;
- any nonzero effective/permitted/inheritable capability;
- `no_new_privs` read-back not equal to one.

The child MUST NOT attempt to continue with a partial transition.

The parent sees the existing generic child failure outcome.

## 15. Security invariants

Implementation MUST preserve all of the following:

1. containment attachment succeeds before the child is released;
2. no workload code runs before the identity transition;
3. host-agent and workload UIDs remain distinct;
4. the workload has no manager-client supplementary group;
5. real/effective/saved UID all become the workload UID;
6. real/effective/saved GID all become the workload GID;
7. filesystem UID/GID become the workload UID/GID;
8. supplementary groups are empty;
9. `no_new_privs=1` before exec;
10. effective/permitted/inheritable capabilities are empty before exec;
11. ambient capabilities are empty before exec;
12. transition failure prevents exec;
13. pinned cwd/executable validation still occurs after the drop;
14. manager descriptors remain non-inheritable/not in the child keep-set;
15. the containment manager gains no execution API;
16. production execution APIs expose no bypass flag, nullable workload policy, or no-op transition mode;
17. ForceCommand execution remains disabled after this phase;
18. expected cross-UID signal denial cannot bypass containment cleanup or erase timeout/output-limit results.

## 16. Test strategy

### 16.1 Unit tests for the transition primitive

Tests must pin exact operation ordering and failure behavior.

Required cases include:

| Case | Expected result |
| --- | --- |
| missing required Linux API | fail closed |
| source identity is root, mixed, or unreadable | fail closed before mutation |
| workload target is root or the reserved all-ones ID | fail closed before mutation |
| workload supplementary groups are non-empty | fail closed before mutation |
| workload UID equals current host-agent UID | fail closed before mutation |
| set no_new_privs fails | transition fails before ID change |
| ambient clear fails | transition fails |
| setgroups fails | no GID/UID transition proceeds |
| setresgid fails | UID transition does not proceed |
| setresuid fails | capability clearing/exec does not proceed |
| capset-to-zero fails | transition fails |
| saved UID mismatch on read-back | transition fails |
| saved GID mismatch on read-back | transition fails |
| filesystem UID mismatch on read-back | transition fails |
| filesystem GID mismatch on read-back | transition fails |
| supplementary group remains, including a duplicate primary GID | transition fails |
| capability ABI/range cannot be verified completely | transition fails |
| capability read-back nonzero | transition fails |
| no_new_privs read-back is zero | transition fails |
| complete transition | verified workload identity returned |

Tests should mock the syscall boundary rather than changing the test runner's actual identity.

### 16.2 Supervisor ordering tests

Tests must prove:

```text
start barrier released
  -> trusted child setup/rlimits
  -> identity transition
  -> native exec helper
```

and:

- transition failure means native exec helper is never called;
- native exec remains generic/fail-closed to the parent;
- no optional/no-op identity path exists in production APIs.

### 16.3 Existing execution regression suite

All current bounded-run, supervisor, pinned-FD, containment, and manager tests must remain green under Python 3.13 and 3.14.

Generic CI MUST remain unprivileged and MUST NOT gain `CAP_SETUID` or `CAP_SETGID` merely to run the ordinary suite. Tests which exercise the existing fork/exec path may replace the private supervisor-module transition symbol before `fork()`; the forked child inherits that test substitution. This is a test-only seam, not a production runtime option.

Production execution APIs still require a non-null explicit workload identity policy. There is no production bypass flag, no “current identity” fallback, and no optional transition mode. The real capability-bearing transition is exercised only by the dedicated live Linux validation.

The test substitution must not hide changed signal permissions. Add runner regressions for both timeout and output-limit paths where group and direct-PID `SIGTERM` return `EPERM`. Assert immediate containment kill, bounded draining/reaping/close, and the preserved result flag. Also cover successful containment kill plus denied defense-in-depth `SIGKILL`, containment-kill failure, non-`EPERM` signaling failure, and direct-child exit with a still-populated scope. Containment doubles must model their own kill authority independently of the denied parent signal calls.

### 16.4 Dedicated Linux live validation

Before merging the implementation, run a dedicated Linux validation environment which grants only the identity-transition capabilities needed for the probe.

The live probe must demonstrate:

1. start from a non-root host-agent-like UID with only `CAP_SETUID`/`CAP_SETGID` effective/permitted authority, and a manager-client supplementary group;
2. transition to a distinct non-root workload UID/GID;
3. verify real/effective/saved IDs equal the workload IDs;
4. verify filesystem UID/GID equal the workload UID/GID;
5. verify supplementary groups are empty;
6. verify current capability sets are empty;
7. verify `no_new_privs=1`;
8. verify attempts to restore the host-agent UID/GID fail;
9. verify an attempt to restore the manager-client supplementary group fails;
10. complete the existing pinned native ELF exec path and observe the same required identity, empty capability/group state, and `no_new_privs` in the executed probe;
11. verify the unchanged parent has no `CAP_KILL` and cannot signal the live, dropped child (a synchronized signal-zero permission check must fail with `EPERM`, not `ESRCH`); record parent credentials before and after to prove only the child changed identity.

Use distinct host-agent and workload primary GIDs for this dedicated probe, with a separate manager-client GID, so the GID-restoration rejection is meaningful. The existing service identity contract permits shared non-manager-client primary GIDs; setting a GID which is already the workload GID is not privilege restoration and must not be expected to fail. The live probe must have bounded lifetime/cleanup in its disposable validation environment. This probe validates the real identity/exec/signal-permission boundary; actual manager-backed termination remains part of the follow-on live containment validation.

This probe MUST NOT make the generic self-hosted runner privileged or add `CAP_SYS_ADMIN`.

## 17. Expected implementation surface

Expected files:

```text
src/ssh_over_mcp/host_agent/workload_identity.py
src/ssh_over_mcp/host_agent/supervisor.py
src/ssh_over_mcp/host_agent/run.py
src/ssh_over_mcp/host_agent/__init__.py
tests/host_agent/test_workload_identity.py
tests/host_agent/test_supervisor.py
tests/host_agent/test_run.py
docs/ssh-host-agent.md
docs/development-plan.md
remote/host_agent/README.md
```

A small dedicated live-validation script/test fixture may be added if required by the implementation plan.

Unrelated privilege or deployment refactors are out of scope.

## 18. Success criteria

This phase is complete when:

1. the supervised child cannot enter native exec without an explicit workload identity policy;
2. the transition is ordered after containment release and before exec;
3. the verified child identity is exactly the configured workload UID/GID with no saved host-agent identity;
4. filesystem UID/GID equal the workload UID/GID;
5. supplementary groups are empty;
6. `no_new_privs=1`;
7. effective/permitted/inheritable/ambient capabilities are empty;
8. transition errors fail closed before exec;
9. pinned cwd/executable validation remains after the identity drop;
10. generic CI remains unprivileged while dedicated live Linux validation proves the real transition;
11. dedicated live Linux validation proves the child cannot restore the distinct host-agent UID/GID or manager-client supplementary group, preserves the parent identity, and verifies state after native exec;
12. Ruff, compile, Python 3.13 tests, and Python 3.14 tests pass;
13. the containment manager protocol is unchanged;
14. ForceCommand execution remains disabled;
15. timeout/output-limit handling survives expected cross-UID `EPERM` through bounded containment-authoritative cleanup.

## 19. Follow-on phases

After this phase:

1. Phase `3d2b2b2c2c`: use the authenticated containment-manager client through the existing start barrier and bounded runner;
2. Phase `3d2b2b2c3`: live delegated-cgroup descendant-kill/resource-limit/self-migration tests;
3. Phase `3d2c`: wire supervised native execution into the ForceCommand CLI only after containment and identity boundaries are enforced.

## 20. Linux contract references

- [kill(2)](https://man7.org/linux/man-pages/man2/kill.2.html): signal permission depends on credentials/capabilities, not parenthood.
- [setresuid(2) / setresgid(2)](https://man7.org/linux/man-pages/man2/setresuid.2.html): saved-ID replacement, filesystem-ID synchronization, reserved sentinel semantics, and checked return values.
- [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html): identity-changing authority, non-root UID-transition behavior, and the ambient subset invariant.
- [Kernel no_new_privs documentation](https://docs.kernel.org/userspace-api/no_new_privs.html): irreversible exec-time privilege restriction and its limits for other privileged operations.
