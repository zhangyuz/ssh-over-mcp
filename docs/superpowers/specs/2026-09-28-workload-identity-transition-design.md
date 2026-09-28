# Workload Identity Transition Design

Date: 2026-09-28

Status: proposed for implementation planning

## 1. Purpose

This design defines Phase `3d2b2b2c2b2b3`: the irreversible Linux identity transition performed by the forked execution child before native `execve`.

The intended outcome is that every structured workload starts under the dedicated workload UID/GID, with:

- real, effective, and saved UID all equal to the configured workload UID;
- real, effective, and saved GID all equal to the configured workload GID;
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
8. post-transition read-back verification;
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

Before any transition syscall, the helper MUST reject a workload policy whose target UID or GID is root, whose supplementary-group set is non-empty, or whose target UID equals the current host-agent UID. The workload transition is never a no-op identity path.

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
11. clear effective, permitted, and inheritable capabilities with `capset`;
12. verify the complete post-drop identity contract;
13. call the existing native execution primitive, which revalidates the pinned cwd/executable immediately before `execve`.

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

supplementary groups == empty
```

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
- `capget`.

If a required primitive is unavailable, returns an error, or produces a state which fails read-back verification, the child MUST NOT call `execve`.

The implementation must check all syscall/libc return values.

## 12. Component boundary

Add a focused module:

```text
src/ssh_over_mcp/host_agent/workload_identity.py
```

Conceptual API:

```python
class WorkloadIdentityTransitionError(RuntimeError):
    ...

def transition_to_workload_identity(
    policy: LinuxProcessIdentityPolicy,
) -> LinuxProcessIdentitySnapshot:
    ...
```

The returned snapshot is the verified post-drop identity.

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
```

The exact naming may change during implementation planning, but an explicit identity input is normative.

Inside the forked child:

```text
trusted setup
  -> transition_to_workload_identity(policy)
  -> exec_prepared_native_in_child(prepared)
```

If transition fails, the existing child failure boundary emits only the existing generic child-exec failure message and exits with the existing failure code. Sensitive syscall or capability details are not exposed to the workload protocol.

## 14. Failure semantics

The following are fatal to the child before exec:

- missing required Linux credential APIs;
- root workload UID/GID, non-empty workload supplementary groups, or no-op workload UID;
- failure to set `no_new_privs`;
- failure to clear ambient capabilities;
- failure to clear supplementary groups;
- failure of `setresgid`;
- failure of `setresuid`;
- failure to clear capability sets;
- any UID/GID read-back mismatch;
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
7. supplementary groups are empty;
8. `no_new_privs=1` before exec;
9. effective/permitted/inheritable capabilities are empty before exec;
10. ambient capabilities are empty before exec;
11. transition failure prevents exec;
12. pinned cwd/executable validation still occurs after the drop;
13. manager descriptors remain non-inheritable/not in the child keep-set;
14. the containment manager gains no execution API;
15. ForceCommand execution remains disabled after this phase.

## 16. Test strategy

### 16.1 Unit tests for the transition primitive

Tests must pin exact operation ordering and failure behavior.

Required cases include:

| Case | Expected result |
| --- | --- |
| missing required Linux API | fail closed |
| workload target is root | fail closed before mutation |
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
| supplementary group remains | transition fails |
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

### 16.4 Dedicated Linux live validation

Before merging the implementation, run a dedicated Linux validation environment which grants only the identity-transition capabilities needed for the probe.

The live probe must demonstrate:

1. start from a non-root host-agent-like UID;
2. transition to a distinct non-root workload UID/GID;
3. verify real/effective/saved IDs equal the workload IDs;
4. verify supplementary groups are empty;
5. verify current capability sets are empty;
6. verify `no_new_privs=1`;
7. verify an attempt to restore the host-agent UID fails.

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

1. the child cannot enter native exec without an explicit workload identity policy;
2. the transition is ordered after containment release and before exec;
3. the verified child identity is exactly the configured workload UID/GID with no saved host-agent identity;
4. supplementary groups are empty;
5. `no_new_privs=1`;
6. effective/permitted/inheritable/ambient capabilities are empty;
7. transition errors fail closed before exec;
8. pinned cwd/executable validation remains after the identity drop;
9. dedicated live Linux validation proves the child cannot restore the host-agent UID;
10. Ruff, compile, Python 3.13 tests, and Python 3.14 tests pass;
11. the containment manager protocol is unchanged;
12. ForceCommand execution remains disabled.

## 19. Follow-on phases

After this phase:

1. Phase `3d2b2b2c2c`: use the authenticated containment-manager client through the existing start barrier and bounded runner;
2. Phase `3d2b2b2c3`: live delegated-cgroup descendant-kill/resource-limit/self-migration tests;
3. Phase `3d2c`: wire supervised native execution into the ForceCommand CLI only after containment and identity boundaries are enforced.
