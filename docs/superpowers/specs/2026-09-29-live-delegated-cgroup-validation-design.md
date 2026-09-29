# Live Delegated Cgroup Validation Design

Date: 2026-09-29

Status: proposed for implementation planning

## 1. Purpose

Phase `3d2b2b2c3` provides the live Linux proof required before ForceCommand execution can be enabled.

The proof must demonstrate that the already-implemented containment manager, authenticated manager client, start barrier, workload identity transition, and `CgroupV2Backend` form an escape-resistant request boundary on a real delegated cgroup-v2 hierarchy.

This is a deployment validation phase. It does not add new containment authority, manager protocol operations, or command-execution features.

## 2. Security claims to prove

The live fixture MUST prove all of the following on the real kernel:

1. the manager can create and control request cgroups only inside one configured delegated root;
2. the host agent and workload do not receive writable cgroup-management authority;
3. the child is attached to its request scope before native workload exec;
4. request-specific CPU, memory, and PID controls are actually enforced;
5. `cgroup.kill` terminates descendants, not only the direct child;
6. the workload cannot migrate itself to the delegated root or a sibling request scope;
7. manager capability or control descriptors do not survive into the workload;
8. the request scope can be removed after bounded cleanup;
9. failure of any escape-resistance assertion fails the live proof closed.

A process that remains inside the outer delegated subtree but escapes its request child cgroup is an escape for this phase.

## 3. Required fixture boundary

The accepted fixture is Linux with a unified cgroup-v2 hierarchy and a dedicated, disposable, writable subtree delegated specifically for this proof.

The delegated root is an operator/server-owned configuration input. It is not derived from MCP/model request data and the test MUST NOT discover arbitrary writable cgroup paths.

The fixture uses the existing four identity concepts:

- containment-manager UID/GID;
- host-agent UID/GID;
- workload UID/GID;
- manager-client supplementary GID.

Manager, host-agent, and workload UIDs remain distinct. The workload has no supplementary groups. The host agent does not receive `CAP_KILL`.

The manager is the only runtime principal granted write authority over the delegated cgroup subtree. The host-agent and workload identities MUST fail write attempts to request, sibling, and delegated-root membership/control interfaces.

The delegated root MUST satisfy cgroup-v2 domain-controller preconditions before the proof begins: `cpu`, `memory`, and `pids` are available to delegate to children, and the root contains no member processes when those controllers are enabled. The manager process itself therefore runs outside the delegated root rather than occupying the internal node used to create request scopes.

The fixture MUST also contain one operator-created host-agent source cgroup directly below the delegated root. Before bootstrap authority is dropped, the delegator places the host-agent process in that source cgroup. The delegated root itself stays empty. Forked execution children inherit source-cgroup membership and the manager later moves only the execution child from the source cgroup to a sibling request scope. This makes the delegated root the nearest common ancestor for the move, so the manager needs write authority only inside the subtree it was delegated.

The host-agent source cgroup is not a second management domain. Its directory and `cgroup.procs` remain writable only by the manager identity; the host-agent/workload identities MUST NOT be able to move themselves out of that source or back into it after request attachment.

A privileged bootstrap may prepare users, groups, endpoint directories, the delegated subtree, and the initial host-agent source-cgroup placement before the assertions begin. That bootstrap authority MUST not remain in the manager, host-agent, or workload processes being tested. The proof MUST NOT rely on `CLONE_INTO_CGROUP` to bypass cgroup-v2 delegation containment; the same cgroup placement permission rules apply.

## 4. Prohibited fixture shortcuts

The proof MUST NOT be made green by:

- enabling `--privileged` on the generic Docker runner;
- mounting the Docker daemon socket;
- granting the generic runner host cgroup write access;
- granting `CAP_SYS_ADMIN` to the host agent or workload;
- granting `CAP_KILL` to the host agent;
- granting the manager write authority to cgroup membership controls above the delegated root;
- using `CLONE_INTO_CGROUP` as a shortcut around delegated-placement permissions;
- running manager and workload under the same UID;
- bind-mounting a writable cgroup tree into the workload;
- changing permissions so the workload can write ancestor or sibling `cgroup.procs`;
- replacing real cgroup files with temporary-file fakes.

macOS Docker Desktop remains useful for ordinary Linux semantics but is not accepted as evidence for this phase.

## 5. Composition under test

The live proof uses the production composition rather than calling the cgroup backend only in isolation:

1. manager process validates its configured identity and remains outside the delegated root;
2. the operator has already placed the host-agent process in the dedicated source child cgroup below the delegated root;
3. manager owns a `CgroupV2Backend` rooted at the delegated subtree;
4. manager serves the existing authenticated Unix protocol;
5. host agent validates its identity and connects through `connect_authenticated_containment_manager()`;
6. the execution child forks while inheriting the host-agent source-cgroup membership;
7. bounded execution creates the sibling request scope through `ContainmentManagerClient`;
8. the existing start barrier blocks the child until the manager moves it from source to request scope and confirms attachment;
9. trusted child setup closes unrelated FDs and applies rlimits;
10. the child irreversibly transitions to the workload identity;
11. the pinned native ELF path executes the live workload probe;
12. bounded cleanup uses manager-authoritative stats/kill/close operations.

No alternate live-only execution path may bypass these production boundaries.

## 6. Native workload probe

Use a small compiled native ELF helper under `tests/live/`. A script or interpreter fixture is insufficient for the escape assertions because this phase must preserve the repository's pinned native fd-exec boundary.

The helper reports its PID, UID/GID, current cgroup membership, and the results of narrowly defined probe actions. It MUST NOT accept an arbitrary path or command from untrusted input.

Fixture paths are controlled by the test harness, not by model input.

## 7. Self-migration escape test

After native exec under the workload UID, the helper attempts both:

1. writing its PID to the delegated root's `cgroup.procs`;
2. writing its PID to a sibling request scope's `cgroup.procs`.

Both attempts MUST fail with a permission error. The harness then reads the kernel's membership state and proves the workload remains in its original request scope.

The test MUST distinguish permission denial from a meaningless failure such as a missing path. The root and sibling membership files must exist and be manager-writable at the time of the attempted escape.

Any successful write or observed membership outside the original request scope fails the entire live proof.

## 8. Descendant kill proof

The workload creates a bounded descendant tree and reports descendant PIDs to the harness. At least one descendant must outlive the direct workload process unless containment kill occurs.

The host agent requests the existing manager `kill_all()` operation. The proof passes only when:

- `cgroup.kill` is used by the real backend;
- every reported process in the request scope disappears;
- `cgroup.events` reaches `populated 0` within a bounded deadline;
- an unrelated sentinel process in a separate sibling child scope remains alive;
- the empty request scope is successfully removed.

Direct process-group signaling is not accepted as the evidence for this test.

## 9. Resource enforcement proof

The live fixture configures deliberately small, finite limits and validates kernel enforcement without relying only on write/read-back.

### 9.1 PID limit

Use a small `pids.max`. The workload performs a bounded fork attempt and must observe process creation refusal before the request scope exceeds the configured limit. `pids.current` is sampled and must remain at or below the ceiling.

### 9.2 CPU quota

Run a bounded CPU-saturating workload long enough for the configured quota to throttle it. The proof compares `cpu.stat` before/after and requires kernel throttling accounting to increase while the scope remains responsive to cleanup.

### 9.3 Memory limit

Use a disposable workload which allocates beyond a small `memory.max` in a bounded way. The proof requires kernel memory-limit enforcement, preferably an increase in request-scope OOM/OOM-kill accounting plus termination or allocation failure attributable to that limit.

Memory assertions MUST avoid host-wide pressure and use a small isolated ceiling. A host-level OOM or unrelated process termination is a test failure.

Resource tests may use separate request scopes so one limit's expected failure does not contaminate another assertion.

## 10. Bounded failure and cleanup

Every live process wait, manager round trip, cgroup-empty wait, and fixture cleanup has a finite deadline.

On assertion failure, cleanup attempts manager-authoritative `kill_all()` for every created request scope before removing fixture state. Cleanup MUST never target the delegated root itself with `cgroup.kill`.

The harness records enough diagnostics to identify the failed invariant but must not expose manager capabilities, secrets, or unrelated host cgroup data.

## 11. Generic-validation isolation

Ordinary `pytest`, GitHub-hosted CI, and the existing hardened self-hosted Docker runner remain capability-free and do not gain writable cgroup access.

The live tests are opt-in and skip unless the dedicated fixture contract is explicitly satisfied. A missing fixture is a skip for generic validation, not a synthetic pass for the live gate.

A dedicated Linux-only workflow/runner label is required for accepted live evidence. The workflow runs from trusted repository code, receives no Docker socket, and uses only the pre-delegated subtree supplied by the operator.

## 12. Evidence required to close the phase

The phase may be marked implemented only after one exact commit passes:

- ordinary Python 3.13 and 3.14 repository gates;
- dedicated live delegated-cgroup preflight;
- real source-cgroup -> request-cgroup attach through the production manager/client/start-barrier/workload composition;
- root and sibling self-migration denial;
- PID, CPU, and memory enforcement proofs;
- recursive descendant kill proof;
- bounded empty-scope cleanup;
- a final review finding no privilege widening or ForceCommand wiring.

The accepted result records the exact commit SHA and the dedicated runner/fixture description used for the proof.

## 13. Non-goals

This phase does not:

- enable the ForceCommand execution path;
- add manager protocol operations;
- introduce arbitrary cgroup-path protocol fields;
- add daemonization or generic root helpers;
- define production systemd packaging;
- change workload command policy;
- weaken the existing workload identity transition.

After this phase, the next execution milestone is Phase `3d2c`: wire the already-contained supervised native execution path into the ForceCommand CLI.
