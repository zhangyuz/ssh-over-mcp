# ADR 0004: Separate containment management from workload privilege

- Status: Accepted
- Date: 2026-09-27

## Context

Per-request cgroup v2 scopes are intended to contain every descendant of one
remote execution and enforce request-specific CPU, memory, and PID ceilings.

Linux cgroup v2 delegation prevents a delegatee from migrating processes across
the outer delegation boundary without permission on the common ancestor.
However, the delegatee is intentionally allowed to reorganize processes inside
its own delegated subtree.

If the host-agent manager and the untrusted workload share the same cgroup
migration authority, a workload placed in a request child cgroup may be able to
write itself into the delegated root or another sibling cgroup. That would keep
the process inside the outer delegated subtree while bypassing the request-level
`memory.max`, `pids.max`, `cpu.max`, and request-scoped `cgroup.kill`
boundary.

The existing `CgroupV2Backend` is therefore a valid manager-side primitive but
is not, by itself, an escape-resistant production boundary for hostile code.

## Decision

Production execution of untrusted or repository-controlled code MUST separate
containment-management authority from the workload privilege domain.

For v1:

1. writable cgroup-v2 management remains outside the workload process;
2. a narrow local containment manager/helper owns the delegated writable cgroup
   subtree and wraps the existing `CgroupV2Backend` operations;
3. the helper exposes only typed containment operations: create, attach,
   kill-all, stats, and close;
4. the helper MUST NOT expose generic command execution, arbitrary filesystem
   operations, shell access, or network administration;
5. the host agent retains the pre-exec start barrier and MUST NOT release the
   child until the manager confirms successful attachment to the request scope;
6. helper authority or scope capabilities MUST NOT survive into the executed
   workload through environment variables, inherited writable cgroup mounts,
   or non-close-on-exec control descriptors;
7. the workload MUST NOT be able to write an ancestor or sibling
   `cgroup.procs` which would permit migration out of its request scope;
8. live validation MUST attempt request-scope self-migration and MUST fail the
   deployment if that migration succeeds.

The exact local IPC framing and helper authentication mechanism are implemented
in subsequent increments, but they must preserve the privilege-separation
invariant above.

## Consequences

- The host deployment gains one additional narrow local security component.
- The direct `CgroupV2Backend` remains useful inside the containment manager
  and in unit tests, but MUST NOT be treated as sufficient production isolation
  when the workload shares its cgroup authority.
- The ForceCommand execution path remains disabled until manager-backed
  containment and live escape-resistance tests pass.
- Deployment becomes more explicit about which process owns writable cgroup
  controls.

## Security impact

Positive: closes the post-attach self-migration gap where a workload could
remain inside the outer delegated subtree yet escape its request-specific
resource and kill boundary.

Cost: introduces a small privileged or separately delegated helper which must
have a minimal typed interface, strict local authentication, bounded resource
use, and independent auditability.
