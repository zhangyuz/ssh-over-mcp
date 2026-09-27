# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3d2b2b2b3 behavior

The ForceCommand request path remains **non-executing**.

The bounded native runner now always uses the contained-spawn path:

1. create/configure the request containment scope;
2. fork a child blocked on the start barrier;
3. attach the child before release;
4. execute with bounded stdin/stdout/stderr and wall timeout;
5. attempt graceful process-group SIGTERM on timeout/output overflow;
6. use recursive containment kill for hard termination;
7. on normal direct-child exit, kill any lingering contained descendants;
8. wait for an empty scope, collect accounting, and remove containment before returning.

Process-group SIGKILL is only defense-in-depth once containment kill succeeds.

Containment is not considered production-complete until live delegated-cgroup
tests prove descendant kill/resource ceilings and prove that workload code
cannot self-migrate through writable ancestor cgroup membership controls.

Next: live delegated-cgroup integration tests. The ForceCommand CLI remains
disabled until those tests and deployment invariants are satisfied.
