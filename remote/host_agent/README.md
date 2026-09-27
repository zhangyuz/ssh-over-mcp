# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3d2b2b2b2 behavior

The ForceCommand request path remains **non-executing**.

The supervisor now has an explicit contained-spawn path:

1. create/configure containment;
2. fork a child blocked on a close-on-exec start-barrier pipe;
3. attach the child's PID to containment;
4. release one byte only after attach succeeds;
5. continue child sanitation and native fd exec.

The containment request ID must match the prepared command request ID.

If attach/release fails, the child is never released into exec and cleanup uses
containment kill plus direct-SIGKILL fallback and bounded reap.

The existing bounded runner still uses the older uncontained spawn function.
Next: switch bounded execution to the contained path and make timeout/output
termination prefer cgroup-wide kill/accounting before process-group fallback.
