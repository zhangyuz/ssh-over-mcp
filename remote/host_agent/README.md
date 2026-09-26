# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3d2b2b2a behavior

The ForceCommand request path remains **non-executing**.

A backend-neutral descendant-containment contract now exists with:

- finite memory/PID/CPU cgroup-style limits;
- one opaque scope per request;
- initial-child attach;
- subtree-wide kill;
- accounting snapshot;
- deterministic cleanup;
- cgroup-v2 host preflight for `cpu`, `memory`, and `pids`.

This phase does not create cgroups and does not yet connect containment to the forked child supervisor.

Next: implement the concrete cgroup-v2 backend and a fork-start barrier so the child cannot exec before successful cgroup attachment.
