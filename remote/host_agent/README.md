# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3d2b2b2b1 behavior

The ForceCommand request path remains **non-executing**.

A concrete cgroup-v2 backend now exists for an already delegated canonical
Linux cgroup subtree. It can:

- require/enable `cpu`, `memory`, and `pids` controllers;
- create a unique per-request child cgroup;
- apply finite `memory.max`, `pids.max`, and `cpu.max`;
- attach a child through `cgroup.procs`;
- recursively terminate the scope through `cgroup.kill`;
- read memory/PID/CPU/populated accounting;
- remove the scope only after it is empty.

The backend is not yet connected to the forked supervisor.

Next: add a fork-start barrier so a freshly forked child cannot exec before the
parent successfully creates/configures its request cgroup and attaches that
child.
