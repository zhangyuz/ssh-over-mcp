# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3d2b2a behavior

The ForceCommand request path remains **non-executing**, but the package now has a bounded parent execution loop around the forked native child.

The runner:

1. rejects oversized stdin before spawn;
2. feeds stdin and drains stdout/stderr with nonblocking selector I/O;
3. enforces the requested wall timeout;
4. shares one output-byte budget across stdout and stderr;
5. retains at most that configured output budget;
6. closes stdin and sends SIGTERM on timeout/output overflow;
7. escalates to SIGKILL after a short grace;
8. drains/closes pipes and reaps the direct child;
9. returns structured output/returncode/limit flags.

This is still not full containment. Process-group cleanup does not stop a deliberately escaping descendant which creates a new session/group; stronger cgroup/sandbox enforcement is still required for high-risk arbitrary-code profiles.

Still missing before remote execution is enabled:

- CPU/address-space/process-count/file-size rlimits;
- stronger descendant containment policy;
- ForceCommand CLI integration.

Next: Phase 3d2b2b adds host-side resource ceilings and defines the stronger containment requirement.
