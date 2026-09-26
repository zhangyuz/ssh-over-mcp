# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3d2b1 behavior

The ForceCommand request path remains **non-executing**, but the package now contains the first forked child supervisor.

For an fd-pinned native ELF command, the supervisor:

1. validates the execution spec before fork;
2. creates close-on-exec stdin/stdout/stderr pipes;
3. forks a disposable child;
4. creates a new child session/process group;
5. clears blocked signals and resets normal signal handlers;
6. sets `umask 077` and disables core dumps;
7. installs the three stdio pipes;
8. closes unrelated child descriptors;
9. invokes the fd-based native exec primitive.

The parent receives the child PID and pipe endpoints. Child setup/exec failure emits only a fixed generic error and exits 125.

Still missing by design:

- wall timeout;
- combined stdout/stderr byte budget;
- termination/kill escalation;
- CPU/memory/process-count limits;
- ForceCommand CLI integration.

Next: Phase 3d2b2 adds bounded execution and process-group cleanup before any remote execution path is enabled.
