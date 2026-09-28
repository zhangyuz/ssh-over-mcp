# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3d2b2b2c2b2b2 behavior

The ForceCommand request path remains **non-executing**.

The containment manager now has a foreground serial service lifecycle. Startup
first validates the configured manager real/effective/saved UID/GID and exact
supplementary groups. The secure Unix endpoint is created only after that check
succeeds.

Each accepted host-agent session is authenticated with the existing
`SO_PEERCRED` policy before protocol traffic. Unauthorized or malformed
sessions are bounded to that connection; listener/endpoint infrastructure
failures remain service-fatal.

The service waits for connections with fixed 100 ms listener-readiness polling
and a caller-owned stop predicate. It installs no signal handler. Shutdown is
idempotent and delegates pathname cleanup to the existing listener, which
removes only the socket inode it created.

There is still no UID/GID transition, daemonization/systemd unit, concurrent
manager session handling, or ForceCommand execution. The next increment drops
the execution child to the dedicated workload identity with no saved privilege
before exec.
