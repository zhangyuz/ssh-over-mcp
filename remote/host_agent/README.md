# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3d2b2b2c2b2b1 behavior

The ForceCommand request path remains **non-executing**.

The containment architecture now has an explicit Linux identity plan:

- manager UID;
- host-agent UID;
- workload UID;
- dedicated manager-client GID.

The three UIDs must be distinct. Host-agent/workload and the client group must
be non-root. Real/effective/saved IDs and supplementary groups are checked
strictly.

The plan derives endpoint ownership and both directions of SO_PEERCRED policy.

No UID/GID transition or manager daemon is started yet. The next increment
enforces the manager identity at service startup and owns listener/session
lifecycle.
