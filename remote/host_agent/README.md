# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3d2b2b2c2b1 behavior

The ForceCommand request path remains **non-executing**.

Pre-connected containment-manager Unix sockets now require Linux
`SO_PEERCRED` authentication before protocol traffic:

- exact expected UID;
- optional exact real GID;
- PID retained only as metadata;
- auth mismatch/unavailable peer credentials fail closed;
- failed authentication closes the socket.

This is only one half of ADR 0004. If workload and host-agent share the same
UID, the workload can present the same peer identity. The next increment must
define the manager endpoint and separate manager, host-agent and workload OS
identities.
