# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3d2b2b2c1 behavior

The ForceCommand request path remains **non-executing**.

The package now contains a narrow containment-manager protocol and a
`ContainmentManagerClient` adapter compatible with the existing
`ContainmentBackend` interface.

Allowed manager operations are only:

- create;
- attach;
- kill;
- stats;
- close.

Each created scope receives an opaque 256-bit capability. Scope operations
require both scope ID and capability, messages are bounded/strict/correlated,
and manager implementation errors are not returned to the client.

The current in-memory manager transport is for tests only and provides no
privilege separation. The next increment provides the real local helper/IPC
boundary and then plugs this client into the existing start-barrier and bounded
execution path.

Remote execution remains disabled until that boundary and live self-migration
tests are complete.
