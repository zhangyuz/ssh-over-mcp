# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3d2b2b2c2a behavior

The ForceCommand request path remains **non-executing**.

The containment-manager client can now communicate over one pre-connected Unix
stream socket. The transport is bounded, timeout-controlled, serialized and
non-inheritable, and invalid manager responses fail closed.

It deliberately has no `connect(path)` API and the server helper deliberately
does not create/listen on an endpoint. Therefore this phase does not yet decide
which process/user is authorized to establish a manager session.

Next: define the Linux manager daemon endpoint, peer-credential policy, and
separate workload OS identity. Then route the existing start-barrier/bounded
runner through that authenticated manager connection.
