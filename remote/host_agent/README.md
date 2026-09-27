# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3d2b2b2c2b2a behavior

The ForceCommand request path remains **non-executing**.

The containment-manager package now owns a secure filesystem Unix listener
primitive:

- canonical absolute endpoint path;
- secure pre-existing parent directory;
- no automatic removal of existing paths;
- explicit socket UID/GID and 0600/0660 mode;
- permission/identity verification before listen;
- non-inheritable listener/accepted descriptors;
- device/inode-bound cleanup which never unlinks a replacement path.

The listener does not yet define daemon lifecycle or production service-account
separation. The next increment must establish distinct manager, host-agent and
workload identities before the authenticated manager path can be used for
hostile execution.
