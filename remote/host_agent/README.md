# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3d2b2b2c2b2b3 behavior

The ForceCommand request path remains **non-executing**.

The containment-manager service and authenticated Unix endpoint remain the
manager-side privilege boundary. The manager protocol itself is unchanged.

For native supervised execution, the child is released only after containment
attachment and trusted child setup. Immediately before the pinned native ELF
exec path it must irreversibly cross from the non-root host-agent identity to
the dedicated workload UID/GID:

- the host agent needs only `CAP_SETUID` and `CAP_SETGID` for the drop and
  does not receive `CAP_KILL`;
- `no_new_privs=1` and ambient-capability clearing precede credential mutation;
- supplementary groups are cleared to an empty set;
- real/effective/saved UID/GID and FSUID/FSGID must all match the workload;
- effective/permitted/inheritable and ambient capabilities must be empty after
  the transition;
- any failed transition prevents native exec.

Once the child has changed UID, direct/process-group signaling by the parent may
return `EPERM`. Recursive containment `kill_all()` is therefore the
authoritative hard-kill path; the parent does not switch identity or gain
`CAP_KILL`.

The real boundary is covered by the dedicated disposable Linux probe:

```bash
./scripts/run-live-workload-identity-probe.py
```

Generic tests remain unprivileged. ForceCommand execution remains disabled.
The next increment is Phase `3d2b2b2c2c`: integrate the authenticated
containment-manager client through the existing start barrier and bounded
runner.
