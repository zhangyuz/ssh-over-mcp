# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3d2b2b2c3 behavior

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

Generic tests remain unprivileged.

Phase `3d2b2b2c2c` now supplies the existing start barrier and bounded runner
with a production authenticated `ContainmentManagerClient`:

- one `ContainmentServiceIdentityPlan` derives both the required host-agent
  process identity and expected manager `SO_PEERCRED`;
- host-agent identity is checked before opening the Unix manager socket;
- the manager socket is non-inheritable, uses a bounded connect/round-trip
  timeout, and is closed by child fd sanitation before native exec;
- the supervisor/runner containment ordering and manager protocol are unchanged.

Phase `3d2b2b2c3` adds accepted real-kernel validation of the complete
containment composition on a dedicated Ubuntu 26.04 x86_64 fixture:

- attach-before-exec through the authenticated manager and start barrier;
- denied root/sibling self-migration;
- real PID/CPU/memory cgroup enforcement and OOM accounting;
- recursive manager-backed `cgroup.kill` with sibling survival;
- bounded cleanup with no delegated-root `cgroup.kill`.

The accepted merged-main evidence is
`22e298fec42d92a963f093a6a073de622589dfc0` on kernel
`7.0.0-28-generic` (`2 passed` manager phase, `4 passed`
production/resource/recursive-kill phase).

ForceCommand execution remains disabled. The next increment is Phase `3d2c`,
which may wire the already-contained supervised native execution path into the
ForceCommand CLI.
