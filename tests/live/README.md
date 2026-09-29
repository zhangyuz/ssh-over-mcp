# Live workload identity transition probe

This directory contains the dedicated Linux proof for the irreversible
host-agent-to-workload credential transition. It is intentionally separate from
ordinary pytest validation because the fixture requires real `CAP_SETUID` and
`CAP_SETGID`.

Run the complete disposable probe from the repository root:

```bash
./scripts/run-live-workload-identity-probe.py
```

The operator script builds a disposable Linux image and runs it with all runtime
capabilities dropped except `SETUID` and `SETGID`. Runtime networking is
disabled and the container is removed even if the probe fails or times out.

The root container process is used only to construct the fixture. Before probe
assertions begin, it drops to the non-root host-agent UID/GID, retains only the
two required effective/permitted capabilities, and keeps the manager-client
supplementary group.

The test then proves the real transition, irreversibility, parent/child
separation, expected cross-UID `kill(pid, 0) -> EPERM`, and state persistence
through the repository's pinned native fd-based ELF exec path.

Ordinary `pytest` runs do not set
`SSH_OVER_MCP_RUN_LIVE_WORKLOAD_IDENTITY=1`, so this probe is skipped and
generic validation does not require identity-changing capabilities.


## Live delegated cgroup-v2 preflight

Phase `3d2b2b2c3` uses a separate Linux-only fixture. Ordinary pytest remains
unprivileged and skips this gate unless:

```text
SSH_OVER_MCP_RUN_LIVE_CGROUP=1
```

is set explicitly.

The operator must provide one pre-created, disposable cgroup-v2 subtree and the
numeric identities used by the fixture:

```text
SSH_OVER_MCP_LIVE_CGROUP_ROOT=/sys/fs/cgroup/<operator-delegated-subtree>
SSH_OVER_MCP_LIVE_CGROUP_MANAGER_UID=<non-root uid>
SSH_OVER_MCP_LIVE_CGROUP_MANAGER_GID=<non-root gid>
SSH_OVER_MCP_LIVE_CGROUP_HOST_UID=<distinct non-root uid>
SSH_OVER_MCP_LIVE_CGROUP_HOST_GID=<distinct non-root gid>
SSH_OVER_MCP_LIVE_CGROUP_WORKLOAD_UID=<distinct non-root uid>
SSH_OVER_MCP_LIVE_CGROUP_WORKLOAD_GID=<distinct non-root gid>
```

The preflight does not search the host for a writable cgroup. It requires the
test process to already be running as the configured non-root manager identity
with zero inheritable/permitted/effective/ambient Linux capabilities.

Before any later live execution proof is accepted, the preflight requires:

- a unified cgroup-v2 mount and a delegated root strictly below the mount root;
- an absolute, canonical delegated path with empty `cgroup.procs`;
- `cpu`, `memory`, and `pids` available and enable-able for children;
- manager ownership of the delegated directory, `cgroup.procs`, and
  `cgroup.subtree_control`;
- no group/other write bit and no POSIX access ACL on those delegated write
  surfaces, so the distinct host-agent/workload identities have no direct DAC
  write path;
- successful creation and removal of one disposable child cgroup;
- restoration of the original `cgroup.subtree_control` state after preflight.

Run only on the dedicated fixture:

```bash
python -m pytest -q tests/live/test_delegated_cgroup.py -k preflight
```

If opt-in is enabled, missing or unsafe fixture state is a hard failure rather
than a skip. The cgroup-v2 mount root itself is explicitly rejected as a
delegated test root.
