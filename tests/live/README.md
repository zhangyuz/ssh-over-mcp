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
SSH_OVER_MCP_LIVE_CGROUP_HOST_SOURCE=/sys/fs/cgroup/<operator-delegated-subtree>/host-agent-source
SSH_OVER_MCP_LIVE_CGROUP_SOURCE_PID=<stopped disposable host-agent-identity pid>
SSH_OVER_MCP_LIVE_CGROUP_MANAGER_UID=<non-root uid>
SSH_OVER_MCP_LIVE_CGROUP_MANAGER_GID=<non-root gid>
SSH_OVER_MCP_LIVE_CGROUP_HOST_UID=<distinct non-root uid>
SSH_OVER_MCP_LIVE_CGROUP_HOST_GID=<non-root gid>
SSH_OVER_MCP_LIVE_CGROUP_WORKLOAD_UID=<distinct non-root uid>
SSH_OVER_MCP_LIVE_CGROUP_WORKLOAD_GID=<non-root gid>
SSH_OVER_MCP_LIVE_CGROUP_MANAGER_CLIENT_GID=<non-root supplementary gid>
```

The preflight does not search the host for a writable cgroup. It builds the
same `ContainmentServiceIdentityPlan` used by production and requires the test
process to already match the configured non-root manager process policy, with
zero inheritable/permitted/effective/ambient Linux capabilities.

The operator also creates the configured `host-agent-source` cgroup as a
direct child of the delegated root. For the real-backend primitive proof, the
operator supplies one disposable process through
`SSH_OVER_MCP_LIVE_CGROUP_SOURCE_PID`. That process must already be stopped,
must match the configured host-agent UID/GID and supplementary-group policy,
and must already reside in `host-agent-source`.

Later production-composition runs place the actual host-agent process there
before bootstrap authority is dropped. Execution children then inherit source
membership and the manager moves them from that source child to sibling request
scopes. The manager remains outside the delegated root; no manager write access
above the delegated root is required.

Before any later live execution proof is accepted, the preflight requires:

- a unified cgroup-v2 mount and a delegated root strictly below the mount root;
- an absolute, canonical delegated path with empty `cgroup.procs`;
- the manager process itself is outside the delegated subtree;
- the configured host-agent source cgroup exists as a canonical direct child of
  the delegated root;
- `cpu`, `memory`, and `pids` available and enable-able for children;
- manager-UID ownership of the delegated directory, root `cgroup.procs`,
  `cgroup.subtree_control`, source directory, and source `cgroup.procs`;
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

The first process that enters the delegated subtree must be placed there by the
operator/delegator. The live suite does not use `CLONE_INTO_CGROUP` or grant
the manager authority above the delegated root to bypass cgroup-v2 delegation
containment.


## Native delegated-cgroup workload probe

`cgroup_workload_probe.c` is the fixed-action native ELF used by later Phase
`3d2b2b2c3` live assertions. It intentionally exposes no shell, command
execution, or generic file-operation surface.

Build it with warnings treated as errors:

```bash
cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
  -o /tmp/ssh-over-mcp-cgroup-workload-probe \
  tests/live/cgroup_workload_probe.c
```

Supported actions are bounded and explicit:

- `state`: emit one JSON record with PID, real/effective/saved UID/GID,
  supplementary groups, capability masks, `NoNewPrivs`, and unified cgroup
  membership;
- `escape-check`: emit `state` first, then attempt self-migration only to
  the configured delegated-root `cgroup.procs` and one configured sibling
  `cgroup.procs`;
- `descendants COUNT HOLD_MS`: create at most 16 descendants which close
  stdio and outlive the direct probe process for a bounded interval;
- `cpu DURATION_MS`: run bounded CPU saturation for at most 10 seconds;
- `memory BYTES HOLD_MS`: fault in at most 128 MiB using volatile page
  touches, then hold for at most 30 seconds;
- `fork ATTEMPTS HOLD_MS`: perform at most 64 fork attempts while successful
  children remain alive for a bounded interval.

All records written to stdout are machine-readable JSON lines. Malformed,
unknown, signed, or out-of-range action arguments fail with usage exit status
`64` before the requested action runs.

The migration action accepts no path argument. It reads only the
operator-controlled `SSH_OVER_MCP_LIVE_CGROUP_ROOT` and
`SSH_OVER_MCP_LIVE_CGROUP_SIBLING_PROCS` fixture values, resolves both
targets, requires them to be existing `cgroup.procs` files under the
configured delegated root, and treats `ENOENT` or any unexpected error as a
hard failure. A successful self-migration exits nonzero so it cannot be
mistaken for the expected permission-denial proof.


## Real CgroupV2Backend primitive proof

With the dedicated fixture opt-in enabled, Task 3 exercises the actual
`CgroupV2Backend` rather than temporary-file cgroup fakes:

```bash
python -m pytest -q \
  tests/live/test_delegated_cgroup.py \
  -k real_cgroup_backend_create_attach_limits_and_cleanup
```

The test requires the operator-supplied source PID described above. It proves:

- the source PID is stopped, has the configured host-agent identity/groups, and
  is resident in the direct-child source cgroup;
- the backend creates the request scope only below the configured delegated
  root and applies exact finite `memory.max`, `pids.max`, and `cpu.max`;
- manager-side `attach()` moves the stopped PID source → request on the real
  kernel and real stats report the populated scope;
- the manager moves the same stopped PID request → source without signaling it,
  waits for `populated 0`, and removes the request scope;
- any controllers enabled by this proof are restored to the original
  `cgroup.subtree_control` state.

The manager remains non-root with zero inheritable/permitted/effective/ambient
capabilities. The proof does not require `CAP_KILL` and does not signal the
operator-owned source PID.
