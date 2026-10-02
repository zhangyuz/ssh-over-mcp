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


## Dedicated workflow gate

Task 8 promotes the live cgroup fixture to a manual dedicated self-hosted gate.
The accepted runner label is:

```text
[self-hosted, linux, x64, ssh-over-mcp-cgroup-live]
```

The GitHub runner process is non-root with zero effective capabilities and no
Docker socket. It does not own the delegated subtree and does not receive
fixture paths or numeric identities from workflow inputs. One root-owned
operator helper installed outside the checkout is the only passwordless sudo
command.

The workflow input is a full 40-hex trusted commit. The checkout must exactly
match that commit before the operator helper may run. Independently, the
root-owned operator config pins the same commit as:

```text
EXPECTED_COMMIT=<operator-approved 40-hex commit>
```

The helper accepts no arguments and fixes the workspace, delegated paths, and
numeric identities in its reviewed source. It creates the disposable delegated
root, direct-child source cgroup, and stopped host-agent source process outside
checked-out code, then passes only those operator-owned values to the launcher.

`scripts/run-live-delegated-cgroup-probe.py` validates the exact clean checkout
and emits one bounded JSON metadata record. It then runs two fixed phases:

1. manager phase: preflight plus the real backend create/attach/limits/cleanup
   proof under the configured non-root manager UID/GID, exact supplementary
   manager-client GID, zero capability bounding/inheritable/effective/ambient
   sets, and `NoNewPrivs=1`;
2. bootstrap phase: after the stopped Task-3 source process is retired, the
   existing Task 4-7 production-composition, PID/CPU, memory, and recursive
   `cgroup.kill` proofs run from the root bootstrap harness.

The launcher does not create users, groups, the delegated root, or initial
source membership. Those remain operator responsibilities outside checked-out
test code. Request-scope cleanup remains bounded and the operator helper owns
final fixture teardown on success or failure.


## Phase 6A hardened application image probe

The Phase 6A production image has a separate opt-in live security probe. Run
it only on an authorized Docker host which can build and execute Linux/amd64
containers:

```bash
docker build --platform linux/amd64 -t ssh-over-mcp:phase6a .
SSH_OVER_MCP_RUN_LIVE_CONTAINER=1 \
SSH_OVER_MCP_CONTAINER_IMAGE=ssh-over-mcp:phase6a \
python -m pytest -q tests/live/test_container_image.py
```

The probe verifies that the image defaults to numeric non-root identity
`10001:10001`; runs successfully with a read-only root filesystem, all Linux
capabilities dropped, and `NoNewPrivs=1`; has no Docker socket; imports the
package and resolves all four project console entry points; and carries no
repository-local secret/config material under the application working tree.

Ordinary pytest does not set `SSH_OVER_MCP_RUN_LIVE_CONTAINER=1`, so these
live cases skip. The hardened self-hosted CI runner intentionally has no
Docker socket; image build/runtime validation therefore runs on the authorized
Mac x86 Docker host rather than weakening the CI runner to support Docker.


## Phase 6B private Compose authority probe

Phase 6B adds an opt-in live Docker Compose proof for the local private
reference deployment. Run it only on the authorized Mac x86 Docker host:

```bash
docker build --platform linux/amd64 -t ssh-over-mcp:phase6b .
SSH_OVER_MCP_RUN_LIVE_COMPOSE=1 \
SSH_OVER_MCP_COMPOSE_IMAGE=ssh-over-mcp:phase6b \
python -m pytest -q tests/live/test_compose_deployment.py
```

The probe creates a unique disposable Compose project and tears it down with
its named volumes. It verifies the resolved Compose configuration before
startup and then proves the live Linux authority boundary:

- ledger bootstrap runs with only `CHOWN` and `DAC_OVERRIDE`;
- MCP and Ledger run non-root with zero effective capabilities and
  `NoNewPrivs=1`;
- MCP receives only the read-only execution-socket volume, while
  `approvalctl` receives only the read-only admin-socket volume;
- legitimate AF_UNIX clients work through read-only mounts but cannot mutate
  the socket directories;
- the Ledger rejects a wrong UID even when that process has the correct socket
  GID;
- no MCP host port is published;
- approval, audit, DB, and HMAC state survive a graceful Ledger restart;
- Ledger outage makes MCP readiness return 503;
- an unexpected stale endpoint path makes Ledger startup fail closed and is
  not removed automatically.

Ordinary pytest leaves `SSH_OVER_MCP_RUN_LIVE_COMPOSE` unset, so the live
Compose cases skip. GitHub CI remains on the hardened self-hosted runner with
no Docker socket; the live Compose proof stays on the separately authorized
Mac x86 Docker host.


## Phase 6C Cloudflare connector reference probe

Phase 6C adds an opt-in local proof for the pinned `cloudflared` connector
without mutating a real Cloudflare account. Run it only on the authorized
Mac x86 Docker host:

```bash
docker build --platform linux/amd64 -t ssh-over-mcp:phase6c .
SSH_OVER_MCP_RUN_LIVE_CLOUDFLARE_REFERENCE=1 \
SSH_OVER_MCP_COMPOSE_IMAGE=ssh-over-mcp:phase6c \
python -m pytest -q tests/live/test_cloudflare_connector_reference.py
```

The fixture uses a deliberately fake Tunnel token file and a disposable
Compose project. It never attempts account provisioning or Portal mutation.
The probe verifies:

- the resolved Compose profile contains the exact pinned
  `cloudflare/cloudflared:2026.9.3` digest and no token value in environment;
- the connector image defaults to numeric non-root identity `65532:65532`;
- the created connector has a read-only root, no Linux capabilities,
  `NoNewPrivs`, no published ports, and only the Tunnel-token file mount;
- connector networking is limited to `origin_internal` and
  `cloudflare_egress`, with the latter selected for default egress;
- the private hostname resolves to MCP inside `origin_internal` while
  unauthenticated `/mcp` requests still receive HTTP 401;
- a fake-token connector failure neither publishes port 8000 nor changes the
  MCP/Ledger authority boundary, and the fake token does not appear in logs.

The fixture token file is mode `0600`. On native Linux, bind mounts preserve
numeric ownership, so production token files must be readable by connector
UID/GID `65532:65532` with mode `0400` or `0600`. Docker Desktop behavior
is not evidence of native-Linux ownership remapping.

Ordinary pytest leaves
`SSH_OVER_MCP_RUN_LIVE_CLOUDFLARE_REFERENCE` unset, so these cases skip.
The hardened self-hosted CI runner still receives no Docker socket; the live
connector proof remains on the separately authorized Mac x86 Docker host.


## Phase 6D reproducible production image probe

Phase 6D closes the production-image reproducibility gate for the supported
reference platform `linux/amd64`. The Dockerfile pins the Python base by OCI
digest, consumes committed SHA-256 hash locks for build/runtime dependencies,
and fixes filesystem/image timestamps with `SOURCE_DATE_EPOCH=315532800`.

Run the two-build proof only on the authorized Mac x86 Docker host:

```bash
SSH_OVER_MCP_RUN_LIVE_REPRODUCIBLE_IMAGE=1 \
PYTHONPATH="$PWD/src" \
python -m pytest -q tests/live/test_reproducible_image.py
```

The probe performs two independent BuildKit builds with `--no-cache`,
`--provenance=false`, and `--sbom=false`. It requires exact equality of
the resulting image IDs and rootfs layer digests, compares runtime config and
installed package inventory, and reruns the non-root/zero-capability/
`NoNewPrivs` runtime assertions.

A differing image ID is a hard failure. Do not replace this gate with a weaker
package-version or layer-count comparison.

Ordinary pytest leaves `SSH_OVER_MCP_RUN_LIVE_REPRODUCIBLE_IMAGE` unset, so
this Docker-dependent probe remains skipped on the hardened self-hosted CI
runner, which intentionally has no Docker socket.
