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


## Full Phase 7A no-network guest matrix

Run the already-trusted main workflow with the exact target commit:

```bash
gh workflow run live-local-e2e.yml --ref main -f commit_sha=<exact-40-hex-target>
```

Only the dedicated self-hosted native Intel macOS `gha-e2e-orchestrator`
account/`ssh-over-mcp-e2e-orchestrator` label runs orchestration. QEMU 11.1.2/HVF
boots the pinned Ubuntu 26.04 image with `-nic none`. See
`docs/self-hosted-runner.md` for the image digest, commit binding, provisioning,
and operator recovery rules. The guest installs the trusted hash-locked
Python 3.14 wheelhouse offline; target code never executes on the host.

The target probe accepts no selector and runs exactly:
1. real SSH/kernel identity;
2. real MCP/SSH/Ledger;
3. filesystem/profile isolation;
4. Task 6 origin/central/remote/host-key failure matrix;
5. Task 7 approvals, Ledger outage, secret retention, and final manager stop.

Task 6 and final containment audit assertions seal the Ledger before offline
inspection. Approval grants run the production approvalctl module in a separate
subprocess against the peer-authenticated admin endpoint. Fixed `STOP_MANAGER`
is the final execution fault; no later fixture may depend on the manager.

Guest identities are manager `2201:3201`, host `2202:3202`, workload
`2203:3203`, probe `2204:3204`, and manager-client GID `3299`; sshd binds only
loopback port `22222`. The launcher digest at verified PR119 merge is
`36cc41be410f696377c6998aae0e946d9f7b596856d09c2da38c5869bbc27ba9`.
The trusted gate verifies installed launcher bytes. Kernel evidence comes from
real capability/identity syscalls and cgroup-v2 files, not mocked state; the
bounded public result does not publish a numeric kernel release or raw logs.

Require full guest success, in-guest cleanup, QEMU exit, provider-state absence,
and checkout cleanup. Repeat ordinary CI and full E2E on the exact merge SHA
before deleting branches/worktrees. Stale provider state requires operator
inspection after verifying no active QEMU/orchestrator; never auto-delete its
marker or cancel a healthy run to replace it.

The 25-criterion evidence matrix and exact run links live in the Phase 7A design
spec. Phase 7A4 closure gates remain pending until explicitly recorded there.

## Dormant staging metadata inventory

`ops/live-e2e/staging_inventory.py` is a dormant stdlib helper with no CLI or
workflow caller. Disposable real-filesystem tests exercise it; it is not invoked
against the dedicated runner's incident state. It borrows an already-open root
directory descriptor, requires the eleven standard staging entries, and records
metadata only. It opens directories relative to pinned descriptors without
following links, never opens regular files for data access, rejects foreign
UID/device, regular-file hardlinks, special objects, writable entries and reused
inodes, and refuses observed identity/metadata/layout drift.

Bounds are 4096 records including the root, depth 12, 4096 filesystem bytes per
relative path, 2 MiB canonical inventory JSON, and a 60-second monotonic deadline
checked during traversal. Regular-file sizes are metadata, not read allocations.
Records sort by filesystem-encoded path bytes; schema version 1 has only
`entries` and `schema_version`, with escaped ASCII JSON, sorted keys, compact
separators and no final newline. Root path is `.`; atime and workflow provenance
are excluded. Borrowed descriptors remain open and owned descriptors are closed.

The helper cannot prove how the caller opened the root or provide an atomic
filesystem snapshot against a concurrent writer. Later activation must pin and
bind the incident root through trusted paths, establish quiescence, authenticate
the marker/process/authority/run context, and separately bound the complete
inspection envelope. This helper grants no deletion or marker-clearance authority
and no live-inspection, Level-3 or A1 closure credit. ADR 0011 defines those
separate gates; unknown/unbound incident state remains excluded.

## Dormant canonical staging envelope and receipt

`ops/live-e2e/staging_envelope.py`, `staging_wire.py` and `staging_receipt.py`
implement the approved inspection wire contract as pure stdlib helpers. They have
no CLI or workflow caller and perform no file access, environment lookup, process
inventory/signalling, network operation, evidence-file write or output emission.
The collector-only JSON format above remains unchanged. The separate envelope
schema includes the two fixed incident catalog bindings, detached metadata and
explicitly supplied inspection authority/run/attempt declarations.

Validation checks exact scalar/container types, canonical sorted ASCII JSON,
topology and catalog consistency, the inventory digest, and the complete 2097152
byte envelope bound. Local balanced decimal conversion accepts budget-valid
metadata integers beyond CPython's default digit guard without changing that
process-wide guard. A fixed-schema scan checks object keys, token bounds,
depth 5, seven ancestors and at most 4096 entries before materializing a decoded
tree. There is no general JSON or caller-selected schema interface.

Receipt encoding returns immutable framed lines; it does not print them. Each
1024-byte raw chunk is independently encoded with standard padded canonical
base64. Reconstruction requires complete ordered chunks, exact length/count,
canonical JSON/base64 and both envelope/inventory consistency checks. It returns
no partial bytes after a rejected or truncated receipt. The receipt is a data
consistency record, **not authenticated workflow evidence or cleanup permission**.

The checked-in synthetic golden fixture has 13 metadata records, 3023 canonical
inventory bytes, 3253 envelope bytes and four chunks. Ruby JSON/Digest/Base64 and
system OpenSSL independently verified its literal bytes/hashes before codec
implementation. The envelope/receipt suites contain 316 tests, covering every
scalar's wrong types, guard-independent integers, before-materialization
refusals, complete 2 MiB equality/overflow, metadata bindings, exact framing,
independent padding and secret-safe errors. Supported full Python 3.13/3.14
self-hosted CI remains required for the exact reviewed revision.

No helper proves that supplied metadata/provenance was freshly observed or
trusted. Later preflight/integration must establish that through already-main
authority before receipt emission. Signal-capable preflight still requires its
separate approved, reviewed, already-main ADR0011 amendment with exact authority
binding. Workflow activation, authenticated original-receipt retrieval, bounded
apply/journal durability and disposal of unknown `recover.cc8Del` state remain
separate gates. No live-inspection, Level-3, A1 or Phase7B1 closure credit is
granted by these codec tests.

## Dormant fixed diagnostic capture

`ops/live-e2e/staging_diagnostics.py` adds argument-free `capture_getconf()` and
`capture_ps()` helpers under approved ADR 0012 and the separately approved fixed
diagnostics plan. The exact already-main authority is
`1ddebe541ee80c0febc4cd35072f3a5046fac5cb`; the module pins and verifies the raw
bytes of ADR 0011, ADR 0012 and the amended inspection spec before spawning.
It has no CLI, workflow caller, receipt emitter or staging/marker access.

Commands, environment, stream budgets and deadlines are fixed. Child exec FDs
contain only disconnected stdin and owned stdout/stderr pipes. Borrowed parent
FD identities, flags and offsets remain intact, including inheritable handles.
Darwin rejects CLOSE actions for the scanner's already-closed FD: a bounded
metadata check omits only EBADF-proven closed non-owned slots before the first
spawn. Every live FD is still excluded; other errors refuse, and there is no
spawn retry or inherited-FD fallback.

Direct `posix_spawn`, own-PID nonblocking waits and kqueue notifications retain
exclusive child ownership. Both EOFs and an exact zero-exit owned wait are
required. Failure may use one SIGKILL only for that invocation's known unreaped
child; cleanup is bounded by two seconds. Unknown ownership/status, failed
signal/reap, an ambiguous low-stdio close or cleanup expiry preserves explicit
uncertainty. An ambiguously closed descriptor is never closed again by the helper. Reaped PIDs and
other pipe holders never become signal targets. No output is printed or returned
on failure, and cleanup success does not convert collection failure into success.

Developer-native evidence on Intel macOS, Darwin 24.6.0: Python 3.13.5 and 3.14.8
each passed 95 diagnostic tests (77 portable plus 18 eligible native, zero native
skips). Python 3.13 additionally passed 498 related codec/inventory/recovery/CI
tests including those diagnostics. Native probes exercise real exec FD exclusion,
closed stdio/high FDs, fixed diagnostics, output equality/overflow, stalled and
EOF-before-exit children, exclusive reaping and an exited child's pipe retained
by another fixture-owned process. Disposable native before/after-close error
fixtures also prove low-stdio cleanup uncertainty without close retry or borrowed
FD changes. Registration races, failed notification setup and concurrent
two-stream budget scheduling are portable boundary-fake evidence; no forced
native proof of those branches is claimed. Only test account eligibility is faked for
UID-501 developer fixtures; actual wait-context checks and native waits remain
real. This does not establish UID-502/GitHub/main workflow-context compatibility.
Linux self-hosted Python 3.13/3.14 regression remains a separate exact-SHA gate;
its native skips earn no macOS evidence.

Capture is a partial component, not accepted path/process metadata, quiescence,
authenticated inspection or cleanup permission. Cancelled-parent/orphan detection
in both snapshots, namespace revalidation and trusted workflow integration still
require their later proofs before any inspection activation. Provider/staging
state and unknown `recover.cc8Del` remain untouched. No Level-3, A1 or Phase 7B1
closure credit is granted by these component tests.

## Dormant process metadata validation

`ops/live-e2e/staging_process_metadata.py` adds pure private parsers and a
snapshot rejection predicate under the separately approved process-metadata
plan. Approval covers reviewed plan head `e1f5d5e33b0c468f9c31b96b7e14d68f97b6d92e`,
merged in #150 as `3101fd4cfc7186b46cce1f9db6af264021b21392`. The same three
normative authority documents remain byte-identical to trusted `1ddebe5`.
The pure module does not verify that authority or observe any host state.

Only exact bytes enter the parsers. The temp-root parser accepts the fixed
native shape and maps its literal `/var` alias to `/private/var`. Process rows
consume exactly one post-PID space, preserving command-leading spaces for
refusal and internal spaces unchanged. Canonical PIDs use the reviewed signed
32-bit Darwin representation bound. Byte, row and line budgets are enforced
before record construction/conversion; returned records are frozen and slotted.

The predicate revalidates exact record/scalar shapes, unique PIDs, printable
ASCII commands, nonempty literal basenames, individual line bounds and the
65536-byte shortest-serialization aggregate including each LF before
classification. Representability authenticates neither source/freshness nor
original capture padding/blank lines/byte count. Exactly one supplied inspection
PID must have a python/pypy prefix and one distinct supplied own-ps PID must have
basename `ps`. Other interpreters, any getconf/extra ps and fixed QEMU/authority
names refuse. Private identity arguments confer no ownership; later integration
must derive them internally from the real inspection and exact owned capture.
A return of None supplies no accepted-preflight object, receipt or capability.

Developer verification on Darwin 24.6.0 x86_64: Python 3.13.5 and 3.14.8 each
passed 139 pure metadata cases, including absent/partially initialized record
slots refusing with the same fixed error. Python 3.13 passed 637 related cases,
including the existing 95 diagnostic cases. Both full Mac runs had 1676 passes, 84 failures
and 177 skips, with exactly the same 84 failure names as the fresh clean main
baseline (1537 passes, 84 failures, 177 skips). These are no-new-failure Mac
results, not full Mac GREEN. Each full run retained all 18 eligible existing
Darwin diagnostic passes and zero native skips. Those tests validate the
existing capture helper; the new pure vectors supply no native orphan or
two-snapshot composition proof. Exact-head self-hosted Linux full regression
and fresh independent review remain separate required gates.

The module has no host-action import, capture caller, CLI or workflow wiring.
Import/validation tests guard host-action surfaces and require no output; they
do not protect against arbitrary malicious code in a compromised parent.
Native fixed UID-502 ps format/PID evidence, actual cancelled-parent diagnostics,
both snapshot identities, inventory/late namespace revalidation and trusted
workflow/receipt integration remain mandatory before activation. Provider and
staging state, unknown `recover.cc8Del`, A1 and N1c remain pending their own gates.


## Dormant native preflight, Slice A — initial namespace primitive

Written implementation plan in
`docs/superpowers/plans/2026-10-07-dormant-native-preflight-composition.md`
was merged on main in PR #152 at `562cb3886fbe87e56c53e2dc033acd36c02d2a5c`
and separately approved by the user. The first A2/A3 micro-increment
introduces `ops/live-e2e/staging_preflight.py` and disposable-only
`tests/ops/test_live_e2e_staging_preflight.py`.

This first PR increment contains the two immutable, exact incident catalog
bindings and private, fixture-only read-only components:
- descriptor-relative `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` chain pinning,
  pre-open/held-FD identity checks and final parent-to-child edge revalidation;
- fixed leaf-name `active-run.json` strict 4096-byte flat ASCII JSON validation,
  duplicate-key and wrong-type rejection, initial/final raw-byte and metadata
  equality with no-follow nonblocking opens;
- fixed leaf-name `payload-content/expected_commit` exactly 41-byte
  SHA-plus-LF read, hardlink/symlink/special-file refusal, safe owner/mode/
  device/mtime/ctime observation and final reread through held payload FD;
- the existing `staging_inventory.collect_staging_inventory` invoked with a
  borrowed pinned-root descriptor and compared to root/expected-commit
  observations, with imported collector path pinned to its sibling module;
- sanitized `PreflightError` with strict internal `cleanup_uncertain: bool`,
  reporting ambiguous helper FD cleanup without exposing lower-level paths.

Disposable RED/GREEN tests cover catalog exclusion, malformed directory
components, symlink and replacement races, final namespace edge changes,
borrowed/owned descriptor lifecycle, strict marker parser including duplicate
keys/nested structures/bools/floats and 4096-byte bound, expected-commit
same-content inode replacement and same-inode rewrite, unsafe modes/hardlinks,
inventoried leaf mismatch, actual full-layout collector binding, and
foreign collector import refusal. Fixed normative ADR/spec files remain the
reviewed bytes. No incident filesystem content is read by these tests.

**This is still not a completed Slice A preflight and not UID-502 proof.**
The flexible component/path/policy values are **private disposable fixture
seams only**, never a production operator/API authority. A later micro-slice
must construct the fixed cache and OS-derived temp parent chains from actual
trusted UID-502 context, bind and check both against the exact incident root,
coordinate marker/inventory/expected-commit observations into one detached
success object, and perform post-inventory edge/marker checks. That work,
A7 final gating, and Slice B's fixed getconf/ps composition remain pending.
There is no production success entrypoint, host capture, process signal,
workflow, receipt, marker clear, staging deletion, target execution, or
Level-3/A1/N1c closure. Unknown `recover.cc8Del` remains excluded.


### PR #153 adversarial review remediation

Independent review at exact head `c90bdc3f5e29e7655c916c3b63553d1df5bce121`
([review #6059100957](https://github.com/zhangyuz/ssh-over-mcp/pull/153#issuecomment-6059100957))
found two Important and one Minor issue, reproduced with seven disposable RED
fault-injection tests. The fixes make `expected_commit` revalidation reread
through the held payload descriptor, then check the live leaf name/metadata
with no-follow stat, then validate the held root-to-payload chain **after**
that read. A replaced live path or leaf during the final reread refuses.
Existing sanitized `PreflightError` is passed through the collector boundary
unchanged so `cleanup_uncertain=True` survives; directory-policy/metadata
allocation and trusted-sibling loader syntax failures yield the fixed public
error without exposing lower-level details. These are observation checks, not
atomic filesystem snapshots.

Local developer Mac Python 3.13 focused/related regression after repair:
**651 PASS**, including all new adversarial tests; Ruff/format checks PASS.
Exact-new-head self-hosted Python 3.13/3.14 CI and fresh independent review
remain required. This repair adds no process/capture authority, CLI, UID-502
activation, receipt, marker clearing, staging mutation, or Level-3/A1 closure.


### Slice A cache namespace increment after merged PR #153

The follow-up dormant preflight component pins the fixed cache ancestor names
relative to an already-borrowed root descriptor:
`Users/gha-e2e-orchestrator/Library/Caches/ssh-over-mcp-e2e`.
The production UID policy is literal root (0) for `Users` and account UID
502 for the home, Library, Caches and cache leaf. Ancestors refuse group/world
write bits; the leaf requires exact 0700. It uses existing descriptor-relative
no-follow identity checks and final edge revalidation, closing only helper-owned
FDs. Private disposable tests substitute fixture ownership, never the actual
UID-502 cache.

This **does not** assert the borrowed root FD represents real `/`, invoke a
live marker read, construct the OS-derived temp chain, emit detached full
preflight evidence, or run diagnostics/workflows. Full runtime-context/root
provenance, authority hash gate, UID-502 native tests and Slice A closure remain
separate stages. Stale provider state and unknown recovery roots are untouched.


### PR #154 root-FD pinning race remediation

Independent review at `ea69c652433ba70409418ba7496dcb8934c48457`
([review #6062651928](https://github.com/zhangyuz/ssh-over-mcp/pull/154#issuecomment-6062651928))
found a root-FD TOCTOU gap: after safe preliminary fstat but before
the directory chain duplicated and recorded the root, owner/mode drift
could be admitted as the baseline. Disposable RED reproduced both
`0700→0777` mode drift during `dup` and a synthetic UID change on
the duplicated root. The repaired wrapper compares the freshly pinned
root metadata **and the stored chain baseline** against the previously
validated, safe borrowed-root metadata, then calls full edge
revalidation. The root baseline is therefore safe on entry and late
changes fail when `chain.revalidate()` is called. A third test checks
late unsafe mode drift; no root namespace/UID-502 proof or live host
inspection is claimed. Current PR remains dormant and read-only.

### Slice A temp ancestry component after merged PR #154

The private temp-chain seam pins only
`private/var/folders/<shard>/<token>/T` relative to a borrowed root FD.
It accepts two exact, bounded lexical components, never a full input path:
the shard is two lowercase ASCII alphanumeric characters; the token uses
lowercase ASCII alphanumeric/underscore characters, with the existing
directory-chain component limit of 255 bytes. Unsupported layout refuses.
This component limit does not replace the pure getconf stdout limit of 1024.
Shared ancestors including the shard require UID 0 and no group/world-write
bits; the token requires UID 502 and mode 0700 or 0755, and T requires UID 502
mode 0700. Both fixed cache and temp wrappers use the same safe-root pinning
check, retaining PR #154's original safe baseline, duplicated-root equality
and current parent-to-child edge checks.

Disposable developer fixtures substitute ownership only in the private
module. All six temp edges are exercised for symlink and late namespace
replacement refusal, including cases where the held original FDs stay valid.
Root drift during dup, stat/open replacement, malformed components before
FD actions, borrowed identity/flags/offset preservation, owned-FD closure
and strict cleanup uncertainty are covered. Metadata/edge checks remain
observations, not atomic snapshots or protection from malicious account ABA.

Fresh developer-Mac verification: Python 3.13.5 and 3.14.8 each pass 172
temp/cache/general cases (64 new temp cases). Python 3.13 related regression
passes 731 cases. Both full Mac runs have 1848 passes, 84 failures and 177
skips; exact failure names equal the fresh merge-main baseline (1784 passes,
84 failures, 177 skips). Each retains all 18 eligible existing Darwin
diagnostic fixture passes with zero native skips. This is no-new-failure Mac
evidence, not full Mac GREEN or new fixed-diagnostic composition proof.
Exact-head self-hosted Linux full CI and independent review remain required.

The seam does not derive or authenticate the OS temp path, prove literal `/`
or the actual UID-502 runtime, select/open a staging root, read incident
content, return full detached preflight evidence, or activate a workflow or
receipt. Slice B must derive these components internally from its actual
fixed, completed/reaped getconf capture; no caller/operator override is
authorized. Final marker, inventory, selected-root and complete namespace
composition remain separate Slice A work. No native getconf/ps composition,
provider mutation, deletion, marker clearing, Level-3/A1/N1c closure or
inspection of the unknown recovery workspace is added here.

### Slice A selected catalog-root component after merged PR #155

The private selected-root seam accepts only the two fixed incident selectors
and a borrowed, already-pinned T descriptor. It pins only that catalog's
literal basename using descriptor-relative no-follow stat/open checks.
The parent must have the catalog UID 502 and exact mode 0700 before any
duplicate/open; the duplicate and its stored baseline must match that original
safe parent observation. The selected root must match the literal catalog
device, inode, UID 502 and mode 0700 before this context yields. Explicit late
revalidation checks both held descriptors and the T-to-selected-root edge.
The shared safe-root helper's optional exact mode policy leaves the fixed
cache/temp wrappers' default policies unchanged.

Disposable fixtures first assert the exact production catalog, then substitute
only their private filesystem identities. The initial 45 new cases failed at
the missing interface before implementation; nine additional coverage cases
exercise existing strict selector/FD/parent-UID rejection without claiming
another behavior change or RED result. Both Python 3.13.5 and 3.14.8 pass 226
selected-root/temp/cache/general cases. Namespace replacement, catalog drift,
original-safe/current-duplicate/stored parent-baseline races, borrowed FD
preservation and strict cleanup uncertainty remain fail-closed.

Python 3.13 related regression passes 785 cases. Both final full Mac runs have
1902 passes, 84 failures and 177 skips; all 84 failure names match fresh clean
main `ec316910015201070595b9b5bb2628bad3696d21` (1848/84/177), and all 18
eligible existing Darwin diagnostic fixtures pass with zero native skips.
This is no-new-failure Mac evidence, not full Mac GREEN or new native diagnostic
composition proof. Supported exact-head self-hosted Linux full CI and fresh
independent review remain mandatory.

This is a partial private composition component. The borrowed descriptor alone
does not authenticate the full OS-derived temp ancestry or the actual UID-502
runtime. Later composition must retain and cross-check the full temp chain,
this selected edge, marker, expected-commit and inventory observations through
the final gate. There is no content read, staging traversal, native diagnostic
composition, full preflight entrypoint, workflow/receipt or mutation here.
The existing stale-provider refusal remains a failed Level-3 gate, with no A1,
N1c or recovery credit. All three fixed authority documents remain unchanged.


### Slice A selected staging evidence micro-increment after PR #156

The next private, fixture-only composition binds a previously pinned
catalog-selected root to the existing 41-byte `expected_commit` reader and
the existing metadata-only inventory collector. It checks selected-root
catalog identity, inventory/expected-commit metadata equality, performs final
expected-commit reread and selected-root edge revalidation, and returns only
a frozen/slotted **selected-staging subset** record containing catalog fields,
the detached inventory tuple and immutable expected-file metadata. It carries
no live descriptors, raw marker bytes or process handles.

Disposable RED→GREEN coverage proves refusal for selector/chain mismatch,
expected-commit drift, selected-root edge replacement during inventory and
**during nested payload descriptor cleanup**, and preserves a pre-sanitized
`cleanup_uncertain=True`. No marker or process capture is invoked.

This is **not** the complete `PreflightObservation`: the actual trusted
root FD, OS-derived temp ancestry, fixed marker cache and initial/final marker
state, UID-502 native capture, two ps snapshots, workflow/receipt authority and
overall final gates remain deferred. No live staging/provider state is touched,
no marker is cleared, and Level-3/A1/N1c closure is not claimed.


A second adversarial self-review test reproduced a raw `SyntaxError` escaping
when the trusted inventory-record class is requested after collection; the
private composition now sanitizes loader `ImportError`/`SyntaxError` at that
boundary while passing through `PreflightError.cleanup_uncertain=True`.
