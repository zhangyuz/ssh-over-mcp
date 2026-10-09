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



### Post-merge PR #157 inventory-owned FD cleanup uncertainty remediation

[Independent review #6064699025](https://github.com/zhangyuz/ssh-over-mcp/pull/157#issuecomment-6064699025)
identified an Important error-contract gap in the existing metadata-only
inventory collector exposed by the new selected-staging composition. An
ambiguous `os.close` outcome for its duplicated root or descendant directory
FD had been collapsed into a generic `InventoryError`, and upstream
`_collect_and_bind` incorrectly reported `PreflightError.cleanup_uncertain=False`.

A narrowly scoped follow-up makes `InventoryError` retain a strict internal
bool `cleanup_uncertain`, raises `True` for failed collector-owned directory
and duplicated-root closes, and converts it to the fixed public
`PreflightError` message without losing `True`. Ordinary invalid layouts
with completed cleanup still report `False`. Disposable RED/GREEN tests inject
a real close followed by an artificial OSError for each owned FD category,
traversal failure followed by ambiguous cleanup, and two simultaneous
ambiguous closes. A separate RED→GREEN test covers the implicit owned
duplicate managed by `os.scandir(fd)`; its iterator close is now checked
explicitly, with ambiguity propagated as `cleanup_uncertain=True`. Strict
boolean construction and borrowed-FD retention are also covered. No existing staging content-read, inventory traversal, workflow,
UID-502 runtime or incident mutation authority is added.

The marker/staging paired-observation work is isolated in a subsequent
reviewable slice based on this remediation.


### PR #158 post-review cleanup-status accessor hardening

Independent review [#6065377839](https://github.com/zhangyuz/ssh-over-mcp/pull/158#issuecomment-6065377839)
found a Minor fail-closed gap: an absent or raising internal
`InventoryError.cleanup_uncertain` accessor was normalized by the outer
adapter into a settled `PreflightError.cleanup_uncertain=False`. A focused
RED reproduced this with a missing slotted field and a throwing property;
the pre-existing non-boolean status control stayed `True`.
The narrow collector-error boundary now guards the read itself and treats
unreadable/malformed cleanup status conservatively as `True`, without
changing the fixed public error text. This does not enable live incident
inspection, marker clearing, or Level-3 completion.


### Slice A marker + selected-staging paired observation after PR #158

The next private fixture-only, read-only component combines **two already
pinned chains**: the fixed marker-cache chain and the selected-catalog-root
chain. It checks both chains before observation; reads only the fixed
`active-run.json` marker; obtains the immutable selected staging/inventory
subset through the previous reviewed component; re-reads/revalidates the
original marker content/device/inode/metadata; then revalidates both held
namespace chains before returning a frozen detached pair containing only
marker target/PID/metadata and the frozen selected subset. A single
`PreflightError(cleanup_uncertain=True)` remains preserved.

Disposable RED/GREEN tests cover strict detached immutable evidence,
marker drift with equal logical state, same-content inode replacement,
cache-edge and staging-edge replacement at separate stages, bad selectors
and foreign chains, uncertain-cleanup propagation and zero process or
mutation authority. The tests substitute fixed ownership only inside a
disposable fixture after asserting the production UID0/UID502 constants.

This is **not** an operational preflight or proof of native UID-502
provenance. The supplied root FD is not authenticated as literal `/`;
OS-derived temp ancestry, the complete native process snapshot sequence,
trusted-main workflow provenance, receipt and any recovery/marker
mutation are still deferred. It does not change the automatic stale-provider
Level-3 refusal or grant A1/N1c/Level-3 completion credit.


### Dormant fixed one-snapshot process guard (next isolated Slice B prerequisite)

The private `_observe_fixed_process_snapshot()` adapter imports only the two
fixed sibling components, obtains a fresh **fixed** `capture_ps()` invocation,
checks the exact detached capture type/kind/bytes/owned child PID, and uses the
existing bounded process-row parser and strict inspection/own-ps predicate.
It separately rejects marker owner PID 38013 in the UID-502 rows and probes
**only** literal `os.kill(38013, 0)` for absence: ESRCH means absent; live,
permission-denied and ambiguous outcomes refuse. It returns no process rows,
raw stdout, child identity, receipt or reusable authority. It never kills a
process; the existing reviewed diagnostic helper alone owns any necessary
cleanup of a child **it spawned**.

Known fixed diagnostic errors are sanitized into `PreflightError` while
preserving an exact `cleanup_uncertain: bool`; absent/throwing/non-boolean
status is treated as uncertain. A separate fresh invocation is needed on each
side of an inventory in the later complete preflight. Two calls must not
infer freshness from unequal PID/stdout/rows: PID reuse and identical output
are permitted. No production caller, workflow, root provenance, getconf
composition, staged read, receipt, provider mutation or new signal authority
is added by this helper. Local fixtures replace the capture boundary only in
tests; they do not prove the UID-502 dedicated runner integration. Existing
stale-provider exit 70 still blocks automatic Level-3.

The fixed owner-presence operation is deliberately isolated in
`ops/live-e2e/staging_owner_probe.py` rather than adding a signal-capable
primitive to the previously no-host-action `staging_preflight.py` file.
The pre-existing static prohibition is retained. Non-contract failures from
a capture that has already begun are conservatively classified with
`cleanup_uncertain=True`, even when the underlying exception does not expose
a trusted boolean status.


### PR #160 adversarial follow-up: malformed capture and cancellation

The full-branch adversarial review found an Important lifecycle-certainty
mismatch: a non-contract return from the fixed `capture_ps()` boundary
previously produced `PreflightError.cleanup_uncertain=False`, incorrectly
asserting settled cleanup. The adapter now reports **True** for untrusted
capture shape/kind/byte type/PID type. Once a strictly typed fixed capture has
returned, a later bounded process-row or fixed owner-liveness rejection
retains the ordinary `False` cleanup status; no retry or signal is issued.
Separate RED-to-GREEN tests cover each stage and retain the existing negative
row/owner cases.

A Minor interruption case is also handled at the precise boundaries:
`KeyboardInterrupt`, `SystemExit` and `GeneratorExit` during an attempted
capture become fixed `PreflightError(cleanup_uncertain=True)`; an unexpected
cancellation during the literal owner signal-zero probe becomes a sanitized
fixed error without asserting an unsettled diagnostic child (because the
successful fixed capture already returned). No generic `BaseException`
catch, caller-controlled PID or new cleanup authorization is added.


### Next dormant Slice B prerequisite: fixed getconf-to-temp-parent adapter

The private no-argument `_observe_fixed_temp_parent()` adapter first requires
the existing fixed UID-502 identity, single-reaper Darwin runtime and full
reviewed authority-file byte/size/SHA-256 checks **before** invoking the
literal `capture_getconf()`. The reviewed capture implementation independently
rechecks its authority and exclusively owns the bounded `/usr/bin/getconf
DARWIN_USER_TEMP_DIR` child lifecycle. No environment/TMPDIR/HOME fallback,
arbitrary command, checkout selector or caller path is accepted.

Only a valid exact `DiagnosticCapture(kind="getconf", stdout=bytes,
child_pid=int)` with a strictly bounded positive PID is treated as a settled
capture. Other non-contract returns and interruptions fail with the fixed
public `PreflightError(cleanup_uncertain=True)`; a trusted
`DiagnosticError` propagates its strictly typed uncertainty boolean, with
missing or throwing internal status conservatively treated as `True`.
The existing pure bounded `_parse_temp_parent` rejects malformed native
bytes and permits only a single canonical `/private/var/folders/.../T/`
mapping. The returned frozen `TempParent` contains no raw capture, child PID,
file descriptor or receipt.

This is **not** full native preflight: no directory is opened, no incident
marker/staging files are read, no process snapshot is triggered here, and no
workflow/receipt/cleanup authority is granted. Later independently reviewed
composition must keep root/cache/temp/staging handles pinned through both
fresh process snapshots, inventory, final content and edge revalidation.
Existing automatic Level-3 stale-provider fail-closed behavior is unchanged.
Disposable RED/GREEN tests cover authority-before-capture sequencing, strict
capture shapes and PID, malformed temp bytes, child cleanup uncertainty and
cancellation. No real UID-502 dedicated host execution is claimed.


### PR #161 adversarial review remediation — capture bound and authority-owned closes

The independent [#6068433034](https://github.com/zhangyuz/ssh-over-mcp/pull/161#issuecomment-6068433034)
review identified two Important fail-closed gaps. The fixed getconf adapter now
checks the reviewed `GETCONF_STREAM_BYTES` limit **inside the capture-return
contract**, before parsing: an oversized (>1024 byte) non-contract result
yields `PreflightError(cleanup_uncertain=True)`, while bounded malformed
native bytes remain a settled capture with `False`.

The reviewed three-document trusted-checkout verifier now tracks every
owned FD close (including transient namespace revalidation handles) with a
single-use callback. Any ambiguous close sets a sticky uncertainty bit;
later success, mismatch, or cleanup does not downgrade it. A deterministic
authority mismatch with settled closes still reports `False`. The new
pre-capture adapter propagates the verifier's strict `DiagnosticError`
uncertainty before any getconf invocation. Adversarial tests use disposable
authority documents, real close-followed-by-OSError injection for owned
regular-file/ancestor descriptors, concurrent authority mismatch and close
failure, and a settled-close mismatch control. A descriptor number may be
reused by a new open and is not, by itself, evidence of a close retry. No
incident files, provider marker or UID-502 runner state are modified.


### Dormant fixed native temp-chain binding (Slice B, intermediate)

The private zero-argument `_pin_observed_native_temp_chain()` context
receives only the already-reviewed successful fixed native getconf
`TempParent`, validates the exact immutable native/canonical path pair,
then opens **only literal /** with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`.
It checks the held root against a fresh literal `/` metadata observation,
and uses the existing `_pin_fixed_temp_chain` policy to open each fixed
Darwin `private/var/folders/<shard>/<token>/T` component descriptor-relative.
The returned pinned chain is private and valid **only inside the context**;
the root and every owned descriptor are closed on every success/failure path.
The complete pinned chain and literal-root identity are checked again before
normal context exit; a late namespace swap rejects the observation. Ambiguous
root close is a fixed `PreflightError(cleanup_uncertain=True)`.

No caller can supply a path, root descriptor, PID, UID or raw getconf output.
Fixture-only substitutions for getconf/root metadata use disposable local
directories and cannot establish UID-502 actual host provenance; live root
access is **not invoked by any workflow or CLI**. No staging root, marker,
payload, unknown incident root, child process snapshot, inventory, receipt or
provider state is accessed by this seam. Later composition must keep this
context alive across both fixed `ps` observations and selected staging
inventory before accepting detached evidence. No A1/N1c/Level-3 credit.


### PR #162 important follow-up: post-close namespace observation

Review #6069210460 found an accepted namespace swap *during* the successful
close of an initially pinned T or ancestor FD. The original end-of-context
revalidation was inside the descendant-owning nested context, so it could
not notice a subsequent successful close with a path replacement.
Deterministic disposable-tree probes reproduced **two RED cases**.

After the initial descendant context has finished its owned FD cleanup, this
private helper now performs a **fresh descriptor-relative component-by-
component no-follow pin** of the same getconf-derived literal ancestry,
compares all six recorded device/inode/type/UID/GID/mode snapshots to the
originals, revalidates all new edges, and lets the second nested context
close its exclusively owned FDs with the already-reviewed uncertainty policy.
A final *stat-only* observation compares every fixed-prefix live edge
against the original snapshots using the still-held literal-root FD; it
happens **after both descendant descriptor sets are closed**, adding no new
descendant close window. A final held-root and literal-root metadata check
also occurs before that remaining root FD is closed.

Adversarial tests now force a successful close-plus-name-swap for the first
T FD, first folders-ancestor FD, then separately the second pass's T FD.
These must all refuse. If the same owned close raises after actually
closing its FD, that failure remains `cleanup_uncertain=True` even when the
live path has been replaced. No retried ambiguous close, incident-root access,
new process operation, receipt, workflow or new cleanup authority is added.
These are bounded point-in-time checks against concurrent mutation, **not**
proof of permanent namespace immutability; complete preflight still needs
an independently reviewed final gate with process quiescence.


### Dormant paired fixed ps observations around selected inventory

The private `_observe_paired_process_inventory(selected_chain, selector)` helper
accepts only an **already pinned** catalog-selected disposable staging chain.
It first checks the fixed selected basename/device/inode/UID/mode and held
name edge, then invokes the already-reviewed **fixed** `_observe_fixed_process_snapshot()`
twice, exactly once before and once after the metadata-only
`_observe_selected_inventory()`. Each fixed invocation independently runs
the reviewed bounded `capture_ps()`, validates the real returned owned-child
PID against internally derived `os.getpid()`, rejects unexpected same-UID
processes and insists fixed owner PID 38013 is absent both from rows and from
the literal signal-zero probe. Equal capture stdout and reused numeric ps
child PIDs are explicitly permitted; invocation **count and order** are the
proof of two fresh capture operations.

After the second snapshot has successfully reaped its diagnostic child, the
helper reopens only fixed `payload-content/expected_commit` under the held
selected-root FD, binds its byte/metadata observation against the earlier
frozen inventory evidence, then revalidates the selected-root live edge after
its own payload-descriptor cleanup. Failure at any stage returns **no**
detached evidence, and preserves typed `PreflightError.cleanup_uncertain`.
Successful results are the existing immutable `_SelectedInventoryEvidence`,
without process output, child identity, FD, receipt or cleanup handle.

**Scope limit:** The caller still owns and must independently prove the
literal root, full native-temp and cache-marker provenance and retain every
required held ancestor FD; this *fixture-only* seam does not authenticate
those requirements, and it is not a full native preflight or operational
entrypoint. No workflow, UID-502 runner call, getconf execution here, marker
read, recovery/clear, incident mutation, generic PID/path/command capability
or Level-3/A1/N1c completion is introduced. Disposable RED/GREEN fixtures
assert process→inventory→process ordering (including identical captures),
bounded failure propagation, selected-root edge replacement and late
expected_commit content drift.


### PR #163 review remediation — post-payload-close binding

The adversarial [#6069838296](https://github.com/zhangyuz/ssh-over-mcp/pull/163#issuecomment-6069838296)
review exposed a successful-close race: rewriting the literal
`payload-content/expected_commit` or replacing its payload directory
**during the final payload FD close** allowed the previous implementation
to return frozen evidence. The disposable real-close fault injectors
reproduced this with two RED cases; an ambiguous close correctly failed
with `cleanup_uncertain=True`.

After the first post-B payload context closes, the fixed helper now reopens
**only** the literal no-follow payload/expected_commit through the pinned
selected-root FD, compares the original payload directory device/inode/owner
and mode plus the exact expected-commit file metadata/content, and closes
the second pinned payload context. A final root-anchored **stat-only** check,
after all descendant descriptors are closed, checks the fixed
`payload-content` directory edge before/after the fixed leaf metadata
(including mtime/ctime); it performs **no file-content reads** or added
descriptor close. The selected catalog root edge is also revalidated.
This defends the documented deterministic close interleavings but does not
claim permanent namespace immutability or the full preflight's required
single payload FD retained across both process snapshots.

The disposable regression matrix covers same-inode content rewrite,
payload directory name replacement, ambiguous owned close plus either
drift, and a normal settled success. No staging/marker/provider state on
the real UID-502 incident runner was touched.


### Dormant fixed cache-chain literal-root provenance (next Slice B prerequisite)

The private zero-argument `_pin_observed_fixed_cache_chain()` opens **only
literal /** through the already-reviewed `_open_fixed_native_root()`,
checks the held FD against a separate literal-root metadata observation,
and pins the **fixed** `Users/gha-e2e-orchestrator/Library/Caches/
ssh-over-mcp-e2e` ancestry through the existing descendant no-follow,
descriptor-relative `_pin_fixed_cache_chain` policy. It yields the chain
only while the owning context is active, and does not accept any path, PID,
UID, root FD, selector, marker content or process/capture input.

The original root/descendant metadata is retained and revalidated on exit.
After the first descendant close boundary, the exact same fixed no-follow
chain is reopened and compared against the original metadata, then all fresh
descendant handles close. During the **second descendant cleanup**, each child close is followed
by a single-component, no-follow edge stat relative to its still-held
parent FD; no slash-containing stat path can act as proof of intermediate
symlink safety. The held root FD and literal-root identity are then
rechecked before root closure. Each owned FD receives exactly one close
attempt even if a prior close returns a cancellation or an uncertain result.
An ambiguous owned close is never retried and yields fixed
`PreflightError(cleanup_uncertain=True)`.
No permanent namespace stability or live UID-502 runner proof is claimed.

Disposable tests cover each unsafe ancestor mode, name replacement while
held, first/second descendant-close replacement, ambiguous close with
replacement, literal-root drift and root closure. These fixtures never
open the *real* UID-502 cache; the helper never opens `active-run.json`,
reads provider state, activates any workflow, emits receipts or changes
provider/staging state. Complete preflight still requires separate marker/
native-temp/selected staging and double-ps provenance composition, exact
final content binding and independent review before any trusted activation.


### PR #164 adversarial review #6070461198 fixes

The final joined-prefix `os.stat("Users/.../Library/Caches",
follow_symlinks=False)` did **not** prohibit traversal through symlinks
in intermediate components. A disposable Library→Library-former symlink
race reproduced false success RED. The final check now relies only on
pinned component-by-component `O_NOFOLLOW|O_DIRECTORY` traversal and,
while a parent descriptor remains held, a **single-component** no-follow
`os.stat(name, dir_fd=parent_fd)` immediately following each descendant
close. No joined-prefix stat is used as a security guarantee. A disposable
symlink replacement between stat and second-pass open is rejected.

The common `_pin_directory_chain` FD owner now continues closing the
remaining descriptors after a known cancellation or ambiguous close,
rather than leaking them and reporting settled cleanup. Known interrupted
close outcomes (`KeyboardInterrupt`, `SystemExit`, `GeneratorExit`,
`MemoryError`) set a sticky uncertainty bit; every FD is attempted once,
without unsafe retry, and the caller receives a fixed
`PreflightError(cleanup_uncertain=True)`. RED→GREEN tests cover
`KeyboardInterrupt`/`MemoryError`, with and without a second close
exception, and verify owned-descriptor closure. No broad exception masking
of programming assertions is introduced, and tests touch no actual runner
cache or incident files.


The first independent post-fix reviewer also found two narrower cleanup issues:
a fixed post-close edge metadata rejection could raise `PreflightError`
*inside* the cleanup loop, interrupting the remaining closes; and the
literal root's last close could raise `MemoryError` without a fixed
uncertainty error. The cleanup edge observer now records that typed
rejection as `edge_invalid` and continues every remaining close before
raising, while the root-close handler maps `MemoryError` to the fixed
`PreflightError(cleanup_uncertain=True)`. Disposable tests force a symlink
swap after the second pass leaf close and assert every owned FD, including
the duplicated and literal root, was attempted exactly once and closed.
A separate root-close `MemoryError` test verifies the exact status and no
secret exception text. The component remains dormant with no host incident
inspection or provider-state mutation.


### Dormant native temp final no-follow revalidation

The private fixed `_pin_observed_native_temp_chain()` used to rely on
`os.stat("private/var/.../T", dir_fd=root, follow_symlinks=False)`
after second-pass cleanup. POSIX/Darwin follows intermediate symlinks for
such *joined* paths, so that is not a final no-follow ancestry guarantee.
The helper now uses the reviewed shared `post_close_validate=True` mode
of `_pin_safe_directory_chain` only for the **second** getconf-derived
`private/var/folders/<shard>/<token>/T` pin. That pass compares
the entire immutable original six-edge ancestry and uses the parent's
still-held descriptor to inspect each *single* fixed edge with
`follow_symlinks=False` directly after closing that child. A further
**reverse-order joined-prefix stat** is performed only as a conservative
*reject-only* drift detector **after all descendant closes**, specifically
to catch T/descendant swaps during later ancestor closes. It is **never**
treated as proof of intermediate no-follow provenance; permanent
namespace stability is not asserted without external process quiescence.
Every close is attempted once even after cancellation/metadata refusal;
literal root identity/cleanup and the first-pass entrypoint are unchanged.

Disposable RED→GREEN coverage rejects the original ascending joined
prefixes as sole final validation, requires the reverse stat pass to run
only after the final descendant closes, detects a `folders` symlink
inserted between a single-edge stat and no-follow open, and rejects T
replacement during either second-pass leaf or parent closure (settled
and ambiguous cases). It also verifies strict `cleanup_uncertain=True`
for ambiguous closes and a normal successful observation.

No arbitrary path/UID/PID is accepted, and no real UID-502 temp,
cache marker, staging, provider state, workflow, receipt, cleanup or
recovery authority is exercised. This fixes one ancestry-observation
boundary only; complete native preflight and Level-3 remain unproven.


### Dormant jointly pinned native temp/cache/selected ancestry (fixture only)

Private `_pin_observed_incident_ancestry(selector)` composes the
already-reviewed independent native getconf→temp, literal-root→cache
and catalog-selected T→staging directory contexts **without** marker
file content access or process snapshots. It accepts only the two
hardcoded incident selectors. The fixed getconf capture is completed
before pinning any host namespace descriptor; fixed cache and temp
ancestors are held concurrently while the selected-root name is opened
with no-follow relative to the pinned T FD. The initial and exit
revalidation steps cover all three held chains. The existing nested
owners independently implement their first/second close-boundary
validation, close exactly their own FD sets and propagate the original
`PreflightError.cleanup_uncertain` on unsettled cleanup.

The return is a **borrowed triple of private chain handles scoped only
to the context**. No detached observation is constructed. The handles
must not escape the context, and no lasting namespace-immutability
proof is claimed after all three contexts have finished closing (a
later ancestor close may still coincide with external name mutation).
A future full preflight needs explicit post-snapshot marker,
expected-commit, every held edge and authority-byte gates; this helper
does not perform them or authorize a receipt, CLI, workflow, provider
cleanup, actual UID-502 inspection, Level-3/A1 or N1c closure.

Disposable fixture tests assert getconf-first order, both fixed
literal-root openings, simultaneous held-FD liveness and post-exit
closure, catalog inode/UID/mode, late cache/temp/selected edge swaps,
invalid selector early rejection, staged symlink refusal, no ps,
marker, inventory or incident-content actions, and fail-closed cleanup
uncertainty. Tests never touch the real incident/stale provider state.


### PR #166 shared literal-root Important review correction

The adversarial review #6071232461 reproduced **false acceptance** of
two simultaneously held but different literal-root objects. The native
temp and fixed marker-cache contexts could each pass their independently
timed root identity observations during a simulated A→B→A root-view
transition. Two independent disposable-root regression cases were
**RED** before the fix. The joint context now calls
`_require_shared_incident_ancestry(cache, temp, selected)` **before
yield and after the final three-chain revalidation**, while all owners
still hold their descriptors. It compares the full immutable
(device/inode/type/UID/GID/mode) root metadata snapshots from cache and
temp, freshly `fstat`s both separately opened root FDs against the same
baseline, and explicitly binds the selected chain's original T parent
snapshot and fresh duplicated T descriptor metadata to the retained temp
chain's last snapshot/held T FD.

The selected parent is independently duplicated by the existing pin
helper: **descriptor integers need not be equal**; object metadata must
be equal. The new guard owns no additional descriptor and does not
close or detach any borrowed FD. Disposable tests verify the different
roots' fail-closed behavior under separately successful local checks,
simulated A→B→A changes, normal common-root acceptance and forged T
baseline rejection. No real incident marker/selected staging is read;
this is still a dormant borrowed-context intermediate, not full
preflight evidence.


### Dormant jointly rooted marker + selected inventory observation

Private `_observe_joint_marker_staging(selector)` applies the previously
reviewed fixed marker/selected-staging observation inside the concurrently
pinned cache, native-temp and catalog-selected staging ownership context.
The fixed two-item selector is validated before any getconf or filesystem
open. The shared literal-root and borrowed selected T identity are checked
before and after observing the fixed `active-run.json` marker and
metadata-only staging inventory. The existing strict descriptor-relative
marker parser and selected inventory are unchanged; only fixed
`payload-content/expected_commit` content is additionally reread under
the held selected FD and compared with the frozen inventory metadata.
The marker is also re-read after that bounded expected-commit operation
and its immutable metadata must match the earlier observation.

The result is only existing immutable `_MarkerStagingEvidence`; it contains
no FD, raw marker bytes, process stdout, child identity, PID argument, receipt,
workflow or recovery capability. All new test reads are confined to
disposable fixture trees. This helper is dormant and not a complete native
preflight; in particular it does **not** establish the exact checkout
authority bytes, a pair of fixed ps captures, trusted workflow provenance,
persistent-runner process quiescence, or namespace immutability after FD
closure. Its partial evidence may not be used for recovery or Level-3/A1.


The first independent PR #167 security reviewer also reproduced a late
expected-commit TOCTOU: the third marker read could rewrite the fixed
expected_commit leaf after its last content revalidation while the outer
composition still accepted stale evidence. The new ordering keeps the
single fixed payload FD held during the late marker read, validates
expected-commit content/metadata again afterward, then closes the owned
payload descriptor. A further fixed marker reread detects marker drift
caused during that owned payload cleanup, and a **reject-only metadata**
check of the fixed payload directory and expected_commit leaf (parent
metadata before and after) rejects a leaf rewrite during the last marker
read or payload close. The slash-separated stat is supplemental drift
detection, not a no-follow proof for intermediate directories; original
descriptor-relative `_pin_expected_commit` provides the content-read
authority. Disposable fault injection demonstrates the reviewer case RED
and the corrected code GREEN, without reading live incident state.


### PR #167 second adversarial Review: last marker leaf and owned file closes

The independent #6072158191 review identified two Important close-boundary
holes in the dormant joint marker/staging partial evidence. A deterministic
disposable fixture makes the fourth fixed marker reader's owned regular-file
close successfully rename `active-run.json` to `old-marker` and install
either a symlink to its original bytes or a freshly created same-byte file
with another inode. Previously partial evidence could be returned; now,
**after that final marker FD is closed**, the wrapper performs a fixed,
single-component `os.stat("active-run.json", dir_fd=held_cache_fd,
follow_symlinks=False)` and compares the complete original strict
regular-file metadata (device/inode/type/UID/GID/mode/nlink/size/mtime/ctime).
This rejects the symlink and different inode, regardless of byte equality.
The pinned cache directory stays held through the check, with no new
regular-file read or temporary FD ownership.

The existing owned-file reader `_read_named_regular` also used to
propagate `KeyboardInterrupt`, `SystemExit`, `GeneratorExit` or
`MemoryError` from its `os.close(fd)` to an outer handler that claimed
`cleanup_uncertain=False`. It now normalizes just those known ambiguous
close failures to the fixed `PreflightError(cleanup_uncertain=True)`,
without retrying, double-closing or exposing native exception details.
The flag also remains True if there was a primary read failure before
the uncertain close. All fault injections operate on disposable fixture
FDs only. This is a bounded end-of-reader marker-name binding, not a
promise of permanent post-context namespace stability or full preflight
authority, and does not authorize any real UID-502 inspection or cleanup.


### Dormant fixed paired process snapshots within jointly pinned ancestry

The private `_observe_joint_paired_inventory(selector)` composes the
previously reviewed catalog-bound cache, native-temp and selected-staging
descriptor contexts with the existing fixed `_observe_paired_process_inventory`
routine. The fixed getconf observation precedes all namespace opens. Both
literal-root objects, the native T directory and the selected basename stay
held simultaneously while **two distinct invocations** of the bounded
fixed `ps` capture bracket metadata-only selected inventory.

The helper revalidates all three held name edges and the explicit shared
root/T identities before and after the paired observations. A ps failure,
unexpected process, selected-content drift or namespace replacement must
fail closed; any typed `cleanup_uncertain=True` propagates. The return is
only existing frozen `_SelectedInventoryEvidence` without raw stdout,
child identity, borrowed FD, receipt or cleanup authority. Catalog
selectors are fixed; there is no caller-selected PID, command, UID or
path. Tests use disposable fixture directories and substituted child
observations, never actual UID-502 incident state.

This is still a **partial, unactivated** composition. It does **not**
authenticate `active-run.json`, prove marker-versus-ps atomicity or
fixed checkout authority bytes, yield a full native preflight envelope,
establish post-close permanent namespace stability, change a workflow,
or authorize provider recovery. Those are separate review gates; PR-only
Level-3 SKIPPED is not acceptance.


### Dormant jointly pinned two-ps selected inventory (next narrow slice)

Private `_observe_joint_paired_inventory(selector)` borrows the already
reviewed fixed native-temp, literal-root cache and catalog-selected T→stage
descriptor chains **concurrently**. It checks the common literal-root and
duplicated selected T identities before and after invoking the existing
`_observe_paired_process_inventory(selected, selector)`, which runs two
independent fixed `ps` capture operations around the selected
metadata-only staging inventory and revalidates the fixed
`payload-content/expected_commit` contents and metadata after ps B.
The three still-held name edges, root identities and T parent binding
are checked before success evidence is detached.

The result is **only the already existing frozen
`_SelectedInventoryEvidence`**. No raw ps output, child PID, FD, marker
bytes, receipt, activation, operator-selected command/UID/path/PID,
provider cleanup or workflow authority is returned. The cache chain is
held but `active-run.json` is **not read** in this intermediate. This
slice cannot claim marker authentication or complete native preflight
and is not a Level-3/A1/N1c completion. No real UID-502 host/incident
state is inspected or changed.

Disposable tests check ps-A→inventory→ps-B order inside the joint
ancestry, selector strictness, rejection of cache/temp/selected
replacement during ps B, expected_commit changes during ps B,
sticky cleanup uncertainty on either snapshot failure, unsafe cache
mode refusal before ps, split-root refusal, and explicit absence of
marker/provider actions. No fixture substitutes a real runner capture.

### Dormant marker + paired fixed ps + selected inventory in one borrowed context

The private `_observe_joint_marker_paired_inventory(selector)` is a single
fixture-only composition over the already-reviewed cache, getconf-derived
native-temp and catalog-selected staging descriptor chains. It differs from
calling `_observe_joint_marker_staging()` and
`_observe_joint_paired_inventory()` sequentially: those separate partial
helpers independently borrow and close their ancestry, which cannot establish
one continuous observation.

In this slice the initial fixed marker read and fixed payload-content directory FD pin
precede `ps A`; two independent owned/reaped fixed `ps` observations bracket
the metadata-only inventory under simultaneously held root/T/cache/selected
and the original payload directory descriptor. The expected_commit file
is opened/read/closed separately on each check. After `ps B`, both marker and
expected_commit contents and original metadata are revalidated. The payload
FD is closed before the final fixed marker reread, followed by the no-follow
single-component marker-leaf check, reject-only expected-commit leaf/parent
checks, three held chain edge checks and root/T identity comparison.
All failures reject with the fixed public error, and typed uncertain cleanup
is sticky. The result is only the existing immutable `_MarkerStagingEvidence`,
with no process stdout/PID, owned FD, receipt or mutation authority.

Disposable fixture adversaries cover early marker symlinks; mutation during
ps A, inventory or ps B; late cache/temp/staging renames; expected_commit
revisions after ps B, on early commit-file close and after the
post-ps-B payload-directory close; final marker FD-close symlink
replacement; missing/invalid selector; and uncertain failure of either
process capture. No actual UID-502 incident access or provider operation
occurs.

This is still a **partial, unactivated internal observation**, not an
approved complete native preflight. It does not emit a complete canonical
preflight object/envelope, confirm the trusted manual workflow origin,
prove actual UID-502 live host state, grant staging apply/marker cleanup,
or guarantee namespace stability after its finite final checks and FD closes.
The exact PR-only Level-3 skip is not an E2E PASS; stale-provider E2E remains
a separate, blocked acceptance gate.

### Dormant paired-ps capture-boundary cleanup uncertainty

The internal `_observe_fixed_process_snapshot_checked()` adapter now guards
both fixed ps invocations in the older `_observe_paired_process_inventory()`
and the single-context marker/paired-inventory wrapper. Typed `PreflightError`
keeps its original strict `cleanup_uncertain` boolean. An untyped exception
escaping an actual snapshot invocation (including OS failures, cancellation,
or unexpected runtime errors) becomes the fixed sanitized refusal with
`cleanup_uncertain=True` **before** descriptor contexts unwind. This does
not reclassify a known-settled later namespace, metadata or payload failure,
and does not retry or signal any foreign process.

Disposable ps-A and ps-B fault injection verifies the old paired helper,
joint ancestry wrapper and new joint marker wrapper preserve uncertainty
without returning partial inventory or new authority. There is no new
workflow, receipt, live UID-502 inspection or stale provider mutation;
the real Level-3, A1 and N1c acceptance gates remain pending.

#### Inventory-owned close and iterator cancellation (review #6073077695)

The dormant `staging_inventory.py` collector owns both duplicated directory
descriptors and `os.scandir(fd)` iterators. Its `close_owned()` and iterator
`close()` boundary now translate interruptions (`KeyboardInterrupt`,
`SystemExit`, `GeneratorExit`) and unexpected typed runtime/OS close failures
into a fixed `InventoryError(cleanup_uncertain=True)` **at the owner**.
The preflight binder preserves that typed uncertainty through the older
ps-A/inventory/ps-B adapter and the jointly pinned ancestry wrapper.
Known-settled invalid metadata still yields the existing False status;
no caller-supplied paths/PIDs, new subprocesses, retry, unlink or receipt.

Disposable fault injection tracks the collector's actual `os.dup`-owned
root descriptor; after a real successful close, injects cancellation,
including a secondary cancellation following a failed traversal. Separate
iterator-close injection tests the `scandir` duplicate. Both composed
paired and joint callers must refuse with `cleanup_uncertain=True`, without
ps B or partial inventory evidence. No live UID-502 incident is accessed,
and Level-3/A1/N1c remain unverified.

### Dormant collector-owned descriptor and iterator acquisition uncertainty

The metadata-only staging collector obtains a private root clone with
`os.dup(root_fd)` private iteration handles with `os.scandir(fd)`, and owned child
directory FDs via no-follow `os.open(name, ..., dir_fd=fd)`.
Failure of any of these acquisitions can occur after allocating the underlying
resource without returning a usable owned handle. Such a failure now
returns only the sanitized `InventoryError(cleanup_uncertain=True)`
instead of claiming conclusively settled cleanup or leaking cancellation.
The borrowed root remains owned by the caller and is never closed here.

Disposable acquisition fault fixtures trigger only at the collector-owned
dup/scandir/child-directory open invocation, perform a real allocation, dispose their own test
clone, then raise untyped errors/cancellation. The collector and both
paired-ps and jointly pinned ancestry callers must refuse as uncertain
before ps B. A control fixture proves ordinary failure on a borrowed
root fstat **before** any allocation retains the settled False status.
No new production path, PID, helper command, receipt, workflow,
provider mutation or UID-502 incident access is introduced.

### Full joint marker/paired inventory collector-acquisition fault matrix

The private `_observe_joint_marker_paired_inventory()` is now exercised at
the final composition boundary for every collector-owned acquisition type:
`os.dup` of a borrowed staging root, `os.scandir` iterator acquisition and
no-follow nested directory `os.open` from `walk`. Disposable fixtures
allocate and explicitly release their *own* clones before raising an
untyped OS error, runtime error or cancellation from the exact collector
operation. The fully composed observer must return the fixed sanitized
refusal with `cleanup_uncertain=True`, stop after ps A (before ps B),
and leave marker and expected-commit bytes intact. An ordinary invalid
inventory mode remains a known-settled `cleanup_uncertain=False` refusal.

This PR adds only regression coverage at the existing private wrapper;
no new API, UID-502 inspection, workflow, receipt or recovery authority.
PR-only Level-3 skip remains separate from main's stale-provider gate.

### Full joint marker/paired inventory release uncertainty

The dormant `_observe_joint_marker_paired_inventory()` now has end-to-end
disposable fixture coverage for collector-owned **release**, complementing
its existing acquisition matrix. Tests trap the exact `close_owned()` calls
for its duplicated inventory-root FD and no-follow child-directory FD, plus
the `names_at()` iterator's `scandir.close()` call. In each fixture the real
owned resource is released first, then a deliberately ambiguous OS/runtime
error or cancellation is raised. The full wrapper must refuse with fixed
`PreflightError(cleanup_uncertain=True)` and no chained error, without
performing ps B or changing marker/expected-commit bytes.

A secondary-failure test first injects a traversal error, then an uncertain
owned-root FD release from the same failure unwind. The secondary uncertain
cleanup state must take precedence over a normally settled traversal error.
None of these fixtures use a real UID-502 incident, provider cleanup,
operator workflow, recovery authority or process signal. Level-3 is not
activated by this evidence-only slice.


### Dormant one-pass detached joint preflight observation

The private `_observe_detached_joint_preflight("stale-target"|"older-target")`
is now a **feature-complete detached evidence projection** for the existing
disposable, read-only joint fixture. It delegates to
`_observe_joint_marker_paired_inventory` exactly once, so it does not
invoke additional getconf/ps captures, re-open incident data or combine
two individually detached (race-prone) partial observations.

The returned frozen/slotted `_DetachedJointPreflightObservation` contains
the canonical, fixed-getconf-derived temp-parent path, an ordered tuple of
root-to-T `_DirectoryAncestor(path, DirectoryMetadata)` snapshots, the
validated fixed marker target/owner/metadata, and the existing frozen selected
catalog/root/expected_commit metadata and complete inventory tuple. Only the
jointly held observer creates the temp-parent projection; older partial
marker/staging helpers leave their optional `temp_parent` unset. The output
has no FDs, child PIDs, capture stdout, mutable mappings, workflow authority,
envelope, receipt or recovery action.

Tests cover a complete happy-path single invocation, exact detached ancestor
paths and metadata, strict selector-only signature and malformed selector
refusal before host effects, immutable records, stale marker at ps A,
inventory and ps B, typed cleanup uncertainty from either snapshot, and
post-ps-B ambiguous owned payload FD closure. A malformed proposed temp
ancestor chain cannot be detached. All failures return only sanitized
`PreflightError`; no partial record or newly authorized operation escapes.

**Boundary:** This is still a private dormant fixture-only function, **not**
a trusted UID-502 incident inspection, native A1/Level-3 certification,
activated workflow, envelope conversion or receipt producer. The separately
approved authority binding, live guest/provider-state recovery and native
acceptance gates remain unchanged. No real incident state is touched.


### Pure detached preflight → canonical inventory projection

The private `staging_projection.project_detached_inventory(observation)`
is a complete offline **data conversion** feature. It consumes only an
already-detached `_DetachedJointPreflightObservation` from the dormant
one-pass observer, validates exact typed/frozen structures and selected
catalog/marker/expected_commit cross-field identities, then projects the
native-getconf canonical root-to-T ancestor snapshots, marker, staging and
the entire metadata-only inventory into the reviewed **inventory v1** wire
shape. It uses the existing `staging_envelope._inventory_valid` domain
predicate and `staging_wire.encode_inventory_payload` canonical bounded
serializer, not a permissive JSON codec.

Output is only frozen `ProjectedInventory(payload: bytes, sha256: str)`.
Fixture golden inventory bytes/digest must match exactly; both incident
selectors, malformed/forged records, wrong ancestor paths, root/inventory
catalog mismatches, wrong expected_commit metadata, unsafe marker modes,
entry order/duplicates, scalar-type misuse (including deceptive `str` subclasses on discarded
ancestor paths), immutability and projection determinism have explicit tests. Host-access traps prove the converter
does not call `os.open/stat/scandir/kill/fork` or the preflight observer.
When the fixed inventory-entry module cache is uninitialized, it refuses
without loading/compiling a file; normal jointly pinned observation has
already initialized that fixed inventory type during collection.

This feature **does not authenticate provenance** of a supplied detached
record. It neither accepts `inspection` authority/run ID/attempt nor
creates envelopes/receipts, writes data, invokes a process, accesses the
UID-502 staging incident, clears a provider marker, or enables recovery.
Its checksum certifies output bytes only, never a trusted workflow or a
real Level-3/A1/N1c result. Production conversion/activation requires
the separately authorized trusted-workflow and host-provenance gates.

### Offline canonical inventory drift report (dormant, data-only)

`staging_drift.compare_detached_observations(before, after)` compares two
supplied frozen joint observations for the **same fixed incident selector**.
It independently passes **both** inputs through the strict canonical inventory
projection, then returns an immutable `DetachedDriftReport`: before/after
canonical payload SHA-256, entry paths newly added/removed, ordered
`ChangedEntry(path, changed_fields)` metadata changes, marker metadata
changes (including fields omitted from the wire payload), native temp-parent
ancestry differences, selected expected-file metadata changes, and an overall
`has_drift` data flag. Record and changed-field ordering is deterministic.

Disposable tests cover exact equality, one regular-file metadata drift,
an expected_commit metadata change that also updates its inventory entry,
allowed nested add/remove, native ancestor metadata change, non-wire marker
timestamp drift even when both output SHA-256 digests remain identical, mixed
selector refusal, forged source records, cold-cache fail-closed, frozen output
and absence of any host observation, file/process operation or workflow call.

**Not an acceptance gate:** The comparator receives supplied offline data.
Neither a matching digest nor `has_drift=False` proves trusted provenance,
freshness, safe recovery, UID-502 state, absence of unseen changes or Level-3
completion. It does not create an envelope, receipt, workflow binding, signal
or deletion eligibility, and it never reads the actual provider/incident.

### Canonical bounded offline drift artifact (v1, no provenance)

The private `staging_drift_artifact` module provides a complete offline
export-and-import function for already computed immutable drift reports:
`encode_detached_drift(report) -> DriftArtifact(payload, sha256)` and
`decode_detached_drift(raw, expected_sha256=...) -> DetachedDriftReport`.
The encoder accepts only the strict `DetachedDriftReport` and
`ChangedEntry` dataclass types, exact incident selector, lowercase
64-character SHA-256 digests, strict boolean flags and consistent
`has_drift`. Added, removed and modified paths must be distinct and
filesystem-byte ordered, canonical, depth/length bounded; changed-field
names must be from the fixed record schema, unique and in schema order.

The exchanged artifact is canonical compact, ASCII-escaped, sorted-key
JSON with an exact `schema_version: 1` schema and 2 MiB upper byte bound.
Decoding rejects duplicate keys, unknown/missing fields, incorrect
types, noncanonical JSON (including alternate ordering/escaping), invalid
paths, impossible flags, checksum mismatch, and oversized bytes; it
re-encodes and requires byte-for-byte equality. Tests verify exact
golden-shaped bytes, checksum, round-trip including a real offline
comparator output, malformed inputs and no filesystem/process/observer
syscalls.

**Security boundary:** The SHA-256 is a *content checksum*, not a signature
or trusted evidence. Someone who controls both artifact bytes and the
expected digest can substitute both. The codec never accepts or grants
inspection authority, trusted source provenance, workflow IDs,
UID-502 access, receipt, recovery, deletion or Level-3 acceptance.

### Cross-binding a portable drift artifact to two frozen offline snapshots

`staging_drift_binding.build_detached_drift_artifact(before, after)`
is a one-step **offline, non-authorizing** composition of independently
validated joint observations into the strict v1 canonical drift artifact.
`verify_detached_drift_artifact(before, after, raw, expected_sha256=...)`
then strictly decodes and checks the supplied artifact, independently
recomputes the report from **both** supplied source observations using
the existing projector/comparator, and requires both complete typed
report equality and exact canonical artifact/digest byte equality.

The returned frozen `ConsistentDetachedDrift(report, artifact_sha256)`
attests only **internal consistency of the three supplied data objects**.
The important distinction is that **a correct SHA-256 of a forged artifact
is insufficient**: forged marker/parent/selected drift *flags*, encoded
inventory fields, or metadata claimed as changed are checked against the
recomputed **v1 report**. This does **not** uniquely bind the full source
snapshot pair: the report stores a `marker_changed` boolean rather than
before/after values for metadata omitted from inventory-v1 wire bytes. For
example, if marker mtime changes from 1 to 42, changing the post-observation
mtime again to 99 or reversing the pair can still produce the same canonical
v1 drift artifact. It is a deliberately **lossy summary**. Tests exercise
a complete builder→verifier round trip, two identical snapshots, forged
report fields with correctly recomputed checksums, changed source records,
swapped before/after, mixed incident selectors, malformed/oversized
payloads, uninitialized cache refusal and host/process/observer I/O traps.

The supplied before/after snapshots, artifact and checksum can all be
controlled by the caller. A matching result is **NOT an authenticated
inspection or freshness claim**, cryptographic signature, trusted receipt,
workflow permission or recovery/Level-3 decision. There is no real UID-502
capture, provider read/clear, marker mutation, or unknown-workspace access.

### Offline ordered snapshot-pair content seal (v1, no host provenance)

`staging_snapshot_seal.build_snapshot_pair_seal(before, after,
artifact_raw, artifact_sha256)` produces a small, byte-stable,
SHA-256-checksummed canonical v1 JSON content seal for the *ordered*
pair of supplied frozen observations **and** their previously validated
canonical drift artifact. `verify_snapshot_pair_seal(..., seal_raw,
seal_sha256)` checks exact keys/version, a bounded canonical JSON
encoding, lowercase SHA-256, duplicate-key refusal, strictly revalidates
the drift artifact against both supplied observations, independently
fingerprints each full supplied snapshot, then requires exact byte/digest
equality with the seal.

The snapshot fingerprint is domain-separated SHA-256 over canonical
inventory-v1 bytes **plus every strictly checked scalar field of the
full marker and selected expected-file regular metadata records**.
The supplementary metadata integers reuse the fixed wire codec's **locally
bounded decimal encoder**, retaining the legacy canonical JSON bytes for
ordinary values while accepting already-valid signed timestamps beyond
CPython's 4300-decimal-digit conversion guard (including 5001/10001-digit
positive and negative values). It never disables or mutates that global guard.
The extra metadata encoding uses a fixed 2 MiB byte budget; failure is
sanitized and does not open a host access path.
This includes marker fields omitted from inventory wire bytes, such as
the actual before/after `mtime_ns` and `ctime_ns` values. Unlike the
lossy v1 drift report's `marker_changed` boolean, this separate
ordered-pair seal refuses replacing a post-marker timestamp 42 with
99 or reversing the only-marker-drift pair, even though the original
v1 drift artifact and its checksum would still verify successfully.

Independent adversarial tests pin the above v1 collision, reject
altered sidecar fields/direction, malformed/reordered/duplicate JSON,
correctly recomputed forged content checksums, unsupported sources,
cold inventory cache and any host/process/observer I/O.

**Important:** The seal is an *unkeyed content fingerprint* of **supplied**
data. It is not an HMAC/signature, authorized producer claim, native
read-only UID-502 inspection, fresh trusted workflow provenance, receipt,
Level-3 acceptance, marker clearing or recovery permission. Someone
who controls both observations and their artifact/seal can replace the
entire coherent tuple. Existing v1 drift artifact wire schema is unchanged.

### Bounded offline snapshot timeline — ordered multi-hop consistency

The private `staging_snapshot_timeline` feature composes **2–17
caller-supplied frozen observations** into **1–16 adjacent pair hops**.
`build_snapshot_timeline(tuple_of_snapshots)` produces a frozen
`BuiltSnapshotTimeline` containing one canonical v1 drift artifact
and one full-content snapshot-pair seal for every hop, plus a bounded
canonical v1 JSON timeline manifest. The manifest records the single
incident selector, **ordered** full-content snapshot digests, per-hop
drift artifact and pair-seal checksums, and zero-based hops reporting
drift; it has its own SHA-256 content checksum.

`verify_snapshot_timeline(snapshots, hops, manifest_raw,
expected_sha256=...)` refuses invalid counts, untyped hop objects,
duplicate/missing/noncanonical manifest keys, digest mismatch, source
splicing, changed intermediate snapshot metadata or reordered pair
seals. It independently runs the previously reviewed strict drift
and full metadata pair-seal verification for every adjacent pair,
then requires byte-identical regeneration of the entire manifest.
The same snapshot at index i feeds both neighboring hops; no caller
may supply a separate unlinked "right side" for one transition.
A fixed bounded count prevents unbounded host work and output size.
Every failure is a sanitized `TimelineError` without exception chains.

This proves **only internal consistency and order of supplied data**.
Unkeyed hashes cannot authenticate who acquired any observation, when
it was acquired, or whether the caller changed the entire tuple.
The feature performs no host/process I/O, UID-502 capture, provider
mutation, trusted workflow/receipt issuance, or native Level-3
authorization. Existing v1 drift and snapshot-seal wire formats are
unchanged. A green offline timeline never closes A1/B8/N1c/Level-3.

### Offline verified timeline change summary — path-free diagnostic output

Private `staging_timeline_summary` composes the merged bounded
`staging_snapshot_timeline` feature into deterministic canonical v1
JSON reporting each adjacent hop's full-content source/artifact/seal
SHA-256s, change flags, and **counts only** for added, removed and
modified inventory paths. Raw inventory paths, raw metadata values and
host capture inputs are not serialized in this new summary. A separate
16-KiB maximum and immutable frozen result types bound the output.
`build_timeline_change_summary(snapshots, hops, manifest_raw,
expected_timeline_sha256=...)` requires the already reviewed strict
per-hop source/seal/timeline verification.
`verify_timeline_change_summary(..., summary_raw,
expected_timeline_sha256=..., expected_summary_sha256=...)`
rejects malformed/duplicate/noncanonical/oversized summary bytes,
incorrect checksums, swapped hops, and forged change flags even if
a self-consistent unkeyed digest is recomputed. Report labels are
classified offline observations, not an authenticated root cause.

This remains a **private offline diagnostic transformation only**,
not a new authority-bearing wire/API, trusted host observation,
chronology, UID-502 inspection, provenance signature, receipt,
native Level-3 PASS, marker cleanup or recovery permission.
A1, B8, paused N1c, native Phase 7B1 and provider disposition
remain independently blocked and open.

### Canonical offline multi-hop change audit (separate complete capability)

The private `staging_timeline_audit` module consumes an existing **exact**
caller-supplied tuple of 2–17 frozen observations, its 1–16 typed timeline
hops and canonical timeline manifest/checksum. `build_timeline_audit(...,
expected_timeline_sha256=...)` emits a new canonical v1 JSON audit with an
independent SHA-256; `verify_timeline_audit(...,
expected_timeline_sha256=..., expected_audit_sha256=...)` strictly regenerates
it and returns an immutable `VerifiedTimelineAudit`. A fixed **128 KiB**
audit budget, strict ASCII canonical encoding and duplicate-key refusal
limit input and output; every rejection is sanitized `AuditError`.

The audit includes each hop's ordered full-content snapshot digests, drift
artifact checksum, changed/unchanged state, marker/parent/selected-metadata
flags, added/removed paths and per-file changed fields. It also records all
changed and stable hop indices, whether the **first and last exact full
content fingerprints** differ, and `revisited_snapshots`: an index matching
a previous exact fingerprint **after a different immediately preceding
fingerprint**, with its first matching index. These are caller tuple positions,
not capture timestamps. Even when net change is false, the report preserves
intermediate changes and evidence of a content return.

Both functions reverify the original timeline and every adjacent pair against
caller-supplied snapshots; canonical audit reconstruction rejects forged
classification, spliced sources/hops and mutated audit content **even when the
attacker recomputes an unkeyed SHA-256**. This is a pure offline diagnostic,
not a source-attested log, timeline of real events, provider inspection,
recovery authorization, B8 workflow receipt, paused N1c input authentication
or native Level-3 completion. No new v1 drift/timeline wire fields or host I/O.

**Data disclosure boundary:** Unlike the #181 path-free count summary, this
private 128 KiB audit intentionally contains caller-provided inventory path
strings and must not be published as a sanitized or low-trust report. Use
the path-free summary where file paths must remain undisclosed. No automatic
logging, host capture or model-facing tool output is added.


### Offline audience-separated timeline casefiles (PR #183)

`staging_timeline_casefiles` provides an end-to-end **pure in-memory**
workflow from the same 2–17 caller-provided frozen observations. Unlike
manually assembling the #180 manifest, #181 path-free summary and #182
sensitive path-bearing audit, this exports one **canonical public casefile**
and, only with explicit opt-in, a linked **private casefile**.

- `build_public_casefile(snapshots)` emits a bounded **32 KiB** canonical v1
  JSON envelope with the full ordered timeline manifest, **path-free**
  summary, their SHA-256s and a new SHA-256 of the complete envelope.
  No raw inventory path strings/modified field names/metadata values are
  serialized in this public representation. It does generate and validate
  sensitive intermediate drift data strictly in process, never exports it.
- `verify_public_casefile(snapshots, raw, expected_sha256=...)` re-creates
  the original sealed hops from the **exact supplied** source tuple, verifies
  the manifest and summary independently, then rejects any noncanonical,
  duplicate-key, oversized or forged public envelope by byte-for-byte match
  even when the outer checksum was recomputed.
- `build_private_casefile(snapshots, allow_sensitive_paths=True)` is the
  separate explicit opt-in API. It exports up to **160 KiB** canonical JSON
  with a full #182 path-bearing audit and its checksum, **bound to the exact
  public casefile SHA-256**. Default/missing, non-boolean or false opt-in
  fails closed; sensitive result types suppress ordinary `repr` content.
- `verify_private_casefile(snapshots, public_raw, private_raw,
  expected_public_sha256=..., expected_private_sha256=...,
  allow_sensitive_paths=True)` validates **both** envelopes, original
  sources, every paired seal, ordered manifest, public summary, private audit
  and cross-casefile digest binding. Wrong sources, altered source order,
  recomputed forged hashes, wrong audience, noncanonical bytes and spliced
  public/private combinations fail closed with fixed sanitized errors.

The two casefiles never embed a trusted event producer or capture time. The
caller **must provide the original observations for verification**; the
casefiles alone are not sufficient for authenticating or reconstructing a
host incident. Content checksums are unkeyed and do not stop coherent
replacement of the entire source tuple and all artifacts. A public casefile
is *path-free*, not automatically approved for arbitrary distribution of
incident selectors or source fingerprints; a private casefile exposes raw
caller-provided paths. This feature performs no host I/O, UID-502 capture,
trusted workflow receipt, provider cleanup, native recovery or Level-3 gate.
A1/B8/paused N1c/Phase 7B1 and stale-provider disposition stay OPEN.

The explicit private-path opt-in is a programming guard against accidental
export, **not** caller authentication or an authorization policy.


### Contiguous path-free public casefile series (PR #184)

`staging_casefile_series` assembles a **complete 2–8-segment offline
verification report** for a longer caller-supplied chain. Each segment is
an exact tuple of **2–17 original frozen observations** accepted by #183's
public casefile exporter and verifier. Each segment is rebuilt and verified
independently with its #180 timeline and #181 path-free counts; the last
full-content snapshot SHA-256 of one segment MUST match the first of the
next segment. The same incident selector is required across the series.

`build_public_casefile_series(segments)` exports one **64-KiB maximum**
canonical ASCII JSON v1 report with ordered public-casefile SHA-256s, each
segment's timeline/summary digests, first/last snapshot fingerprints and
added/removed/modified inventory **counts**, a de-duplicated global ordered
sequence of up to **129 snapshot fingerprints / 128 hops**, global changed
and stable hop indices, first-to-last content net-change and non-adjacent
full-content revisits. Shared segment endpoints count only once. Reports
contain **no raw paths, modified-field names or raw metadata values**.

`verify_public_casefile_series(segments, raw, expected_sha256=...)` rejects
invalid input containers, noncanonical/duplicate-key/non-ASCII/oversized
report bytes, stale digests, reordered or spliced segments, a missing shared
endpoint, wrong incident and forged counters/revisit indices **even with a
recomputed unkeyed SHA-256**, by regenerating the entire casefile series
from the exact original observations. All failures are fixed sanitized
`SeriesError` without chained exceptions.

**Security:** Like #180–#183, all supplied ordering is *caller order*, not
capture chronology or producer authentication. A fully replaced coherent
tuple and accompanying regenerated report can still verify. Path-free
output still discloses incident selectors and content fingerprints; public
means *no raw inventory paths*, not unconditional release approval. The
series path never invokes #182's private audit. No host/process/UID-502
observation, network access, staging mutation, trusted receipt, stale-provider
recovery or native Level-3 permission is introduced. A1/B8/paused N1c,
Phase 7B1 and real E2E validation remain separate OPEN gates.

Post-#183 merge-main workflow `37942814022`: Ubuntu Python 3.13/3.14
validation PASS; no-network Level-3 FAIL-CLOSED (pre-existing stale
provider state, exit 70). Nothing in #184 restores provider authority.

### Opt-in private path-bearing casefile series (PR #185)

`staging_private_casefile_series` extends #184's fully verified path-free
contiguous series with a distinct, private **2-MiB maximum canonical JSON**
report. `build_private_casefile_series(segments, allow_sensitive_paths=True)`
returns **both** the original path-free public series and a private report
bound to the exact public series SHA-256. The private report includes every
source-reverified #183 sensitive segment audit, each segment's exact public
and private casefile digests, the private audit digest, global hop offset,
changed-hop indices and net-change classification. Path-bearing per-segment
added/removed inventory names and modified field details remain confidential;
they are never appended to or constructed by the #184 public-series API.
The result objects suppress ordinary `repr` to avoid accidental disclosure.

`verify_private_casefile_series(segments, public_raw, private_raw,
expected_public_sha256=..., expected_private_sha256=...,
allow_sensitive_paths=True)` validates canonical ASCII bytes, SHA-256s and
strict 64-KiB public/2-MiB private bounds **before** untrusted JSON parsing,
regenerates all source snapshots, paired seals, segment casefiles and
cross-segment boundaries, checks path-detail counts against independent public
count-only reports, and requires byte-exact reproduction of BOTH series.
Rehashing forged audits or attempting to pair a genuine private series with
another public series is rejected with a fixed sanitized `PrivateSeriesError`.

The exact-True opt-in is a programming guard to reduce accidental path export,
**not** authentication or authorization. Raw path strings are sensitive; no
host/provider/process inspection, staging access, trusted chronology or
signed receipt is acquired. A1/B8, UID-502, ADR-paused N1c, the native
Phase 7B1 prerequisite, provider recovery and native Level-3 are still OPEN.

#184 merge-main CI `37946298917`: Ubuntu Python 3.13/3.14 PASS, native
no-network Level-3 FAIL-CLOSED (stale provider state, exit 70).
