# Self-hosted Ubuntu 26.04 x86 Docker runner

The optional hardened validation runner is an ephemeral GitHub Actions runner
container on the dedicated Intel/x86 Mac host. The container is always
**Ubuntu 26.04 x86_64**. Apple Silicon/M4 is intentionally excluded from
runner scheduling.

For continuous availability on the dedicated Intel Mac, install the per-user
supervisor from the repository root:

```bash
bash scripts/supervise-mac-x86-runner.sh install
```

By default, the launchd-managed **primary** supervisor keeps exactly one
hardened ephemeral runner available. An **opt-in, separately supervised
secondary slot** can add one more independent runner without replacing the
primary launchd service. Each runner accepts exactly one GitHub Actions job,
then deregisters and is removed; the slot supervisor mints a fresh short-lived
registration token through authenticated `gh` before replacement. The one-shot
`deploy-mac-x86-runner.sh up` entrypoint remains available for maintenance
and bootstrap validation.

### Optional second ephemeral runner (staged CI capacity rollout)

Only enable this after CI-security review and confirmed Docker Desktop capacity:
the Intel Mac presently has **8 logical CPUs / 16 GiB RAM**, and Docker Desktop
has been allocated **8 vCPUs / 12 GB RAM**. Each slot gets a distinct GitHub
runner name, Docker container, launchd agent, logfile and lock; both register
the existing `ssh-over-mcp-mac-x86` runner label and retain the **same**
non-root/zero-capability/no-new-privileges/no-Docker-socket security limits.

| Slot | GitHub name | Docker container | CPU | RAM |
|---|---|---|---:|---:|
| primary | `ssh-over-mcp-mac-x86` | `ssh-over-mcp-runner-mac-x86` | 2 vCPU (existing default) | 4 GiB |
| secondary | `ssh-over-mcp-mac-x86-b` | `ssh-over-mcp-runner-mac-x86-b` | 3 vCPU | 4 GiB |

**After merging the implementation PR**, and only after checking runner idle
status / resource pressure, enable the secondary slot with:

```bash
RUNNER_SUPERVISOR_SLOT=secondary bash scripts/supervise-mac-x86-runner.sh install
RUNNER_SUPERVISOR_SLOT=secondary bash scripts/supervise-mac-x86-runner.sh status
```

The original primary service is untouched by these commands. Its CPU allowance
remains 2 vCPU until a separately planned **idle-only** redeployment; the
optional 3+3 vCPU / 4+4 GiB allocation is a *later* tuning experiment, not a
requirement for enabling the secondary slot. Docker VM memory must leave room
for other containers and caches, and macOS host swap/memory pressure must stay
healthy. Do **not** run both slots at a combined allocation exceeding available
host/VM resources.

Rollback the secondary slot while idle using:

```bash
RUNNER_SUPERVISOR_SLOT=secondary bash scripts/supervise-mac-x86-runner.sh uninstall
```

Uninstall stops *supervision*, not an already running job: do not manually
kill a busy runner. An orphaned secondary runner can be retired only after its
job finishes and its GitHub registration is gone. The original primary slot
must remain available as fallback.

This change only adds safe runner **capacity**, not parallel test execution
within each runner. A later, separate PR will assess `pytest-xdist` and
source-bound hot paths; no 10-minute CI claim is made until both Python
versions pass their exact-head required checks in real Canary runs and the
end-to-end P95 is verified.

## What this runner validates

The Docker runner is intended to validate:

- Python 3.13 and 3.14;
- Python stdlib `sqlite3` against the image-provided `libsqlite3.so.0`;
- process creation with `fork()`;
- fd-based `execve()`;
- stdin/stdout/stderr supervision;
- POSIX signals and process groups;
- rlimits;
- the read-only cgroup-v2 capability probe;
- the normal project test suite.

It does **not** claim to validate writable cgroup containment.

Writable-cgroup evidence is provided by a separate dedicated Linux live
runner with a deliberately delegated subtree. The general Docker runner is
still not granted `--privileged`, `CAP_SYS_ADMIN`, host cgroup write access,
or the Docker daemon socket.

## Host requirements

The active runner host is:

- Intel/x86_64 macOS with Docker Desktop.

Recommended capacity:

- 2 CPU or more;
- 4 GiB RAM or more;
- outbound HTTPS access to GitHub;
- no inbound network service required.

Both the dedicated deploy entrypoint and the supervisor reject arm64/Apple
Silicon hosts. The lower-level `deploy-runner.sh` remains available for
maintenance, but project workflow scheduling requires the x86-specific label.

## Runner image

The image is defined in:

```text
ops/runner/Dockerfile
```

Properties:

- active base image: `ubuntu:26.04`;
- GitHub Actions Runner version pinned at build time;
- official runner archive SHA-256 verified before extraction;
- active runner architecture: Linux x64;
- job process runs as fixed non-root UID/GID 1001;
- normal GitHub runner self-update remains enabled by default.

The current pinned bootstrap runner is `2.337.0`. When changing the pinned
version, update the matching official SHA-256 values in
`scripts/deploy-runner.sh`.

The image explicitly installs the SQLite runtime package `libsqlite3-0`.
The Python toolcache installed by `actions/setup-python` includes the
`_sqlite3` extension but dynamically links to `libsqlite3.so.0`; keeping that
runtime library in the base image is therefore part of the authoritative CI
contract.

Ubuntu 26.04 uses uutils multi-call coreutils for paths such as `/usr/bin/cat`.
Anonymous fd-based exec does not preserve the applet dispatch name for that
binary. The runner image therefore also installs the coexisting
`gnu-coreutils` package; fd-exec integration fixtures prefer its `gnu*`
binaries while leaving the system's essential uutils installation untouched.

## Security properties of the container

The deployment script starts the container with:

```text
--cap-drop ALL
--security-opt no-new-privileges:true
--pids-limit 1024
--cpus 2
--memory 4g
--tmpfs /tmp:rw,exec,nosuid,nodev,size=512m
```

The explicit `exec` on `/tmp` is required because the Linux integration tests
create temporary executable fixtures under pytest's default temporary directory.
Docker Desktop may otherwise mount container tmpfs with `noexec`, which makes
valid `0755` test executables fail `X_OK` checks and `execve()` with
permission denied.

The deployment also does not mount:

- `/var/run/docker.sock`;
- host credentials;
- a writable host cgroup tree;
- the repository working tree.

The runner's job workspace lives only in the container filesystem. In
ephemeral mode the container is removed after its one assigned job.

**Primary PR and main-push CI runs on GitHub-hosted Ubuntu 26.04 x86 VMs**,
not on this self-hosted container. The two historical Python 3.13 / 3.14
required check names are preserved as separate **fail-closed aggregate
checks**. Each Python version runs its **complete test suite distributed
without omissions** across 3 independent hosted VM jobs (four exact
projection hot-node IDs, all other projection tests, all other project
tests). Each shard uses `pytest-xdist -n 2` and a 15-minute timeout.
Both required aggregate checks fail unless all six shard jobs succeed,
and both remain dependencies of the exact-main native Level-3 E2E.
All six VMs run complete Ruff/compile checks. Hosted runners use a
read-only token, `pull_request` (not `pull_request_target`), SHA-pinned
actions, full Git history, and a strictly non-root `setpriv` environment
with the hosted VM's extra supplementary groups cleared. This adapts the
test harness to the same strict identity policy without relaxing product
security assertions. Fork PRs do not receive secrets or write permissions.

The **explicit** `.github/workflows/self-hosted-security.yml` is retained
for manual security regressions dispatched from trusted `main`. Its
`inputs.ref` may still name a different commit: **the operator must verify
that target is trusted before dispatch**, since the workflow only checks
that the event ref is `main`, not that `inputs.ref` resolves to `main`.
It validates the full Python 3.13 / 3.14 suites on this hardened ephemeral
Docker runner with non-root identity, zero capabilities, no-new-privileges,
no Docker socket, and the read-only cgroup-v2 probe. The selected target must
be independently trusted; this manual workflow is **not** a PR CI or
substitute for native Level-3.

The merge-main **no-network Level-3 E2E** remains on the dedicated
non-admin macOS x86 QEMU orchestrator, testing the exact merged main SHA
inside a disposable Ubuntu 26.04 guest with no network access. The E2E
workflow is still fail-closed after **both hosted required checks** succeed
on main. A green hosted PR result proves its full test suites, **not**
hardened-container or native E2E acceptance; native E2E only runs on main.
See `docs/ci-hosted-primary.md` for the trust boundary and rollout gates.

## Deploy on the Intel Mac

For normal operation, authenticate `gh` for the repository and install the
supervisor:

```bash
gh auth status
bash scripts/supervise-mac-x86-runner.sh install
```

The supervisor:

1. requires macOS on `x86_64` and rejects Apple Silicon/M4;
2. verifies Docker Desktop and authenticated `gh` access;
3. builds the pinned Ubuntu 26.04 Linux x64 image only when it is missing
   (or when `RUNNER_SUPERVISOR_REBUILD=true`);
4. starts or adopts at most one runner container;
5. waits for that ephemeral runner to finish its single job and retire;
6. starts a replacement with a newly minted registration token;
7. is restarted by a per-user launchd service after login or process failure.

The supervisor deliberately rejects `RUNNER_TOKEN`. A repository runner
registration token is short-lived and one-time bootstrap material, so reusing
one across replacement containers would be incorrect. Authenticated `gh`
mints a fresh token on every call to the existing deploy entrypoint.

The launchd plist stores repository paths and a command search path only. It
does not store GitHub tokens or repository secrets.

For a one-shot runner without launchd supervision:

```bash
bash scripts/deploy-mac-x86-runner.sh up
```

That maintenance entrypoint may still accept an explicitly supplied one-time
`RUNNER_TOKEN`, or it can mint one with authenticated `gh`.

## Common commands

Install/start continuous launchd supervision:

```bash
bash scripts/supervise-mac-x86-runner.sh install
```

Show supervisor and current container status:

```bash
bash scripts/supervise-mac-x86-runner.sh status
```

Follow supervisor logs:

```bash
bash scripts/supervise-mac-x86-runner.sh logs
```

Stop launchd supervision and remove its plist:

```bash
bash scripts/supervise-mac-x86-runner.sh uninstall
```

Run the supervisor in the foreground:

```bash
bash scripts/supervise-mac-x86-runner.sh run
```

Run exactly one supervised lifecycle, useful for maintenance:

```bash
bash scripts/supervise-mac-x86-runner.sh once
```

The original one-shot deployment commands remain available:

```bash
bash scripts/deploy-mac-x86-runner.sh up
bash scripts/deploy-mac-x86-runner.sh status
bash scripts/deploy-mac-x86-runner.sh logs
bash scripts/deploy-mac-x86-runner.sh down
bash scripts/deploy-mac-x86-runner.sh build
```

## Ephemeral vs persistent

Ephemeral is the default:

```text
RUNNER_EPHEMERAL=true
Docker --rm
one GitHub Actions job
container exits
container is removed
runner is automatically deregistered by GitHub
```

This is the preferred validation mode.

The dedicated macOS x86 entrypoint rejects `--persistent`. Each runner instance
is one-job ephemeral by policy. The host-side supervisor is persistent, but the
GitHub Actions runners it creates are not: one container equals one registration
equals one job. The lower-level maintenance script still has a persistent mode,
but it is not part of the active project runner workflow.

## Linux host behavior

On Linux, the Ubuntu container shares the Linux host kernel. This provides
useful validation of fork, fd execution, rlimits, signals, and read-only
cgroup-v2 discovery.

The container intentionally has no privilege to mutate the host's cgroup tree.

Live writable-cgroup tests use the separate dedicated Linux runner described
below with a narrowly delegated subtree; they are not run in this generic
Docker container.

## macOS host behavior

On macOS, Docker Desktop executes the Ubuntu container inside its Linux VM.

This validates the Linux userspace/kernel behaviors exposed by that VM, which
is sufficient for the current test suite.

It does not prove how a production Linux host delegates writable cgroups and
is therefore not accepted as live containment evidence.

No `--privileged` workaround should be added to make the dedicated live gate
run inside Docker Desktop.

## Run validation

The normal CI workflow automatically queues on `main` pushes and trusted
same-repository pull-request updates. The supervisor keeps a disposable runner
available to accept the next queued job, so no operator action is required
between successful runner lifecycles.

For manual diagnostics, the repository's dedicated self-hosted validation
workflow can still be dispatched from trusted `main` against an explicitly
selected branch, tag, or commit SHA.

The job requires:

```yaml
runs-on: [self-hosted, linux, x64, ssh-over-mcp-mac-x86]
```

The preflight verifies:

- job UID is non-root;
- OS is Ubuntu 26.04;
- architecture is x86_64;
- effective Linux capabilities are zero;
- `NoNewPrivs=1`;
- Docker socket is not mounted;
- cgroup v2 is visible;
- `cpu`, `memory`, and `pids` controllers are visible.

Only then is the selected ref checked out.

The complete Python 3.13 and 3.14 test suites run in separate matrix jobs.
Each job uses its own hardened ephemeral runner and 20-minute timeout.
With only one available runner, the jobs queue and execute sequentially;
this does not combine their time budgets or skip either suite.

## Updating the runner bootstrap version

The Docker build verifies the official Actions Runner archive checksum.

For the repository-pinned version, the deploy script already contains the
official x64 and ARM64 hashes.

To test another version without first changing the repository:

```bash
RUNNER_VERSION='<version>' \
RUNNER_SHA256='<official-sha256-for-this-architecture>' \
bash scripts/deploy-runner.sh build
```

A non-default version without an explicit checksum is rejected.

The image leaves GitHub runner automatic updates enabled so a bootstrap image
does not silently become unusable as GitHub advances the minimum accepted
runner version. Rebuild the image regularly and update the pinned version and
hashes in source control.

## Dedicated live cgroup runner

Writable-cgroup evidence uses a separate disposable Linux fixture with the
custom label:

```yaml
runs-on: [self-hosted, linux, x64, ssh-over-mcp-cgroup-live]
```

The generic Docker runner remains unprivileged and is never upgraded for this
purpose. macOS Docker Desktop is not accepted as live cgroup evidence.

The live runner process itself is non-root and has zero effective Linux
capabilities. It has no Docker socket, production secrets, or host credentials.
Unlike the generic hardened Docker runner, it cannot set `NoNewPrivs=1`
because the job must invoke one narrowly authorized setuid-`sudo` handoff.
No other sudo command is permitted.

### Operator handoff contract

The workflow calls exactly one host-installed helper:

```text
/usr/local/libexec/ssh-over-mcp-live-cgroup-gate
```

Its reviewed source of truth is `ops/live-cgroup/ssh-over-mcp-live-cgroup-gate`.
The operator installs an exact copy outside the checkout at the path above. The
workflow pins and verifies that installed file's SHA-256 before privileged
execution.

The installed helper must be root-owned, mode `0555` or `0755`, and be the only
passwordless sudo command available to the live runner. It accepts **no
arguments**. The root-owned mode-`0600` file
`/etc/ssh-over-mcp/live-cgroup-gate.conf` contains exactly one setting:

```text
EXPECTED_COMMIT=<operator-approved 40-hex commit>
```

Workspace, cgroup paths, UID/GID values, and the root-owned Python environment
are fixed inside the reviewed helper rather than supplied by the GitHub job.
The helper rejects a dirty checkout or any HEAD which differs from the
operator-approved commit.

The helper owns all fixture configuration. Before repository test code starts,
it prepares the disposable users/groups, delegated cgroup-v2 root, direct-child
`host-agent-source`, and one stopped source process already running under the
configured host-agent identity in that source cgroup. The delegated root itself
must stay empty and the manager must remain outside it.

The helper then invokes the checked-out
`scripts/run-live-delegated-cgroup-probe.py` with only operator-controlled
fixture paths/IDs plus `SSH_OVER_MCP_LIVE_EXPECTED_COMMIT`. The launcher
first runs preflight and the real-backend primitive under the configured
non-root manager identity with zero capabilities, then retires the stopped
source fixture and runs the production-composition/resource/recursive-kill
proofs through the existing root bootstrap harness.

On every exit path the operator helper must kill/reap its disposable fixture
processes, remove only request scopes below its dedicated root, restore the
original controller state, and remove the disposable delegated subtree. It
must never call `cgroup.kill` on the delegated root itself.

The live workflow is manual-only from trusted `main`, requires a full exact
commit SHA, receives no repository secrets, and records only the exact commit,
kernel/machine, delegated paths, configured numeric identities, source PID, and
available controller names needed to audit the proof.

### Accepted live evidence

The current accepted merged-main live proof is:

```text
commit: 22e298fec42d92a963f093a6a073de622589dfc0
guest: Ubuntu 26.04 x86_64
kernel: 7.0.0-28-generic
manager phase: 2 passed
production/resource/recursive-kill phase: 4 passed
```

Post-run verification confirms `/sys/fs/cgroup/ssh-over-mcp-live` is absent and
the `gha-live` sudo policy contains exactly one command:
`/usr/local/libexec/ssh-over-mcp-live-cgroup-gate`.

## Disposable full-E2E orchestrator

Phase 7A full-product E2E does **not** run capability-bearing target code on a persistent Linux runner. ADR 0006 requires a disposable Linux VM for every Level-3 run, and ADR 0008 requires that the VM have no virtual network device.

The persistent host role is a dedicated native Intel-macOS account:

```text
account: gha-e2e-orchestrator
runner label: ssh-over-mcp-e2e-orchestrator
home: /Users/gha-e2e-orchestrator
```

The account is non-admin, non-root, and has **no sudo**. It must not be reused for ordinary validation jobs.

Host prerequisites:
- Intel macOS x86_64 with Hypervisor support;
- QEMU 11.1.2 (`qemu-system-x86_64` and `qemu-img`) installed by the operator;
- the pinned Ubuntu 26.04 base image available in the orchestrator's fixed cache and re-hashed before every run;
- trusted-main repository checkout only for orchestrator source and trusted runtime lock;
- no Docker socket requirement;
- no production SSH keys, Cloudflare credentials, Ledger secrets, or application credentials.

The E2E guest uses:

```text
https://cloud-images.ubuntu.com/releases/resolute/release-20260720/ubuntu-26.04-server-cloudimg-amd64.img
sha256:117816726abbdefc5ef3e38902e81a76f1c76c3610e709999d0885f9d5d9b477
```

The host creates a fresh qcow2 overlay and starts QEMU with HVF and `-nic none`. The guest receives no host filesystem share/mount, no QEMU monitor, no Docker socket, no production secret, and no target-controlled host socket/device. The target commit never becomes a host worktree.

The orchestrator uses a private temporary bare repository to create the exact Git bundle. It also prepares a Python 3.14 linux/amd64 wheelhouse from trusted-main `requirements/runtime.lock` using hash enforcement, then packages the bundle, lock, wheelhouse, exact expected commit, trusted-main guest harness, and trusted offline bootstrap into read-only payload/seed media. Guest bootstrap performs no apt/PyPI/GitHub access.

The ordinary `CI` workflow automatically calls the trusted reusable Live Local E2E workflow only after validation succeeds for a push to `main`; `workflow_dispatch` remains available for an exact manual `commit_sha` rerun. The called workflow inherits the caller push SHA/ref, so the trusted-main authority and tested merge SHA stay commit-bound.

Target identity is established by equality of:

```text
commit_sha
= bare target ref
= payload expected commit
= guest checkout HEAD
= guest EXPECTED_COMMIT
= serial result commit
```

The GitHub read token remains host-only and is not present in seed/payload media or guest command environments.

The guest returns evidence only over a host-bounded serial pipe capped at 2 MiB. Success requires the trusted-main guest harness to produce exactly one `SSH_OVER_MCP_E2E_RESULT=<commit>:PASS` record matching the requested commit and a clean QEMU exit.

A stale QEMU/provider process/artifact before a run is a hard failure requiring operator inspection. After every attempted run the orchestrator terminates only the QEMU PID it created, waits for exit, and removes the overlay, seed ISO, payload ISO, temporary bare repository/bundle, and wheelhouse. Failure to remove run-owned state fails the workflow.

In-guest cleanup is still tested independently. Destroying the whole disposable guest state is an additional containment boundary, not a substitute for product cleanup assertions.

### Required exact-head gates

Level-3 E2E is required for changes affecting SSH, authorization,
approvals/Ledger, credentials, host-agent, containment, filesystem mutation,
audit, workload identity, OS hardening, egress, SSH CA, secret-manager
integration, or the E2E fixture. Phase closure and release candidates always
require full E2E. Ordinary CI stays unprivileged on its separate self-hosted
Linux runner; it receives no Docker socket or privileged fixture access.

Dispatch only the already-trusted workflow from main:

```bash
gh workflow run live-local-e2e.yml --ref main -f commit_sha=<exact-40-hex-target>
```

Require exact PR-head ordinary CI, independent final review, guest E2E,
provider-state absence, and checkout cleanup before merge. Then repeat ordinary
CI and trusted-main E2E for the exact merge SHA before branch/worktree cleanup.
Do not cancel an active E2E merely to replace it. A stale provider marker is
never auto-deleted: an operator first verifies no active QEMU/orchestrator
process, inspects the recorded state, and only then performs recovery.

The trusted root gate and orchestrator come from already-merged main. Target
manager/probe/support/application code runs only inside the guest after the
fixed non-root handoff. A target PR never supplies the authority certifying it.

### Cancelled Live Local E2E recovery

Do not manually delete `active-run.json` and do not add automatic stale cleanup.
Use the manual `Live Local E2E Provider Recovery` workflow on trusted `main`.
Dispatch once with the exact stale target and PID `0` to inspect without mutation;
review the reported owner PID and temp-state inventory, then dispatch again with
the exact PID only if no temp directories remain. Recovery refuses a live owner,
any runner-owned QEMU, changed marker identity, ownership/mode/schema mismatch,
or remaining E2E temp state. It only unlinks the fixed runner-owned marker and
never uses sudo, kills processes or recursively deletes unknown state.

The recovery marker reader classifies the no-follow metadata before a data open,
then uses no-follow/nonblocking open and verifies the opened device/inode against
that observation before reading. A FIFO present initially or substituted at open
is refused without waiting for a writer; an inode replacement is refused even if
its JSON is otherwise valid. These checks do not change marker-clear conditions
or authorize cleanup of staging directories. They do not establish an atomic
snapshot or protect against a compromised runner account changing file contents
in place; recovery still requires quiescent operator state and fresh revalidation.
