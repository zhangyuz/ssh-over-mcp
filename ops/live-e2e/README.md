# Phase 7A live E2E assets

These files are security-sensitive reference assets for the Phase 7A disposable Linux E2E.

The outer E2E boundary is ADR 0006: capability-bearing target code runs only inside a fresh disposable Linux guest. The persistent Mac orchestrator does not install this launcher on the host and never executes the target checkout.

## Host-agent capability launcher

Reviewed source:

```text
ops/live-e2e/ssh-over-mcp-host-agent-launcher.py
```

Inside the disposable guest, the E2E gate installs the exact target commit's launcher at:

```text
/usr/local/libexec/ssh-over-mcp-host-agent-launcher.py
```

The installed copy must be a root-owned regular non-symlink file and must not be writable by the SSH account.

Production managed hosts use the same launcher contract, but the installed production copy is operator-managed outside the writable application checkout rather than installed from an unmerged target commit.
## Exact ForceCommand sudo target

The dedicated SSH account is:

```text
ssh-over-mcp-e2e-host
```

Its only passwordless sudo command is the exact no-argument command:

```text
/usr/bin/python3 -I -S /usr/local/libexec/ssh-over-mcp-host-agent-launcher.py
```

Do not authorize:
- a shell;
- a wildcard command;
- launcher arguments;
- `SETENV`;
- caller-selected Python/module paths;
- another passwordless sudo target.

The sudoers policy must preserve only the sshd-owned invocation context required for validation, for example `Defaults:ssh-over-mcp-e2e-host env_keep += "SSH_ORIGINAL_COMMAND SSH_TTY"`, while keeping `SETENV` disabled. `SSH_ORIGINAL_COMMAND` must equal `mcp-v1`; any non-empty `SSH_TTY` is rejected. `SUDO_USER`, `SUDO_UID`, and `SUDO_GID` are supplied by sudo itself. Arbitrary user-provided environment is not preserved into application execution.
## Privilege transition

The launcher starts as root only for the bounded credential/capability transition.

Before importing any `ssh_over_mcp` application module it must:
1. reject all argv;
2. validate the fixed sshd/sudo context;
3. replace the environment with fixed safe values;
4. retain capabilities across the UID change temporarily;
5. set supplementary groups exactly to manager-client GID 3299;
6. set real/effective/saved GID to 3202;
7. set real/effective/saved UID to 2202;
8. set effective/permitted capabilities to only `CAP_SETGID|CAP_SETUID`;
9. require inheritable and ambient capability sets to be zero;
10. disable keepcaps and read back the exact final state.

Only after that verification may it add the fixed guest application paths and import `ssh_over_mcp.host_agent.cli`.

The launcher does not use subprocesses or a shell.

## Installation boundary

Phase 7A repository tests do not install users or sudoers on the persistent Mac host.

The disposable guest gate owns guest-local users, sudo policy, launcher installation, sshd state, delegated cgroups, and teardown. Whole-guest destruction is mandatory after the run.

Production installation of the launcher/sudo rule remains an operator action and is not performed by repository tests.

## Persistent macOS E2E orchestrator

Full Level-3 E2E uses a dedicated native Intel-macOS account named `gha-e2e-orchestrator` with the self-hosted runner label `ssh-over-mcp-e2e-orchestrator`.

The account is non-admin, non-root, has **no sudo**, and has an isolated home at `/Users/gha-e2e-orchestrator`. It is separate from the ordinary Docker-based validation runner.

The trusted host provider is QEMU 11.1.2 using Hypervisor.framework (`hvf`) on x86_64. ADR 0008 rejects Lima/VZ for Level-3 E2E because its user-mode network remains reachable from guest root even when mounts and product port forwards are disabled. The guest image remains the dated Ubuntu 26.04 server cloud image:

```text
https://cloud-images.ubuntu.com/releases/resolute/release-20260720/ubuntu-26.04-server-cloudimg-amd64.img
sha256:117816726abbdefc5ef3e38902e81a76f1c76c3610e709999d0885f9d5d9b477
```

The QEMU guest is created with `-nic none`, no host filesystem share/mount, no monitor, no Docker socket, and no target-controlled host socket/device. The target commit never becomes a host worktree. The trusted-main orchestrator fetches the exact target into a private temporary bare Git repository, prepares a hash-verified Python 3.14 linux/amd64 runtime wheelhouse from trusted-main `requirements/runtime.lock`, separately prepares the hash-locked `pip==26.2.1` bootstrap wheel from `requirements/e2e-bootstrap.lock`, and packages the bundle/wheelhouses/locks/expected-commit/trusted-main guest harness/trusted bootstrap into read-only payload/seed media.

The host-only read token is used only by Git/askpass while creating the bundle. It is not copied into seed/payload media and is absent from guest command environments. The clean Ubuntu image intentionally does not need `python3-pip` or `python3-venv`: guest bootstrap creates the environment with `python3 -m venv --without-pip`, starts pip from the separately hash-pinned wheel, installs that pip wheel against `e2e-bootstrap.lock`, then installs runtime dependencies against `runtime.lock`, all with `--no-index` and hash enforcement. The guest returns only a trusted-harness commit-bound result over a host-bounded 2 MiB serial stream.

The payload ISO root intentionally contains only short fixed filenames (`bootstrap.sh` and `payload.tar`). The target bundle, runtime lock, full wheel filenames, and trusted harness live inside `payload.tar`. The bootstrap verifies the archive SHA-256, safely extracts only regular files/directories, then applies the existing per-file manifest and `pip --require-hashes` checks. This avoids Linux ISO9660/Joliet filename-view differences truncating wheel filenames while preserving both archive-level and file-level integrity checks.

After extraction, the trusted guest gate and its fixed stdlib `ledger_guest_preflight.py` are copied into a dedicated guest-local tmpfs at `/mnt/som-trusted-harness`. That tmpfs is remounted `ro,nosuid,nodev,noexec` before the gate is imported or executed. Target manager/probe/support code still comes from the exact target workspace, but the root lifecycle gate executes only from this independent read-only trust root; the initial host-agent capability set excludes `CAP_SYS_ADMIN`. ADR 0005/0006/0008 nevertheless accept guest-root-equivalent target authority: the read-only tmpfs separates the supplied lifecycle source and catches ordinary mutation, but it is not a tamperproof boundary against malicious guest-root target code. Persistent-host isolation comes from the disposable VM with no NIC, host share, or host secret.

## Exact target identity

The ordinary `CI` workflow automatically calls this trusted reusable workflow only after validation succeeds for a push to `main`; `workflow_dispatch` remains available for an exact manual `commit_sha` rerun. Reusable-workflow calls inherit the caller push SHA/ref, keeping trusted-main workflow authority and the tested merge SHA commit-bound.

The tested commit is authoritative only when all of these are equal:

```text
workflow commit_sha
= bare Git target ref object ID
= guest checkout HEAD
= root-owned guest EXPECTED_COMMIT
```

A mismatch fails closed before the guest gate runs.

## Guest lifecycle

Before each run the orchestrator rejects stale QEMU/provider state rather than silently reusing it. Every run gets a fresh disposable qcow2 overlay plus fresh seed/payload media. The overlay virtual size is capped at 8 GiB; orchestration requires at least 16 GiB host free space, caps the target bundle at 256 MiB, and caps captured serial output at 2 MiB.

After every attempted run the orchestrator terminates only the QEMU process it created (if still alive), waits for exit, and removes the overlay, seed ISO, payload ISO, temporary bare repository/bundle, and wheelhouse. Failure to remove run-owned state fails the workflow.

In-guest process/socket/cgroup/key/data cleanup remains part of the test. QEMU process termination plus deletion of the **whole disposable guest state** is the final outer containment boundary.


## Lifecycle integrity and stale-state checks

Before fetching a target, trusted orchestration rejects either an existing
provider marker (including a dangling symlink) or any existing
`qemu-system-x86_64` process owned by the dedicated orchestrator account.
Process inventory uses a bounded `ps` query for executable names only; failure
to obtain inventory fails closed. It never deletes a marker or kills an unknown
process. Operator recovery still requires verifying no active provider.

Inside the fresh guest, the gate snapshots the exact checkout launcher digest
before copying it, verifies installed owner/type/mode, and compares installed
bytes to that snapshot before writing the sudo authorization. Content mismatch
fails before the launcher can be invoked. This proves installation integrity;
it does not assert that unreviewed target launcher code is safe.

The trusted-main gate independently owns bootstrap, fixed fixture setup,
commit binding, and cleanup. Product assertions live in the reviewed exact
target probe/support and the gate checks its exit status. Acceptance combines
those target assertions, ordinary contracts, and independent review; a target
probe that simply exits zero is not product coverage. The fixed full-matrix
probe contract and review must detect omitted fixtures. No claim of hardware
attestation or tamperproof product assertions against guest root is made.

## Fixed guest no-core guard

After verifying root, the exact clean target workspace, the independent read-only trusted harness and absence of fixture state, the gate establishes the guest-only no-core policy before creating fixture keys or executing any target code. It lowers the controller's soft and hard `RLIMIT_CORE` to `(0, 0)`, writes only `core\n` to the fixed `/proc/sys/kernel/core_pattern`, and verifies both effective settings. A pipe collector, unexpected readback, unavailable setting or nonzero limit fails closed. This operation has no caller-selected path/value and never runs on the persistent Mac or production hosts.

The stdlib preflight leaf is packaged from the checked-out trusted-main authority, hash-verified with the payload, installed root-owned `0444` in the same read-only guest tmpfs and loaded by its fixed canonical path. Each direct manager/probe spawn and the trusted sshd spawn verifies the parent guard and rechecks it in the fork child before exec; non-root descendants inherit hard zero and cannot raise it without privilege. Future systemd services need separate effective `LimitCORE=0:0` verification because PID 1 does not inherit controller limits.

This is guest authority preparation under ADR 0009. Exact-head legacy E2E still uses the previously merged authority; the exact merge-main run is the first live exercise of the new guard. It does not certify installed Ledger/systemd composition or native canaries. The existing disposable-VM trust model accepts guest-root-equivalent target code: this guard is not protection against malicious guest-root code changing kernel policy. VM destruction remains mandatory.

## Dormant native package-data reader

Phase 7B1 native prerequisite N1a adds `native_archive.py` as a stdlib-only,
metadata-only reader for already-decompressed package data tar streams. It does
not authenticate a package, parse a `.deb` envelope, resolve dependencies,
materialize files, execute package content, or participate in any live workflow.
Those authorities remain blocked on later N1/N2/N3/N4 slices.

The reader records only immutable path/type/mode/owner/size/digest/link metadata.
It rejects noncanonical or escaping paths, duplicate entries, hardlinks, special
files, set-ID bits, extended metadata, escaping/cyclic/excessive symlink chains,
and entries exceeding the reviewed count/path/file/expanded-data bounds. Its
fixed public error does not include archive-controlled content.

## Manual orphan-provider marker recovery

Cancellation can leave `active-run.json` when the orchestrator is stopped before
its `finally` cleanup completes. Normal E2E stays fail-closed and never removes
stale provider state automatically.

`Live Local E2E Provider Recovery` is manual-only on trusted `main`, runs as the
same non-admin orchestrator account and shares the `live-local-e2e` concurrency
group. First use the exact stale target with owner PID `0`; this is inspect-only.
It reports the marker PID and any fixed-prefix E2E temp directories. Recovery
requires a second dispatch with that exact PID and is allowed only when the PID
is dead, no runner-owned QEMU exists, the fixed marker identity/schema/mode are
unchanged, and **no E2E temp directories remain**. The workflow only unlinks the
fixed marker; it has no sudo, process-kill, recursive-delete, arbitrary-path or
provider-restart authority. Any remaining temp state requires renewed review.

Temp diagnostics read only the fixed `payload-content/expected_commit` binding
relative to pinned directory descriptors. Both components prohibit symlink
following and require runner ownership; the leaf must be regular, exactly 41
bytes, and canonical lowercase 40-hex plus newline. The leaf is opened
only after no-follow metadata classification, then its descriptor identity and
type are revalidated. Nonblocking opening also prevents a raced FIFO from
waiting for a writer. Missing
metadata reports an unbound directory; malformed or unsafe metadata refuses
inspection. This read-only binding is not cleanup authorization.
