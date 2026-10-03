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

The trusted host provider is Lima 2.2.0 using Virtualization.framework (`vz`) on x86_64. The guest image is the dated Ubuntu 26.04 server cloud image:

```text
https://cloud-images.ubuntu.com/releases/resolute/release-20260720/ubuntu-26.04-server-cloudimg-amd64.img
sha256:117816726abbdefc5ef3e38902e81a76f1c76c3610e709999d0885f9d5d9b477
```

The guest is created with no host filesystem mounts, no product port forwards, containerd disabled, `propagateProxyEnv: false`, and the Lima host resolver disabled. The target commit never becomes a host worktree. The trusted-main orchestrator fetches the exact target into a private temporary bare Git repository and transfers only a Git bundle into the disposable guest.

The host-only read token is used only by Git/askpass while creating the bundle. It is not copied into the guest and is absent from guest command environments.

## Exact target identity

The manual trusted-main workflow accepts exactly one `commit_sha`. The GitHub workflow run `headSha` identifies the trusted-main workflow/orchestrator revision; it is **not** the tested target identity.

The tested commit is authoritative only when all of these are equal:

```text
workflow commit_sha
= bare Git target ref object ID
= guest checkout HEAD
= root-owned guest EXPECTED_COMMIT
```

A mismatch fails closed before the guest gate runs.

## Guest lifecycle

The fixed Lima instance name is `ssh-over-mcp-e2e`. If it already exists before a run, orchestration stops for operator inspection and does not silently reuse or delete it.

After every attempted run, the orchestrator executes the equivalent of:

```text
limactl delete --force ssh-over-mcp-e2e
```

and verifies the instance is absent. In-guest process/socket/cgroup/key/data cleanup remains part of the test, but destruction of the **whole disposable guest** is the final outer containment boundary.
