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
