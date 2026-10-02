# ADR 0007: ForceCommand host-agent capability handoff uses a fixed launcher

- Status: Accepted
- Date: 2026-10-02

## Context

ADR 0005 requires the production host agent to remain non-root while holding only the two Linux capabilities needed for the irreversible child workload identity transition:

- `CAP_SETUID`;
- `CAP_SETGID`.

The child later clears those capabilities and verifies the final workload identity before native exec.

Existing live workload-identity evidence proves the transition when a trusted bootstrap harness constructs the host-agent process with that exact capability state. Existing ForceCommand evidence proves the host-agent execution path itself. A complete real-sshd E2E exposes the missing deployment bridge between those two proofs: OpenSSH normally starts ForceCommand under the dedicated SSH account and does not directly grant the required process capabilities.

The project needs a production-representative handoff without:
- making the SSH account root;
- granting generic sudo;
- granting `CAP_SYS_ADMIN` or `CAP_KILL`;
- giving the ordinary CI runner privilege;
- running repository/application code while still root.

Three approaches were considered:

1. fixed root-owned no-argument capability launcher authorized by one exact sudo rule;
2. a native executable carrying file capabilities;
3. a long-running capability-bearing host-agent service reached over another authenticated IPC boundary.

## Decision

Use one fixed operator-installed capability launcher.

OpenSSH ForceCommand invokes exactly one fixed no-argument sudo target. The installed launcher is root-owned, non-symlink, and not writable by the SSH account. The sudo policy authorizes only that exact command with no arguments.

The launcher begins as root only for a bounded credential/capability transition. Before any `ssh_over_mcp` application module is imported or executed, it must:

1. reject every command-line argument;
2. validate the ForceCommand invocation context, including exact `SSH_ORIGINAL_COMMAND=mcp-v1` and no PTY;
3. ignore/sanitize caller-controlled Python/import environment;
4. establish the exact host-agent supplementary-group set, including only the configured manager-client group;
5. set real/effective/saved GID and UID to the configured non-root host-agent identity;
6. retain only `CAP_SETUID` and `CAP_SETGID` in effective/permitted sets;
7. require zero inheritable and ambient capabilities;
8. verify absence of `CAP_KILL`, `CAP_SYS_ADMIN`, and every other capability;
9. read back and verify the complete resulting UID/GID/group/capability state.

Only after that state is verified may the process enter the host-agent application code.

The launcher source is reviewed in the repository, but the launcher used by the trusted managed-host/E2E fixture is an operator-installed copy outside the checkout. The dedicated live workflow verifies the installed artifact's owner, mode, fixed path, and SHA-256 before use.

The launcher does not accept caller-selected UID/GID, group, executable, module path, policy path, socket path, or capability set.

The existing host-agent protocol, containment-manager protocol, start barrier, child workload identity transition, and workload zero-capability/`no_new_privs` requirements remain unchanged.

## Consequences

Positive:
- real sshd → ForceCommand execution can reach the already-designed host-agent capability state;
- the SSH account remains non-root;
- the host agent still receives only the two identity-changing capabilities required by ADR 0005;
- repository/application code is not trusted while the process has root identity;
- no generic privileged helper or arbitrary sudo surface is introduced;
- the complete local E2E can prove the real deployment handoff rather than a bootstrap-only approximation.

Cost:
- the launcher becomes a small security-critical operator-installed component;
- deployment must install and integrity-check the launcher and its exact sudo rule;
- the process briefly begins as root before application import;
- launcher identity/capability transition logic needs dedicated live Linux testing.

Rejected alternatives:
- file capabilities reduce the sudo handoff but add persistent capability-bearing executable deployment semantics and a separate native build/release surface;
- a long-running service could remove per-request sudo but adds a new privileged IPC/service lifecycle and is too large for the Phase 7A foundation.

## Security impact

The launcher is trusted infrastructure. Its root phase must be minimal and must not import repository/application code.

The SSH account must not be able to:
- alter the launcher;
- pass launcher arguments;
- choose identities or capabilities;
- invoke other passwordless sudo commands;
- alter the root-owned launcher configuration;
- influence Python/module search paths used before the privilege drop.

The E2E/managed-host preflight must fail closed if:
- launcher owner/mode/path/hash is wrong;
- the sudo policy contains any additional authorized command;
- the ForceCommand context is not exact;
- the post-transition host-agent identity differs from the configured UID/GID/groups;
- effective/permitted capabilities differ from exactly `CAP_SETUID|CAP_SETGID`;
- inheritable or ambient capabilities are nonzero;
- any `ssh_over_mcp` application module is observed imported before the transition is complete.

This decision does not weaken the workload boundary. The workload still executes only after containment attachment and the existing irreversible child transition to zero capabilities plus `no_new_privs=1`.
