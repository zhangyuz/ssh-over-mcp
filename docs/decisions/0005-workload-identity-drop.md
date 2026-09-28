# ADR 0005: Forked child performs the one-way workload identity drop

- Status: Accepted
- Date: 2026-09-28

## Context

ADR 0004 separates containment-management authority from the untrusted workload privilege domain.

The service identity contract defines three distinct identities:

- containment manager;
- host agent;
- workload.

The host-agent and workload identities are non-root and have distinct UIDs. The workload must not retain the manager-client supplementary group.

The current execution child is forked by the host agent, waits behind the containment start barrier, and then enters the native fd-based exec path. Without an explicit credential transition, it would still execute under the host-agent identity.

Because the host-agent UID and workload UID are intentionally different, a non-root host agent needs narrow Linux credential-changing authority in order to set the child's real/effective/saved UID/GID to the workload identity.

Three designs were considered:

1. the forked host-agent child performs an irreversible identity drop;
2. a new privileged identity-switch helper performs the drop;
3. the containment manager also becomes the workload spawner.

## Decision

Use the forked child to perform the workload identity transition.

The production host-agent remains non-root and is granted only the identity-changing capabilities required for this operation:

- `CAP_SETUID`;
- `CAP_SETGID`.

No `CAP_SYS_ADMIN`, root host-agent identity, or generic privileged execution helper is introduced by this decision.

After the existing containment manager confirms request-scope attachment and the parent releases the start barrier, the child:

1. completes trusted stdio/FD/rlimit setup;
2. sets `no_new_privs=1`;
3. clears ambient capabilities;
4. removes supplementary groups;
5. sets real/effective/saved GID to the workload GID;
6. sets real/effective/saved UID to the workload UID;
7. clears effective, permitted, and inheritable capability sets;
8. reads back and verifies the complete identity/capability state;
9. only then enters the existing pinned native exec path.

The child must fail closed before exec if the workload target is root, includes supplementary groups, reuses the current host-agent UID, or if any transition or verification step fails.

The containment manager remains limited to typed containment operations and does not spawn or execute workloads.

The child does not require its capability bounding set to be empty. Instead, the execution boundary requires:

- `no_new_privs=1`;
- zero effective/permitted/inheritable capabilities;
- zero ambient capabilities.

This avoids adding `CAP_SETPCAP` merely to modify the bounding set.

Production deployment should constrain the host-agent capability bounding set to the minimum required authority.

## Consequences

Positive:

- the workload no longer shares the host-agent OS identity;
- saved UID/GID cannot retain the host-agent identity;
- the workload loses the manager-client supplementary group;
- setuid/setgid mode bits and file capabilities cannot grant new privilege through normal structured exec because `no_new_privs` is set;
- the containment manager's narrow API remains unchanged.

Cost:

- the host-agent service holds `CAP_SETUID` and `CAP_SETGID`;
- the child transition code is security-sensitive Linux-specific code;
- production deployment must grant and constrain those capabilities correctly;
- a dedicated live Linux capability-transition validation is required.

Deferred:

- a separate identity-switch helper may be reconsidered if reducing host-agent capability possession becomes worth the additional IPC/service complexity;
- exact startup verification of the host-agent capability bounding set may be added as a later hardening increment.

## Security impact

This closes the privilege-domain gap between the authenticated host-agent identity and the executed workload identity.

A successful transition requires exact read-back verification of:

- real/effective/saved UID;
- real/effective/saved GID;
- supplementary groups;
- `no_new_privs`;
- effective/permitted/inheritable capabilities;
- ambient capabilities.

The workload must not execute if any of these checks fail.

ForceCommand execution remains disabled until the later containment-manager-client and live escape-resistance phases are complete.
