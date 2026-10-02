# ADR 0006: Full local E2E uses a dedicated operator-owned privilege fixture

- Status: Accepted
- Date: 2026-10-02

## Context

Phase 6 closed the private reference deployment and established strong isolated evidence for the MCP control plane, Security Ledger, approvals/audit, SSH host agent, containment manager, workload identity, container networking, and Cloudflare reference boundary.

Phase 7 adds stronger host and credential hardening. Before changing those boundaries further, the project needs a complete product-level E2E safety net.

A complete E2E must exercise real Linux behavior:
- OpenSSH sshd;
- ForceCommand;
- authenticated containment-manager IPC;
- delegated cgroup-v2;
- workload identity/capability transition;
- real filesystem and native execution.

The ordinary CI runner is intentionally hardened:
- non-root;
- no Docker socket;
- no writable delegated cgroup authority;
- no generic sudo;
- no host PID namespace.

Weakening that runner to make E2E convenient would expand the trusted computing base and allow checked-out pull-request code to obtain authority that normal validation does not need.

Three designs were considered:

1. run full E2E on the ordinary CI runner by adding privilege;
2. run an all-in-one privileged container that simulates the host boundaries;
3. retain the ordinary runner security posture and use a dedicated operator-owned fixture helper outside the checkout.

## Decision

Use a dedicated operator-owned full-E2E fixture.

The ordinary PR-validation runner remains unprivileged.

High-privilege E2E setup is owned outside the repository checkout:
- root-owned fixed helper;
- root-owned helper configuration;
- narrowly scoped sudo permission for that helper only;
- helper integrity/hash verification;
- exact trusted 40-hex commit input;
- disposable fixture identities, sshd state, cgroups, sockets, keys, and test data.

The checked-out repository may invoke the fixed fixture operation but does not receive a generic root shell or arbitrary helper arguments.

The E2E path must use the real product security boundaries:

```text
MCP HTTP
→ central policy / Security Ledger
→ pinned-host-key SSH
→ real sshd
→ ForceCommand
→ host agent
→ authenticated containment manager
→ delegated cgroup-v2
→ one-way workload identity drop
→ native executable / typed filesystem operation
```

Full E2E becomes required merge evidence for changes touching SSH, authorization, approvals/Ledger, credentials, host-agent, containment, filesystem mutation, audit, workload identity, host sandboxing, egress, SSH CA, secret-manager integration, or the E2E fixture itself.

Phase closure and release-candidate work always require full E2E.

Docs-only or otherwise unrelated changes continue to use the ordinary validation gate unless they alter a security boundary.

Cleanup is part of the E2E result. Unknown stale privileged fixture state causes fail-closed startup. Passing business assertions with failed cleanup is a failed E2E run.

## Consequences

Positive:
- later Phase 7 hardening receives a real integration safety net;
- ordinary CI does not gain Docker/root/cgroup escape surfaces;
- real kernel/service behavior is tested rather than simulated;
- E2E evidence can be required without trusting arbitrary PR code with generic root;
- fixture lifecycle and cleanup become explicit security contracts.

Cost:
- full E2E requires a dedicated Linux x86 fixture/operator helper;
- the E2E gate is more expensive than ordinary CI;
- helper/config maintenance becomes security-sensitive infrastructure;
- trusted-commit/operator workflow is more deliberate than automatic pull-request execution.

Deferred:
- live Cloudflare account E2E remains a separate explicitly approved external-state workflow;
- additional Phase 7 OS hardening, SSH CA, secret-manager, and fuzz/property testing build on this foundation.

## Security impact

This decision preserves the least-privilege posture of ordinary CI while allowing authoritative product-level validation of privileged host behavior.

The operator helper and its root-owned configuration are trusted infrastructure and MUST be reviewed accordingly.

Checked-out code MUST NOT be able to:
- choose arbitrary root helper arguments;
- choose arbitrary UIDs/GIDs/cgroup roots;
- install or modify the sudo rule;
- rewrite the helper or helper config;
- obtain a Docker socket or generic root shell through the E2E workflow.

The E2E fixture MUST verify teardown and reject stale privileged state rather than silently repairing or reusing it.
