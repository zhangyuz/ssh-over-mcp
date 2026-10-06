# ADR 0009: Harden the Security Ledger through a separate systemd service profile

- Status: Proposed; written design awaits approval
- Date: 2026-10-05
- Design: [Phase 7B1](../superpowers/specs/2026-10-05-phase-7b1-ledger-systemd-design.md)

## Context

Phase 7A proved real SSH, approval/audit and containment behavior in a disposable
no-network guest. Phase 7B calls for OS and egress hardening. The Ledger already
has a foreground entrypoint, strict Linux identity/group checks, separate
peer-authenticated Unix endpoints, and service-owned durable SQLite/key files.
It has no reason to create network sockets or acquire capabilities.

A generic service sandbox can break these contracts: DynamicUser changes peer
identity, one managed directory group cannot describe both endpoint authorities,
and automatic runtime-directory removal can hide replaced or stale endpoints.
The source-only guest also must not execute a target package build or application
setup as root merely to make a reference unit run.

## Proposed decision

Start with one reference systemd profile for the Ledger. Preserve its protocol,
authorization, audit, storage and peer-identity behavior. Use a static non-root
identity with exact supplementary groups, no capabilities or privilege gain,
read-only runtime/key, narrow database/socket write exceptions, and effective
AF_UNIX-only/private-network restrictions. Verify the real service and denial
attempts rather than treating a systemd security score as acceptance evidence.

Provisioning and unknown-state recovery remain explicit operator responsibilities.
The service neither removes unknown endpoints nor automatically restarts after
failure. It exposes no MCP approval mutation, generic privileged helper, or new
diagnostic protocol operation.

The initial reference requires zero hard/soft core limits and an effective
non-pipe kernel core pattern before service start. Pipe collectors require
separate review because core limits alone do not prevent memory processing or
temporary dump retention. Crash/denial canaries must verify this boundary; no
generic production-host core-policy mutator is introduced.

Any root/systemd guest fixture extension is a separate authority prerequisite
merged and verified on main before the target profile/probe is certified. Root
setup accepts only a canonical already-trusted profile, fixed paths, identities
and lifecycle operations; target application imports happen after identity drop.
The existing five-fixture probe and its final STOP_MANAGER control remain intact.
ADR 0008's no-network outer VM boundary and cleanup requirements remain unchanged.

This proposed ADR becomes accepted only after written-design approval. It does
not authorize implementation, deployment, or a weakened fallback by itself.

## Consequences

Positive: confines an existing local security service without adding application
authority, and supplies a small deployment model that later profiles can learn
from without copying incompatible identity or cgroup assumptions.

Cost: static provisioning and canonical trusted-profile duplication require
careful maintenance. The production installed-package entrypoint and the
source-only guest adapter need explicit separate evidence. Missing mandatory
kernel/systemd support is a deployment failure, not a compatibility fallback.

Deferred: other service profiles, AppArmor/SELinux, general egress, SSH CA,
secret-manager integration, key rotation, and reusable approvals.

## Security impact

The profile reduces filesystem, kernel and network authority of the Ledger.
It does not make a compromised Ledger trustworthy or protect its database from
host root. Exact peer checks, fail-closed required audit, one-attempt consumption,
secret-retention constraints and uncertainty semantics remain authoritative.
No persistent-host privilege or network/device channel is added to Level-3 E2E.
