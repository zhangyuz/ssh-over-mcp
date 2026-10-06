# ADR 0009: Harden the Security Ledger through a separate systemd service profile

- Status: Accepted 2026-10-06; implementation plan pending review
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

## Decision

Start with one reference systemd profile for the Ledger. Preserve its protocol,
authorization, audit, storage and peer-identity behavior. Use a static non-root
identity with exact supplementary groups, no capabilities or privilege gain,
read-only runtime/key, narrow database/socket write exceptions, and effective
AF_UNIX-only/private-network restrictions. Verify the real service and denial
attempts rather than treating a systemd security score as acceptance evidence.

Provisioning and unknown-state recovery remain explicit operator responsibilities.
The service neither removes unknown endpoints nor automatically restarts after
failure. It exposes no MCP approval mutation, generic privileged helper, or new
diagnostic protocol operation. Pairwise-distinct primary/execution/admin GIDs
and no client cross-membership preserve DAC separation independently of peer
authentication. New-key provisioning retains CSPRNG, exclusive/no-follow create,
exact secure metadata, complete writes and file/parent fsync without exposing
key bytes or repairing unknown existing state.

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

Final acceptance must exercise the actual installed non-editable artifact with
the production ExecStart inside the canonical systemd profile. Build/install
runs as a separate non-root identity; trusted setup quiesces writers, attests
and seals the fixed runtime without executing target artifacts as root. Source
adapter and unsandboxed-wheel proofs alone cannot close the deployment slice.
After forced-stop safety, fixed operator/test recovery must verify no owner and
original run-owned endpoint identity before bounded removal, then prove restart
with unchanged key and preserved audit/approval state. This is not automatic
production recovery or target-selected privileged cleanup.

The user approved this written design on 2026-10-06. Implementation follows
the separately reviewed small-slice plan; this decision does not authorize
production deployment or a weakened fallback.

## Consequences

Positive: confines an existing local security service without adding application
authority, and supplies a small deployment model that later profiles can learn
from without copying incompatible identity or cgroup assumptions.

Cost: static provisioning and canonical trusted-profile duplication require
careful maintenance. Installed-runtime sealing and the exact package/systemd
composition need live evidence; source-only diagnostics cannot replace it.
Missing mandatory
kernel/systemd support is a deployment failure, not a compatibility fallback.

Deferred: other service profiles, AppArmor/SELinux, general egress, SSH CA,
secret-manager integration, key rotation, and reusable approvals.

## Security impact

The profile reduces filesystem, kernel and network authority of the Ledger.
It does not make a compromised Ledger trustworthy or protect its database from
host root. Exact peer checks, fail-closed required audit, one-attempt consumption,
secret-retention constraints and uncertainty semantics remain authoritative.
No persistent-host privilege or network/device channel is added to Level-3 E2E.
