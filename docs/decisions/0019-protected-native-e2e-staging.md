# ADR 0019: Protected native E2E staging namespace

- Status: written design approved 2026-10-13; first implementation plan review pending, no activation authority
- Date: 2026-10-13 (America/Toronto)
- Baseline: main b39e08aa31355e8c0abc441a501e5546279ecb46

## Context

The historical stale-provider incident is resolved: PR #240 recovery and PR #241
closure reached exact-main hosted/native/cleanup PASS. Future orchestration
still creates a Python-selected temporary workspace; marker-only recovery uses
Python temp selection while incident preflight binds native getconf. UID 502
observed different parents. The installed /tmp cleaner explains a concrete
retention hazard, without proving the historical deletion cause.

A reliable staging lifecycle is a prerequisite to returning to Phase 7B1
native-toolchain and Ledger sandbox work. Recovery must continue to fail closed
on unknown state; changing placement cannot hide older roots.

## Approved design decision

For future runs only, use the literal private staging namespace:
`/Users/gha-e2e-orchestrator/Library/Application Support/ssh-over-mcp-e2e/staging-v1`.

Keep the current image cache and active-run marker path/schema unchanged.
Use strict mtime_ns/ctime_ns drift refusal on all pinned edges, including shared
/private/tmp; even unrelated foreign churn blocks the current inspection. This
explicit availability cost never permits timestamp masking, foreign deletion
or automatic namespace-check retries.
A shared trusted internal namespace module validates/pins fixed ancestors,
creates only fixed missing owned descendants and fresh exclusive run children,
and supplies bounded protected/legacy admission, recovery and post-run checks.
Require owner/mode/ACL evidence and final namespace-edge revalidation.
No environment/caller-selected root, permission repair or arbitrary cleanup.

Continue metadata-only blocking checks of both supported legacy parents:
literal /private/tmp and the dedicated account's canonical native getconf temp
parent. Match dedicated-owner prefix entries of every type; any private staging
entry blocks. Unknown/unsafe/inaccessible/drifted or over-budget observations
refuse. Native discovery is a fixed bounded positively-owned child under new
reviewed authority, not an extension of frozen incident helpers. Its native
confstr operation may create a missing OS-managed temp parent; that narrow
effect is explicit, not a strictly read-only claim. Python selector admission
uses bounded lexical values only, never tempfile probes or arbitrary realpath.
The root-owned sticky /private/tmp inspection exception cannot admit the
private protected namespace.

Use explicit live workspace handles with no deleting destructor. Only the
invocation's original freshly created workspace may undergo ordinary live
cleanup after guest termination, namespace/identity checks and the documented
exclusive-writer assumptions. Marker removal follows verified cleanup and
repeated namespace absence. Manual stale-marker recovery keeps exact target,
PID/death/QEMU/identity guards and never removes directories.

Freeze ADRs 0011/0012 pinned historical authority, old envelopes/receipts and
ADR 0018's exhausted incident disposition. Do not relocate historical evidence,
hide it behind a migration, reuse old deletion authority or claim A1/B8/N1c
closed. No guest networking, host shares, target execution on persistent host,
production/MCP capability or generic process/root authority is added.

## Alternatives and consequences

Native getconf placement alone is smaller but remains OS temporary storage.
Environment/operator-configured roots introduce selection authority and are
rejected. Fixed Application Support storage separates run evidence from the
known tmp cleaner and cache namespace, but needs explicit provisioning,
ACL/namespace validation and bounded legacy compatibility.

This is not protection against root, compromised same-account writers, disk
loss or manual/OS removal. POSIX identity checks/removal are not atomic.
Unsupported platform metadata, unknown state or uncertain cleanup blocks the
provider; no fallback or automatic repair is allowed.

## Review and acceptance boundary

The [written design](../superpowers/specs/2026-10-13-protected-native-e2e-staging-design.md)
defines the proposed bounds, lifetime, migration, rollback and acceptance rows.
The operator approved the written design on 2026-10-13. The first
[implementation plan](../superpowers/plans/2026-10-13-protected-staging-health-inspection.md)
is limited to dormant shared namespace health inspection and awaits plan review
and execution-method selection. The rollout has three separately reviewed
deliveries: dormant shared inspection, dormant owned workspace lifetime, then
already-main activation.
The [source-linked activation checklist](../superpowers/specs/2026-10-13-protected-native-e2e-staging-design.md#required-activation-checklist)
requires replacing every existing tempfile/free-space/recovery route, not adding
a shared scanner beside legacy selection;
require fresh independent review, exact-head hosted/legacy gates and actual
post-merge protected-placement native E2E/cleanup. A docs proposal, fixture PASS
or old-namespace legacy PASS cannot certify this new namespace.
