# ADR 0026 (PROPOSED): Complete typed filesystem operations before Mode B

**Status: PROPOSED — unapproved design; no new MCP/SSH operation enabled.**

## Decision requested

Deliver the agreed full eight-tool filesystem API **before** beginning Mode B
deployment work. Reuse the existing Mode A isolated two-node topology for each
actual end-to-end acceptance. Preserve the current v3/v4 four-tool private pilot
and all security and STOP78 release boundaries. Source of prioritization:
operator's 2026-10-28 instruction.

## First-principles rationale

A distributed three-host install magnifies the cost of correcting an unstable
typed filesystem contract. First prove the exact user operation, permission
boundary and recovery result on the already-running Mode A setup; then install
**the same** reviewed semantics on three independent Mode B Engines. Don't
turn a prior test artifact, offline Docker supply chain or no-NIC guest into
a product networking prerequisite. The existing trusted-main no-NIC Native
Level-3 security test remains required.

## Staged delivery sequence (one feature PR, reviewable vertical slices)

1. **Visibility:** `fs_list`, then `fs_search`, over a versioned,
   centrally authenticated SMCP v2 policy snapshot bound to host identity,
   profile, principal, digest and monotonic epoch. Host Policy v5 must
   check every path **before** metadata/content access and prune denied
   subtrees. The central plane rechecks authorized results and denies stale
   epochs. Include descriptor-anchored traversal without following symlinks,
   constant upper bounds, deterministic ordering, no denied totals, and a
   coherent snapshot/cursor invalidation story. Existing SMCP v1/Host Policy
   v3/v4 refuses both tools.
2. **Mutations:** add `fs_write(replace/append)`, `fs_move` (regular files
   only), and `fs_delete` (regular files / empty directories only) using
   exact source/target permissions, strict if-match and absent-destination
   preconditions. No recursive delete or directory move.
3. **Durability:** operation ID + host-bound fingerprint, one-use Ledger
   approval, per-host durable journal and fsync ordering; reject conflicting
   replay and preserve UNKNOWN through crash/transport partitions. This
   design must be reviewed before any non-idempotent mode is enabled.
4. **Acceptance:** real central MCP HTTP → Ledger → two actual OpenSSH nodes,
   positives and denial/race/crash/replay cases on the same exact source,
   immutable artifacts and current-head CI/Native Level-3; independent review
   and operator-authorized deployment. Only afterward start Mode B.

## Initial implementation checkpoint

`src/ssh_over_mcp/host_agent/visibility_policy_v5.py` is an **inactive
syntactic validation candidate**. It requires explicit version 5, positive
epoch, digest shape, nonempty strict allow roots, operation-specific deny
subtrees, canonical paths and a disabled-by-default switch. This data model
**does not authenticate the digest, sign a snapshot, pin an inode, traverse
files, authorize any real request, or change the running host-agent**.
The `visible()` and `matches()` methods are lexical test helpers, not
permission decisions. This code deliberately does not register a MCP tool,
SMCP v1 request or v5 Host Policy loader. Never reinterpret its local tests
as runtime E2E acceptance.

## Must be independently resolved before wiring

- Host-owned and central-owned policy epoch/revocation ACK barrier and
  authenticated, host-key-bound snapshot transport; fail closed on refresh,
  rollback and mismatches.
- Linux FD-anchored and root-anchored traversal, symlink/mount denial,
  concurrent mutation, type budgets, stable page snapshot and UTF-8 ordering.
- Signed/verifiable durable operation result semantics on ambiguous writes,
  with a human-controlled UNKNOWN reconciliation procedure; **not** the
  earlier unsafe assumption that avoiding automatic retry is enough.
- Uniform stable API errors that never reveal denied child names/counts;
  host policy denial precludes remote traversal or content reads.

Any architectural decision that weakens a current invariant requires
independent approval. No private pilot key or overlay is placed in Git.
