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

## 2026-10-28 Superpowers checkpoint: Linux FD-list candidate

- Plan: [2026-10-28 fs_list FD primitive](../superpowers/plans/2026-10-28-fs-list-primitive.md).
- Added **inactive** `host_agent/visibility_listing_candidate.py` with three
  explicit trusted-callback positions: each traversed prefix, directory
  enumeration, and each child before *any child metadata*.
- Resolves ancestry with Linux `O_PATH|O_DIRECTORY|O_NOFOLLOW`, pins the
  final inode, reopens the pinned directory via `/proc/self/fd/<fd>`,
  checks identity, enumerates at most 64 physical entries, and sorts
  authorized results by UTF-8 basename bytes. Refuses unsupported/symlink
  entries and detects directory inode identity changes during enumeration.
  The only optional path data returned is individually authorized stat
  metadata; callback exceptions fail closed. No shell or direct pathname
  data-capable opens.
- **Limitations intentionally unresolved:** callback values currently have
  no authenticated source; a lexical visibility matcher cannot stand in
  for an epoch-bound central policy or revocation ACK. No stable multi-page
  snapshot, no central result recheck, and no complete global race-proof
  directory view. The module is not called by SMCP v1, MCP, Host Policy
  v3/v4, or the live Yuz.local Mode A deployment. Linux behavior must be
  verified on actual Ubuntu CI before claiming that tests passed.

## 2026-10-28 checkpoint: authenticated snapshot candidate (INACTIVE)

This iteration intentionally builds no operator entrypoint or new SMCP v2
receiver. The new `host_agent/visibility_snapshot_v5.py` has the following
test-first **candidate** contract:

- **One host-specific independent 32-byte HMAC-SHA256 key** (not the Ledger
  key) signs a deterministic canonical JSON payload under a fixed SMCPv2
  domain separator. The payload includes the *full effective central
  allow/deny rule set*, request ID, principal, host ID, SHA-256 host-key
  identity, operation, profile, query root, policy digest, policy epoch,
  random snapshot ID, 1–64 scan budget, issued-at and ≤60-second expiry.
  A MAC over only a digest or only the root permission is insufficient.
- Verification compares the signed fields against a **separately supplied
  trusted exact request binding**, the configured **enabled v5 Host Policy**
  (host/profile/epoch/digest) and a caller-supplied atomic replay-consumption
  callback. A failed MAC, stale epoch, disabled policy, caller mismatch,
  signature expiry or nonce-store failure never produces the verified object.
  All visible children require the signed central rule **and** local Host
  Policy rule to allow their path. Allowed ancestors may be opened only via
  O_PATH in order to reach the separately authorized root; they do not
  authorize listing or returning their metadata.
- The FD helper now accepts a **verified** object with a mandatory live
  epoch guard, checks epoch on every authorized prefix/child and after
  directory enumeration, and fails closed on revocation. The new Linux
  regression tests check that neither centrally nor host-denied children
  are opened, and that no partial output escapes during a revocation.

**Still required before anything becomes live:** trusted key provisioning
and file permissions, distinct central signer authority and host verifier,
persistent *atomic* nonce consumption across restarts, trusted monotonic
policy epoch/ACK barrier including in-flight cancellation, expiry refresh
during traversal, secure host-key-byte canonicalization, full central
PolicyEngine compilation (including recursive deny patterns), mount/rename
containment, consistent bounded pagination, result reauthorization and
real MCP/Ledger/SSH positive/negative E2E. The callback arguments in
this candidate can be spoofed by tests; they are **not** trust boundaries
until wired exclusively to the authenticated host-local runtime. The HMAC
scheme is a candidate for independently reviewing this specific trust
model, not a broad approval to distribute secrets or enable an SSH tool.

## 2026-10-28 checkpoint: central policy compiler and response reauthorization (INACTIVE)

- Candidate `policy/visibility_compiler_v5.py` now checks the actual
  `PolicyEngine.evaluate(root)` result and the effective roles, host,
  capabilities, and tool selectors of existing central rules. To avoid
  unsafe `fnmatchcase` assumptions, it accepts only canonical literal
  paths or terminal `/literal/**` subtree expressions. Unsupported
  patterns **deny compilation** rather than falling back to a root-only
  allow. A subtree permission must cover descendants; an exact-path
  root-only permission is not sufficient for `fs_list`. Any applicable
  ancestor/global deny rejects the request. Deny `/private/**` also
  hides the `private` entry itself; exact denies conservatively hide
  their descendants. Nested deny roots are deduplicated and the host
  visibility hard limit remains 64, with no truncation.
- Central `reauthorize_list_paths` accepts only an exactly current policy
  digest, bounded sorted **direct child** paths with per-child
  `PolicyEngine.evaluate` ALLOW **and** the compiled deny-first
  visibility rules; it checks a caller-supplied live epoch guard before,
  throughout and after the batch, and exposes no partial results.
  This rejects path/count/order tampering even if a future remote
  response is malicious, but validates **paths only**, not remote
  stat metadata/inode identity, response authenticity, output bytes,
  policy-key provisioning, policy-update synchronization or stable
  cursor state.
- These two functions are unregistered test-first **candidate** code. They
  do not sign on behalf of any trusted central service, authenticate
  host-keys, provision keys, implement SMCP v2 or activate any capability.
  The existing central policy's `paths: []` means all paths if the
  remaining rule selectors match; the compiler always clamps such a
  grant to the *one requested canonical root*. Central risk decisions
  requiring approvals cannot be silently treated as ALLOW.
- **Ruling (YAGNI / fail-closed):** do not implement a generic glob-to-tree
  language or rewrite all existing policy rules in this slice. Unhandled
  central path patterns are a deliberate **deny** until separately
  specified, tested and reviewed. The cost is refusal of some currently
  expressible central policies, not permission expansion.

**Remaining before #347 can become Ready:** Freeze central/host snapshot
signer and hostkey pin identity, persistent nonce and monotonic epoch ACK
protocol, FD mount/hardlink/rename race guarantees, a bounded coherent
directory snapshot/page protocol, typed SMCP v2 host policy loader, audited
SSH/MCP glue, exact-response metadata validation, two-node positive/negative
real Mode A E2E and exact-head Native Level-3 cleanup PASS. No Mode B.

## 2026-10-28 checkpoint: synthetic two-root Linux pipeline

- `tests/host_agent/test_visibility_pipeline_linux.py` composes the
  actual central rule compiler, HMAC signer, strict host binding and
  replay-consumer interface, host-local visibility intersection,
  descriptor-pinned Linux listing and final central path recheck. It
  verifies two different *test directories* with different logical host
  IDs, central deny subtree pruning, host deny rules and cross-host
  signature-binding rejection.
- **This is an in-process Linux kernel integration test, NOT Mode A
  acceptance:** no real SSH transport, ForceCommand, MCP, Ledger, live
  key provisioning or monotonic epoch ACK. The host-key bytes and HMAC
  key are synthetic and replay consumption is not durable. Never call
  this a real two-node SSH test or a release receipt.


## 2026-10-28: isolated SMCP v2 + local state checkpoint (NOT ACTIVATED)

- `ssh/protocol_v2.py` introduces a separate `SMCP\\x00\\x02` frame,
  exact `mcp-v2` ForceCommand check, strict fs_list-only metadata and
  duplicate-key/trailing-bytes rejection. Legacy `SMCP\\x00\\x01` and
  Host Agent v3/v4 execution remain untouched and cannot silently downgrade.
- `host_agent/visibility_runtime_v5.py` validates a dedicated owner-only
  v5 config and a distinct 32-byte HMAC key using no-follow fd reads,
  requires a 0700 owner-only private parent, and consumes snapshot IDs
  through a local persistent SQLite nonce table (no implicit pruning).
  This blocks replay after process restart when storage remains intact.
- `host_agent/cli_v2.py` is a **separate uninstalled entrypoint**. It
  validates the signed request with trusted host/config fields, checks
  policy file/expiry during and after every FD listing, and returns a
  bounded JSON response. Test cases include wrong protocol, stale epoch,
  insecure config, and durable request replay. The legacy ForceCommand and
  running Mode A pilot do **not** invoke the new entrypoint.
- These controls do not implement a globally monotonic epoch ledger, ACK
  barrier or revocation of a previously issued snapshot during network
  partitions. The signed principal is not independently derived from an
  SSH execution identity; the central signing authority still needs a
  trusted mapping. This is deliberately **not** a production v2 release.
- No paging/cursor or entire host-side safety proof exists. A bounded
  single-directory response is not a stable paginated snapshot. A
  genuine two-node Mode A MCP→Ledger→SSH user feature remains absent.
- Ruling: prioritize an isolated, falsifiable v2 Host Agent contract
  over changing the existing v1 ForceCommand or pretending v5 policy
  parsing alone authorizes traversal. Runtime activation requires
  separate security/design approval under the existing release gates.

## 2026-10-28: fixed v2 SSH transport candidate (NOT ACTIVATED)

`StructuredSSHTransport.run_v2()` sends pre-framed bytes using the literal
SSH command `mcp-v2`; existing `run()` continues to select `mcp-v1`.
Neither public entrypoint accepts a command override, and their shared
private channel path rejects any command outside those two exact literals
before connection acquisition. Payload bytes never select the SSH command;
there is no retry or protocol downgrade on failure.

Both methods retain inventory-owned connection identity and host-key pins,
per-host session limits, no PTY/X11/environment forwarding, binary I/O, the
shared stdout/stderr byte budget, timeout/cancellation cleanup and sanitized
definite-open versus uncertain-post-send failure semantics. Framing and
authorization remain the caller/receiver responsibilities; this transport
does not grant filesystem access or validate a signed snapshot.

The v2 method has no production caller or new MCP registration. Local mock
channel tests establish selection and refusal/limit behavior, not real SSH
or Mode A acceptance. Deployed ForceCommand/configuration, trust material,
approvals and all full-feature/Level-3 activation gates remain unchanged.

## 2026-10-28: opt-in control-plane adapter checkpoint (NOT ACTIVATED)

`SSHFilesystemClient.list` now composes authorization/audit, signed compiled
visibility and fixed v2 transport only with an explicitly injected trusted
authority. Strict metadata validation and central per-child reauthorization
reject whole responses, including stale policy/epoch across audit awaits.
See [ADR0027](0027-proposed-fs-list-control-plane-adapter.md) for the injection,
pin canonicalization, binding and refusal contracts. Earlier "no caller"
statements describe historical checkpoints; there is still no production
composition, default MCP registration, live host-policy change or deployed
acceptance. ADR0027 now records the separately authorized, construction-only
MCP opt-in; its production activation gates remain open.
