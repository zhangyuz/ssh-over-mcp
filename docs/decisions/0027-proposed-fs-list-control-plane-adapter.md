# ADR 0027: Opt-in fs_list control-plane adapter

Status: PROPOSED for runtime activation. The operator authorized this local,
initially unregistered adapter increment within Draft PR #347 on 2026-10-28. ADR0026,
v2 deployment and host policy remain PROPOSED.

## Outcome and boundary

An independently testable caller can request one bounded directory through
`SSHFilesystemClient.list(host=..., path=..., max_entries=..., context=...)`.
Success contains a complete tuple of typed, centrally reauthorized children;
any invalid or denied child rejects the entire response. This is local adapter
evidence, not a deployed MCP feature or two-node acceptance.

The smallest sufficient integration reuses the existing authorization gate,
ApprovalExecutionFacts, audit recorder, central compiler and fixed `run_v2`.
There is no new approval mechanism or shell fallback. The subsequent
construction-only MCP adapter is described below.
The compiler requires direct central ALLOW; approval-required subtree grants
remain unsupported even if a Ledger grant was consumed. No automatic approvals.

## Trusted injection contract

`visibility_authority=None` is the default and refuses before SSH. An explicitly
injected `VisibilityAuthority` supplies a central PolicyEngine, current epoch,
snapshot signer and live epoch/revocation predicate. This interface is not a
trust anchor: production provisioning, signer identity and authenticated
monotonic epoch/ACK authority remain unresolved. No default construction,
secret loader or environment-controlled opt-in is introduced. (Later
increment, below: an opt-in `ImmutableVisibilityAuthority` class and
construction-time `build_application` parameters exist, but nothing in the
production entrypoint constructs them.)

The authority engine and transport must share the inventory object. The adapter
parses the inventory OpenSSH public key with AsyncSSH and hashes its RFC 4253
public blob (SHA-256 hex, excluding comment/line formatting). It never accepts
a pin, key, principal, profile, epoch or request ID as a tool argument.
Principal/profile/request ID come from trusted OperationContext. A production
provider must configure the host verifier with exactly this public-blob identity.

Full compiled rules, host pin, trusted identity, root, digest, epoch, random
snapshot ID, 60-second validity and 1–64 visible-entry bound enter the signed snapshot.
The signer must return the exact payload supplied. Stable JSON intent containing
host/root/pin/digest/epoch/max_entries is bound through the existing stdin
length/fingerprint ApprovalExecutionFacts fields; this is a semantic intent
fingerprint, not the randomized wire frame. Identity/path/policy/timeout/output
limits also retain existing approval bindings. No key or MAC is audited.

Policy authorization and required start audit precede network access. Before
sending and before/after completion audit, the adapter checks the actual policy
hash, current authority engine, inventory pin, epoch, expiry, and live authority
predicate. Every returned path is re-evaluated centrally; no result is returned
across a failed audit or stale state. A completed execution audit can be followed
by a failed event if policy changes while completion persistence awaits; that
completed event alone is not proof of disclosure to the caller.

## Response and refusal contract

Only fixed `mcp-v2` transport is used. The response byte ceiling is 64 KiB,
with nesting checked before JSON parsing (maximum three containers). Duplicate
keys, malformed UTF-8/JSON, nonfinite numbers, extra/missing fields, coercible
metadata and special inode kinds fail closed. Metadata has integer range bounds;
mode is permission bits, not inode type bits. Request/host/root/epoch/snapshot
must match. Entries are strictly sorted, unique direct children within the
requested bound; denied children fail the whole batch. The host response does
not echo the policy digest; its snapshot ID binds the request's signed digest,
which is independently checked against current central policy.

SSH authenticates the channel; these checks do not prove remote stat truth,
inode stability or mount/race containment. No paging/cursor is claimed.
Cancellation and failures are audited using existing semantics, without retries.

## Evidence and remaining gates

Synthetic tests compose real central policy, authorization/audit records,
snapshot signing, v2 framing and a mocked transport with inventory pins.
Run `tests/ssh/test_filesystem_list_v2.py` with this worktree's `src` on PYTHONPATH.
No configuration example can safely bootstrap a production authority yet.

Before activation: independently approved signer/key provisioning and epoch ACK/
revocation protocol, host identity configuration, filesystem race/mount guarantees,
stable pagination scope, dependency-complete supported-Linux regression, exact-head
CI, independent review, real MCP→Ledger→SSH two-node Mode A positive/negative
acceptance and Native Level-3 cleanup. No live Mode A edit or Mode B authority is
conferred by this ADR or local tests.

## 2026-10-28 MCP adapter increment (default disabled)

The operator authorized local MCP wiring in the same Draft PR, without production
activation. `build_mcp_server(enable_fs_list=True)` requires an already constructed
client with a non-null trusted visibility authority; default construction never
registers the tool. The switch is server-owned and absent from MCP/runtime inputs.
This implements the existing adapter contract without adding a signer, trust root,
approval mechanism or transport path. (Superseded by the composition
increment below: `api/ssh_runtime.py` now accepts an optional
`visibility_authority`, default `None`.)

The real MCP handler/service delegate to `SSHFilesystemClient.list` with trusted
OperationContext and required request audit, after bounded input validation and
host visibility checks. Input is only host/path/max_entries; public output omits
internal snapshot/epoch fields. See [MCP contract and usage](../mcp-api.md#opt-in-fs_list-not-installed-in-the-production-runtime).
Synthetic in-process MCP tests exercise actual central authorization and audit,
with a test-only signer and mocked remote channel, including default absence,
input injection, identity/path mismatch, failed audit, and unauthenticated HTTP.
They are not real SSH, durable Ledger or two-node acceptance. All activation gates
above remain open; controller review is required for this uncommitted increment.

## 2026-10-28 composition increment (opt-in, production default off)

- `build_ssh_runtime(..., visibility_authority=None)` passes an optional
  authority to `SSHFilesystemClient`; the default stays `None`.
- `build_application(settings, visibility_authority_factory=None,
  enable_fs_list=False)` accepts a server-owned factory that receives the
  application's own `PolicyEngine` and must return an authority bound to that
  same engine object (otherwise construction fails). `enable_fs_list=True`
  without a factory fails. `api/main.py` calls `build_application(settings)`
  with neither, so the production entrypoint registers no `fs_list` and has
  no signer.
- `ssh/immutable_visibility_authority.py` provides `ImmutableVisibilityAuthority`
  for one immutable release generation (ADR0028): a fixed epoch, a required
  independent 32-byte HMAC key per inventory host (all distinct, exactly the
  inventory's host set), no hot reload, and a `generation_active` callback.
  It signs only when the policy digest, epoch and pinned host-key identity
  still match. The callback is supplied by the release controller and is
  **not** by itself evidence of a durable fence; key provisioning and the
  trusted adapter remain separate operator gates.
- Review fixes (2026-10-28): an approval-required `fs_list` is audited and
  refused before any Ledger approval is created; a central compile refusal is
  audited as `POLICY_DENIED` and returned as a policy denial; authority
  failures before authorization record `EXECUTION_FAILED`; snapshots are
  backdated by 5 s within the 60 s TTL for host clock lag.
