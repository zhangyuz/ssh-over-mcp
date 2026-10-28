# ADR 0027: Opt-in fs_list control-plane adapter

Status: PROPOSED for runtime activation. The operator authorized this local,
unregistered adapter increment within Draft PR #347 on 2026-10-28. ADR0026,
v2 deployment and host policy remain PROPOSED.

## Outcome and boundary

An independently testable caller can request one bounded directory through
`SSHFilesystemClient.list(host=..., path=..., max_entries=..., context=...)`.
Success contains a complete tuple of typed, centrally reauthorized children;
any invalid or denied child rejects the entire response. This is local adapter
evidence, not a deployed MCP feature or two-node acceptance.

The smallest sufficient integration reuses the existing authorization gate,
ApprovalExecutionFacts, audit recorder, central compiler and fixed `run_v2`.
There is no new approval mechanism, shell fallback or MCP registration.
The compiler requires direct central ALLOW; approval-required subtree grants
remain unsupported even if a Ledger grant was consumed. No automatic approvals.

## Trusted injection contract

`visibility_authority=None` is the default and refuses before SSH. An explicitly
injected `VisibilityAuthority` supplies a central PolicyEngine, current epoch,
snapshot signer and live epoch/revocation predicate. This interface is not a
trust anchor: production provisioning, signer identity and authenticated
monotonic epoch/ACK authority remain unresolved. No default implementation,
secret loader or environment-controlled opt-in is introduced.

The authority engine and transport must share the inventory object. The adapter
parses the inventory OpenSSH public key with AsyncSSH and hashes its RFC 4253
public blob (SHA-256 hex, excluding comment/line formatting). It never accepts
a pin, key, principal, profile, epoch or request ID as a tool argument.
Principal/profile/request ID come from trusted OperationContext. A production
provider must configure the host verifier with exactly this public-blob identity.

Full compiled rules, host pin, trusted identity, root, digest, epoch, random
snapshot ID, 60-second validity and 1–64 scan bound enter the signed snapshot.
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
