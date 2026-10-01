# Phase 5 Security Ledger, Audit, and Approval Design

Date: 2026-10-01

Status: self-reviewed revision awaiting human approval before implementation

## 1. Purpose

Phase 4 closed the MCP surface at exact main commit
`6b9d47d3d546f719f0fb76ab4ae8f6819f013152`. The control plane now exposes
server-owned identity, central policy, structured SSH execution, read-only
filesystem access, and create-only filesystem mutation without raw-shell or
destructive namespace fallbacks.

Phase 5 adds two trust-sensitive capabilities:

1. durable audit records for MCP/domain request lifecycle events; and
2. explicit operator approval for policy decisions which are
   `approval_required`.

The approval subsystem is an authorization boundary, not a convenience flag.
An MCP client MUST NOT be able to convert an approval-required decision into
allow by asserting a boolean, inventing an approval identifier, editing local
storage, or replaying an already consumed approval.

The audit subsystem is part of the security contract. Once Phase 5 runtime
integration is enabled, operations MUST NOT silently continue without their
required audit/approval ledger.

## 2. Design goals

Phase 5 must provide:

1. one stable server-generated request ID before policy evaluation;
2. durable append-oriented audit events with bounded, non-secret payloads;
3. a local Security Ledger service isolated from the MCP process;
4. operator grant/deny authority separate from the normal execution client;
5. exact approval binding to trusted identity, normalized operation, policy
   version, effective execution bounds, and payload fingerprints;
6. server-owned expiration and mandatory single-use approval consumption;
7. atomic approval state transitions and replay prevention;
8. policy re-evaluation on every retry, with explicit deny remaining
   non-overridable;
9. approval validation before any SSH/network side effect;
10. preservation of Phase 4 host-agent enforcement and mutation uncertainty
    semantics;
11. a small MCP approval UX which does not expose grant/deny authority;
12. independently reviewable implementation slices with exact-head
    self-hosted verification.

## 3. Non-goals

Phase 5 does not implement:

- Cloudflare OAuth, Portal, Tunnel, or claim-to-profile mapping;
- remote SIEM transport;
- multi-node or distributed consensus for approvals;
- destructive filesystem namespace mutation;
- raw-shell enablement;
- generic privileged helpers;
- arbitrary MCP audit query access;
- approval delegation between principals;
- reusable/multi-use approvals;
- background approval workers or scheduled approval execution;
- secret storage for command arguments, stdin, environment values, or file
  bodies;
- host-agent verification of approval artifacts.

A fully compromised control-plane process remains outside the approval
subsystem's protection boundary. Host-agent policy, ForceCommand, OS identity,
and containment remain the independent defense against a compromised origin.
The ledger prevents normal MCP callers and ordinary control-plane code paths
from self-granting, mutating approval storage, or replaying consumed approval
state.

## 4. Architectural decomposition

The dependency direction is:

```text
MCP SDK / HTTP
      |
      v
MCP tool adapters
      |
      v
MCPService + OperationContext
      |
      +----> discovery / policy_explain audit
      |            |
      |            v
      |      SecurityLedgerClient
      |
      v
SSHExecutor / SSHFilesystemClient
      |
      v
ExecutionAuthorizer
      |
      +----> PolicyEngine (pure evaluation)
      |
      +----> SecurityLedgerClient
      |          |
      |          v
      |     authenticated AF_UNIX
      |          |
      |          v
      |     Security Ledger service
      |       |              |
      |       |              +--> approval state
      |       +-----------------> append audit
      |                         SQLite
      |
      v
StructuredSSHTransport
      |
      v
host-agent / OS enforcement
```

The Security Ledger is a separate local service and OS identity. It owns the
SQLite database and the approval-binding HMAC key. The MCP process does not
open the database directly and does not receive the HMAC key.

## 5. Trust boundaries

### 5.1 MCP caller

The MCP caller is untrusted for authorization. It may submit syntactically
valid operations, retry calls, supply an opaque `approval_id`, or query
approval status for its own trusted principal.

It cannot:

- choose `principal_id` or profile;
- grant or deny approvals;
- select approval TTL;
- supply binding hashes;
- mark approvals consumed;
- change policy version;
- bypass central policy;
- write audit rows directly.

### 5.2 Control-plane process

The MCP process is trusted to:

- obtain the trusted principal from `PrincipalProvider`;
- validate MCP input;
- call `PolicyEngine`;
- construct binding input from policy-normalized values and actual payload
  fingerprints;
- call the Security Ledger before network access;
- pass only an authorized operation to SSH/filesystem execution.

The MCP process does not have database-file or HMAC-key access.

### 5.3 Security Ledger service

The ledger service is trusted to:

- authenticate local Unix peers;
- own server time for approval TTL checks;
- canonicalize binding input;
- compute the binding HMAC;
- create/reuse active approval requests;
- grant/deny only through the admin authority;
- atomically consume granted approvals;
- append immutable-through-protocol audit events;
- recover approval state after process restart.

### 5.4 Operator approval authority

Grant/deny authority is local-operator authority, not MCP authority.

The first implementation uses a separate admin Unix socket with stricter
filesystem permissions and peer-credential policy than the execution-client
socket. Only the operator/admin OS identity may invoke grant/deny operations.

There is no MCP `approval_grant` or `approval_deny` tool.

### 5.5 Remote host

The host agent does not trust approval state. It continues to independently
validate SMCP, host-local policy, filesystem roots/limits, executable identity,
OS permissions, containment, and create-only filesystem semantics.

## 6. Principal identity

Phase 5 extends the repository-owned trusted principal value to contain:

```text
PrincipalContext(
    principal_id: str,
    profile: str,
)
```

The static Phase 4 provider maps its configured profile to a stable identity:

```text
principal_id = "static:" + profile
```

Clients cannot supply either field.

Future OAuth integration may replace `principal_id` with a verified upstream
subject while retaining the same approval binding contract. Approval rows bind
both `principal_id` and profile so a role/profile change cannot silently reuse
old state.

## 7. OperationContext and request identity

Every MCP tool invocation receives a server-generated request ID before policy
or domain evaluation:

```text
req_<128-bit random identifier>
```

`OperationContext` contains at least:

- request ID;
- trusted principal ID;
- trusted profile;
- receive timestamp;
- optional approval ID supplied by the client.

The request ID is correlation identity, not authorization. A client cannot
supply or reuse it.

Successful Phase 4 side-effecting outputs continue returning their existing
server-generated request ID. Internally, the same request ID must be passed
through policy, ledger events, SSH/SMCP, and completion events rather than
generating a second identifier below the MCP boundary.

## 8. Policy and authorization composition

`PolicyEngine` remains pure and unchanged in authority:

```text
EvaluationRequest -> PolicyDecision
```

An explicit central-policy DENY is terminal. No approval can override it.

Phase 5 introduces `ExecutionAuthorizer`. It owns the transition from a policy
decision to permission to reach the network:

1. evaluate central policy;
2. append the policy decision event;
3. if DENY, return a stable denial;
4. if ALLOW, return an authorized decision;
5. if APPROVAL_REQUIRED and no usable approval is supplied, create/reuse one
   active approval and return approval-required;
6. if APPROVAL_REQUIRED and an `approval_id` is supplied, recompute the exact
   binding and request atomic consumption;
7. only after successful consumption return an authorized decision.

`SSHExecutor` and `SSHFilesystemClient` own this gate as an injected
dependency and invoke it internally before they build/send a structured
transport request. `MCPService` passes the trusted `OperationContext` and
validated operation data into those existing execution adapters; it does not
perform a second approval implementation.

This preserves the Phase 4 structural invariant: an internal caller cannot
reach the executor/client transport path with a raw `EvaluationRequest`
without passing through the same authorizer first. The network path remains
unreachable before authorization returns success.

## 9. Canonical approval binding

### 9.1 Binding objective

An approval authorizes one exact execution attempt. Any material change creates
a different binding.

The versioned binding contains:

- binding schema version;
- trusted principal ID;
- trusted profile;
- logical host alias;
- tool;
- fixed privilege;
- central policy version;
- policy-normalized executable;
- argv count plus one length-delimited SHA-256 argv fingerprint;
- policy-normalized cwd;
- policy-normalized path;
- sorted environment names plus SHA-256 fingerprints of values;
- stdin length plus SHA-256 fingerprint;
- filesystem-write content length plus SHA-256 fingerprint;
- effective timeout;
- effective max output bytes;
- effective max stdin bytes;
- tool-specific effective byte limits where applicable.

Fields which do not apply to a tool are encoded canonically as null/empty
values rather than omitted ambiguously.

### 9.2 Sensitive payloads

Raw argv, environment values, stdin, and `fs_write` bytes are never sent to
the ledger or persisted there.

The control plane computes bounded SHA-256 fingerprints from the actual
validated values. Argv uses a versioned length-delimited encoding before
hashing so argument-boundary changes cannot collide through concatenation.
Environment values, stdin, and `fs_write` content are fingerprinted without
placing raw values in ledger protocol models. The ledger receives only those
fingerprints plus non-secret normalized metadata and computes a keyed HMAC over
the complete canonical binding.

Persisted approval rows contain only:

```text
hmac-sha256:v1:<hex>
```

plus a bounded safe summary.

The HMAC key is readable only by the ledger service. Phase 5 v1 does not
support online key rotation: the database records a non-secret SHA-256 key ID
at creation, and startup with a different key fails closed rather than leaving
persisted approvals in a misleading partially-invalid state. Key rotation and
migration require a separately reviewed procedure.

### 9.3 Canonical encoding

Binding input uses one versioned canonical JSON representation:

- UTF-8;
- sorted object keys;
- fixed field set for the binding version;
- compact separators;
- no floats except fields whose normalized representation is explicitly
  specified;
- no unordered maps after canonical sorting.

Canonicalization lives in one repository-owned module shared by ledger client
tests and ledger service tests. Multiple independent implementations are not
allowed.

## 10. Safe approval summary

The ledger must provide enough information for an operator to distinguish the
target operation without becoming a secret store.

Persisted/displayed summary may include:

- principal ID/profile;
- host alias;
- tool;
- normalized executable;
- normalized cwd/path;
- argv count and aggregate fingerprint, not raw argv;
- environment variable names, not values;
- stdin/content length and fingerprint, not bytes;
- effective timeout/byte limits;
- policy version;
- risk;
- short binding fingerprint.

Raw argv is not stored by default because command arguments may contain
tokens/passwords. A later richer approval UI requires a separate secret-safe
design rather than silently widening audit retention.

## 11. Approval state machine

Approval identifiers are server-generated opaque values:

```text
apr_<128-bit random identifier>
```

The v1 state machine is:

```text
              +---------- grant ----------+
              |                           v
pending ------+-----------------------> granted
   |          |                           |
   | deny     | expire                    | consume atomically
   v          v                           v
 denied     expired                    consumed
   |                                      |
   +------------- expiry window ----------+
```

Rules:

- `pending`, `granted`, and `denied` are active records until expiry;
- `expired` and `consumed` are terminal;
- grant/deny is accepted at most once;
- a denied approval cannot later be granted;
- a granted approval cannot be denied;
- a consumed approval cannot be reused;
- expiry is controlled only by ledger service time;
- v1 approvals are always single-use;
- no background sweeper is required.

On create/status/grant/consume, the ledger first transitions an active
pending/granted record whose expiry has passed to `expired` and appends exactly
one expiry event.

## 12. Approval deduplication and TTL

For one exact binding, there may be at most one active approval record in
`pending`, `granted`, or `denied` state.

Repeated calls for the same binding before expiry return the same approval ID
and state rather than creating approval spam.

A denied binding remains denied until its approval expires. A new approval for
the same binding may be created only after expiry.

Server-owned defaults:

- default TTL: 10 minutes;
- hard maximum TTL: 60 minutes.

The ledger service owns both TTL values. The execution/admin protocol carries
no caller-selected TTL field, and the MCP client, control-plane process, and
operator grant command cannot extend TTL. Future ledger configuration may
tighten the default by risk but cannot widen the hard maximum without a
separately reviewed configuration change.

## 13. Atomic approval consumption

Consumption is the replay-prevention boundary.

The ledger performs consumption inside one SQLite write transaction:

1. begin an immediate transaction;
2. load approval by ID;
3. apply expiry if necessary;
4. require state == `granted`;
5. require principal ID/profile, binding HMAC, host/tool, and policy version to
   match;
6. update `granted -> consumed` with a conditional state predicate;
7. append `approval_consumed` audit event in the same transaction using the
   current retry request ID supplied by the execution client;
8. commit.

Exactly one concurrent caller may observe successful consumption.

Consumption authorizes one execution attempt, not one successful remote
outcome. If SSH connection creation, host-key verification, remote policy, or
execution later fails, the approval remains consumed. It is never restored or
replayed automatically.

This intentionally prefers a lost approval over duplicate side effects.

## 14. Security Ledger transport and process model

The ledger exposes no TCP/HTTP listener.

It uses authenticated `AF_UNIX/SOCK_STREAM` endpoints:

- execution/client socket: audit append, approval create/status/consume;
- admin socket: approval list/show/grant/deny.

Both client and server validate peer credentials with the same fail-closed
principles already used by the containment-manager Unix boundary.

Protocol requirements:

- strict versioned operation discriminator;
- bounded frame size;
- bounded string/list/map sizes;
- additional fields rejected;
- one request -> one response;
- fixed timeout;
- no file descriptor passing;
- no shell commands;
- no caller-supplied database path or HMAC-key path.

Phase 5A fixes the protocol envelope at `SLED\x00\x01` plus one unsigned
big-endian 32-bit JSON length and a 64 KiB JSON payload maximum. Every message
carries protocol version 1 and a server-generated/caller-library-generated
`msg_<128-bit hex>` correlation ID.

Execution requests are exactly `ping`, `append_audit`, `ensure_approval`,
`approval_status`, and `consume_approval`; admin requests are exactly
`list_approvals`, `show_approval`, `grant_approval`, and
`deny_approval`. Request/response unions use different discriminators and
reject cross-union decoding.

A maximum legal canonical binding is already large enough that transmitting
both the binding and a duplicated `ApprovalSafeSummary` would exceed the
64 KiB cap. Therefore `ensure_approval` carries request ID, canonical binding,
and risk only. The ledger service derives the safe summary from that binding
plus risk before persistence. `consume_approval` carries the current retry
request ID, approval ID, and canonical binding so the atomic consume transaction
can correlate its `approval_consumed` event to the execution attempt. Admin
list responses use bounded lightweight items; show/status responses may return
full `ApprovalStatus`. No request contains caller-selected TTL, operator
identity, or binding HMAC.

The two sockets have distinct filesystem ownership/mode policy. The execution
client identity cannot connect to the admin authority endpoint.

## 15. SQLite durability and storage contract

The ledger service owns one local SQLite database under a directory writable
only by its dedicated service identity.

Startup fails closed if:

- database parent path is not absolute;
- parent ownership/mode permits unauthorized replacement;
- an existing database path is not a regular non-symlink file;
- schema version is unknown;
- HMAC key is missing/invalid;
- the database key ID does not match the configured HMAC key;
- configured sockets cannot be created safely.

SQLite runtime settings must include:

- foreign keys enabled;
- WAL journal mode;
- `synchronous=FULL`;
- bounded busy timeout;
- explicit transactions for every state transition.

No external process receives the SQLite path as an MCP argument.

The application protocol exposes no UPDATE/DELETE operation for audit events.

## 16. Storage model

The exact SQL may evolve during implementation, but the semantic tables are:

### 16.1 approvals

Stores:

- approval ID;
- binding HMAC/version;
- safe summary;
- principal ID/profile;
- host/tool/privilege;
- policy version;
- risk;
- state;
- first request ID;
- created/expires/decided/consumed timestamps;
- deciding operator identity.

A unique active-binding constraint prevents duplicate active approvals.

### 16.2 audit_events

Append-oriented event rows store:

- monotonically increasing local sequence;
- random event ID;
- request ID;
- ledger-owned timestamp;
- event type;
- principal ID/profile;
- host/tool;
- safe operation summary;
- policy version;
- policy decision/risk;
- approval ID when applicable;
- bounded outcome metadata.

The database does not store:

- credentials;
- host keys;
- OAuth/service tokens;
- private keys/certificates;
- raw argv;
- environment values;
- stdin bodies;
- `fs_write` bodies;
- stdout/stderr bodies.

## 17. Audit event lifecycle

At minimum the ledger records:

- `request_received`;
- `policy_allowed`;
- `policy_denied`;
- `approval_required`;
- `approval_granted`;
- `approval_denied`;
- `approval_expired`;
- `approval_consumed`;
- `execution_started`;
- `execution_completed`;
- `execution_failed`;
- `execution_cancelled`;
- `remote_policy_denied`;
- `host_key_failure`;
- `mutation_outcome_uncertain`;
- `filesystem_write_committed_durability_uncertain`.

Events are facts, not reconstructed guesses. If the process crashes after
`execution_started` and before a completion event, the absence of completion
remains visible; restart logic must not invent a successful/failed outcome.

For execution results, persist bounded metadata such as exit status/signal,
duration, stdout/stderr byte counts, timeout/truncation flags, but not output
bodies.

## 18. Ledger availability and application lifecycle

Once Phase 5 runtime integration is enabled, ledger availability is mandatory
for MCP request processing.

- `/healthz` remains process liveness and does not depend on the ledger;
- `/readyz` requires successful local ledger configuration/handshake;
- readiness still performs no SSH or remote-host probe;
- if the ledger becomes unavailable after startup, MCP/domain operations fail
  closed before policy-authorized network side effects;
- a required pre-network audit append failure keeps the transport call count
  at zero;
- if required outcome-audit persistence fails after a side-effecting transport
  attempt, ordinary success must not be returned: otherwise-successful
  `ssh_exec`/mutation calls return a stable audit-persistence-outcome-
  uncertain error with explicit do-not-retry-blindly wording;
- existing more-specific non-retryable mutation outcomes remain more specific:
  generic mutation-outcome-uncertain and `fs_write` committed/durability-
  uncertain are never collapsed into an ordinary audit error;
- read-only/discovery completion-audit failure returns a stable audit-
  persistence error and may be retried only after ledger recovery;
- no operation silently degrades to unaudited execution.

A ledger outage is a local control-plane failure, not a reason to bypass audit
or approval.

## 19. MCP approval UX

### 19.1 Approval-required execution

Every policy-gated executable/filesystem tool which can receive an
`APPROVAL_REQUIRED` decision gains at most one optional client field:
`ssh_exec`, `fs_stat`, `fs_read`, `fs_mkdir`, and `fs_write`.

```text
approval_id: str | null
```

It is an opaque lookup handle, never an authorization assertion.

On an approval-required call without a usable approval, the tool returns a
stable MCP tool error whose model-visible text contains:

- request ID;
- approval ID;
- state (`pending` or `denied`);
- expiry timestamp;
- explicit instruction that the exact operation must be retried only after
  approval.

Current MCP Python SDK behavior returns `ToolError` as
`CallToolResult(is_error=True)` with model-visible text and no
`structured_content`. Phase 5 therefore does not depend on structured error
payload support.

### 19.2 approval_status

Phase 5 adds one MCP read-only tool:

```text
approval_status(approval_id)
```

It returns a strict structured result containing:

- approval ID;
- state;
- expiry;
- host/tool;
- risk;
- safe summary/fingerprint.

The service returns status only when the approval belongs to the current trusted
principal/profile. Unknown and non-visible approval IDs use the same public
not-visible error so the tool is not an approval-enumeration oracle.

`approval_status` cannot grant, deny, consume, or alter TTL.

### 19.3 No request_elevation tool in v1

An approval-required operation automatically creates/reuses its approval
request. A separate `request_elevation` tool would duplicate the operation
schema and create a second path for request binding, so it is intentionally
absent from Phase 5 v1.

## 20. Retry and policy-change semantics

Every retry re-evaluates the current central policy before approval consumption.

If current policy is:

- DENY: fail immediately; an old approval is irrelevant;
- ALLOW: execute without consuming an old approval;
- APPROVAL_REQUIRED: require exact binding/approval validation.

Because policy version is part of the binding, a granted approval created under
an older policy version cannot be consumed under a newer approval-required
decision.

Any change to host, tool, normalized executable/path/cwd, argv count or
fingerprint, environment value fingerprint, payload fingerprint, privilege,
policy version, or effective execution bounds invalidates the approval.

## 21. Side-effect and uncertainty semantics

Approval state does not alter existing remote outcome classification.

For `fs_mkdir` and `fs_write`:

- approval is consumed before network access;
- generic post-send ambiguity remains mutation-outcome-uncertain;
- clean `fs_write` status 74 remains the distinct
  committed/durability-uncertain outcome;
- no failure restores a consumed approval;
- no blind automatic retry is introduced.

For `ssh_exec`, existing timeout/output/cancellation semantics remain
authoritative.

## 22. Operator CLI

Phase 5 provides a local operator CLI over the admin socket.

Minimum commands:

```text
approvalctl list
approvalctl show <approval_id>
approvalctl grant <approval_id>
approvalctl deny <approval_id>
```

The CLI never opens SQLite directly. Grant/deny identity is derived from the
authenticated admin Unix peer, not a command-line `--actor` string.

CLI output is bounded and secret-safe. It shows the persisted safe summary and
binding fingerprint, not environment/stdin/file contents.

There is no automatic approval mode.

## 23. Audit export boundary

Phase 5 local SQLite is the durable local security ledger, not the final
enterprise audit destination.

Define an internal audit-export boundary so a later phase can forward committed
events to append-oriented remote storage/SIEM.

Phase 5 does not:

- require external network access for audit;
- block a committed local event waiting on SIEM;
- claim local SQLite is tamper-proof against root compromise.

Cloudflare/SIEM export belongs to the deployment/integration phase.

## 24. Security invariants

Phase 5 must preserve all of the following:

1. MCP input cannot select trusted principal/profile.
2. MCP input cannot grant/deny approval.
3. Explicit central DENY cannot be overridden by approval.
4. Approval-required execution cannot reach SSH without atomic consumption.
5. Consumed approval cannot be reused concurrently or after restart.
6. Approval binding changes when any material execution input changes.
7. Policy-version change invalidates old approval-required grants.
8. Ledger service time, not client time, owns expiry.
9. Execution client cannot connect to admin grant authority.
10. MCP process does not directly open approval/audit SQLite storage.
11. HMAC key is not available to MCP callers or MCP process.
12. Audit/approval outage cannot silently degrade to unaudited side effects.
13. Approval does not bypass host-agent policy or OS enforcement.
14. No structured denial falls back to raw shell.
15. No destructive filesystem tool is introduced.
16. Audit rows do not contain credentials, raw argv, secret env values, stdin,
    file bodies, or unbounded output.
17. `fs_write` committed/durability-uncertain remains distinct.
18. Approval consumption is one attempt, not one successful execution.

## 25. Required adversarial tests

### Principal and request identity

- client cannot supply principal ID/profile/request ID;
- static principal ID is deterministic and server-owned;
- one request ID correlates MCP, policy, ledger, SSH, and completion events.

### Binding

- canonical binding is deterministic;
- field order does not change binding;
- any material operation change does;
- environment value/content/stdin changes alter binding without persistence of
  raw values;
- effective server limit changes alter binding;
- HMAC key is never serialized or returned.

### Approval state

- duplicate active binding reuses one approval;
- grant/deny are terminal and mutually exclusive;
- denied stays denied until expiry;
- expired approval cannot grant/consume;
- concurrent consume yields exactly one success;
- consumed state survives ledger restart;
- policy-version change rejects consumption;
- wrong principal/host/tool/binding rejects consumption;
- explicit policy DENY wins even with a granted approval.

### Unix boundary

- execution peer cannot use admin methods;
- wrong peer UID/GID fails before protocol handling;
- wrong ledger-server peer identity fails client connection;
- unsafe socket/database ownership/modes fail startup;
- malformed/oversized protocol frames fail closed.

### Audit

- every required transition emits one bounded event;
- secret-bearing values never appear in database rows, protocol errors, or full
  tracebacks;
- crash-shaped incomplete execution remains incomplete rather than inferred;
- mutation uncertainty and status-74 committed uncertainty retain separate
  event types.

### Network ordering

- approval-required without grant -> SSH connection count zero;
- granted approval is atomically consumed before first SSH connection attempt;
- ledger failure -> SSH connection count zero;
- host-agent remote policy remains independently authoritative after approval.

### Restart/crash

- pending/granted/denied records survive service restart;
- consumed approvals remain consumed;
- expiration is applied after restart from persisted expiry;
- crash after consume but before execution does not restore approval;
- crash after execution-start does not invent completion.

## 26. Implementation slices

Phase 5 is intentionally decomposed into small independently merged slices.

### 5A — domain contract and canonical binding

Status: implemented as domain/protocol infrastructure; no runtime execution
behavior change.

Add:

- extended trusted `PrincipalContext`;
- `OperationContext`;
- audit/approval domain models;
- canonical binding and payload fingerprints;
- ledger client/service protocol models;
- no runtime execution behavior change.

Exit: pure model/canonicalization tests plus full regression suite.

### 5B — Security Ledger service

Add:

- dedicated local ledger daemon;
- execution/admin Unix sockets with peer credentials;
- SQLite schema/migrations;
- HMAC key handling;
- approval state machine;
- atomic consume;
- append audit;
- local `approvalctl`.

No MCP/SSH execution integration yet.

Exit: storage, restart, concurrency, peer-auth, malformed-frame, and secret
leakage tests.

### 5C — request/audit lifecycle integration

Add:

- server-owned request ID at MCP boundary;
- mandatory ledger readiness;
- request/policy/execution audit events;
- stable failure semantics for ledger outage;
- no approval execution yet: approval-required still fails closed.

Exit: all existing tools audited, no behavior widening, network remains blocked
on audit failure.

### 5D — approval-aware ssh_exec

Add:

- `ExecutionAuthorizer` as an internal `SSHExecutor` gate;
- optional `approval_id` on `ssh_exec`;
- approval create/status/consume path;
- `approval_status` MCP tool;
- exact retry/binding semantics.

Exit: RED/GREEN proof for deny precedence, policy change, wrong binding,
concurrent replay, ledger outage, and network-before-approval ordering.

### 5E — filesystem approvals

Inject the same authorizer inside `SSHFilesystemClient` for every filesystem
operation which central policy can mark approval-required:

- `fs_stat`;
- `fs_read`;
- `fs_mkdir`;
- `fs_write`.

Read-only operations preserve their existing result/error semantics;
`fs_read` binds its effective/requested byte limit. Create-only operations
preserve every mutation uncertainty semantic, including the distinct
status-74 committed/durability-uncertain outcome.

Exit: approval cannot widen path/read/body/limit semantics, read-only approval
cannot authorize mutation (or vice versa), and consumed mutation approvals are
never restored after uncertain outcomes.

### 5F — final Phase 5 security review

Prove on one exact main commit:

- full MCP/audit/approval lifecycle;
- no grant authority in MCP;
- atomic single-use replay prevention;
- no secret retention;
- ledger fail-closed ordering;
- host-agent independent enforcement;
- no raw shell/destructive mutation;
- Python 3.13/3.14 full suites on hardened Ubuntu 26.04 x86.

Each slice follows RED -> minimal GREEN -> focused/full verification ->
whole-branch security review -> exact-head self-hosted CI -> merge if clean.

## 27. Evidence required to close Phase 5

Phase 5 may be marked complete only after one exact main commit demonstrates:

- local ledger process and SQLite persistence are active;
- admin grant authority is peer-separated from execution-client authority;
- approval-required request produces no SSH before approval;
- one granted approval can be consumed at most once;
- restart cannot resurrect consumed approval;
- current policy is re-evaluated before consume;
- explicit DENY always wins;
- audit events cover decision and execution lifecycle;
- secret-bearing payloads are absent from stored audit/approval records;
- ledger outage fails closed;
- existing host-agent policy remains authoritative;
- create-only mutation/uncertain-outcome contracts remain unchanged;
- no raw shell/destructive MCP capability appears;
- hardened self-hosted Python 3.13/3.14 full suites pass.

## 28. Deferred work

Explicitly deferred:

- OAuth/user-claim principal IDs;
- human approval through Cloudflare/remote web UI;
- multi-node approval consensus;
- reusable approvals;
- remote SIEM/export implementation;
- MCP `audit_query`;
- raw-shell break-glass enablement;
- destructive filesystem namespace mutation;
- privileged helper approval;
- online HMAC-key rotation/migration.

Those capabilities require separate design/review and must not be smuggled into
the local Phase 5 ledger as convenience features.
