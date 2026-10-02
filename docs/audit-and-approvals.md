# Audit and approvals

## Current implementation status

Phase 5A-C provide the local audit foundation:

- every MCP call has one server-owned request ID and trusted principal context;
- the dedicated Security Ledger service owns SQLite persistence and exposes a
  peer-authenticated execution Unix socket;
- MCP readiness requires an authenticated ledger ping, while health remains
  process-only and neither endpoint probes SSH hosts;
- request_received is persisted before the domain call; policy-gated SSH/filesystem
  operations persist policy outcome and execution_started before transport;
- completion/failure/cancellation events retain bounded metadata only;
- required pre-network audit failure blocks SSH; an otherwise-successful
  side-effecting operation whose required completion event cannot be persisted
  returns a non-retryable audit-persistence-outcome-uncertain error;
- existing mutation-outcome-uncertain and fs_write committed/durability-
  uncertain outcomes remain more specific if their audit append also fails.

Phase 5D now consumes exact single-use approvals for `ssh_exec`. An
approval-required call without a usable grant remains pre-network and
creates/reuses a ledger-owned approval; an exact granted retry is atomically
consumed before `execution_started` and before any SSH connection is acquired.
Filesystem approvals remain fail-closed until Phase 5E.

## Audit event requirements

Every request receives a stable request ID. The system records at least:

```json
{
  "request_id": "req_01...",
  "timestamp": "...",
  "profile": "operator",
  "client_class": "interactive",
  "host": "prod01",
  "tool": "service_action",
  "normalized_operation": {
    "service": "webapp.service",
    "action": "restart"
  },
  "policy_version": "sha256:...",
  "decision": "allow",
  "risk": "medium",
  "approval_id": null,
  "execution": {
    "exit_code": 0,
    "duration_ms": 923,
    "stdout_bytes": 120,
    "stderr_bytes": 0,
    "truncated": false
  }
}
```

## What not to log by default

- raw argv;
- secret environment values;
- SSH private keys/certificates;
- Access service tokens;
- stdin or fs_write bodies;
- stdout/stderr bodies (only bounded byte counts/status metadata are retained);
- bearer tokens or OAuth tokens.

## Decision events

At minimum:

- request_received;
- policy_allowed/denied;
- approval_required;
- approval_granted/denied/expired/consumed;
- execution_started;
- execution_completed/failed/cancelled;
- host_key_failure;
- remote_policy_denied;
- mutation_outcome_uncertain;
- filesystem_write_committed_durability_uncertain.

## Approval binding

Implemented approvals bind:

- trusted identity/profile;
- target host;
- tool/operation;
- normalized executable/cwd/path as applicable;
- argv count + SHA-256 fingerprint;
- environment names + per-value SHA-256 fingerprints;
- stdin/content length + SHA-256 fingerprint when applicable;
- effective server-owned execution limits;
- privilege scope;
- policy version;
- ledger-owned expiration.

Changing any bound field invalidates the approval.

An execution request MUST NOT contain a boolean or similar self-asserted field
which converts an approval-required decision into an allow decision. Approval
state comes only from the trusted Security Ledger. Phase 5D MCP input can carry
one opaque `approval_id`; it cannot carry grant/deny state, TTL, operator
identity, or binding material. `ssh_exec` re-evaluates current policy and only
reaches the network after exact atomic consumption. Phase 5E applies the same
model to filesystem tools.

## Risk model

Suggested baseline:

- **low** — inspection/read operations;
- **medium** — bounded development or service mutation;
- **high** — destructive mutation, package/container operations, security-relevant service control;
- **critical** — raw shell, privilege escalation, firewall/network administration, root-equivalent access.

The policy, not the client, decides risk.

## Break-glass

Raw administrative shell can be implemented as break-glass access with short TTL and a distinct approval path. It SHOULD be visibly separate from normal agent tools and SHOULD generate high-priority audit events.

## Storage

Phase 5B uses the dedicated local Security Ledger service as the durable local
audit/approval store. It owns a SQLite database with WAL + synchronous FULL,
secure service-owned paths, and an execution/admin Unix authority split. The MCP
process never opens that database directly.

Remote append-oriented storage/SIEM export is still recommended for deployment
hardening and is explicitly deferred; local storage is not claimed to resist a
root-level host compromise.
