# Audit and approvals

## Fresh systemd reference provisioning prerequisite

`ops/systemd/ssh-over-mcp-ledger-provision` is an explicit Linux operator action
for a fresh split layout, not a Ledger RPC, application startup hook, sudo
profile, migration or automatic recovery command. Install the reviewed script
at `/opt/ssh-over-mcp/ops/systemd/ledger_provision.py` in a root-owned, immutable
release tree. Its fixed launcher uses `/opt/ssh-over-mcp/venv/bin/python -I -S -B`;
no arguments, environment-selected paths, identities or loader hooks are accepted.
`-S` prevents installed site hooks from executing while this operator process is
root. Only the reviewed stdlib `approvals/keyfile.py` from the fixed non-editable
installed tree is loaded through its validated, pinned source descriptor;
application package initialization and bytecode caches are not executed.
The interpreter, stdlib and installed release must already be operator-trusted;
root ownership alone is not release provenance. Python 3.13/3.14 standard Unix
venv layouts are supported. The daemon's production command remains the approved
non-root `python -I -B -m ssh_over_mcp.approvals.main` composition.

Resolve numeric IDs from the trusted account database for
`ssh-over-mcp-ledger`, `ssh-over-mcp-exec` and `ssh-over-mcp-admin`, each with its
own same-named primary group. The additional endpoint groups are
`ssh-over-mcp-ledger-exec` and `ssh-over-mcp-ledger-admin`; these five GIDs and
the three non-root UIDs must be distinct. No UID/GID aliases or unexpected
memberships are accepted. Each role primary GID belongs only to that role in
the account database; no account may use an endpoint GID as its primary GID.
Both primary memberships and supplementary memberships are checked. Ledger has both endpoint groups; each client has
only its own primary and corresponding endpoint group. Each endpoint group's
explicit members are exactly Ledger and its corresponding client. Full workload
identity and service sandbox acceptance remain later Phase 7B1 tasks.

The operator must prevent concurrent starts and keep the Ledger identity
quiescent throughout provisioning. The tool verifies absence of Ledger UID
processes before creation, before generation and before success. It lowers
hard/soft core limits to zero and requires an effective non-pipe core pattern
before loading the helper or generating key material.
Core preconditions are checked again immediately before key generation and
before success; the operator must keep the no-core host policy stable throughout.
Canonical root-owned
ancestors are pinned, prohibit group/other writes and reject symlinks. The
configuration parent is root:root 0755. Only fresh children are created:

| Path | Ownership | Mode |
| --- | --- | --- |
| `/etc/ssh-over-mcp/ledger-key` | Ledger:Ledger | 0700 |
| `/var/lib/ssh-over-mcp-ledger` | Ledger:Ledger | 0700 |
| `/run/ssh-over-mcp-ledger-exec` | Ledger:execution endpoint group | 0750 |
| `/run/ssh-over-mcp-ledger-admin` | Ledger:admin endpoint group | 0750 |

Any existing child refuses, including an empty apparently valid directory.
Key creation uses `O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC` with initial mode 0600.
The shared writer generates exactly 32 CSPRNG bytes, completes writes, sets
Ledger UID/GID and final mode 0400, validates metadata and fsyncs the file.
The operator then checks the key's single-link inode/path identity, fsyncs
the key directory and revalidates the pinned ancestry/key before success.
Directory creation and ownership metadata are also synced through child and
parent descriptors. Unknown existing keys, symlinks, FIFOs, metadata/path
changes, active Ledger processes or durability failures refuse. The tool emits
no success output, and only `Ledger provisioning failed` on expected failure;
no key bytes appear in argv, environment or output.

Failure can leave newly created state whose durability is uncertain. Preserve
it for explicit operator inspection and recovery; never blindly unlink, rerun
as a repair, replace a key, or treat failure as successful initialization.
Existing container/legacy bootstrap continues to validate an existing key
without replacement and retains its same-parent layout. This prerequisite does
not certify installed-package/systemd composition or close Phase 7B1.
Disposable guest root authority must use already-trusted main helpers, never
same-target installed code to certify that target.

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
