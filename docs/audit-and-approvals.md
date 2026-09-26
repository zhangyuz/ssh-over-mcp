# Audit and approvals

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

- secret environment values;
- SSH private keys/certificates;
- Access service tokens;
- full stdin when it may contain secrets;
- unlimited stdout/stderr;
- bearer tokens or OAuth tokens.

## Decision events

At minimum:

- request_received;
- policy_denied;
- approval_required;
- approval_granted/denied/expired;
- execution_started;
- execution_completed/failed/cancelled;
- host_key_failure;
- remote_policy_denied.

## Approval binding

Approvals SHOULD bind:

- trusted identity/profile;
- target host;
- tool/operation;
- normalized request hash;
- privilege scope;
- policy version;
- expiration;
- optional single-use nonce.

Changing any bound field invalidates the approval.

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

Audit logs SHOULD be exported to append-oriented remote storage or SIEM in addition to local logs. Local process/container logs are not sufficient as the only record because the controlled environment may be compromised or deleted.
