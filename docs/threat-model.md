# Threat model

## Protected assets

- managed hosts and services;
- production data;
- source code and deployment artifacts;
- SSH credentials and signing keys;
- Cloudflare Access/service-token credentials;
- audit records;
- policy and host inventory;
- secrets readable by managed workloads.

## Adversaries and failure modes

### Prompt-injected or compromised agent

Assume an MCP caller may request any syntactically valid tool operation, including operations contrary to operator intent.

Mitigation: server-side authorization, typed tools, role restrictions, approval for high-risk actions, OS-level boundaries.

### Malicious repository content

A permitted `npm test`, `pytest`, `make`, `cargo`, interpreter, or build tool can execute repository-controlled code.

Mitigation: execute development workloads as constrained OS identities or sandboxes; restrict filesystem and network access; do not treat a named build/test tool as inherently safe.

### Compromised MCP origin

An attacker may gain code execution in the control-plane container/process.

Mitigation: keep host credentials scoped; use one key/certificate profile per trust domain where possible; use remote `ForceCommand`; avoid root SSH service accounts; make remote OS permissions authoritative.

### Stolen SSH credential

Mitigation: dedicated non-login or ForceCommand accounts, no PTY/forwarding by default, host-local protocol validation, short-lived SSH certificates where practical.

### MITM / changed SSH host

Mitigation: pinned `known_hosts` entries or SSH host CA. Unknown/changed key fails closed.

### Policy bypass through shell syntax

Mitigation: normal execution uses executable plus argv rather than `shell=True`; raw shell is separate and privileged.

### Policy bypass through alternate executable

Mitigation: canonical executable resolution, profile-controlled executable paths, remote OS permissions, and capability classification.

### Filesystem path traversal or symlink escape

Mitigation: canonical path resolution for typed filesystem tools; use safe OS APIs where available; protected roots; remote OS permissions remain final boundary.

### Cgroup self-migration / containment escape

A repository-controlled workload may attempt to move itself from its
request-specific cgroup into the delegated root or a sibling cgroup if it shares
the containment manager's migration authority. Remaining inside the outer
delegated subtree is not sufficient because request-specific resource ceilings
and `cgroup.kill` would no longer cover the escaped process.

Mitigation: keep writable cgroup controls in a separate containment-manager
privilege domain; retain the pre-exec attach barrier; do not expose ancestor
membership controls to the workload; require a live self-migration test before
enabling remote execution.

### Credential exfiltration via logs

Mitigation: structured redaction, no secret environment logging, bounded output retention, access-controlled audit backend.

### Cloudflare or portal configuration error

Mitigation: origin authentication, private routing, no published host port, control-plane policy remains authoritative.

### Approval replay

Mitigation: approvals bind identity/profile, host, operation, normalized request hash, policy version, and expiration. One-time approvals SHOULD be consumed atomically.

## Explicitly out of scope for v1

- defending a fully privileged remote host after root compromise;
- kernel-level isolation guarantees;
- arbitrary Windows host administration;
- transparent SSH interactive terminal emulation for all clients;
- replacing enterprise PAM/SSH CA products.
