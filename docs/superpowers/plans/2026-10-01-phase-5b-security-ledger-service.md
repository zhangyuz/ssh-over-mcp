# Phase 5B Security Ledger Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the local Security Ledger daemon with SQLite persistence, HMAC-bound single-use approvals, append audit, peer-separated execution/admin Unix sockets, and a local operator CLI, without integrating MCP execution yet.

**Architecture:** The ledger is a separate foreground process and OS identity. It owns the SQLite database and 32-byte HMAC key, exposes two pathname AF_UNIX/SOCK_STREAM endpoints, reuses the repository's hardened endpoint/peer-auth primitives, and serves the strict Phase 5A protocol. The MCP server is not changed in this slice.

**Tech Stack:** Python 3.13+, stdlib sqlite3/hmac/hashlib/socket, Pydantic v2, Linux SO_PEERCRED, pytest.

**Spec:** `docs/superpowers/specs/2026-10-01-phase-5-security-ledger-design.md`

## Global Constraints

- No TCP/HTTP listener.
- Reuse `UnixManagerEndpointPolicy`, `UnixContainmentManagerListener`, `LinuxPeerCredentialPolicy`, `authenticate_linux_unix_peer`, and `require_linux_process_identity` as hardened local-IPC/process primitives; do not refactor containment-manager behavior in this slice.
- Execution socket cannot invoke admin operations; admin socket cannot be selected by MCP input.
- SQLite uses WAL, `synchronous=FULL`, foreign keys ON, bounded busy timeout, explicit write transactions.
- Database/key paths are absolute and lexically canonical under trusted non-group/world-writable parents; an existing database/key path must be a non-symlink regular file, while a missing database may be created only after parent validation.
- Ledger data directory is owned by the ledger service identity and not group/world writable; database mode is 0600, HMAC key mode is 0400 or 0600, and key file contains exactly 32 raw bytes. Errors never print key/path contents.
- Approval TTL is ledger-owned: default = 600 seconds, hard max = 3600 seconds; execution/admin protocol requests carry no TTL field.
- Approval consume is atomic and single-use; crash after consume never restores grant.
- The database stores a non-secret SHA-256 HMAC-key ID; startup with a different key fails closed. Online key rotation is deferred.
- Application protocol exposes no audit UPDATE/DELETE.
- No MCP/API/SSH runtime integration in 5B.

## Review Focus

- Two concurrent consumers of one granted approval must yield exactly one success even across separate SQLite connections.
- A denied approval must retain active-binding dedup until expiry; consumed/expired approvals must release the binding for a future approval.
- Database/key symlinks or writable/replaced parent directories must fail startup before socket listen.
- Wrong execution/admin peer UID/GID must fail before protocol dispatch and must not leak the unauthorized request body.
- Restart after grant/consume/expiry must reconstruct state from SQLite without resurrecting approvals or duplicating expiry events.

---

### Task 1: Secure ledger storage settings and schema

**Files:**
- Create: `src/ssh_over_mcp/approvals/storage.py`
- Create: `tests/approvals/test_storage.py`

**Interfaces:**
- Produces `LedgerStorageSettings(db_path: Path, hmac_key_path: Path, service_uid: int, service_gid: int, busy_timeout_ms: int = 2000)`.
- Produces `load_ledger_hmac_key(settings) -> bytes`.
- Produces `LedgerDatabase.open(settings) -> LedgerDatabase`, `.close()`, and `.connection` internal access.
- Schema version is exactly 1 with tables `meta`, `approvals`, `audit_events`; `meta` stores the schema version and non-secret HMAC-key ID.
- `approvals.active_binding_hmac` is nullable UNIQUE; active pending/granted/denied rows retain it, expired/consumed rows clear it.

- [ ] **Step 1: Write failing path/key/schema tests**
- [ ] **Step 2: Verify RED with `python -m pytest -q tests/approvals/test_storage.py`**
- [ ] **Step 3: Implement path validation and exact 32-byte key load; open/create only after validating the trusted parent and reject symlink/non-regular existing paths**
- [ ] **Step 4: Implement SQLite pragmas/schema bootstrap with schema version + `sha256(hmac_key)` key ID in `meta`**
- [ ] **Step 5: Run `python -m pytest -q tests/approvals/test_storage.py` and require PASS including unknown schema-version, key-ID mismatch, unsafe-path, and traceback sanitization cases**
- [ ] **Step 6: Commit `Feat: add Security Ledger storage`**

### Task 2: Approval state machine and audit append transactions

**Files:**
- Create: `src/ssh_over_mcp/approvals/ledger.py`
- Create: `tests/approvals/test_ledger.py`
- Create: `tests/approvals/test_ledger_concurrency.py`

**Interfaces:**
- Consumes Phase 5A domain/binding types.
- Produces `SecurityLedgerStore(database, hmac_key, clock=utc_now, default_ttl_seconds=600, max_ttl_seconds=3600)`; the injectable clock returns timezone-aware UTC and all TTL/expiry decisions use this ledger-owned clock. Constructor validation requires `1 <= default_ttl_seconds <= max_ttl_seconds <= 3600`.
- Persisted approval/operator display fingerprint is a short prefix of the keyed binding HMAC, never an unkeyed digest of the full binding.
- Methods:
  - `append_audit(event: AuditEventInput) -> str`;
  - `ensure_approval(binding: ApprovalBindingInput, summary: ApprovalSafeSummary, request_id: str) -> ApprovalStatus`; expiry is derived only from ledger-owned `default_ttl_seconds`;
  - `get_approval(approval_id: str, *, principal_id: str | None = None, profile: str | None = None) -> ApprovalStatus | None`;
  - `grant(approval_id: str, *, operator_identity: str) -> ApprovalStatus`;
  - `deny(approval_id: str, *, operator_identity: str) -> ApprovalStatus`;
  - `consume(approval_id: str, binding: ApprovalBindingInput) -> ApprovalStatus`;
  - `list_active(limit: int = 100) -> tuple[ApprovalStatus, ...]`.
- Binding authorization uses `HMAC-SHA256(key, canonical_binding_bytes(binding))` and constant-time comparison.

- [ ] **Step 1: Write failing state/TTL/dedup tests, including concurrent ensure calls which must converge on one active approval ID**
- [ ] **Step 2: Verify RED**
- [ ] **Step 3: Implement ensure/get/grant/deny/expiry in explicit transactions; ensure/reuse appends one approval_required event for the current request, grant/deny append their decision event, and expiry transition appends exactly one approval_expired event**
- [ ] **Step 4: Add failing concurrent-consume/restart tests**
- [ ] **Step 5: Implement `BEGIN IMMEDIATE` consume transaction and same-transaction `approval_consumed` event**
- [ ] **Step 6: Verify exactly one concurrent consume succeeds and restart preserves consumed state**
- [ ] **Step 7: Verify raw test secrets are absent from database text dumps and exception tracebacks**
- [ ] **Step 8: Commit `Feat: add atomic approval ledger`**

### Task 3: Execution/admin protocol dispatchers and clients

**Files:**
- Create: `src/ssh_over_mcp/approvals/transport.py`
- Create: `src/ssh_over_mcp/approvals/dispatcher.py`
- Create: `src/ssh_over_mcp/approvals/client.py`
- Create: `tests/approvals/test_transport.py`
- Create: `tests/approvals/test_dispatcher.py`
- Create: `tests/approvals/test_client.py`

**Interfaces:**
- Produces synchronous one-shot `LedgerTransport.round_trip(frame: bytes) -> bytes` and `UnixLedgerTransport(socket_path: Path, expected_server: LinuxPeerCredentialPolicy, timeout_seconds=2.0)`; each round trip opens/connects one AF_UNIX/SOCK_STREAM socket, authenticates the server with SO_PEERCRED, exchanges one frame, and closes.
- Produces `ExecutionLedgerDispatcher(store).dispatch(request, *, peer: LinuxPeerCredentials)` accepting only ping/audit/ensure/status/consume.
- Produces `AdminLedgerDispatcher(store).dispatch(request, *, peer: LinuxPeerCredentials)` accepting only list/show/grant/deny; grant/deny derive operator identity exactly as `uid:<uid>:gid:<gid>` from `peer`, never from request data.
- Produces async `SecurityLedgerClient` and `SecurityLedgerAdminClient`; each public call uses `asyncio.to_thread` around one fresh `UnixLedgerTransport.round_trip`. Clients retain socket path + expected ledger peer policy, not a live socket, so daemon restart can recover without restarting MCP.

- [ ] **Step 1: Write failing wrong-operation and malformed-frame tests**
- [ ] **Step 2: Verify RED**
- [ ] **Step 3: Implement client one-request/one-response transport and prove wrong server UID/GID fails before response decoding**
- [ ] **Step 4: Implement server accepted-peer authentication, then dispatch exactly one decoded frame and close the connection**
- [ ] **Step 5: Implement execution/admin dispatchers with stable public error codes; assert admin operator identity comes only from authenticated peer credentials**
- [ ] **Step 6: Implement typed clients and response correlation checks**
- [ ] **Step 7: Verify cross-authority rejection and reconnect behavior: execution client cannot grant/deny, admin client cannot consume, and a new call succeeds after ledger service restart without recreating the client object**
- [ ] **Step 8: Commit `Feat: add Security Ledger local protocol`**

### Task 4: Two secure Unix endpoints and foreground service

**Files:**
- Create: `src/ssh_over_mcp/approvals/service.py`
- Create: `src/ssh_over_mcp/approvals/runtime.py`
- Create: `src/ssh_over_mcp/approvals/main.py`
- Modify: `src/ssh_over_mcp/approvals/__init__.py`
- Modify: `pyproject.toml`
- Create: `tests/approvals/test_service.py`
- Create: `tests/approvals/test_runtime.py`

**Interfaces:**
- Produces `SecurityLedgerRuntimeSettings` loaded from `SSH_OVER_MCP_LEDGER_*` environment values, including ledger process UID/GID, trusted data/key paths, execution/admin socket ownership/modes, and exact execution/admin peer UID/GID policies.
- Produces `SecurityLedgerService` owning execution/admin listeners, store, and shutdown; it verifies its own configured process identity before database/key open or socket creation and uses `select` over both hardened listener FDs to serve one authenticated one-frame connection at a time.
- New script: `ssh-over-mcp-ledger = "ssh_over_mcp.approvals.main:main"`.
- Execution/admin endpoint policies are constructed server-side from settings; protocol requests never contain socket/database/key paths.

- [ ] **Step 1: Write failing runtime/settings and dual-endpoint tests**
- [ ] **Step 2: Verify RED**
- [ ] **Step 3: Implement settings validation and service lifecycle**
- [ ] **Step 4: Verify wrong process/peer identity fails before request dispatch**
- [ ] **Step 5: Verify endpoint cleanup refuses inode replacement and never removes unrelated paths**
- [ ] **Step 6: Commit `Feat: add Security Ledger daemon`**

### Task 5: Operator approvalctl

**Files:**
- Create: `src/ssh_over_mcp/approvals/cli.py`
- Modify: `pyproject.toml`
- Create: `tests/approvals/test_cli.py`

**Interfaces:**
- New script: `ssh-over-mcp-approvalctl = "ssh_over_mcp.approvals.cli:main"`.
- Commands exactly: `list`, `show <approval_id>`, `grant <approval_id>`, `deny <approval_id>`.
- Operator identity comes from authenticated admin peer credentials; grant/deny protocol requests contain no caller-supplied actor field and CLI accepts no `--actor` override.
- CLI runs the async admin client with `asyncio.run`; it never opens SQLite/key files directly.

- [ ] **Step 1: Write failing CLI parsing/output tests**
- [ ] **Step 2: Verify RED**
- [ ] **Step 3: Implement bounded secret-safe output over `SecurityLedgerAdminClient`**
- [ ] **Step 4: Verify no database/key direct access and no secret values in output/errors**
- [ ] **Step 5: Commit `Feat: add local approval operator CLI`**

### Task 6: Full 5B adversarial verification and merge gate

**Files:**
- Modify: `docs/development-plan.md`
- Modify: `docs/superpowers/specs/2026-10-01-phase-5-security-ledger-design.md`

**Interfaces:**
- Consumes the complete 5B daemon/storage/client/CLI surface.
- Produces no new runtime interface; produces reviewed evidence required by 5C.

- [ ] **Step 1: Run all approvals/audit tests including Linux SO_PEERCRED/fork concurrency tests**
- [ ] **Step 2: Restart the real ledger service in tests and verify pending/granted/denied/consumed/expired persistence**
- [ ] **Step 3: Run Ruff, compileall, full pytest**
- [ ] **Step 4: Whole-branch security review focuses on filesystem races, peer auth, transaction atomicity, and secret retention**
- [ ] **Step 5: Exact-head self-hosted Ubuntu 26.04 x86 Python 3.13/3.14 gate**
- [ ] **Step 6: Merge only if review and CI are clean**
