# Phase 5C Request and Audit Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Security Ledger mandatory for MCP runtime readiness and audit every request/policy/execution lifecycle while preserving current approval-required fail-closed behavior.

**Architecture:** The MCP boundary creates one `OperationContext` per tool call and passes it through service/execution adapters. A new audit-aware authorization gate evaluates current central policy inside `SSHExecutor`/`SSHFilesystemClient`, records policy facts, but in this slice still rejects `APPROVAL_REQUIRED` exactly as Phase 4 did. The ledger is mandatory before side-effecting network access.

**Tech Stack:** Existing MCP v2 server, Phase 5A/5B ledger client, PolicyEngine, SSHExecutor, SSHFilesystemClient, pytest.

**Spec:** `docs/superpowers/specs/2026-10-01-phase-5-security-ledger-design.md`

## Global Constraints

- No approval grant/consume behavior in 5C.
- No new MCP `approval_id` fields yet.
- Exactly one request ID is generated at MCP entry and reused in ledger + SSH/SMCP.
- Ledger outage must keep `get_connection()` call count at zero.
- `/healthz` remains ledger-independent; `/readyz` requires a successful ledger ping and performs no SSH.
- PolicyEngine remains pure; audit side effects live outside `PolicyEngine.evaluate`.
- Existing Phase 4 public tool outputs/errors remain stable except their request IDs now originate at MCP entry.
- Discovery/read-only calls are audited too; no tool silently bypasses the ledger after Phase 5C is enabled.

## Review Focus

- Cancellation between `execution_started` and remote completion must record `execution_cancelled` without inventing success.
- Ledger failure after policy allow but before transport must prevent SSH and surface one stable local failure; required `request_received`/policy/`execution_started` appends are all pre-network gates.
- Request ID must not fork into a second executor-generated ID.
- SDK-rejected malformed/secret-bearing input must not be copied into audit rows or public errors; valid handler invocations receive request identity only after schema validation.
- Readiness must fail when ledger is unavailable but health must remain 200 and no readiness probe may open SSH.

---

### Task 1: MCP OperationContext creation and propagation

**Files:**
- Modify: `src/ssh_over_mcp/api/server.py`
- Modify: `src/ssh_over_mcp/api/service.py`
- Modify: `tests/api/test_mcp_server.py`
- Modify: `tests/api/test_service.py`
- Modify: `tests/api/test_ssh_exec.py`
- Modify: `tests/api/test_filesystem.py`
- Modify: `tests/api/test_mkdir.py`
- Modify: `tests/api/test_write.py`

**Interfaces:**
- Consumes `new_request_id()`, `OperationContext`, trusted `PrincipalContext`.
- Every server tool creates context only after schema validation and principal retrieval; callers cannot supply request_id/principal_id.
- Service side-effecting methods receive `context: OperationContext` explicitly.
- Invalid SDK/schema calls which never enter the tool handler generate no domain audit row; tests must prove their secret-bearing invalid values stay out of public errors and ledger storage.

- [ ] **Step 1: Write failing tests proving one server-owned context per valid tool call**
- [ ] **Step 2: Verify RED**
- [ ] **Step 3: Thread context through server/service without changing behavior**
- [ ] **Step 4: Verify existing strict-schema tests still reject request_id/principal_id extras**
- [ ] **Step 5: Commit `Refactor: propagate MCP operation context`**

### Task 2: API ledger runtime and readiness

**Files:**
- Modify: `src/ssh_over_mcp/api/runtime.py`
- Create: `src/ssh_over_mcp/api/ledger_runtime.py`
- Modify: `src/ssh_over_mcp/api/app.py`
- Modify: `tests/api/test_runtime.py`
- Create: `tests/api/test_ledger_runtime.py`
- Modify: `tests/api/test_http_app.py`

**Interfaces:**
- `MCPRuntimeSettings` adds server-owned ledger socket path plus expected ledger UID/GID.
- Produces `build_ledger_client(settings) -> SecurityLedgerClient`.
- `readyz` calls ledger `ping()`; failure -> 503 stable JSON; `healthz` stays 200.

- [ ] **Step 1: Write failing config/readiness tests**
- [ ] **Step 2: Verify RED**
- [ ] **Step 3: Implement strict runtime parsing/client composition with sanitized failures**
- [ ] **Step 4: Verify app startup/readiness does not resolve SSH credentials or call `get_connection`**
- [ ] **Step 5: Commit `Feat: require Security Ledger readiness`**

### Task 3: Audit-aware policy gate inside SSH adapters

**Files:**
- Create: `src/ssh_over_mcp/approvals/authorization.py`
- Modify: `src/ssh_over_mcp/ssh/executor.py`
- Modify: `src/ssh_over_mcp/ssh/filesystem.py`
- Modify: `src/ssh_over_mcp/api/ssh_runtime.py`
- Create: `tests/approvals/test_authorization_audit.py`
- Modify: `tests/ssh/test_executor.py`
- Modify: `tests/ssh/test_filesystem_client.py`
- Modify: `tests/api/test_ssh_runtime.py`

**Interfaces:**
- Produces stable protocol `ExecutionAuthorizationGate.authorize(context: OperationContext, request: EvaluationRequest, facts: ApprovalExecutionFacts) -> Awaitable[PolicyDecision]`; 5D/5E replace only the implementation, not this SSH-adapter interface.
- The gate is the only runtime component which evaluates policy; after evaluation it calls `build_approval_binding(...)` when approval/audit binding material is needed. Callers never pre-evaluate policy to obtain normalized values.
- Produces concrete `AuditOnlyExecutionAuthorizer(policy, ledger)`.
- ALLOW: append `policy_allowed`, return decision.
- DENY: append `policy_denied`, raise existing `SSHPolicyDenied`.
- APPROVAL_REQUIRED: append `approval_required`, raise existing `SSHApprovalRequired`; no approval row creation yet.
- `SSHExecutor` and `SSHFilesystemClient` receive `authorizer`; raw `policy` is no longer their runtime authorization dependency.
- `SSHExecutor.execute(..., *, context: OperationContext, ...)` and every `SSHFilesystemClient` operation require `context` as a keyword-only argument. Remove their independent `request_id` override parameters and always use `context.request_id` so one call cannot fork correlation identity.

- [ ] **Step 1: Write failing policy-event/network-order tests**
- [ ] **Step 2: Verify RED**
- [ ] **Step 3: Implement `AuditOnlyExecutionAuthorizer` and inject it in `build_ssh_runtime`**
- [ ] **Step 4: Adapt exec/fs callers to build only `ApprovalExecutionFacts` from effective limits/payload fingerprints; verify the authorizer combines those facts with its own normalized `PolicyDecision` and no second policy evaluation occurs**
- [ ] **Step 5: Verify DENY/APPROVAL_REQUIRED/ledger failure all keep transport call count zero**
- [ ] **Step 6: Commit `Refactor: gate SSH through audited authorization`**

### Task 4: Request and execution audit lifecycle

**Files:**
- Create: `src/ssh_over_mcp/audit/recorder.py`
- Modify: `src/ssh_over_mcp/api/service.py`
- Modify: `src/ssh_over_mcp/api/errors.py`
- Modify: `src/ssh_over_mcp/ssh/executor.py`
- Modify: `src/ssh_over_mcp/ssh/filesystem.py`
- Create: `tests/audit/test_recorder.py`
- Create: `tests/api/test_audit_lifecycle.py`

**Interfaces:**
- Produces async `AuditRecorder` backed by async `SecurityLedgerClient.append_audit`.
- Existing sync discovery MCP wrappers become async wrappers so they can await audit I/O while keeping the pure `MCPService.list_hosts/get_host/explain_policy` methods synchronous.
- MCP boundary records `request_received` and bounded completion/failure for discovery/read-only calls.
- SSH adapters record `execution_started` immediately before first transport call and exact outcome event afterward.
- Outcome metadata includes only status/signal/duration/byte counts/timed_out/truncated; never stdout/stderr bodies.
- Produces stable `AuditPersistenceError` for required read-only/discovery audit persistence failures.
- If a required completion/outcome audit append fails after an otherwise-successful side-effecting transport attempt, return repository-owned `AuditPersistenceOutcomeUncertainError` containing `do not retry blindly`; never return ordinary success.
- If the remote classifier already produced `SSHRequestOutcomeUncertain` or `SSHFilesystemWriteCommittedUncertain`, preserve that more-specific non-retryable public classification even if its audit append also fails; do not collapse status 74 or generic mutation uncertainty into an ordinary audit error.

- [ ] **Step 1: Write failing tests for `request_received -> policy -> execution_started -> outcome` ordering and assert pre-network append failure leaves transport call count zero**
- [ ] **Step 2: Run `python -m pytest -q tests/audit/test_recorder.py tests/api/test_audit_lifecycle.py` and verify RED on missing lifecycle hooks/errors**
- [ ] **Step 3: Implement recorder plus lifecycle hooks with bounded outcome metadata only**
- [ ] **Step 4: Add cancellation RED: `execution_started -> execution_cancelled`, with no fabricated completed/failed event; implement minimal cancellation handling and verify GREEN**
- [ ] **Step 5: Add audit-persistence precedence REDs: read-only completion failure -> `AuditPersistenceError`; otherwise-successful ssh_exec/mutation post-attempt audit failure -> `AuditPersistenceOutcomeUncertainError`; existing mutation uncertain/status-74 classifications remain unchanged**
- [ ] **Step 6: Run the focused audit/API/SSH tests and require PASS with distinctive secret markers absent from stored rows, public errors, and full tracebacks**
- [ ] **Step 7: Commit `Feat: audit MCP execution lifecycle`**

### Task 5: Real HTTP fail-closed integration and merge gate

**Files:**
- Modify: `tests/api/test_http_app.py`
- Modify: `docs/development-plan.md`

**Interfaces:**
- Consumes the mandatory ledger-ready application and audited SSH adapters.
- Produces no new runtime interface; proves 5C fail-closed and correlation contracts for 5D.

- [ ] **Step 1: Run a real local ledger service + Streamable HTTP app integration test**
- [ ] **Step 2: Prove readiness failure and every required pre-network ledger append failure (`request_received`, policy event, `execution_started`) keep SSH connection count zero**
- [ ] **Step 3: Prove one request ID appears in MCP result, audit rows, and SMCP envelope**
- [ ] **Step 4: Run Ruff, compileall, full pytest**
- [ ] **Step 5: Whole-branch review: no unaudited side-effect path, no duplicate policy engine, no secret body retention**
- [ ] **Step 6: Exact-head self-hosted Python 3.13/3.14 CI; merge if clean**
