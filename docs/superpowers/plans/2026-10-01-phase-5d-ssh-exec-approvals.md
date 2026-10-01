# Phase 5D Approval-Aware ssh_exec Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add exact single-use operator approval to `ssh_exec` plus read-only `approval_status`, without exposing grant/deny authority to MCP.

**Architecture:** Replace the Phase 5C audit-only gate with `ExecutionAuthorizer`. It re-evaluates policy on every attempt, creates/reuses approval rows for approval-required decisions, atomically consumes a matching grant before transport, and leaves explicit DENY terminal. MCP receives only an opaque optional `approval_id` and a read-only status tool.

**Tech Stack:** Phase 5 ledger service/client, PolicyEngine, MCP v2, Pydantic, pytest.

**Spec:** `docs/superpowers/specs/2026-10-01-phase-5-security-ledger-design.md`

## Global Constraints

- Only `ssh_exec` gains optional `approval_id` in 5D.
- MCP cannot grant, deny, select TTL, submit binding HMAC, or choose principal/profile.
- Existing ALLOW executions do not consume irrelevant old approvals.
- DENY wins even if caller supplies a granted approval.
- APPROVAL_REQUIRED without usable grant creates/reuses pending approval and never opens SSH.
- Consume occurs atomically before first SSH connection attempt.
- Consume authorizes one attempt; any later SSH/remote failure leaves approval consumed.
- Current policy version and all material normalized inputs/effective bounds must match binding.
- `approval_status` is read-only and principal-scoped; hidden/unknown IDs have one public not-visible error.
- Current SDK approval-required error text carries request_id/approval_id/state/expiry; no structured error dependency.

## Review Focus

- Granted approval supplied after policy changes to ALLOW must execute without consuming the stale approval.
- Wrong principal with a guessed approval ID must not reveal whether the ID exists.
- Concurrent identical retries with one grant must yield one consume/one execution; the loser must not reach SSH.
- Changing only argv, stdin/env value, timeout, or output bound must invalidate approval despite identical executable/path; raw argv/env/stdin must not cross the ledger protocol.
- Crash/failure after consume but before SSH must not recreate or refund the approval.

---

### Task 1: Approval-aware ExecutionAuthorizer

**Files:**
- Modify: `src/ssh_over_mcp/approvals/authorization.py`
- Modify: `tests/approvals/test_authorization_audit.py`
- Create: `tests/approvals/test_execution_authorizer.py`

**Interfaces:**
- Produces `ExecutionAuthorizer(policy, ledger)` implementing the Phase 5C `ExecutionAuthorizationGate`; approval TTL remains entirely ledger-owned.
- `async authorize(context, request, facts: ApprovalExecutionFacts) -> PolicyDecision`; it evaluates policy once, then builds the complete `ApprovalBindingInput` internally from the returned normalized decision.
- On APPROVAL_REQUIRED/no approval: `ledger.ensure_approval(...)` creates/reuses the approval and atomically appends the one `approval_required` event for this request; the authorizer must not append a duplicate event, then raises a repository-owned approval-required exception carrying safe approval status.
- On supplied approval: call atomic `consume_approval` only after the same authorization call evaluates current policy and reconstructs the exact binding; there is no caller-side policy preflight.

- [ ] **Step 1: Write failing deny/allow/pending/granted tests**
- [ ] **Step 2: Verify RED**
- [ ] **Step 3: Implement policy re-evaluation and approval create/consume flow**
- [ ] **Step 4: Add REDs for policy-version mismatch, wrong binding/principal, concurrent replay, and policy-change-to-ALLOW; include one argv-only change proving `argv_count/argv_fingerprint` invalidates the old grant without raw argv in ledger frames**
- [ ] **Step 5: Implement exact error normalization without exposing binding HMAC or raw secret values**
- [ ] **Step 6: Verify ledger failure and consume failure keep transport call count zero**
- [ ] **Step 7: Commit `Feat: add single-use execution authorizer`**

### Task 2: ssh_exec approval_id MCP contract

**Files:**
- Modify: `src/ssh_over_mcp/api/models.py`
- Modify: `src/ssh_over_mcp/api/server.py`
- Modify: `src/ssh_over_mcp/api/service.py`
- Modify: `src/ssh_over_mcp/api/errors.py`
- Modify: `tests/api/test_ssh_exec.py`
- Modify: `tests/api/test_mcp_server.py`

**Interfaces:**
- `SSHExecRequest` gains `approval_id: str | None` matching approved ID format.
- `OperationContext.approval_id` receives that value; no raw approval field enters `EvaluationRequest`.
- Approval-required public text format is stable and contains request ID, approval ID, state, expiry, and exact-retry instruction only.

- [ ] **Step 1: Write failing strict-schema and error-text tests**
- [ ] **Step 2: Verify RED**
- [ ] **Step 3: Add optional opaque field and service/context plumbing**
- [ ] **Step 4: Verify extra grant/ttl/binding fields are rejected and malformed secret-bearing IDs are sanitized**
- [ ] **Step 5: Commit `Feat: expose ssh_exec approval handle`**

### Task 3: Read-only approval_status tool

**Files:**
- Modify: `src/ssh_over_mcp/api/models.py`
- Modify: `src/ssh_over_mcp/api/server.py`
- Modify: `src/ssh_over_mcp/api/service.py`
- Create: `tests/api/test_approval_status.py`

**Interfaces:**
- Request: `ApprovalStatusRequest(approval_id: str)`.
- Result: approval ID, state, UTC-aware expiry serialized by Pydantic, host, tool, risk, safe summary, and short keyed-HMAC fingerprint prefix.
- Tool annotation: read-only, non-destructive, closed-world.
- Service queries through `SecurityLedgerClient` using current trusted principal/profile.

- [ ] **Step 1: Write failing visible/hidden/expired/status schema tests**
- [ ] **Step 2: Verify RED**
- [ ] **Step 3: Implement principal-scoped status lookup**
- [ ] **Step 4: Verify unknown and other-principal IDs return identical not-visible public errors**
- [ ] **Step 5: Verify there is still no MCP grant/deny tool**
- [ ] **Step 6: Commit `Feat: add read-only approval_status tool`**

### Task 4: Real HTTP approval round trip

**Files:**
- Modify: `tests/api/test_http_app.py`
- Create: `tests/api/test_approval_http.py`

**Interfaces:**
- Consumes `ExecutionAuthorizer`, `approval_id`, `approval_status`, and the admin client.
- Produces no new runtime interface; proves the end-to-end retry/consume contract.

- [ ] **Step 1: Start real ledger + MCP app with an approval-required ssh_exec policy**
- [ ] **Step 2: Call ssh_exec without approval and prove `get_connection()==0` while pending ID is returned**
- [ ] **Step 3: Grant through admin client, retry exact operation with approval_id, prove one consume then one SSH attempt**
- [ ] **Step 4: Retry the consumed approval and prove `get_connection` count does not increment; also prove a connection/remote failure after consume leaves the approval consumed**
- [ ] **Step 5: Mutate argv/env/stdin/timeout and prove old grant cannot be consumed; inspect captured ledger frames to prove raw argv/env/stdin values are absent**
- [ ] **Step 6: Verify audit ordering includes approval_required/granted/consumed/execution_started/outcome**

### Task 5: Full verification and merge gate

**Files:**
- Modify: `docs/development-plan.md`
- Modify: `docs/mcp-api.md`

**Interfaces:**
- Consumes the complete 5D ssh_exec approval surface.
- Produces reviewed public contract/evidence consumed by 5E.

- [ ] **Step 1: Document exact approval retry/status contract**
- [ ] **Step 2: Run Ruff, compileall, full pytest**
- [ ] **Step 3: Whole-branch security review focuses on self-approval, replay, oracle leakage, policy-change semantics, and network ordering**
- [ ] **Step 4: Exact-head hardened Ubuntu 26.04 x86 Python 3.13/3.14 CI**
- [ ] **Step 5: Merge if and only if review and CI are clean**
