# Phase 5E Filesystem Approval Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the same exact single-use approval gate to `fs_stat`, `fs_read`, `fs_mkdir`, and `fs_write` while preserving Phase 4 read-only and create-only safety invariants.

**Architecture:** `SSHFilesystemClient` already owns the Phase 5C `ExecutionAuthorizationGate` before typed SMCP transport. Phase 5E adds optional MCP approval handles to every filesystem tool that central policy can mark `APPROVAL_REQUIRED`. Read-only operations bind normalized path and effective read limits without mutation semantics; create-only operations additionally preserve the existing non-retryable mutation outcome classifications.

**Tech Stack:** Existing Phase 5 `ExecutionAuthorizer`, filesystem client, MCP v2, pytest.

**Spec:** `docs/superpowers/specs/2026-10-01-phase-5-security-ledger-design.md`

## Global Constraints

- Only `fs_stat`, `fs_read`, `fs_mkdir`, and `fs_write` gain optional `approval_id`.
- No mode/owner/recursive/parents/overwrite/append fields are introduced.
- `fs_read` 1 MiB MCP hard cap and `fs_write` 64 KiB decoded cap remain unchanged.
- Host-agent `read_roots`, `mkdir_roots`, `write_create_roots`, read/write byte limits, 0700/0600 modes, and create-if-absent primitives remain authoritative.
- Approval binding uses central normalized path for all filesystem tools.
- `fs_read` binding includes the effective/requested max-read byte limit.
- `fs_write` binding includes decoded content length + SHA-256 content fingerprint; raw file bytes/base64 never cross the ledger protocol.
- Approval consumption occurs before transport and is never restored after timeout, status 69, status 74, remote denial, cancellation, or any uncertain outcome.
- Clean status 74 remains distinct committed/durability-uncertain; approval must not collapse it into generic failure.
- Approval for one filesystem tool must never authorize another tool even for the same principal/host/path.
- There is still no fs_move/fs_delete/overwrite MCP tool.

## Review Focus

- Policy-configured approval for `fs_stat`/`fs_read` must be satisfiable; it must not remain a permanent approval-required dead end.
- Changing only `fs_read.max_bytes` must invalidate a previously granted read approval.
- Same path with one changed `fs_write` byte must require a different approval.
- Granted filesystem approval followed by central DENY must not consume or execute.
- Concurrent retries of one grant must produce at most one transport call; read-only and mutation tools cannot cross-authorize.

---

### Task 1: Read-only fs_stat/fs_read approval handles and exact bindings

**Files:**
- Modify: `src/ssh_over_mcp/api/models.py`
- Modify: `src/ssh_over_mcp/api/server.py`
- Modify: `src/ssh_over_mcp/api/service.py`
- Modify: `src/ssh_over_mcp/ssh/filesystem.py`
- Modify: `tests/api/test_filesystem.py`
- Modify: `tests/ssh/test_filesystem_client.py`

**Interfaces:**
- `FsStatRequest` gains only `approval_id: str | None`.
- `FsReadRequest` gains only `approval_id: str | None`.
- Service copies the opaque handle into `OperationContext.approval_id`; `EvaluationRequest` remains approval-unaware.
- `fs_stat` binding includes principal/profile, host, tool, normalized path, privilege, policy version, effective timeout/output bounds.
- `fs_read` binding additionally includes its effective/requested max-read byte limit.

- [ ] **Step 1: Write REDs where policy requires approval for fs_stat/fs_read; without approval assert transport call count is zero and an approval ID is returned**
- [ ] **Step 2: Run `python -m pytest -q tests/api/test_filesystem.py tests/ssh/test_filesystem_client.py -k 'fs_stat or fs_read'` and verify failures are the missing approval plumbing**
- [ ] **Step 3: Thread `approval_id` through `OperationContext` and use the existing internal authorizer; do not add policy evaluation in MCPService**
- [ ] **Step 4: Grant and retry exact fs_stat/fs_read operations; assert one consume then one transport call and unchanged read-only result schemas**
- [ ] **Step 5: Change only path/tool/read max-bytes and assert the old grant cannot be consumed; unknown/mismatched approval stays pre-network**
- [ ] **Step 6: Verify client-owned profile/request-id/SSH fields and existing read-size caps remain rejected**
- [ ] **Step 7: Commit `Feat: add approval gating to read-only filesystem tools`**

### Task 2: fs_mkdir approval handle and create-only binding

**Files:**
- Modify: `src/ssh_over_mcp/api/models.py`
- Modify: `src/ssh_over_mcp/api/server.py`
- Modify: `src/ssh_over_mcp/api/service.py`
- Modify: `src/ssh_over_mcp/ssh/filesystem.py`
- Modify: `tests/api/test_mkdir.py`
- Modify: `tests/ssh/test_filesystem_client.py`

**Interfaces:**
- `FsMkdirRequest` gains only `approval_id: str | None`.
- Binding includes principal/profile, host, `tool="fs_mkdir"`, normalized path, privilege, policy version, and effective timeout/output bound.
- Existing `ExecutionAuthorizationGate` interface is unchanged.

- [ ] **Step 1: Write REDs for approval-required mkdir, wrong binding, central DENY with granted approval, and concurrent replay**
- [ ] **Step 2: Run `python -m pytest -q tests/api/test_mkdir.py tests/ssh/test_filesystem_client.py -k fs_mkdir` and verify RED**
- [ ] **Step 3: Thread approval ID through `OperationContext` to the existing filesystem authorizer**
- [ ] **Step 4: Verify old client-owned mutation controls remain rejected and host-agent create-only semantics are unchanged**
- [ ] **Step 5: Verify concurrent replay yields exactly one transport call and loser remains pre-network**
- [ ] **Step 6: Commit `Feat: add approval gating to fs_mkdir`**

### Task 3: fs_write approval handle and content binding

**Files:**
- Modify: `src/ssh_over_mcp/api/models.py`
- Modify: `src/ssh_over_mcp/api/server.py`
- Modify: `src/ssh_over_mcp/api/service.py`
- Modify: `src/ssh_over_mcp/ssh/filesystem.py`
- Modify: `tests/api/test_write.py`
- Modify: `tests/ssh/test_filesystem_client.py`

**Interfaces:**
- `FsWriteRequest` gains only `approval_id: str | None`.
- Binding uses decoded bytes length and `fingerprint_bytes(data)`; raw bytes/base64 never enter ledger protocol/storage.
- Existing server-derived `content_length` remains the only SMCP content length.

- [ ] **Step 1: Write REDs for same-path/different-content binding, invalid approval, and central DENY with an otherwise-valid grant**
- [ ] **Step 2: Run `python -m pytest -q tests/api/test_write.py tests/ssh/test_filesystem_client.py -k fs_write` and verify RED**
- [ ] **Step 3: Add content fingerprint facts before the existing internal authorizer; do not alter SMCP write framing**
- [ ] **Step 4: Verify invalid/oversized base64 fails before approval creation and raw bytes/base64 are absent from captured ledger frames**
- [ ] **Step 5: Commit `Feat: bind fs_write approvals to content`**

### Task 4: Preserve mutation uncertainty and read-only semantics after consume

**Files:**
- Modify: `tests/api/test_filesystem.py`
- Modify: `tests/api/test_mkdir.py`
- Modify: `tests/api/test_write.py`
- Modify: `tests/api/test_http_app.py`
- Create: `tests/api/test_filesystem_approval_http.py`

**Interfaces:**
- Consumes approved read/mkdir/write authorization plumbing from Tasks 1-3.
- Produces no new runtime type; pins approval consumption to existing filesystem outcome semantics.

- [ ] **Step 1: Add end-to-end RED: approved fs_read returns the same binary-safe result and a consumed grant cannot be replayed**
- [ ] **Step 2: Add end-to-end RED: grant -> consume -> mkdir timeout -> approval stays consumed and public error remains mutation outcome uncertain**
- [ ] **Step 3: Add end-to-end RED: grant -> consume -> write clean status 74 -> approval stays consumed and committed/durability-uncertain remains distinct**
- [ ] **Step 4: Implement only missing plumbing; do not alter Phase 4 read/mutation outcome classifiers**
- [ ] **Step 5: Verify wrong tool/path/read-limit/content/principal/policy version fails before transport**

### Task 5: Audit lifecycle and secret-retention verification

**Files:**
- Modify: `tests/audit/test_recorder.py`
- Modify: `tests/api/test_filesystem_approval_http.py`

**Interfaces:**
- Consumes Phase 5C audit recorder and Phase 5E filesystem approvals.
- Produces no new runtime interface.

- [ ] **Step 1: Assert approval_required/granted/consumed/execution_started/outcome ordering for one read-only and one mutation operation**
- [ ] **Step 2: Assert audit DB/protocol/errors contain neither raw argv/env/stdin nor fs_write bytes/base64, hidden host metadata, or credentials**
- [ ] **Step 3: Assert status 74 emits `filesystem_write_committed_durability_uncertain`, not generic mutation/audit uncertainty**
- [ ] **Step 4: Assert read-only completion-audit persistence failure uses `AuditPersistenceError` while otherwise-successful side-effecting post-attempt audit failure follows the 5C non-retryable contract**

### Task 6: Full verification and merge gate

**Files:**
- Modify: `docs/development-plan.md`
- Modify: `docs/mcp-api.md`

**Interfaces:**
- Consumes the complete 5E filesystem approval surface.
- Produces reviewed evidence and public contract consumed by 5F.

- [ ] **Step 1: Document approval handles for fs_stat/fs_read/fs_mkdir/fs_write, exact binding fields, and mutation retry prohibition**
- [ ] **Step 2: Run `python -m ruff check src tests && python -m compileall -q src tests && python -m pytest -q` and require PASS**
- [ ] **Step 3: Whole-branch security review focuses on replay, read-limit/content binding, mutation uncertainty, create-only invariants, and secret retention**
- [ ] **Step 4: Require exact-head hardened Ubuntu 26.04 x86 Python 3.13/3.14 CI success**
- [ ] **Step 5: Merge only if review and CI are clean**
