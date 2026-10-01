# Phase 5F Final Security Review and Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the complete Phase 5 ledger/audit/approval surface on one exact main commit, add any missing adversarial regression tests, and close Phase 5 without widening capabilities.

**Architecture:** This is a hardening/review slice, not a feature slice. It exercises real local ledger + MCP + SSH test doubles across restart, concurrency, outage, replay, secret-retention, and mutation-uncertainty boundaries. Any discovered defect is fixed only through a fresh RED/GREEN loop before closure documentation.

**Tech Stack:** Full repository stack, Linux SO_PEERCRED, SQLite, MCP v2, pytest, self-hosted Ubuntu 26.04 x86 Python 3.13/3.14.

**Spec:** `docs/superpowers/specs/2026-10-01-phase-5-security-ledger-design.md`

## Global Constraints

- No raw shell, destructive filesystem mutation, OAuth, remote SIEM, reusable approvals, or new privilege surface in 5F.
- Closure requires one exact main commit and one successful authoritative self-hosted run.
- Do not mark Phase 5 complete while any Critical/Important review finding remains.
- Review must verify both source structure and executable adversarial evidence.
- Dirty historical worktrees/branches are not deleted unless independently proven safe.

## Review Focus

- Crash after approval consume but before SSH must leave approval consumed and no invented completion event.
- Ledger restart must not duplicate expiry events or resurrect consumed/expired state.
- MCP process must lack any grant/deny protocol route and direct SQLite/HMAC-key access.
- Every policy-gated path must fail closed on required pre-network ledger outage before SSH, including internal executor/filesystem callers; read-only filesystem approvals are included.
- Ledger frames/stored rows/full tracebacks must remain free of credentials, host keys, raw argv, env values, stdin, fs_write body/base64, and stdout/stderr bodies.

---

### Task 1: Build the Phase 5 adversarial integration matrix

**Files:**
- Create: `tests/integration/test_phase5_security.py`
- Modify existing Phase 5 test files only when a focused regression belongs with the owning component.

**Interfaces:**
- Consumes the complete 5A–5E runtime and test fixtures.
- Produces no new runtime interface; produces cross-component adversarial evidence.

- [ ] **Step 1: Add restart matrix for pending/granted/denied/expired/consumed approvals**
- [ ] **Step 2: Add concurrent single-use matrix for ssh_exec/fs_stat/fs_read/fs_mkdir/fs_write**
- [ ] **Step 3: Add current-policy-change matrix: DENY wins, ALLOW bypasses stale approval, APPROVAL_REQUIRED requires exact current binding**
- [ ] **Step 4: Add wrong principal/host/tool/path/argv-fingerprint/env/stdin/content/read-limit/effective-limit matrix**
- [ ] **Step 5: Add ledger outage at readiness, request/policy/consume/execution-start, and completion-audit boundaries; pre-network failures block transport, read-only completion failure returns `AuditPersistenceError`, otherwise-successful side-effecting post-attempt failure returns non-retryable audit-persistence-outcome-uncertain, and existing mutation uncertain/status-74 classifications remain more specific**

### Task 2: Secret-retention and authority-separation audit

**Files:**
- Create: `tests/integration/test_phase5_secret_retention.py`
- Create: `tests/integration/test_phase5_authority_separation.py`

**Interfaces:**
- Consumes ledger storage/protocol, API runtime, and MCP registry surfaces.
- Produces no new runtime interface; proves storage secrecy and grant-authority separation.

- [ ] **Step 1: Seed distinctive markers in credential refs/host keys/env/stdin/argv/fs_write/output; inspect captured ledger frames, SQLite rows, MCP/admin-visible responses, public errors, and full tracebacks. Raw argv/env/stdin/fs_write bodies must never cross the ledger protocol; only approved fingerprints/counts may appear, and stdout/stderr bodies must never be persisted**
- [ ] **Step 2: Assert execution socket has no grant/deny op and admin socket has no consume/execution op**
- [ ] **Step 3: Assert MCP registry has `approval_status`; ssh_exec/fs_stat/fs_read/fs_mkdir/fs_write accept only optional opaque `approval_id`; no grant/deny/audit-query/raw-shell/fs_move/fs_delete tool exists**
- [ ] **Step 4: Assert MCP process runtime receives ledger client socket config only, not database or HMAC-key path**

### Task 3: Host-agent and mutation invariant regression

**Files:**
- Modify: `tests/api/test_filesystem_approval_http.py`
- Modify: `tests/host_agent/test_filesystem_mutation.py` only if review finds a missing remote-side assertion.

**Interfaces:**
- Consumes Phase 5 mutation approval flow plus existing host-agent policy/primitives.
- Produces no new runtime interface; proves approval never overrides remote enforcement.

- [ ] **Step 1: Prove an approved request can still be independently denied by host-agent policy**
- [ ] **Step 2: Prove fs_mkdir remains one-level create-if-absent with 0700 maximum**
- [ ] **Step 3: Prove fs_write remains create-if-absent/O_TMPFILE/0600 and status 74 remains distinct**
- [ ] **Step 4: Prove consumed approvals are never restored after remote policy denial, timeout, status 69, status 74, cancellation, or transport uncertainty**

### Task 4: Whole-branch review and defect loop

**Files:**
- No predetermined production files; touch only owners of defects found by review.

**Interfaces:**
- Consumes all Phase 5 implementation diffs and spec invariants.
- Produces only focused regression fixes justified by a concrete review finding.

- [ ] **Step 1: Review exact diff from Phase 4 closure commit through Phase 5 head against all 18 spec invariants**
- [ ] **Step 2: For every concrete defect, use systematic-debugging to establish root cause**
- [ ] **Step 3: Add one focused failing regression test before each fix**
- [ ] **Step 4: Apply the smallest fix, rerun focused test, then full suite**
- [ ] **Step 5: Repeat until no Critical/Important finding remains**

### Task 5: Closure evidence and merge

**Files:**
- Modify: `docs/development-plan.md`
- Modify: `docs/superpowers/specs/2026-10-01-phase-5-security-ledger-design.md`
- Modify: `docs/mcp-api.md` if final public approval/error wording changed during hardening.

**Interfaces:**
- Consumes the final reviewed implementation and authoritative CI evidence.
- Produces the Phase 5 closure record; no capability widening is allowed here.

- [ ] **Step 1: Run fresh Ruff + compileall + full pytest locally/Linux**
- [ ] **Step 2: Push draft PR and record exact head SHA**
- [ ] **Step 3: Require hardened Ubuntu 26.04 x86 Python 3.13/3.14 exact-head CI success**
- [ ] **Step 4: Record final whole-surface review evidence, exact main implementation commit, authoritative run ID, registry surface, and deferred work**
- [ ] **Step 5: Merge if clean, then require the merge-main exact commit CI to succeed before marking Phase 5 complete**
