# Phase 5A Domain Contract and Canonical Binding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the trusted request identity, approval/audit domain types, canonical approval-binding representation, and strict ledger protocol models without changing runtime execution behavior.

**Architecture:** Phase 5A is pure domain infrastructure. It extends trusted principal identity, introduces one server-owned `OperationContext`, centralizes secret-safe payload fingerprints and deterministic binding serialization, and defines protocol messages used later by the Security Ledger. No socket, SQLite, MCP approval field, or SSH behavior changes in this slice.

**Tech Stack:** Python 3.13+, Pydantic v2, hashlib, canonical JSON, pytest, Ruff.

**Spec:** `docs/superpowers/specs/2026-10-01-phase-5-security-ledger-design.md`

## Global Constraints

- Python requirement remains `>=3.13`; no new third-party dependency.
- `PrincipalContext` becomes exactly `principal_id + profile`; both remain server-owned.
- Static identity is exactly `principal_id="static:" + profile`.
- Request IDs are server-generated `req_<32 lowercase hex chars>`.
- Approval IDs are server-generated `apr_<32 lowercase hex chars>` in later slices; clients never create them.
- Raw argv, env values, stdin, and fs_write bytes must never appear in ledger protocol/storage domain serialization.
- Payload fingerprints use `sha256:<64 lowercase hex chars>`.
- Canonical binding uses one fixed versioned JSON field set, UTF-8, sorted keys, and compact separators.
- This slice must not change MCP tool schemas, policy decisions, SSH transport, readiness, or network behavior.
- Authoritative merge gate remains hardened Ubuntu 26.04 x86 with Python 3.13 and 3.14 full suites.

## Review Focus

- Existing callers which construct `PrincipalContext(profile=...)` must fail visibly until updated; no compatibility default may make `principal_id` client-selectable.
- Equivalent env dictionaries with different insertion order must produce identical canonical binding bytes.
- Changing one argv boundary/value, env value, stdin byte, fs_write byte, effective timeout, or effective byte limit must change binding material without sending/persisting the raw sensitive value.
- Unsupported/non-finite numeric values must be rejected before canonicalization rather than serialized inconsistently.
- Protocol unions must reject extra fields and cross-operation fields so a later ledger dispatcher cannot accept ambiguous requests.

---

### Task 1: Trusted principal identity and OperationContext

**Files:**
- Modify: `src/ssh_over_mcp/api/models.py`
- Modify: `src/ssh_over_mcp/api/principal.py`
- Create: `src/ssh_over_mcp/api/context.py`
- Modify: `tests/api/test_principal.py`
- Create: `tests/api/test_operation_context.py`

**Interfaces:**
- Produces: `PrincipalContext(principal_id: str, profile: str)`.
- Produces: `new_request_id() -> str`.
- Produces: `OperationContext(request_id: str, principal: PrincipalContext, received_at: datetime, approval_id: str | None = None)`.
- Later tasks consume these exact names; no request context is stored in global/contextvar state.

- [ ] **Step 1: Write failing identity/context tests**

Assert:
- `StaticPrincipalProvider(profile="developer", ...).get_principal() == PrincipalContext(principal_id="static:developer", profile="developer")`;
- `PrincipalContext(profile="developer")` fails;
- `new_request_id()` matches `^req_[0-9a-f]{32}$` and is unique across a sample;
- `OperationContext` forbids extra fields, requires a timezone-aware UTC `received_at`, and rejects malformed request/approval IDs.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `python -m pytest -q tests/api/test_principal.py tests/api/test_operation_context.py`

Expected: FAIL because `principal_id`, `OperationContext`, and `new_request_id` do not exist.

- [ ] **Step 3: Implement the minimal trusted identity/context types**

Implement `PrincipalContext` as frozen/extra-forbid Pydantic, update `StaticPrincipalProvider`, and implement `OperationContext` plus `new_request_id()` in `api/context.py`.

- [ ] **Step 4: Run focused tests and update existing test fixtures**

Run: `python -m pytest -q tests/api/test_principal.py tests/api`

Expected: PASS after all repository-owned test principals explicitly include `principal_id="static:developer"` or the appropriate static profile identity.

- [ ] **Step 5: Commit**

```bash
git add src/ssh_over_mcp/api tests/api
git commit -m "Refactor: add trusted operation identity"
```

### Task 2: Audit and approval domain models

**Files:**
- Create: `src/ssh_over_mcp/audit/models.py`
- Modify: `src/ssh_over_mcp/audit/__init__.py`
- Create: `src/ssh_over_mcp/approvals/models.py`
- Modify: `src/ssh_over_mcp/approvals/__init__.py`
- Create: `tests/audit/test_models.py`
- Create: `tests/approvals/test_models.py`

**Interfaces:**
- Produces: `AuditEventType` enum with all event names from spec section 17.
- Produces: `AuditEventInput` safe append model; it contains IDs, safe summary/outcome metadata, never secret bodies.
- Produces: `ApprovalState = pending|granted|denied|expired|consumed`.
- Produces: `ApprovalSafeSummary`, `ApprovalStatus`, `ApprovalExecutionFacts`, and `ApprovalBindingInput`.
- `ApprovalStatus` contains approval ID, state, UTC-aware expiry, host, tool, risk, safe summary, and a short keyed-binding fingerprint field; it never exposes the full binding HMAC.
- `ApprovalExecutionFacts` contains only pre-policy execution facts the caller uniquely owns: effective timeout/output/stdin/tool byte limits plus stdin/fs_write length+SHA-256 fingerprints. It contains no normalized executable/path/cwd.
- `ApprovalBindingInput` is the complete fixed canonical field set from spec section 9 and is constructed only after a `PolicyDecision` exists.

- [ ] **Step 1: Write failing strict-model tests**

Pin exact enum values, frozen/extra-forbid behavior, ID formats, bounded summary fields, and the absence of fields named credential/private_key/token/stdin/body/stdout/stderr value containers.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest -q tests/audit/test_models.py tests/approvals/test_models.py`

Expected: FAIL because domain modules/types do not exist.

- [ ] **Step 3: Implement the domain models**

Use strict Pydantic models and exact spec state/event names. Keep raw payload fields out of the type system rather than relying on caller discipline.

- [ ] **Step 4: Verify GREEN**

Run: `python -m pytest -q tests/audit/test_models.py tests/approvals/test_models.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ssh_over_mcp/audit src/ssh_over_mcp/approvals tests/audit tests/approvals
git commit -m "Feat: add Phase 5 audit and approval domain models"
```

### Task 3: Secret-safe fingerprints and canonical binding

**Files:**
- Create: `src/ssh_over_mcp/approvals/binding.py`
- Create: `tests/approvals/test_binding.py`

**Interfaces:**
- Consumes: `PrincipalContext`, `EvaluationRequest`, `PolicyDecision`, `ApprovalExecutionFacts`, and `ApprovalBindingInput`.
- Produces: `fingerprint_bytes(value: bytes) -> str`.
- Produces: `fingerprint_text(value: str) -> str` using UTF-8 bytes.
- Produces: `fingerprint_argv(argv: tuple[str, ...]) -> str` using prefix `b"argv-v1\\x00"` plus one 4-byte big-endian UTF-8 byte length and exact UTF-8 bytes per argument before SHA-256.
- Produces: `build_approval_binding(principal: PrincipalContext, request: EvaluationRequest, decision: PolicyDecision, facts: ApprovalExecutionFacts) -> ApprovalBindingInput`.
- Produces: `canonical_binding_bytes(binding: ApprovalBindingInput) -> bytes`.

- [ ] **Step 1: Write failing determinism and sensitivity tests**

Assert:
- exact `sha256:` format;
- repeated canonicalization is byte-identical;
- dict insertion order does not alter bytes;
- each material field mutation changes bytes;
- `build_approval_binding` uses decision.normalized_executable/cwd/path and decision.policy_version; argv enters only as `argv_count + fingerprint_argv`, env values enter only as name+fingerprint pairs, and effective bounds/payload fingerprints come from `ApprovalExecutionFacts`;
- `("ab", "c")` and `("a", "bc")` produce different argv fingerprints, proving argument boundaries are length-delimited;
- raw argv/env/stdin/fs_write sample secrets are absent from ledger-safe fields and protocol serialization;
- non-finite timeout/limit input cannot instantiate `ApprovalExecutionFacts` or `ApprovalBindingInput`.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest -q tests/approvals/test_binding.py`

Expected: FAIL because binding helpers do not exist.

- [ ] **Step 3: Implement canonicalization**

Use `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)` over the model's fixed field set, then UTF-8 encode.

- [ ] **Step 4: Verify GREEN**

Run: `python -m pytest -q tests/approvals/test_binding.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ssh_over_mcp/approvals/binding.py tests/approvals/test_binding.py
git commit -m "Feat: add canonical approval binding"
```

### Task 4: Versioned Security Ledger protocol models

**Files:**
- Create: `src/ssh_over_mcp/approvals/protocol.py`
- Create: `tests/approvals/test_protocol.py`

**Interfaces:**
- Produces strict discriminated request/response unions for:
  - execution socket: `ping`, `append_audit`, `ensure_approval`, `approval_status`, `consume_approval`;
  - admin socket: `list_approvals`, `show_approval`, `grant_approval`, `deny_approval`.
- Produces `LEDGER_PROTOCOL_MAGIC = b"SLED\\x00\\x01"`.
- Produces `MAX_LEDGER_MESSAGE_BYTES = 64 * 1024`.
- Produces `encode_ledger_message(model) -> bytes`, `decode_ledger_request(frame)`, and `decode_ledger_response(frame)`.
- Every message carries `version=1` and `message_id` matching `^msg_[0-9a-f]{32}$`.

- [ ] **Step 1: Write failing framing/schema tests**

Cover round-trip, wrong magic/version, truncated/oversized frame, extra fields, wrong operation fields, invalid IDs, response/request discriminator confusion, and explicit rejection of caller-supplied TTL, operator identity, or binding-HMAC fields on all execution/admin requests. Assert a maximum legal binding using maximum bounded executable/cwd/path strings, all 256 argv entries, the maximum env-name set, and all payload/limit fingerprints remains below `MAX_LEDGER_MESSAGE_BYTES` because raw argv/env values/payload bytes are fingerprinted rather than framed.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest -q tests/approvals/test_protocol.py`

Expected: FAIL because protocol module does not exist.

- [ ] **Step 3: Implement protocol-only models/framing**

Follow the existing containment-manager framing pattern; do not add socket or storage behavior.

- [ ] **Step 4: Verify GREEN and full slice regression**

Run:
`python -m pytest -q tests/approvals tests/audit tests/api/test_principal.py tests/api/test_operation_context.py`

Expected: PASS.

- [ ] **Step 5: Run repository static/full verification**

Run: `python -m ruff check src tests && python -m compileall -q src tests && python -m pytest -q`

Expected: PASS with only existing live-only skips/deprecation warnings.

- [ ] **Step 6: Commit**

```bash
git add src/ssh_over_mcp/approvals tests/approvals
git commit -m "Feat: define Security Ledger protocol"
```

### Task 5: Slice documentation and merge gate

**Files:**
- Modify: `docs/development-plan.md`
- Modify: `docs/superpowers/specs/2026-10-01-phase-5-security-ledger-design.md`

**Interfaces:**
- No runtime interface changes.

- [ ] **Step 1: Record Phase 5A implemented scope and explicitly state no runtime behavior change**
- [ ] **Step 2: Run `git diff --check` and the full Python 3.13 local gate**
- [ ] **Step 3: Request whole-branch security review; fix any Critical/Important finding with RED/GREEN**
- [ ] **Step 4: Push draft PR and require exact-head hardened Ubuntu 26.04 x86 Python 3.13/3.14 success**
- [ ] **Step 5: If review and CI remain clean, mark ready and squash merge**
