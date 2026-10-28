# FD-pinned fs_list primitive implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove a bounded, Linux FD-pinned, per-node authorized single-directory enumeration primitive without exposing an unsafe MCP tool.

**Architecture:** Add one inactive Host Agent implementation module with explicit `authorize_traverse`, `authorize_directory` and `authorize_child` callbacks supplied by a trusted, future signed policy authority; callbacks are invoked before corresponding descriptor opens/metadata reads. Only the future SMCP v2 + Host Policy v5 authenticated/epoch-bound layer may wire this primitive to MCP. Do not claim snapshot pagination or recursive search.

**Tech Stack:** Python 3.13+, `os.open`, Linux `O_PATH|O_NOFOLLOW`, `os.scandir(dir_fd)`, `os.fstat`, `pytest`.

**Spec:** `docs/superpowers/specs/2026-10-23-private-compose-rw-mvp-design.md`; `docs/decisions/0026-proposed-fs-visibility-v5-first.md` (proposed; do not interpret as approved runtime activation).

## Global Constraints

- No new MCP tool or SMCP v1 operation, no default enablement, no runtime host policy authorization based on an unauthenticated digest.
- No filesystem traversal through untrusted symlinks, and no client-supplied executable/SSH host.
- Every traversed directory prefix is authorized before its `os.open`; directory listing authorized before `os.scandir`; child authorization before `os.open` / `fstat` or result serialization.
- Hard ceiling 64 directory entries **scanned** per invocation; 64 result entries maximum; fail rather than truncate when limit is exceeded.
- Every path component is canonical strict UTF-8 (not lossy), without NUL, dot segments, slash ambiguity; deny overrides allow.
- Skip no errors silently, return no partial results, close every acquired fd in success/error/cancel paths, no data-capable open on a symlink/FIFO.
- Native Linux test is required; Mac may skip Linux `O_PATH` tests; broad CI/Native Level-3 must remain green before review/merge.
- This is a primitive, **not** a complete `fs_list` user feature: no central signed snapshot, epoch ACK, stable cursor, audit, budget integration or MCP tool until separately reviewed.

## Review Focus

1. A denied child name must never be passed to `os.open` or `stat`; test with monkeypatch.
2. Denied ancestry must stop traversal before opening any denied component; test nested root with callback trace.
3. Symlink/FIFO/special inode cannot trigger a data-capable open or be serialized as a regular file; test.
4. Concurrency during directory scan invalidates the enumeration rather than emitting a partial/stale result; test.
5. More than 64 physical directory entries fails even if most would be denied; test.

---

### Task 1: Linux FD-anchored bounded, per-child-authorized directory listing

**Files:**
- Create: `src/ssh_over_mcp/host_agent/visibility_listing_candidate.py`
- Create: `tests/host_agent/test_visibility_listing_candidate.py`
- Modify: `docs/decisions/0026-proposed-fs-visibility-v5-first.md`

**Interfaces:**
- Consumes: `filesystem._canonical_absolute_path`, `filesystem._open_root`, `filesystem._open_pinned_final`, `filesystem._same_read_identity`, `filesystem._result_stat` and `FilesystemAccessError` (not accessible from MCP).
- Produces: `list_directory_candidate(path: str, *, authorize_traverse: Callable[[str], bool], authorize_directory: Callable[[str], bool], authorize_child: Callable[[str], bool], max_entries: int = 64) -> tuple[ReadOnlyFileStat,...]`. It only succeeds with explicit true authorization at all three layers.

- [ ] **Step 1: Write failing tests.** Single small directory with sorted allowed files/subdirectories, denied child not opened, denied intermediate not opened, special symlink/FIFO refusal, over-limit refusal, invalid paths/limits and directory-changed-during-scan fail.
- [ ] **Step 2: Run RED.** `PYTHONPATH=src:. python -m pytest -q tests/host_agent/test_visibility_listing_candidate.py`; expect missing module/function (RED).
- [ ] **Step 3: Implement minimal candidate** using `O_PATH` descriptor pinned root/ancestors, `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK` reopening via `/proc/self/fd/<pinned>`, `scandir(fd)`, strict per-child authorization, bounded count before metadata, and sorted UTF-8 byte order.
- [ ] **Step 4: Run GREEN** targeted tests on Linux CI. Mac skip for OS-unavailable primitives, plus pure import validation; do not weaken Linux preconditions for Mac.
- [ ] **Step 5: Run lint/format, previous visibility contract tests and legacy SSH tests**, `git diff --check`, then update ADR with limitations and commit.

### Task 2: Mainline integration prerequisites (NOT YET AUTHORIZED; separate review gate)

**Files:**
- Future only: `ssh/protocol.py` new SMCP v2, host policy v5 authenticating snapshot, SSH/Host Policy adapters, `api/server.py`, audit/approval, tests.
- No code changes in Task 1 for these files.

**Interfaces:**
- Consumes: Task 1 primitive only after trusted `authorize_*` adapters have a verified MAC/signer, host + principal binding, monotonic epoch and revocation barrier.
- Produces: actual `fs_list` user function with 1–64 page size, coherent snapshot/cursor semantics, stable errors, double-checked centrally.

- [ ] **Step 1: Independent approval** of epoch/signer/revocation and stable-cursor protocols; ADR becomes accepted before runtime wiring.
- [ ] **Step 2: TDD for protocol downgrade, stale epoch, denied subtree and central result recheck** with genuine Linux E2E on isolated Mode A.
- [ ] **Step 3: Implement and verify exact-source remote `fs_list` over MCP → Ledger → SSH both nodes**; update security/policy/MCP API docs and test assertions, do not silently enable `fs_search`.
- [ ] **Step 4: Full CI + Native Level-3 + independent review before Ready, separate merge and deployment consent.**

### Task 1A: Authenticate the snapshot before FD enumeration (inactive candidate)

**Files:**
- Create: `src/ssh_over_mcp/host_agent/visibility_snapshot_v5.py`
- Test: `tests/host_agent/test_visibility_snapshot_v5.py`
- Modify: `src/ssh_over_mcp/host_agent/visibility_listing_candidate.py`

**Interfaces:** `sign_snapshot(payload, key)`, `verify_snapshot(signed, *, trusted_key, expected, active_host_policy, now, consume_snapshot_id)` and `list_verified_directory_candidate(verified, *, is_epoch_active)`. All are **private candidate helpers** with no runtime caller; none may be used with untrusted callback/active-policy/key inputs.

- [x] RED: missing module then missing adapter and `may_traverse`; recorded test-first failures.
- [x] GREEN: canonical domain-separated HMAC, strict identity/epoch/root/deny/TTL/budget fields, replay callback and fail-closed two-layer path intersection; Linux integration tests deny both central/local children and mid-scan epoch revocation.
- [x] Local lint/targeted protocol test and strict Linux skips (do not count skips as E2E).
- [ ] Fresh exact-HEAD hosted Ubuntu full suite and Linux callback/inode tests after push, before accepting the candidate checkpoint.

**Deferred security gates:** trusted provisioning of signer/verifier keys, persistent atomic nonce store, monotonic epoch and revocation ACK, expiry during traversal, entire SMCP v2 schema and trustworthy result verification. These are not optional for activating the feature.

### Task 1B: central deny-first policy projection and result recheck (INACTIVE)

**Files:**
- Create: `src/ssh_over_mcp/policy/visibility_compiler_v5.py`
- Test: `tests/policy/test_visibility_compiler_v5.py`

- [x] Write RED test; `ModuleNotFoundError` for candidate compiler.
- [x] GREEN: consume real `PolicyEngine` rule decisions, refuse complex
  paths, preserve inherited-role/global denies, hide `secrets/**` entry
  and descendants, return strictly root-bounded rules plus policy hash.
  Reject exact-root-only ALLOW and approval-required decisions.
- [x] Write RED test for absent central `reauthorize_list_paths` hook.
- [x] GREEN: central `evaluate` every returned direct child against
  the live policy, deny malformed/stale/duplicate/unsorted/over-limit
  results, check epoch guard before/throughout/after, no partial result.
- [ ] Run full exact-head Ubuntu CI and targeted Linux test suites on
  resulting commit. Remains no runtime activation.

### Task 1C: in-process Linux multi-root integration (not deployed E2E)

**File:** `tests/host_agent/test_visibility_pipeline_linux.py`

- [x] Construct test-only two logical host policies, compile central
  subtree rules, sign and verify against host-specific expected identity
  and local deny roots, inspect two real Linux test directories,
  reauthorize paths centrally. Assert cross-host snapshot replay and
  denied result injection are refused.
- [ ] Verify on a fresh exact-head Ubuntu 26.04 CI run. Do not count
  local macOS SKIP as Linux PASS or this kernel test as two-OpenSSH E2E.


### Task 1D: strict standalone v2 Host Agent read-only candidate (unregistered)

- [x] TDD RED→GREEN for `ssh/protocol_v2.py`: explicit magic,
  `mcp-v2`, versioned fs_list request and signed payload, no v1
  downgrade, strict metadata with duplicate-key/EOF/schema rejection.
- [x] TDD RED→GREEN for `host_agent/visibility_runtime_v5.py`:
  separate host-bound v5 config, owner-only private 0700 parent, secure
  no-follow key/config fd reads, persistent bounded nonce ledger.
- [x] TDD RED→GREEN for `host_agent/cli_v2.py`: separate uninstalled
  v2 entrypoint, verified request-to-host policy bindings, timestamp
  and policy freshness during FD listing, bounded output, fail-closed
  response. No v1 Host Agent change or live activation.
- [ ] Hosted Ubuntu CI (required; macOS skips real Linux FD case).
- [ ] Trusted configuration bootstrap and signer identity,
  monotonic epoch ACK/revocation cancellation, filesystem race audit,
  error contract, central result/metadata recheck, MCP/SSH/Ledger wiring,
  actual two-OpenSSH Mode A E2E, Native Level-3 and independent review.

**Ruling:** This increment is not an independently usable feature PR and
does not qualify #347 for Ready. It is intermediate work on the same
Draft PR. The full runtime activation design remains PROPOSED.

### Task 1E: operator-authorized control-plane adapter (unregistered)

- [x] Test-first `SSHFilesystemClient.list` with explicit trusted authority
  injection, signed compiled rules, inventory public-key identity and fixed v2.
- [x] Strict whole-response metadata validation and central path recheck,
  policy/epoch freshness across awaits, required audit failure refusal.
- [x] Local synthetic SSH/policy/approvals/audit and candidate regression.
- [ ] Production signer provisioning/epoch ACK authority, independent review,
  exact-head Linux CI, real two-node MCP/SSH and Native Level-3 evidence.

This newer operator-scoped increment supersedes Task 1's historical no-adapter
scope only for inactive local code. Task 2 runtime gates remain open. See ADR0027.


### Task 1E: operator-approved plan A rotation guard (isolated, uninstalled)

- [x] Operator approved stop/drain/rotate/bilateral attest/resume architecture,
  **not** runtime deployment or merger; record exact scope in ADR 0028.
- [x] TDD RED then GREEN for a candidate sequencer with 2 pinned hosts and
  exact expected epoch, policy digest and generation digest.
- [x] Refuse every failed stage (including false vs true proof), spoofed
  receipts and rollback. No ingress reopen before both host receipts.
- [x] TDD RED then GREEN for mutable release input: isolate deep copies and
  reject a trusted adapter attempting to rewrite the expected host keys.
- [ ] Implement and independently review a **real** durable ingress fence,
  zero-inflight proof and hostkey-authenticated two-host attestation adapter.
  A mocked callback is not a security proof. Do not install a live runner
  until full source+OS+network validation and independent review.
- [ ] Split administrator-owned immutable config/key (unwritable by the Host
  Agent UID) from the separate persistent Host Agent nonce/epoch DB; current
  euid-owned 0700 v5 trust loader is unsafe to activate.
- [ ] Run exact-head Linux CI, mandatory Native Level-3 and real two-node
  MCP/SSH/Ledger acceptance before PR Ready. No live deployment approved.
