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
