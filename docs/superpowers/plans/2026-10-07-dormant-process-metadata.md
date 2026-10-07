# Dormant Process Metadata Implementation Plan

> **For agentic workers:** Preserve the chosen native execution method: implement locally with RED → minimal GREEN, then independent whole-branch review. Tasks use checkbox syntax. Read the approved spec and repository development methodology before implementation.

**Goal:** Add only pure bounded parsing and rejection predicates for diagnostic metadata, as the next small component of native preflight.

**Architecture:** One dormant stdlib module parses detached stdout bytes into immutable records. Its private snapshot predicate validates a supplied observation; it performs no observation itself and grants no process ownership, receipt, filesystem access or cleanup permission. Later trusted native integration must supply the actual inspection PID and exclusively captured ps PID, call the predicate for both snapshots, and preserve all remaining preflight gates.

**Tech Stack:** Python 3.13/3.14 stdlib, pytest, Ruff. No package, installer, lock, compiler, workflow or production change.

**Spec:** `docs/superpowers/specs/2026-10-06-incident-staging-inspection-design.md`, Root provenance / Fresh bounded process preflight / Acceptance; ADR 0012, Later inspections and detectable leftover diagnostics.

**Status:** Proposed written plan; not approved for implementation. The design/ADR authority is already approved and on main. Preserve native execution; this document requires its own review/approval before implementation.

## Baseline and immutable authority

Start implementation from the then-current clean main only after this written plan is approved; record that exact base and baseline tests. PR #149 merged the fixed capture helper as `cec7dd463b984edcecb652bdf7c11188fbc5ae5a`, reviewed exact head `2bb6e8a7a7243db4098ec8315ff75e77eec7a8f2`, exact-head CI `37653348533` PASS. Its independent final review found 0 Critical/Important/Minor after the low-FD uncertainty fix. Developer native evidence: 95 diagnostic passes per Python version including 18 native, zero eligible skips; 498 related passes on 3.13. Full Mac runs retain the exact same 84 failures as clean main and are not full Mac GREEN. Exact merge-main run `37654059386` passed ordinary Python 3.13/3.14 validation; its automatic Level-3 refused before guest with stale provider state, exit 70. Provider absence failed, checkout cleanup passed, overall run failed. Authority/checkout/target all bind exact `cec7dd4`; no Level-3/A1 closure credit.

Retain the same already-main normative authority, **`1ddebe541ee80c0febc4cd35072f3a5046fac5cb`**. No replacement mapping, status edit or future merge SHA may certify the target. Verify these exact blobs and checkout bytes before implementation; keep them unchanged:

| Fixed path | Bytes | SHA-256 |
| --- | ---: | --- |
| `docs/decisions/0011-incident-bound-e2e-staging-recovery.md` | 11227 | `c98f99d29f8e02bae4c90f56565241818f23e10a229afcecafbebd2a91b43e3b` |
| `docs/decisions/0012-owned-diagnostic-child-lifecycle.md` | 11238 | `980801f685dba9eee8a8e76c0e39641fd7aa61d5c3453ecd6e10d9ba5f4a51a3` |
| `docs/superpowers/specs/2026-10-06-incident-staging-inspection-design.md` | 22821 | `650d65243e023f647e4c7424357ad1e2b19d6317eb603cfa1bebde388e358882` |

Pure parsing does not authenticate these bytes or its inputs at runtime. The existing fixed capture helper and later native integration must retain the same runtime authority binding; passing parser tests is never authority verification.

## Global constraints

- No signal, spawn, wait, process lookup, file read/write, network, environment lookup, path resolution, import-time host action, CLI or workflow caller. In particular, no live incident observations in tests.
- Do not change `staging_diagnostics.py`, its command/FD/lifetime interfaces, `src/`, workflows, provider or recovery APIs. Self-hosted CI only.
- Exact bytes only: reject str, bytearray and other coercible values. Fixed public failure text: `staging process metadata rejected`; return no partial records on error.
- Temp stdout: at most **1024 bytes**, exactly one ASCII native `/var/folders/<two lowercase alphanumeric characters>/<nonempty lowercase alphanumeric-or-underscore token>/T/` path with one final LF, no other controls. Map only the literal `/var` prefix to `/private/var`; no normalization, arbitrary symlink resolution or fallback.
- Process stdout: at most **65536 bytes**, at most **256 nonempty rows**, each raw line at most **4096 bytes excluding its LF**. Nonempty input must end with LF. Blank LF-only lines may be ignored within the total byte bound; whitespace-only rows refuse.
- Row grammar: optional ASCII-space PID padding, canonical positive decimal PID, a greedy one-or-more ASCII-space field separator, then a nonempty printable ASCII command. Reject tabs/CR/NUL/DEL/non-ASCII, leading/trailing spaces in the command, duplicate PIDs and missing fields. Accept embedded command spaces without splitting/rejoining them.
- Additional fail-closed scalar ceiling proposed for review: PID **1..2147483647**, at most ten digits. Inspection and ps identity parameters must be exact int values in that range, distinct; bool never counts as int. This is a representation bound, not permission to signal or infer ownership.
- Classify only the literal last slash-delimited command component, ASCII case-insensitively; never consult the filesystem. No caller patterns or suffix-version parser.
- Require exactly one inspection row with basename starting `python` or `pypy`, and exactly one own-ps row with basename exactly `ps`. Reject every other python/pypy prefix, every `getconf` row and every additional `ps` row.
- Reject basenames starting `qemu-system-`, exact `qemu-img`, and the fixed authority basenames `run-live-local-e2e-orchestrator.py`, `ssh-over-mcp-live-e2e-gate`, `recover_provider.py`, including mixed case.
- Unknown/malformed observations refuse. No retries, skipped checks or weaker alternate parser. These are predicates on supplied data, not proof the data was observed, complete or fresh.
- Unknown `recover.cc8Del`, provider marker/staging, incident PID 38013 and running E2E remain untouched. N1c remains paused. No A1/Level-3/phase closure or cleanup credit.

## Files and interfaces

Create `ops/live-e2e/staging_process_metadata.py` with only pure records/parsers/predicate. Create `tests/ops/test_live_e2e_staging_process_metadata.py`; update `tests/live/README.md` with actual counts and component-only limits. Do not import the capture helper or add a native entrypoint in this slice.

Task 1 produces frozen/slotted `TempParent(native_path: str, canonical_path: str)`, `ProcessRow(pid: int, command: str)`, fixed-text `ProcessMetadataError(RuntimeError)`, private `_parse_temp_parent(stdout: bytes) -> TempParent` and `_parse_process_rows(stdout: bytes) -> tuple[ProcessRow, ...]`.

Task 2 consumes those exact types and produces private `_require_snapshot(rows: tuple[ProcessRow, ...], *, inspection_pid: int, own_ps_pid: int) -> None`. Revalidate exact tuple/record/scalar shapes, row count, unique PIDs, command ASCII/control/edge-space, individual line-size and aggregate representability constraints before classification so forged intermediate records cannot bypass parser bounds. The shortest legal serialization of each record is canonical decimal PID + one ASCII space + command + LF: its line excluding LF must be at most 4096 bytes and the sum including every LF must be at most 65536 bytes. This is a necessary representability check only; original padding, blank lines, source, freshness and actual capture byte count are not authenticated by detached records. A command must have a nonempty final slash-delimited component; no filesystem semantics are inferred. A return of None is only a successful predicate; it supplies no capability or accepted preflight object.

Later trusted integration derives `inspection_pid` internally from its own process and `own_ps_pid` from that exact invocation's completed `DiagnosticCapture.child_pid`. No model/tool/workflow input may supply those identities. This pure unit interface must never become a public inspection override.

## Review focus

1. Malformed or overlarge input must refuse before expensive decoding/integer allocation and never produce a partial result — Task 1 boundary/type tests.
2. Whitespace/path tricks must not change the command basename or native temp-root interpretation — Task 1 grammar/alias tests.
3. Prefix near-misses and mixed-case interpreters must not become ordinary processes — Task 2 literal classification vectors.
4. Claimed own identity must not hide an extra ps/getconf or missing/mismatched inspection row — Task 2 identity/both-stage vectors.
5. Pure validation must not acquire host authority or turn supplied PID/metadata into ownership — Task 2 no-host-action tests and explicit later-gate documentation.

## Task 1: Bounded immutable diagnostic parsers

**Consumes:** detached bytes and Global Constraints. **Produces:** the Task 1 interfaces above.

- [ ] **Step 1: Write RED.** Add `test_temp_parent_literal_alias_and_shape`, `test_temp_parent_refuses_controls_extra_lines_and_environment_style_paths`, `test_process_rows_preserve_command_spaces`, `test_bytes_rows_line_pid_bounds`, `test_duplicate_noncanonical_pid_and_wrong_types_refuse`, `test_records_are_immutable_and_failure_has_no_partial_output`. Pin literal values rather than deriving expected vectors from implementation. Cover 1024/1025 and 65536/65537 byte equality/overflow, 4096/4097 line lengths, 256/257 rows, exact PID endpoints, LF/control/whitespace ambiguity and unsupported shapes. Valid byte-limit vectors must also meet every other bound; do not let a row-count failure mask byte-equality behavior.

  ```python
  def test_temp_parent_literal_alias_and_shape(metadata):
      value = metadata._parse_temp_parent(b"/var/folders/ab/token_123/T/\n")
      assert value.native_path == "/var/folders/ab/token_123/T/"
      assert value.canonical_path == "/private/var/folders/ab/token_123/T/"
  ```

- [ ] **Step 2: Run RED.** `PYTHONPATH=src python -m pytest tests/ops/test_live_e2e_staging_process_metadata.py -q -o addopts=--import-mode=importlib`. Expected missing module/interfaces or intended assertions, not collection/dependency/platform errors. Preserve actual output.
- [ ] **Step 3: Implement the exact Task 1 interfaces.** Check exact byte type/length before decoding, raw line lengths/counts before record creation, canonical PID text/length before int conversion. Use lexical matching and immutable detached records only; no filesystem/env fallback or process classification yet.
- [ ] **Step 4: Run GREEN and commit.** Same focused command PASS; full Ruff `src tests ops/systemd ops/live-e2e`, new module/test compile and diff check PASS. Record counts. Commit parser module/tests only.

## Task 2: Pure snapshot rejection and slice evidence

**Consumes:** Task 1 records/errors/parsers. **Produces:** `_require_snapshot` and README evidence; no capture/preflight caller.

- [ ] **Step 1: Write RED.** Add `test_exact_distinct_own_identities_required`, `test_interpreter_prefix_vectors_and_case_fold`, `test_fixed_qemu_authority_and_leftover_names_refuse`, `test_both_snapshot_stage_vectors_reject_orphans`, `test_forged_intermediate_records_refuse`, `test_forged_snapshot_aggregate_equality_and_overflow`, `test_import_and_validation_perform_no_host_action_or_output`. Assert one own inspection and one own ps required; missing/wrong/duplicate/conflated identities, extra ps, any getconf and every other interpreter prefix refuse. Pin `Python`, `python3.13td`, `python3.7dm`, `pypy3.10dm`, `python3..13`, `python3.13tdx`, `python-tools` and mixed case. Positive vector includes only the two correct own rows and bounded ordinary rows. Both-stage vectors use different fresh ps PIDs, put the adversary only in before then only in after, and exercise the same predicate; never claim actual two-snapshot wiring from these vectors. Pin forged correct-own-row plus 18 ordinary 4000-character-command records: their shortest legal encoding exceeds 72000 bytes and must refuse despite valid row/line bounds. For aggregate equality, use own records (411, "Python") and (512, "ps"), 15 ordinary records with PIDs 1000..1014 and 4091 ASCII z characters each, and (1015, 4057 ASCII z characters): shortest legal serialization is exactly 65536 bytes and must pass. Increase only the last command to 4058 characters for 65537-byte refusal; every PID/row/line bound still passes. Assert those independent literal lengths before invoking the predicate; do not build expected totals with an implementation serializer.

  ```python
  def test_extra_ps_cannot_become_owned(metadata):
      rows = metadata._parse_process_rows(
          b"411 /framework/Python\n512 /bin/ps\n613 /bin/Ps\n"
      )
      with pytest.raises(metadata.ProcessMetadataError):
          metadata._require_snapshot(rows, inspection_pid=411, own_ps_pid=512)
  ```

- [ ] **Step 2: Run RED.** Same focused command, filtered to new predicate cases; expected missing predicate/behavior. Confirm Task 1 cases stay green.
- [ ] **Step 3: Implement `_require_snapshot`.** Validate immutable record shapes, shortest legal aggregate serialization bound and distinct strict identities, derive literal basenames, require the two exact own rows and reject fixed candidates. No host call, receipt, process handle, PID probe or cleanup. A row PID never becomes a signal target.
- [ ] **Step 4: Run GREEN and regression.** Focused suite PASS on both supported interpreters. Run existing diagnostic/codec/inventory/receipt/recovery/CI suites plus the new suite, full Ruff/compile/diff check and full regression. Compare Mac failures with fresh clean baseline by exact names; supported self-hosted Linux full CI must pass separately. Existing eligible Darwin diagnostic cases must not silently skip or count as new native parser/orphan proof.
- [ ] **Step 5: Document and commit.** README records actual parser/related counts and limitations below. Commit predicate/tests/README. No normative authority-byte change.
- [ ] **Step 6: Fresh review and exact gates.** Independent whole-branch adversarial review, fix findings via focused RED/minimal GREEN/regression. Require unchanged exact PR head ordinary CI PASS and no unresolved Critical/Important before expected-head merge. Require exact merge-main ordinary CI PASS; record actual automatic Level-3 result without cancelling or normalizing stale state. This is component merge evidence, not Level-3 closure.
- [ ] **Step 7: Retain evidence and next plan.** Keep incident worktrees/evidence until A1 is closed; audit status without discarding changes. Prepare the subsequent native composition/namespace plan. Do not activate inspection or resume N1c.

## Explicit remaining native acceptance

This slice does not launch or observe any process and earns no native quiescence proof. The next separately approved native integration plan must finish/reap getconf before both snapshots; derive identities from the real fixed capture; verify fixed owner absence, complete validated inventory, both own-ps identities and late marker/cache/temp/root/expected-commit namespace state before any receipt. It must test actual cancelled-parent/still-running getconf and ps fixtures at each stage, extra/missing/wrong own ps, mixed-case basenames, no orphan signals, no success output and unchanged state. Fixture owners dispose of only their own disposable resources; no incident orphan-killing authority. Developer UID-501 OS-boundary substitutions must be identified as such, never claimed as UID-502/GitHub/main compatibility.

PR #149's portable-only registration race, failed-notification and concurrent two-stream scheduling evidence remains explicitly limited; do not silently promote it to native proof. Native composition must specify any additional forced interleaving evidence before full preflight/activation acceptance. Workflow authority, authenticated receipt retrieval, apply/journal/delete, marker clearing and unknown workspace provenance/disposal remain separate gates.

## Self-review and approval handoff

Scope is intentionally smaller than the whole inspection spec: Task 1 pure parsing feeds Task 2 pure rejection, with matching types and no capability-bearing integration. Each Review Focus class has owning tests. Actual process observation, namespace/root validation, native orphan detection and workflow activation are omitted explicitly rather than given fictional evidence. The proposed PID/format bounds are fail-closed and require review with this plan. Written plan review/approval remains required before code; preserve the already selected native execution method.
