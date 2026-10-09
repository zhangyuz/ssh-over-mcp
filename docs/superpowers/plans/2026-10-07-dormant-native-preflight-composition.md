# Dormant Native Preflight Composition and Namespace Plan

> **For agentic workers:** Preserve the established native execution method and authority boundaries. Implement only after this written plan receives explicit review/approval. Use RED → minimal GREEN → focused regression → fresh independent whole-branch review. Keep implementation slices independently reviewable.

**Goal:** Compose the already-main fixed diagnostic capture, pure process metadata validation, fixed incident namespace provenance, expected-commit observation and staging inventory into a dormant read-only native preflight observation. This slice must not emit a receipt, activate a workflow, mutate provider/staging state, clear the marker, delete anything or execute target code.

**Architecture:** Ship two implementation slices. Slice A adds descriptor-pinned fixed namespace/marker/expected-commit observation with no process spawning. Slice B composes the already-approved fixed `getconf`/`ps` captures and pure metadata predicate around Slice A and the existing metadata-only inventory collector. The result is immutable detached evidence only. Trusted workflow provenance, envelope construction/receipt framing and persistent-runner invocation remain a later separately reviewed activation slice.

**Tech stack:** Python 3.13/3.14 stdlib, descriptor-relative Darwin filesystem APIs, existing dormant helpers, pytest/Ruff, disposable Intel-macOS fixtures plus self-hosted Linux regression. No dependency, package, production, guest, compiler or workflow change.

**Normative authority:** `docs/decisions/0011-incident-bound-e2e-staging-recovery.md`, `docs/decisions/0012-owned-diagnostic-child-lifecycle.md`, and `docs/superpowers/specs/2026-10-06-incident-staging-inspection-design.md`. The fixed authority remains the exact already-main binding embedded in `ops/live-e2e/staging_diagnostics.py`: commit `1ddebe541ee80c0febc4cd35072f3a5046fac5cb` and the three pinned document byte sizes/SHA-256 values. This plan does not rewrite those authority bytes.

| Fixed approved authority file | Bytes | SHA-256 |
| --- | ---: | --- |
| `docs/decisions/0011-incident-bound-e2e-staging-recovery.md` | 11227 | `c98f99d29f8e02bae4c90f56565241818f23e10a229afcecafbebd2a91b43e3b` |
| `docs/decisions/0012-owned-diagnostic-child-lifecycle.md` | 11238 | `980801f685dba9eee8a8e76c0e39641fd7aa61d5c3453ecd6e10d9ba5f4a51a3` |
| `docs/superpowers/specs/2026-10-06-incident-staging-inspection-design.md` | 22821 | `650d65243e023f647e4c7424357ad1e2b19d6317eb603cfa1bebde388e358882` |

The native-preflight implementation must verify **each literal byte count and SHA-256** and the already-main `1ddebe5` authority commit before any fixed child capture/other signal-capable helper is invoked. Unexpected authority bytes must fail closed; moving `main` is not a substitute for this binding.

**Status:** Proposed written plan; implementation is not approved yet. Base is exact main `48e71ed83f457e31300c6a35c12f12f1afe6e7cc`, produced by merged PR #151. PR #151 exact-head CI `37682885197` passed at `6aa4cdaa8726bbfb15f4fe894096bb3e070b4907`; fresh independent review found 0 Critical / 0 Important / 0 Minor and local focused metadata verification passed 139 tests plus Ruff/diff check. Exact merge-main run `37698364151` passed ordinary self-hosted Python 3.13/3.14 validation; its automatic Level-3 job failed at the pre-existing stale-provider gate before a usable E2E result, provider-state absence also failed, and checkout cleanup passed. No Level-3/A1/native-preflight closure credit is implied by component success.

## Global constraints

- Dormant only: no CLI, no GitHub workflow caller, no printing/log framing, no `GITHUB_*` provenance consumption, no receipt/envelope emission, no network and no target execution.
- Read-only host authority only. No unlink/rmdir/rename/chmod/chown/write/sudo/process-group signal/operator-selected signal/PID search. The only delivered-signal capability remains inside the already-approved fixed diagnostic child lifecycle in `staging_diagnostics.py`. Separately, owner-death observation uses only the fixed existing recovery semantic `os.kill(38013, 0)`: `ProcessLookupError` means absent, `PermissionError` means live, and any other ambiguous error refuses. Signal zero delivers no signal and grants no cleanup or general PID-probe authority.
- Only fixed incident selectors `stale-target` and `older-target`. No caller-selected path, UID, inode, marker path, expected commit, command, PID, environment, process pattern or inventory JSON.
- Fixed UID is 502; selected staging root must match its literal catalog basename/device/inode/mode 0700/expected commit from the approved spec.
- Fixed marker path is the literal absolute `/Users/gha-e2e-orchestrator/Library/Caches/ssh-over-mcp-e2e/active-run.json`; never expand `~`, `HOME` or caller environment. Its exact stale target is `47531dadb58d365f74089dd5f52ce1b61bb0fdd1` and owner PID is 38013.
- Derive the temp parent only from successful fixed `capture_getconf()` bytes parsed by `_parse_temp_parent`; never use `TMPDIR`, `tempfile`, environment fallback, arbitrary symlink resolution or caller text.
- Both process snapshots come only from separate successful fixed `capture_ps()` invocations. Pass each capture's exact `child_pid` to `_require_snapshot`; derive the inspection PID internally from `os.getpid()`. Never accept either identity as an argument to the top-level fixed preflight.
- Finish/reap fixed getconf before either process snapshot. Snapshot predicate must reject any getconf, extra ps, other python/pypy, QEMU and fixed authority processes. At both pre- and post-inventory stages, require the fixed signal-zero owner probe to report PID 38013 absent **and** require PID 38013 absent from the validated UID-502 snapshot rows regardless of command basename. Never infer marker-owner death solely from `ps -U 502`.
- Keep every necessary marker-cache and temp/staging namespace descriptor pinned through final post-snapshot revalidation. All owned descriptors close on every success/failure path; caller/fixture borrowed descriptors remain unchanged.
- **Separate host-state and trusted-checkout read allowlists.** From incident host state/staging, read regular-file content **only** for the fixed provider marker and the selected root's fixed `payload-content/expected_commit`. Separately, read **only** the three literal, reviewed **checkout authority documents** in the table above to verify their bounded byte counts/SHA-256 before the first fixed diagnostic capture; they are not staging data or a general checkout-file read permission. No other staging file, Git object, bundle, ISO, wheel, package, overlay, arbitrary path or checkout file may be opened for content.
- Existing `collect_staging_inventory(root_fd, uid=502)` remains the only staging-tree traversal. Preserve its limits and semantics unchanged.
- No success evidence is returned until the second process snapshot and every required final namespace/marker/expected-commit revalidation succeeds.
- Fail closed with fixed public `PreflightError("staging preflight rejected")`; suppress lower-level paths, file content, raw exceptions, child identities and stdout/stderr. Its only extra internal diagnostic status is a **strict `bool` `cleanup_uncertain` field (default `False`)**. When sanitizing an existing `DiagnosticError`, propagate exactly its validated `cleanup_uncertain` boolean; preserve `True` on any uncertain signal/reap/cleanup outcome, never downgrade it to `False` because another handler ran. For other failures default to `False` only when there is no owned diagnostic child or cleanup is conclusively settled; if status cannot be determined, fail closed with `True`. No diagnostics, receipt, logging or caller-selectable error field is added. A later approved activation separately decides whether/how to surface only that safe boolean.
- Unknown `ssh-over-mcp-e2e-recover.cc8Del` stays excluded. This plan grants no provenance, inspection, deletion or ignore rule for it.
- No A1, Level-3 or Phase 7B1 completion credit. N1c remains paused until recovery/A1 closes.

## Fixed namespace contract

### Marker-cache chain

Pin from `/` through the fixed cache directory using descriptor-relative `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` opens and pre-open/post-open metadata equality.

Canonical chain:

1. `/`
2. `/Users`
3. `/Users/gha-e2e-orchestrator`
4. `/Users/gha-e2e-orchestrator/Library`
5. `/Users/gha-e2e-orchestrator/Library/Caches`
6. `/Users/gha-e2e-orchestrator/Library/Caches/ssh-over-mcp-e2e`

System ancestors must be root-owned and not group/world writable. Account-owned ancestors must be UID 502 and not group/world writable. Final cache must be UID 502 mode 0700. Do not repair missing or unsafe parents.

Open `active-run.json` relative to the pinned final cache descriptor with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`, after descriptor-relative no-follow metadata classification. Preserve the existing 4096-byte maximum, regular type, UID 502, mode 0600 and pre-open/opened device/inode comparison. The new descriptor-relative parser must accept exactly one flat ASCII JSON object with **one occurrence each** of keys `target` and `owner_pid`: target is the fixed lowercase 40-hex string; owner PID is an exact JSON integer 38013 (never boolean/float/string). Before general JSON materialization, use a bounded, quote/escape-aware structural scan to reject nested objects/arrays, excessive depth, malformed/truncated strings and wrong outer shape; then reject duplicate keys via pair-preserving decode and reject nonstandard constants/floats. Bound all allocations by the 4096-byte input ceiling and convert parsing/OS/type/recursion failures to fixed `PreflightError`, without leaking raw bytes or paths. Do **not** change or silently reuse permissive semantics from the older absolute-path `recover_provider._load_state` function. Record its initial identity and exact parsed state. Re-read/revalidate through the same cache descriptor after the second process snapshot; the target/PID and device/inode must remain identical, with no accepting replacement or changed content after the first read.

Do not reuse an absolute-path `_load_state()` call as provenance proof. The new reader is descriptor-relative and must independently enforce the stricter, unambiguous schema; existing recovery-only marker-clear authority and APIs remain unchanged.

### Temp and selected staging chain

`capture_getconf()` must succeed and be fully reaped first. Parse exactly one native `/var/folders/.../T/` path, map only literal `/var` to `/private/var`, then pin from `/` through:

`/private` → `/private/var` → `/private/var/folders` → fixed OS-returned two-character shard → fixed OS-returned account token → `T`. Every owned directory FD is opened no-follow with `O_CLOEXEC` as well as the required directory/read flags.

Shared ancestors are root-owned and not group/world writable. The per-account token is UID 502 mode 0700 or 0755. `T` is UID 502 mode 0700. Record canonical ancestor metadata in root-to-T order.

Open only the selected catalog basename relative to pinned `T`; require exact literal device/inode, UID 502 and mode 0700 before any inventory or expected-commit read. No prefix/glob discovery grants authority.

Immediately before success return, after the second process snapshot, revalidate every held parent-to-child edge for both cache and temp chains via `stat(..., dir_fd=parent, follow_symlinks=False)` against the held child's original device/inode/type/UID/GID/mode and current `fstat`. Directory timestamps are not authority and need not remain stable. Recheck the selected staging root catalog identity. Holding descriptors alone is not final namespace proof.

## Expected-commit contract

Open fixed `payload-content` relative to the selected root with `O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`; require same device, UID 502 and safe mode, and keep that payload descriptor pinned through the final reread/edge checks. Open only `expected_commit` relative to that held descriptor with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`.

Require:
- runner-owned regular file;
- link count 1;
- exact size 41;
- safe non-group/world-writable mode;
- same staging device;
- content exactly selected 40 lowercase-hex catalog SHA plus LF;
- metadata tuple `(device,inode,uid,gid,mode,nlink,size,mtime_ns,ctime_ns)` stable before/after the bounded read.

Record the first observation before inventory. The existing inventory entry `payload-content/expected_commit` must equal the file observation's metadata fields. After inventory and the second process snapshot, re-open only `expected_commit` relative to the same held payload descriptor, reread it, and require identical content and identical metadata to the first observation plus final root→payload and payload→file edge revalidation. Missing, replaced, rewritten or metadata-drifted state refuses.

The helper claims only the observed quiescent checks from the approved design; malicious same-account ABA changes remain outside the guarantee.

## Process composition contract

Order for a successful preflight is fixed:

1. validate the fixed non-admin Darwin/x86_64 account/runtime context and exact authority binding;
2. complete/reap fixed getconf capture and parse the temp parent;
3. pin cache/temp/staging descriptors and read initial marker + first expected_commit observation;
4. capture/parse/validate **snapshot A** using internally derived inspection PID and that capture's own ps PID; require the fixed signal-zero owner probe to report PID 38013 absent and require PID 38013 absent from the validated rows;
5. collect the complete metadata-only staging inventory using the pinned root descriptor; require its root and expected-commit entry agree with the fixed observations;
6. invoke a second independent fixed ps capture, then parse/validate **snapshot B** using that invocation's exclusively owned child PID; require the fixed signal-zero owner probe to report PID 38013 absent and require PID 38013 absent from the validated rows;
7. reread/revalidate marker and expected_commit;
8. revalidate every cache/temp/root namespace edge and fixed staging catalog identity;
9. only then construct and return immutable detached `PreflightObservation`.

No fallback/retry snapshot is allowed. Snapshot A and B must come from two distinct *invocations* of the fixed capture function, one on each side of inventory; a caller cannot supply capture bytes/objects. Do not infer whether an invocation happened from equality/inequality of PID, stdout, captured objects or parsed rows. After the first child is reaped, legitimate kernel PID reuse is possible; steady process rows and identical bounded output are also possible. A failed or cleanup-uncertain diagnostic causes preflight failure and no evidence return, with the safe cleanup-uncertainty boolean preserved on the sanitized error.

The top-level helper must not accept captured bytes, inspection PID, ps PID or open descriptors. Private fixture seams may substitute the OS/capture boundary only in tests and must assert the fixed production operation before substitution.

## Evidence shape

Create immutable/slotted data records in the new preflight module. The exact implementation may use nested frozen dataclasses, but success must detach the evidence from live FDs and include only:

- fixed incident selector;
- canonical temp parent path;
- ordered temp-parent ancestor metadata required by the approved envelope; cache-chain provenance is proven internally and must not grow the reviewed wire schema;
- marker device/inode/target/owner PID;
- selected staging basename/device/inode/UID/mode/expected commit;
- complete `InventoryEntry` tuple from the existing collector;
- first/final expected-commit metadata equality already proven internally.

Do **not** include workflow authority SHA/run ID/attempt, receipt digest/chunks, file descriptors, process handles, cleanup handles, raw getconf/ps bytes or mutable mappings. A later activation slice owns the exact conversion from this observation plus trusted workflow provenance into the already-reviewed canonical envelope.

## Review focus

1. **Authority containment:** no generic path/PID/command/capture input, no accidental workflow/receipt surface, no mutation.
2. **Namespace provenance:** every path component no-follow pinned; final edge revalidation detects replacement even while old FDs remain valid.
3. **Content binding:** expected_commit's first read, inventory metadata entry and final reread cannot disagree or normalize drift.
4. **Quiescence:** real capture child PIDs and internally derived inspection PID feed both snapshots; fixed signal-zero owner-death probes plus row absence enforce PID 38013, and detectable cancelled diagnostic leftovers refuse.
5. **Resource lifecycle:** all owned descriptors/captures close/reap under every induced failure; borrowed fixture descriptors remain usable and unchanged; no partial success evidence.

## Slice A — Descriptor-pinned namespace observation

**Files:** create `ops/live-e2e/staging_preflight.py` and `tests/ops/test_live_e2e_staging_preflight.py`; update `tests/live/README.md`. Do not yet import/call `staging_diagnostics.py` from the production success path in Slice A. Slice A is a dormant primitive/evidence component, not a successful full preflight entrypoint: any fixture-only temp/cache root substitution must stay behind private test seams. No shipped callable may accept an arbitrary temp/cache path or claim fixed-host provenance before Slice B supplies the validated fixed getconf result.

- [ ] **A1 — Establish exact baseline.** Start from the then-current clean main after this plan is approved. Record exact main, #151 merge-main ordinary CI result and existing focused component counts. Verify each of the three literal **trusted-checkout** authority paths, byte lengths and SHA-256 values above against on-disk files, plus the fixed already-main authority commit, before any signal-capable integration. RED requires a one-byte mutation in each authority file to fail closed **before the first fixed `getconf`/`ps` capture invocation**: instrument the capture boundary and assert zero calls on each mismatch. Do not access incident staging to perform this authority-file verification and do not allow ancestry-only fallback.
- [ ] **A2 — Write focused RED for fixed catalog + descriptor chains.** Test literal selector catalog, cache chain policy, native temp-chain policy, symlink/replacement/type/owner/mode/device failures, final edge replacement while held FDs remain open, and unknown selector/root exclusion. Use disposable directories and private fixture seams; no incident paths.
- [ ] **A3 — Implement minimal fixed namespace open/revalidate primitives.** Descriptor-relative only, no `Path.resolve`, no arbitrary production input paths, close owned descriptors exactly once. Private fixture seams may provide disposable already-validated component names/descriptors only for tests; they are not capability-bearing APIs. Keep the shipped selector catalog fixed to the two incident entries and expose no complete production success entrypoint until Slice B.
- [ ] **A4 — Expected-commit RED/GREEN.** Cover exact content/41-byte bound, FIFO/symlink/special/hardlink refusal, ownership/mode/device mismatch, replacement between stat/open, same-inode rewrite via changed ctime/mtime, inventory-entry disagreement and final reread/edge drift. Never read another staging regular file.
- [ ] **A5 — Marker RED/GREEN.** Add descriptor-relative hardened marker read under the pinned cache FD and the new strict 4096-byte flat JSON parser. RED must cover duplicate `target` and `owner_pid` keys in both orders, nested/deep 4096-byte JSON, wrong/missing/extra keys, boolean/string/float/NaN/infinite/oversized owner PID, malformed ASCII/escapes and valid schema at the exact byte ceiling where possible; every rejection uses fixed `PreflightError`, never an uncaught JSON/recursion/OS error. Also test replacement, FIFO, raw content drift with unchanged target/PID, initial/final reread and exact fixed device/inode. Preserve existing marker-clear authority and do not change its parser.
- [ ] **A6 — Inventory composition without process capture.** On disposable fixtures, call the existing collector with the held selected-root FD and prove immutable detached evidence contains exactly the collector records and fixed observations. No envelope/receipt.
- [ ] **A7 — Regression/review/gates.** Focused suite, existing inventory/recovery/codec/diagnostic/process-metadata tests, Ruff/compile/diff check, disposable macOS path fixtures, self-hosted Python 3.13/3.14 exact-head CI and fresh independent review. Merge Slice A only with unchanged reviewed head and expected-head guard. Automatic Level-3 stale-state refusal remains expected evidence, not success credit.

## Slice B — Fixed native diagnostic composition

**Files:** modify only the preflight module/tests/README unless a narrowly reviewed sibling import seam is required. No workflow.

- [ ] **B1 — RED the exact sequence.** Instrument the **fixed capture call boundary** with a private spy/fake, recording each executed invocation and its position relative to inventory: completed/reaped getconf, `capture_ps()` call A, inventory, **second actual `capture_ps()` call B**, then final marker/expected-commit/namespace checks. A test double that bypasses the second invocation must fail the invocation-count/order assertion, **not** a PID/stdout/row equality test. Allow A/B to return identical stdout/rows and, after separate reaping, the same numeric child PID; assert both calls occurred and the owner identities were validated per invocation. Both stages require fixed PID-38013 signal-zero absence and UID-502 row absence. Owner-probe RED covers `ProcessLookupError` as absent, `PermissionError` as live, a live PID as refusal, and unexpected/ambiguous OS errors as refusal; no delivered signal is permitted.
- [ ] **B2 — Compose the fixed helpers and failure status.** Call existing `capture_getconf`, `_parse_temp_parent`, `capture_ps`, `_parse_process_rows` and `_require_snapshot`. Derive inspection PID internally. Validate capture kind exactly. Call `capture_ps()` twice; bind each snapshot to that invocation's returned owned PID. Add a fixed no-argument owner-absence helper whose only process-existence target is literal PID 38013 and whose signal-zero semantics match existing recovery `_process_exists`; pair that observation with row absence at both stages. Freshness is the controlled invocation/lifecycle, not numeric PID inequality. Convert `DiagnosticError` into sanitized `PreflightError` while preserving its strict boolean `cleanup_uncertain` and suppressing raw exception chaining; never retry an uncertain capture. Test ordinary rejected capture (`False`), unknown wait/child status (`True`), timed-out owned-child signal/reap failure (`True`), and low-stdio/descriptor cleanup ambiguity (`True`) without leaking child details.
- [ ] **B3 — Cancellation/orphan adversarial fixtures.** On developer UID 501, use disposable native `getconf`/`ps`-named children plus a private capture-boundary substitution that first asserts the fixed production capture operation; feed the real native rows into snapshot A and separately B. Preflight must refuse without signalling/reaping that orphan, output, receipt or state mutation; fixture owner alone tears it down. Record this as native row/composition evidence only, not end-to-end fixed `-U 502` capture proof. Actual UID-502 cancelled-parent/orphan composition remains mandatory in the later trusted-main workflow slice.
- [ ] **B4 — Native format/PID evidence.** On developer Intel macOS, exercise the real one-byte ps projection and real child PID representation where possible. Record UID-501 substitutions explicitly. Do not claim UID-502/GitHub/main proof. Preserve PR #149's documented limitations for registration-race/notification/two-stream branches unless this slice adds real native forcing evidence.
- [ ] **B5 — End-to-end disposable preflight fixture.** Use a fully disposable cache/temp/staging tree and capture-boundary fixture to prove success returns only immutable detached evidence after both snapshots/final checks. Induce failure at every late stage and assert no partial evidence/output, all owned descriptors close, and strictly typed `PreflightError.cleanup_uncertain`: `False` for settled failures, **`True` for every injected unresolved cleanup/reap/notification/descriptor outcome**, including diagnostic failure followed by a secondary cleanup exception. Public message remains fixed, exception chaining suppressed and no receipt/console framing exists. Prove the safe boolean remains accessible internally after sanitization and cannot be forged from a non-bool or supplied by caller input.
- [ ] **B6 — Full regression + fresh adversarial review.** Require no unresolved Critical/Important findings, resolve Minor or justify safe deferral, run focused suites plus full supported CI/Ruff/compile/diff check and compare Mac failure names against fresh clean main.
- [ ] **B7 — Exact-head merge and merge-main evidence.** Merge only with exact reviewed head. Require exact merge-main ordinary CI PASS. Record actual automatic Level-3/provider-state result without cancelling, deleting stale state or weakening guards.
- [ ] **B8 — Handoff.** Preserve incident worktrees/evidence. Next write/review the fixed trusted-main manual workflow integration plan that binds actual UID-502/main context, adds trusted workflow authority/run/attempt to the canonical envelope, emits the already-reviewed receipt only after complete preflight, and obtains the first live read-only incident receipts. No apply/delete/marker-clear action is implied.

## Explicit evidence still deferred after this plan

Even complete Slice A+B does not prove:
- actual dedicated UID-502 account compatibility on the persistent runner;
- GitHub `workflow_dispatch`/main/checkout authority and exact workflow provenance;
- authenticated retrieval/retention of a successful receipt;
- staging deletion eligibility or complete apply byte/file ceilings;
- journal durability, partial-delete recovery or marker clearance;
- provenance/disposal of unknown `recover.cc8Del`;
- successful current-main Level-3 after stale state is removed.

Those require later independently reviewed gates. Only already-main code may run on the persistent orchestrator.

## Implementation progress note — 2026-10-09 (does not close plan gates)

The component-level dormant work has delivered an immutable joint fixture
observation (PR #174, merged) and a pure canonical inventory-v1 projection
(PR #175, merged; review follow-up explicitly fixed deceptive ancestor paths
and forbidden cold-cache load). The adjacent offline drift-report slice only
compares **two already detached and independently validated records**; it
does not authorize an additional capture or offer freshness/provenance proof.

This progress must not be mistaken for completing Slice A1 authority-file
mutation-before-capture acceptance, trusted-main workflow integration, UID-502
host evidence, provenance/receipt emission, or final Level-3. Those items
remain unchecked above and require the exact reviewed authority context and
native acceptance prescribed by this plan. All drift/projection comparisons
are deterministic data operations against disposable fixtures, with no actual
stale provider or unknown recovery workspace touch.

## Follow-on offline exchange slice — 2026-10-09

After the merged canonical projection (#175) and data-only comparator
(#176), a separate *dormant and non-authorizing* functional slice adds
a bounded canonical drift-report artifact encoder/decoder (v1), strict
byte validation, and a SHA-256 content check. This codec consumes a
supplied already-frozen offline report. It does **not** attest the
preflight capture, authenticate workflow provenance, substitute for
incident receipt integration in B8, or resume paused N1c. N1c remains
a distinct native-input authentication subtask deferred until
recovery/A1 closure per ADR 0011. Existing trusted-main and native
acceptance checkboxes in this plan remain open.

## Offline artifact cross-binding progress — 2026-10-09 (not a plan gate)

After merged PRs #176 (immutable comparator) and #177 (canonical bounded
drift artifact), the follow-up **offline** feature cross-checks the entire
portable claim against two supplied frozen observations by independently
validating/projecting each snapshot and requiring full typed report and
canonical byte equality, **even when a forged artifact has a freshly
recomputed content checksum**. It is a private data-consistency function,
not an additional native capture, authoritative observation, trusted
receipt or incident recovery eligibility test. A1, B8 trusted-main workflow,
actual UID-502 preflight, N1c native-input authentication (paused until
recovery/A1 closure under ADR 0011) and native Level-3 remain separate
unmet acceptance gates; this feature does not turn them green.

## New offline snapshot-pair fingerprint slice — 2026-10-09

The next **separately reviewed offline-only** capability fingerprints
both ordered supplied frozen observations at metadata-field granularity,
alongside their strictly verified v1 drift-report artifact. The content
seal is domain separated, bounded and canonical. It resolves the known
v1 summary collision in marker timestamp values and direction without
changing v1 drift-report compatibility or adding untrusted host I/O.

This remains a *content-only, caller-supplied* data integrity check,
not trust evidence. A1 authority-byte-before-capture tests, UID-502
native proof, B8 trusted workflow provenance/receipts, recovery/A1
before resumed native-input N1c, and real Level-3 remain independent,
uncompleted gates. No incident/provider access is authorized.

## Offline ordered timeline feature — 2026-10-09 (separate data milestone)

Following snapshot-pair content sealing, another dormant-only feature
checks **a bounded sequence of multiple caller-provided snapshots**
rather than isolated pairs. It builds and independently verifies every
adjacent canonical drift artifact and exact full-metadata pair seal,
then produces a compact deterministic manifest of ordered per-snapshot
and per-hop content digests and detected drift indices. It rejects
spliced/reordered/forged intermediate transitions and malformed wire,
but no trusted producer identity or chronology is conferred by a
checksum. All original native incident authority, A1/B8, and paused
N1c acceptance gates remain uncompleted; a multi-hop offline match
is explicitly not a recovery/Level-3 permission.


## Offline path-free timeline change report — 2026-10-09

Separate from native N1c, the #181 detached-only feature derives a
bounded canonical per-hop change classification and path **counts**
from the verified #180 multi-snapshot source tuple and linked pair
seals. Exact summary-byte reconstruction rejects rehashed forged
reports. No actual file paths, timestamps, producer identity,
chronology, A1/B8 authority, UID-502 host access, or provider/Level-3
recovery entitlement comes from this diagnostic. All native
preflight/incident gates remain blocked, including paused N1c.

## Offline timeline audit report — 2026-10-09 (separate feature)

This dormant feature consumes exactly the validated #180 ordered snapshot
tuple, typed hops and manifest. It emits an independent canonical v1 JSON
audit capped at 128 KiB, then supports strict re-verification against the
same original source tuple. The report adds per-hop added/removed/modified
path details and flags, full first-versus-last content change, stable versus
changed hop indices, and non-adjacent repeats of exact snapshot fingerprints.
An intermediate change is not hidden when first and last match.

Every build/verification rechecks the complete #180 timeline and all paired
seals, rejects altered or reordered evidence and forged audit bytes (including
freshly recomputed content hashes), and performs no host/process I/O. This
is not a trusted event chronology, signature, producer attestation, receipt,
UID-502 capture, A1/B8/N1c authority, or recovery/Level-3 permission. Main
merge #180 reached Python CI PASS but the no-network Level-3 push gate failed
closed due to pre-existing stale provider state. No cleanup was authorized.

This detailed #182 audit is deliberately separate from the #181 path-free
count summary. Its raw caller-supplied paths are potentially sensitive and
are not approved for broader dissemination or automated logging.


## Offline path-separated timeline casefile export — 2026-10-09

After #181 (path-free summary) and #182 (private path-bearing audit) merged,
PR #183 composes one bounded reproducible **public** timeline casefile
(manifest + count-only summary) and a separately opt-in **private** path audit
casefile whose content is bound to the public digest. Both have canonical
strict re-verification from the entire original supplied typed observation
tuple and refuse rehashed forgeries or swaps. Public export never includes
path/field contents from the private report. This remains offline fixture-only
processing; no signed provenance, chronology, UID-502 access, trusted A1/B8
workflow receipt, paused N1c input approval, stale-provider recovery or native
Level-3 acceptance is conveyed. #182 merge-main Python 3.13/3.14 validation
passed but no-network Level-3 failed closed on the prior stale provider state.

The explicit private-path opt-in is a programming guard against accidental
export, **not** caller authentication or an authorization policy.
