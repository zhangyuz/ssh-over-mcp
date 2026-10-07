# Dormant Staging Envelope Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Preserve the approved native execution method: implement locally, then obtain a fresh independent whole-branch review. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pure, dormant canonical inspection-envelope and receipt codec with independently pinned bytes and adversarial rejection evidence.

**Architecture:** Compose detached inventory metadata with fixed incident bindings and explicitly supplied trusted provenance. Encode and validate bounded canonical bytes without observing the host or emitting output. A receipt decoder establishes wire consistency only, never workflow authenticity, quiescence, deletion eligibility or approval.

**Tech Stack:** Python 3.13/3.14, stdlib JSON/hashlib/base64, pytest, Ruff; no new dependency or lock authority.

**Spec:** `docs/superpowers/specs/2026-10-06-incident-staging-inspection-design.md`, approved at `7e882cd5c3acc8940cba2ce45aa4eb938a9e1a8a`, merged by #144 as `4e81fcb1f6981a05f31d4b9f6497a895b778cdf1`.

**Status:** Written plan for review; implementation not started. Baseline: 87 recovery/inventory/CI tests PASS on that merge SHA. No implementation RED/GREEN or Level-3 credit.

## Global Constraints

- This is only the first, signal-free envelope slice; no CLI, workflow caller, subprocess, process signal, filesystem access, environment lookup, network, persistent file, deletion or marker mutation.
- No production, guest gate, runner provisioning or native-package change. Self-hosted runners only.
- Unknown `ssh-over-mcp-e2e-recover.cc8Del` stays excluded. The fixed two-selector catalog, marker target/PID, UID 502 and root mode 0700 are copied exactly from the spec; no caller-selected path or identity becomes authority.
- Preserve collector limits: 4096 entries including root, depth 12, 4096-byte filesystem-encoded relative paths, same device/UID, regular files/directories, regular nlink 1, no group/world-writable entries or repeated device/inode identities.
- Complete canonical envelope limit: 2097152 bytes. Raw chunks: 1024 bytes; at most 2048. No output or oversized serialized intermediate retained beyond its checked budget.
- Exact fields/types, catalog values, canonical paths, ancestor ordering, lowercase SHA strings, decimal provenance strings and JSON/base64/framing follow the spec's entire wire table; do not coerce values.
- Canonical JSON bytes must match `ensure_ascii=True`, `sort_keys=True`, `separators=(",", ":")`, `allow_nan=False`, ASCII bytes, no final LF. Use a local integer codec rather than passing unbounded integers to stdlib JSON/int decimal conversion; never change Python's process-wide digit guard. Hash inventory bytes separately; envelope digest lives only in the receipt.
- `run_id` and `attempt` are strings: positive ASCII decimal, no leading zero, at most 19 digits and value at most `2**63-1`. Authority SHA is 40 lowercase hex; digest strings are 64 lowercase hex.
- Signal-capable preflight remains forbidden until a separately written-approved/reviewed ADR0011 amendment is already on main with exact commit/path/content-digest binding. This plan creates no such authority.
- Pure data validation cannot prove that supplied metadata/provenance was freshly observed or trusted. Only future already-main preflight/integration may establish those facts before calling the codec.

## Review Focus

1. Python bool/int equivalence, subclasses or duplicate JSON keys must not manufacture canonical typed evidence — Task 1 scalar tests and Task 2 decoder tests.
2. Caller mutation after encoding or provenance-only changes must not alter retained bytes or inventory equality — Task 1 detached-result tests.
3. Individually bounded records can overflow the complete envelope, especially through JSON escaping or large integers — Task 1 aggregate/escaping tests and Task 2 input bounds.
4. Hash-consistent malformed topology or inconsistent catalog/root/expected_commit metadata must refuse — Task 1 binding/topology tests, reused by Task 2 decoding.
5. Permissive base64/JSON parsing, independent padding or missing chunks must not create a usable partial receipt — Task 2 canonical framing and reconstruction tests.

## File and Interface Map

Create `ops/live-e2e/staging_envelope.py`: pure schema validation and bounded canonical inventory/envelope encoding.

Create `ops/live-e2e/staging_wire.py`: internal fixed-schema scan/parse and canonical scalar encoding shared by envelope and receipt. Its permitted kinds are only `envelope`, `receipt` and `chunk`; no caller-supplied schema or general JSON parser API.

Create `ops/live-e2e/staging_receipt.py`: pure receipt framing and strict reconstruction using the same envelope validator; it does not authenticate log origin.

Create `tests/ops/test_live_e2e_staging_envelope.py` and `tests/ops/test_live_e2e_staging_receipt.py`; follow the existing importlib loader pattern for the hyphenated ops directory.

Create checked-in literal fixture files under `tests/ops/fixtures/staging-envelope-v1/`: `inventory.json`, `envelope.json`, `receipt.log`, `expected.json`. First two contain exact hashed ASCII bytes without LF; the log contains framed lines with LF. `expected.json` pins lengths, both digests and chunk count, plus the independent derivation method. Fixture contents are synthetic metadata, not host evidence or credentials.

Modify `tests/live/README.md`: explain dormant codec scope, acceptance evidence and remaining preflight/activation/apply gates. Existing collector and recovery APIs remain unchanged; CI already covers `ops/live-e2e` and the new tests.

This plan-only branch also records the user's written design approval in the spec's status line; the approved substantive contract is unchanged.

## Task 1: Strict Canonical Inventory and Envelope

**Consumes:** `staging_inventory.InventoryEntry` fields and bounds, plus the spec's exact wire schema. Do not call `collect_staging_inventory()` or its encoder; the existing collector-only object has a different schema.

**Produces in `staging_envelope.py`:**

- `EnvelopeError(RuntimeError)`, defined in `staging_wire.py` and re-exported from `staging_envelope.py`, fixed public text `staging envelope rejected`; suppress lower-level exception detail. The shared wire module must not import the envelope/receipt modules.
- `encode_envelope(inventory: dict, inspection: dict) -> bytes`: exact built-in dict/list/str/int inputs with recursively checked schema; returns detached immutable complete canonical envelope bytes.
- `validate_envelope(raw: bytes) -> None`: exact built-in bytes, bounded strict parsing, full schema/binding/hash/canonical-byte verification, no normalized acceptance of alternative encodings.

Inputs are internal detached wire-shaped data, not a public caller interface. Do not expose path collection, catalog overrides, arbitrary schema versions or a workflow entrypoint.

**Local numeric and pre-schema strategy (owned by Task 1):**

- In `staging_wire.py`, define `encode_integer(value: int, *, max_bytes: int) -> bytes` for exact built-in integers only; `max_bytes` must be an exact integer from 1 through 2097152. Account for the sign first; zero is `0`, never `-0`. Reject impossible bit lengths before creating powers (a bit length greater than four times the remaining decimal budget already cannot fit), then compare against `10**remaining_digits` to enforce the exact available decimal budget. Find the exact digit count with bounded integer-power comparisons. Render by balanced `divmod` splits at powers of ten, padding lower halves to their known width, down to leaves of at most nine digits; only those small leaves use decimal `str()`. Check the output budget before extending the buffer. No `str()`/`repr()`/JSON encoding of the whole large integer, floating logarithm, independent digit-width cap or global guard change.
- Define `decode_integer(token: bytes, *, max_bytes: int) -> int`. Before numeric allocation, check byte length, optional single minus, ASCII digits, no leading zeros and no negative zero. Parse leaves of at most nine digits and combine them in a balanced tree using integer arithmetic and powers of ten; no whole-token `int()` or stdlib JSON number conversion. Bounds cover the token and resulting integer/arithmetic temporaries by the existing complete-envelope budget. Signed values are accepted only at timestamp schema positions. This is mathematical, finite work under the byte budget, not a live native-stat attestation or hard runtime deadline.
- Define `parse_wire(raw: bytes, *, kind: Literal["envelope", "receipt", "chunk"]) -> dict`. Perform a first schema-directed scan over the size-bounded ASCII bytes **before** creating any decoded dict/list/string/integer tree. Dispatch only to the three literal schemas. Object keys must be the exact expected ASCII names in canonical sorted order; reject a duplicate, missing, extra or out-of-order key at its occurrence, before retaining a key/value collection. Check the expected scalar/container type before descending. No generic `json.loads()`/`raw_decode()` over an envelope, receipt or chunk.
- The scanner follows the fixed grammar: envelope container depth at most **5** (root counts as 1), at most **11** members in any object, exactly **7** parent ancestors (`/`, `/private`, `/private/var`, `/private/var/folders`, bucket, account token, `T`) and at most **4096** entries. Check array count before scanning the next element. The complete envelope has at most **4109 objects and 2 arrays**, derived from six fixed objects plus seven ancestors plus 4096 entries. Receipt/chunk each have one object, no arrays or nested containers, and exactly four/two members respectively. These are bounds derived from the approved schema, not arbitrary JSON complexity allowances.
- The first pass validates string lexing without decoding/copying a token. Fixed keys and fixed literal values have their exact lengths; SHA strings have 40/64 characters, provenance strings at most 19, and chunk data at most 1368. Entry paths have at most **24578 raw JSON-token bytes** (4096 filesystem bytes at worst six ASCII escape bytes each, plus quotes), followed by the existing decoded filesystem-byte/depth checks. Parent/ancestor path tokens are bounded by remaining complete-envelope bytes, then checked against the native canonical path grammar. All token scans, including integers and escaped strings, consume the aggregate byte budget; an unterminated or oversized token refuses before decoding. No unknown-schema strings, keys or nested containers are retained.
- Only after the first pass reaches the exact end may a second schema-directed pass materialize the bounded tree, using `decode_integer` for numbers and stdlib JSON decoding only for an individually bounded string token. Reuse the first-pass limits and domain validation, then exact canonical re-encoding/hash verification. Neither pass accepts whitespace, alternate escapes or numeric spellings as canonical success. Lower-level parse/recursion/conversion errors map to the fixed `EnvelopeError`, without raw details.
- `parse_wire` is shared by Task 2. Receipt line limits additionally narrow its inputs; no parallel eager JSON path is allowed. Internal helpers are not workflow or authenticated-evidence interfaces.

- [ ] **Step 1: Pin the complete valid golden fixture and failing tests.** Use `stale-target`, the literal spec root identity, fixed marker PID/target, a synthetic canonical `/private/var/folders/ab/test_token/T` parent with its ordered prefix ancestors, all eleven direct names plus root and `payload-content/expected_commit` (13 records). Use unique identities, UID 502, safe modes, regular nlink 1 and expected_commit size 41. Hand-write canonical fixture bytes and independently compute lengths/digests/base64 chunks with a second toolchain, never the codec under test. Record that method and fixed values in `expected.json` before implementation.

  Tests assert `encode_envelope(fixture_inventory, fixture_inspection) == literal_envelope_bytes`, both literal digests/lengths, and `validate_envelope(literal_envelope_bytes) is None`. Include both catalog selectors in binding tests. Add the spec's literal 69/97-byte primitive vectors as supplementary checks, not substitutes for the full fixture.

- [ ] **Step 2: Run focused RED.** `env PYTHONPATH=src /tmp/pr119-verification-venv/bin/python -m pytest tests/ops/test_live_e2e_staging_envelope.py -q -o addopts=--import-mode=importlib`. Require missing codec/interface failure; preserve the failing output and SHA.

- [ ] **Step 3: Implement the smallest strict validator and encoder.** Reject missing/extra keys, wrong exact scalar/container types, malformed paths or order, duplicate entries/identities, absent parent directories, wrong fixed layout/kinds and inconsistent incident bindings. Root entry identity/UID/mode must match staging. All entries must match root device/UID and collector invariants. The metadata-only entry at `payload-content/expected_commit` must be regular, size 41, nlink 1 and have safe permissions. Separately, `inventory.staging.expected_commit` must equal the selected catalog's literal SHA. The entry has no content field; the codec performs no file-content validation or live-read proof.

  Parent ancestors must be the exact ordered canonical prefixes from `/` through the declared native temp parent. Apply the spec's root/account owner and mode constraints. No path resolution, stat or permission repair. Marker device/inode are detached observations; only target/PID have fixed incident values.

  Implement the local numeric codec and two-pass fixed-schema parser above. Enforce entry/path/depth bounds before traversal/retention. Bound string lengths before scanning, account for canonical ASCII escaping before creating each encoded value, and check projected aggregate bytes before extending buffers. Only timestamps may be negative; modes must fit stat.S_IMODE permission bits. Exact canonical-byte comparison also rejects alternate escapes. Do not rely on catching CPython's digit guard or recursion error after eager JSON materialization as the parsing bound.

- [ ] **Step 4: Add focused adversarial RED cases, then minimal GREEN.** Cover every wire field's wrong type (including bool and subclass), extra/missing/duplicate keys, malformed hex, numeric/zero/leading-zero/oversized provenance, record order/topology and catalog mismatch. Recompute valid hashes in mutation tests so rejection demonstrates schema enforcement rather than only digest mismatch. A provenance-only change keeps inventory bytes/hash identical but changes envelope bytes/hash; changing marker identity changes inventory hash. Mutating input containers after encoding leaves the returned bytes unchanged.

  Cover exactly 4096 versus 4097 records, depth/path boundaries, surrogate-escaped filesystem names, escaping amplification, and a valid complete envelope exactly 2097152 bytes versus a valid-shaped 2097153-byte candidate. Construct boundary inputs independently and pin their length; do not monkeypatch the production limit or substitute a collector-only object. Safe metadata integer widths may provide the final byte adjustment, subject to the actual complete-envelope budget.

  Numeric RED vectors must cover 4299, 4300, 4301, 5001 and 10000 decimal digits, using arithmetic such as `10**(digits-1)` and independent literal token bytes `b"1" + b"0"*(digits-1)` rather than guarded whole-value conversion. Put values in an unconstrained nonnegative metadata field and positive/negative timestamp fields; encode and validate must agree below/above Python's default 4300-digit guard. Test local `max_bytes` equality versus one byte overflow, including the minus sign, and reuse the complete 2097152/2097153-byte fixtures for aggregate agreement. Assert `sys.get_int_max_str_digits()` unchanged after success/failure and patch `sys.set_int_max_str_digits` to fail if called; no test or implementation may relax it.

  Pre-schema RED inputs must include a <=2097152-byte value nested 10000 levels, a <=2097152-byte wrong-schema array with 100000 small elements, an oversized object, duplicate keys, an overlong key/string, an unfinished token and a 4097th well-shaped entry. Spy on the internal second-pass materializer: each first-pass rejection must raise fixed `EnvelopeError` with zero materializer calls. Exercise the valid depth-5/7-ancestor/4096-entry boundaries as well. Do not count an exception after construction of the hostile tree as evidence for this gate.

- [ ] **Step 5: Run focused GREEN and commit.** All envelope tests PASS; Ruff and diff check clean. Commit only codec, literal fixtures and envelope tests, with RED/GREEN evidence in the ignored progress ledger. Review this component before adding transport.

## Task 2: Bounded Receipt Codec and Slice Gates

**Consumes:** `validate_envelope(raw: bytes) -> None`, `EnvelopeError` and `parse_wire(raw: bytes, *, kind: Literal["envelope", "receipt", "chunk"]) -> dict` from Task 1. Reuse those validators/parser; do not introduce a weaker duplicate envelope schema or eager receipt JSON path.

**Produces in `staging_receipt.py`:**

- `encode_receipt(envelope: bytes) -> tuple[bytes, ...]`: validates the envelope, returns immutable fully framed receipt/chunk lines including LF; performs no printing.
- `decode_receipt(lines: tuple[bytes, ...]) -> bytes`: validates bounded framing, receipt and independently decoded chunks, verifies exact byte length/count/digest, then the complete canonical envelope. Returns bytes only after all checks pass; raises the same fixed `EnvelopeError` on rejection.

- [ ] **Step 1: Write transport RED tests against the literal full `receipt.log`.** Assert exact tuple of framed bytes and exact reconstructed golden envelope. Include a multi-chunk envelope so nonfinal 1024-byte chunks end in independent padding. Confirm missing/duplicate/reordered/truncated chunk lines cannot return partial data.

- [ ] **Step 2: Run focused RED.** Use the Task 1 pytest command with `tests/ops/test_live_e2e_staging_receipt.py`; require missing receipt/interface failure and retain evidence.

- [ ] **Step 3: Implement minimal GREEN.** Validate complete envelope first, split raw bytes into 1024-byte chunks and independently standard-base64 encode. Build the exact spec receipt/chunk objects and prefixes; hash unframed envelope bytes only. For decoding, check tuple/bytes exact types, line count at most 2049, receipt at most 256 bytes and each chunk line at most 1536 bytes before parsing/retention. These derived transport ceilings cover all permitted 2 MiB envelopes and fixed schema fields; they grant no new host input authority. Parse through Task 1's first-pass structural gate and second-pass materializer for the exact receipt/chunk kinds. Check canonical JSON bytes, consecutive indexes, strict decode plus exact standard re-encode, decoded chunk sizes and projected reconstructed byte budget before extending a buffer. Require exactly one receipt, exactly its chunk count, and a final LF on every line; no other log prefixes or trailing lines are accepted by this pure codec.

- [ ] **Step 4: Add adversarial RED cases, then minimal GREEN.** Cover URL-safe alphabet, unpadded data, whitespace, surplus padding and nonzero pad bits (`+/8=` and `/w==` valid primitive encodings; `-_8=`, `+/8`, `/x==` refuse). Pin strict chunk decoding separately since these primitives are not complete envelopes. Cover uppercase/prefixed hashes, bool/numeric-string fields, duplicate JSON keys, noncanonical escaping, wrong count/byte length, receipt/chunk bounds, oversized tuple/line, wrong chunk sizes, digest mismatch and a correctly hashed but invalid envelope. Test complete 2 MiB round-trip and overflow refusal with Task 1's independent boundary fixtures.

- [ ] **Step 5: Run regression and document actual evidence.** Focused suites plus existing recovery/inventory/CI tests must PASS. Run Ruff over `src tests ops/systemd ops/live-e2e`, compile the new modules, and full supported Linux Python 3.13/3.14 CI. Record existing Mac-only platform failures distinctly if full local pytest is used; do not claim a green full regression from the 87-test baseline. Update README with dormant/data-only limitations and the actual implementation test counts. No workflow or live incident invocation is permitted.

- [ ] **Step 6: Fresh adversarial whole-branch review and fixes.** Review both codecs, independent fixtures, bounded allocation/parsing, strict typing/canonicality, complete-envelope bound, no host authority, no output before success and absence of workflow callers. Convert findings into focused RED/minimal GREEN and rerun affected regression. Require no unresolved Critical/Important findings; resolve Minor findings or explicitly justify safe deferral.

- [ ] **Step 7: Exact-head CI, merge, exact merge-main verification.** Open a small implementation PR; ordinary self-hosted CI must PASS on the reviewed unchanged exact head before expected-head merge. Record exact merge-main ordinary validation. ADR0011's recovery-only prerequisite permits this isolated slice while stale provider state blocks automatic Level-3; record that refusal accurately, with no A1/Level-3/Phase7B1 completion credit and no guard weakening or cancellation. If any unrelated failure appears, inspect and resolve rather than assuming stale-state refusal.

- [ ] **Step 8: Preserve incident evidence and move to the next gate.** Audit branch/worktree status. Preserve current recovery worktrees under the existing incident retention ruling until A1's exact-main gates pass; do not discard dirty work or unknown staging. Next prepare the separate diagnostic-child ADR amendment for written review. No preflight implementation may start until its approved authority is on main. N1c remains paused until A1 recovery is fully closed.

## Plan Self-Review and Handoff

The envelope/wire section and its acceptance cases map to Tasks 1–2. Filesystem provenance, fresh expected_commit observations, bounded native child lifecycle and final namespace checks deliberately remain later preflight/integration slices; authenticated receipt retrieval, deletion/journal durability and unknown-root disposal remain separate apply/operator contracts. No later gate is claimed by these codec tests.

All five Review Focus classes have owning tests above. Interfaces return immutable bytes, use one error category, a shared pre-schema parser and one envelope validator; receipt validation proves consistency rather than authorization. Local balanced integer conversion preserves the approved numeric domain without altering the global guard. Explicit depth/member/array/token limits apply before a decoded tree exists. This two-task plan ships one capability in one implementation PR without production or workflow changes.

Written plan review precedes implementation. Native execution preference is preserved; approval of #144 did not approve an unwritten implementation plan or the separate signal exception.
