# T5B-0 C0 offline structure preflight — non-authorizing

**Status:** structural evidence helper only, `C0_COLLECT_HOLD_INCOMPLETE`. Follow [C0 object classes and unresolved fields](2026-10-17-adr19-t5b0-c0-inert-candidate-object-allowlist.md). The stdlib-only `ops/t5b0/c0_manifest_preflight.py` reads a local JSON file and performs **no network, installation, import of candidate materials, trust-root import or verifier execution**. It neither generates a download command nor grants consent. No C0 candidate bytes were collected.

Usage: `python3 ops/t5b0/c0_manifest_preflight.py /path/to/untrusted-proposed-manifest.json`; exit 0 means only `STRUCTURE_ONLY_PASS; C0_COLLECT_HOLD; NO_NETWORK; NO_AUTHORIZATION`, exit 2 means refusal. JSON keys must be exactly `schema`, `objects`, `approval`; schema `som-t5b0-c0-preflight-v1`, `approval: null`. Each object must contain exactly `id`, `url`, `sha256`, `bytes`, `max_bytes`; ID from `C0-W1/P1/R1/T1`, no duplicates, 1–4 objects, SHA256 64 lowercase hex, integer positive exact bytes no greater than cap (hard cap 100 MB), and syntactically pinned HTTPS URL without query, credentials, port, fragment or parent traversal, percent-encoded path components, noncanonical dot/empty path segments, backslashes, non-ASCII URL characters, or malformed ports. Input safety: `os.open(O_RDONLY|O_NONBLOCK|O_NOFOLLOW)` plus `fstat` regular-file enforcement and a single bounded `os.read(16385)` reject FIFO/symlink/directory and oversized files before parsing; changed length and JSON recursion errors refuse with exit 2. This is a best-effort offline input check, not an adversarial shared-filesystem snapshot guarantee. The checker does not establish immutability, validate endpoint identity, enforce source allowlists, resolve DNS, check bytes or attestations, or establish signer/clock trust. Passing is never permission to fetch.

Run offline tests: `python3 -m unittest discover -s ops/t5b0 -p 'test_*.py' -v`. Tests include malformed URL, digest, size, duplicate ID, duplicate JSON keys, FIFO blocking, oversized regular files, symlinks, deep JSON, unauthorized approval marker and unexpected schema fields. **No tests contact external services.** The manifest itself is not committed with pretend trusted values: object URLs, byte sizes, OS image and downloader digests, original-byte custody/retention, independently authenticated OOB root/clock and operator consent remain missing. Separate operator authorization and independent review of the full exact-object manifest and isolated environment are mandatory before any collection. T5B-0 admission, T5B-1, Mac UID502/APFS, real pkg and Linux Slice C remain HOLD.

## Hosted regression coverage

A `tests/ops` pytest bridge runs all offline C0 fixtures on both Python 3.13 and 3.14 in the existing `rest` shard, under the existing non-root, cleared-supplementary-groups Linux execution policy. Failures block the existing required aggregate contexts. Crucially, the frozen-authority `.github/workflows/ci.yml` remains byte-identical; no CI privilege, runner, external endpoint or network allowance changes.

## Canonical URL spelling (fail closed)

The local syntax check additionally rejects percent-encoded path components (including encoded dot segments and separators), dot/empty path segments, backslashes, non-ASCII URL text, and malformed ports. This avoids ambiguous URL spellings and parser exceptions; it does **not** authenticate DNS, endpoint provenance, artifact immutability or approve fetching. No network is used.

## Machine-readable offline result (`--json`)

`python3 ops/t5b0/c0_manifest_preflight.py --json /path/to/proposal.json` prints one JSON object on stdout. Fields are `status` (`STRUCTURE_ONLY_PASS` or `REFUSED`), `errors` (array of diagnostic strings), `authorization` (`NO_AUTHORIZATION`), `collection` (`C0_COLLECT_HOLD`), and `network` (`NO_NETWORK`). Exit status remains 0 for a structurally valid proposal and 2 for refused/unreadable input. Without `--json`, the original text output and exit codes are unchanged. The JSON report is an **offline syntax/structure observation only**, not proof of artifact authenticity, source identity, network permission, operator consent, or Sigstore verification.

Example successful output (field order is not contractual):

```json
{"status":"STRUCTURE_ONLY_PASS","errors":[],"authorization":"NO_AUTHORIZATION","collection":"C0_COLLECT_HOLD","network":"NO_NETWORK"}
```

Automations must check both process exit code and `status`, and must never treat `STRUCTURE_ONLY_PASS` as permission to collect or execute candidate materials.

## Stable machine-readable error categories

The opt-in `--json` report adds `error_codes` as an array of stable identifiers. `[]` means no structural errors; `INVALID_STRUCTURE` means a parsed JSON manifest violated the C0 schema/semantic constraints; `INVALID_MANIFEST` means the file could not be read or parsed (including duplicate keys). The existing human-readable `errors` array remains diagnostic only, not a programmatic contract. A failure currently has exactly one category, and consumers should tolerate future additional categories. The CLI still exits 0 for structure-only success and 2 for refusal; all reports preserve `NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, and `NO_NETWORK`. These categories grant no collection, provenance or verification authority.

## Bounded offline batch preflight

Use `python3 ops/t5b0/c0_manifest_preflight.py --batch file1.json file2.json` to inspect 1–16 local manifests in input order without any network activity. Batch mode always prints one aggregate JSON object with `status`, `errors` (batch-level diagnostics), `results` (one `{path, status, errors, error_codes, authorization, collection, network}` object per input), and the invariant aggregate `NO_AUTHORIZATION`/`C0_COLLECT_HOLD`/`NO_NETWORK` markers. All valid structural inputs yield aggregate `STRUCTURE_ONLY_PASS` and exit 0; any refused item or more than 16 paths yields aggregate `REFUSED` and exit 2. Over-limit input is rejected before opening any manifest (`results: []`). Batch validation is independent per file; a refused item does not skip later files. Existing one-file text and `--json` contracts remain unchanged. A pass is strictly offline structure-only and never authorizes material collection or trust-root import.

## Offline directory audit (C0, non-authorizing)

`python3 ops/t5b0/c0_manifest_preflight.py --directory ./manifests` performs one nonrecursive, deterministic lexicographically ordered audit of 1–16 immediate `.json` entries. Other names and nested directories are ignored **only within a 64-total-entry scan budget**; the 65th immediate entry refuses the entire audit before any manifest is opened. Non-JSON names (including nested directories) count toward this budget, preventing unlimited enumeration/memory retention even when there are just 1–16 matching `.json` files. The tool opens the directory without following a directory symlink and anchors child opens to the directory descriptor; each child must be a bounded regular file without a symlink. The machine-readable report contains `status`, `errors`, `passed`, `refused`, `results` and invariant `NO_AUTHORIZATION`/`C0_COLLECT_HOLD`/`NO_NETWORK` markers. Each result includes the input `path`, legacy classification and `sha256` of the **exact bytes read**, or `null` if no bytes could be read. Hashes are repeatability aids, **not provenance, authenticity, trust or permission evidence**. Empty directories, >16 matching entries, unreadable directories and symlinks fail closed; overflow is refused before any manifest file is opened. Any refused entry causes exit 2; all valid structures exit 0. Single-file and `--batch` outputs are unchanged. No collection or admission authority is conferred.

## C0 offline directory consistency audit and evidence handoff (2026-10-18)

The existing `--directory` command now additionally checks **cross-file** consistency after reading the same bounded, descriptor-anchored inputs exactly once. Only structurally valid manifests contribute objects to the cross-file comparison. Duplicate object IDs across different files are refused with `DUPLICATE_OBJECT_ID` on **all involved files**, even when declarations are identical. Contradictory declarations for the same ID (URL/digest/size/cap), for a shared URL (ID/digest/size/cap), or for a shared SHA-256 with different declared byte sizes are refused with `CROSS_FILE_CONFLICT` on all involved files. Existing `INVALID_MANIFEST`/`INVALID_STRUCTURE` codes remain distinct. Cross-file conflicts never stop processing later files. `passed`/`refused`, aggregate `status` and exit 0/2 reflect final post-consistency outcomes.

The directory report adds `audit_sha256`, a SHA-256 of deterministic compact JSON containing the **sorted immediate filename and exact-read SHA-256** pairs; it is `null` for empty/over-limit/unreadable directory or if any entry was unreadable. This is an input-observation fingerprint, **not** an authenticated seal, trusted provenance or proof that a mutable directory remained unchanged during scanning. Individual `results[].sha256` still hashes exact bytes read and can exist for malformed JSON. File paths are for diagnostics, not trusted identity. All output is deterministic for the same observed inputs, without timestamps, network or writing any report file.

`evidence.status` always remains `UNVERIFIED` and `evidence.gaps` explicitly enumerates `SOURCE_AUTHENTICITY`, `TRUST_ROOT`, `TRUSTED_TIME`, `EXECUTION_ENVIRONMENT`, and `OPERATOR_AUTHORIZATION`, each `UNVERIFIED`. Even a structure-only success has all five gaps: no manifest content can approve collection or cryptographic verification. Existing single-file and `--batch` CLI outputs remain unchanged; `NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, `NO_NETWORK`, T5B-0/T5B-1 HOLD, real Mac/UID502/APFS HOLD and Linux Slice C deferral are unchanged.

Example: `python3 ops/t5b0/c0_manifest_preflight.py --directory ./manifests > local-audit.json` (redirection is optional, performed by the caller, not the checker). Treat this JSON as **review evidence only**. The audit does not perform signature checks, artifact acquisition, environment admission or any external authorization step.

## Two-directory offline review diff (2026-10-18)

`python3 ops/t5b0/c0_manifest_preflight.py --compare-directories ./before ./after` compares two **independently observed** bounded, nonrecursive, no-follow directory audits. The command prints deterministic JSON with `before` and `after` complete directory reports, `added`, `removed`, `changed` (same immediate filename, different exact-read SHA-256), and `regressions` (same filename changed from `STRUCTURE_ONLY_PASS` to `REFUSED`). `UNCHANGED` means the observed filename/byte hashes match; `CHANGED` means they differ while both directory audits passed; `REFUSED` means **either** directory audit failed, including symlinks, malformed files, cross-file conflicts, missing/empty/overflow directories. Exit code is 0 for `UNCHANGED`/`CHANGED`, 2 for `REFUSED`. Even a `CHANGED` result is **not** acceptance or permission to collect; callers must review changes.

If a directory is refused, any listed additions/removals/changes are only partial diagnostics and **not a complete inventory**; inspect both `before.status` and `after.status`, errors and `audit_sha256` (`null` if a complete exact-read fingerprint cannot be computed). The command does not write snapshots, does not authenticate either baseline, does not compare against a signed policy, and does not assert immutability or atomicity across directories. The same five evidence gaps remain `UNVERIFIED` and invariant `NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, `NO_NETWORK` markers are present at every report level. The preexisting single-file, `--json`, `--batch` and `--directory` output contracts remain unchanged.

## Semantic C0 object review delta (2026-10-18)

`--compare-directories` now additionally emits `object_diff`, computed from the **same bounded descriptor-anchored reads**, never by reopening files. Only when **both** directory audits pass fully is `object_diff.status=AVAILABLE` with sorted object-ID `added`/`removed` and `changed` entries `{id, fields}`. `fields` lists only changed allowlisted manifest attributes `url`, `sha256`, `bytes`, `max_bytes`; it deliberately does not echo URL or digest values. Moving an identical object between filenames changes the filename delta but not the object delta. If either directory is refused for any reason, `object_diff={"status":"UNAVAILABLE","reason":"DIRECTORY_AUDIT_REFUSED"}`: no partial or ambiguous semantic inventory is offered as complete. This is a reviewer observation, not cryptographic authenticity, approved policy, authorization, collection or evidence-gap closure. All five evidence gaps remain `UNVERIFIED`; legacy single-file/`--batch`/`--directory` report contracts remain unchanged.

## Opt-in offline review change gate (2026-10-18)

For a reviewer or CI workflow that must stop on *any* observed file-level change, use `python3 ops/t5b0/c0_manifest_preflight.py --compare-directories BEFORE AFTER --fail-on-change`. The flag is valid with **either** `--compare-directories` or `--compare-stdin-to-directory BEFORE_DIR`; unrelated input modes reject it before reading input. The directory mode gates filename/exact-byte changes; the streamed-successor mode gates object-ID semantic changes. The deterministic JSON output is **identical** with and without the flag within each mode; only the exit code changes. Directory comparison includes filename and semantic object diffs; streamed successor comparison includes bounded baseline/NDJSON reports, semantic object diffs, evidence gaps and safety markers. For directory-to-directory mode with the gate, exit 0 requires matching observed filenames and exact-read file bytes; exit 3 reports any filename/byte difference, including filename-only moves. For streamed-successor mode with the gate, exit 0 means object-ID semantic equality and exit 3 means added/removed IDs or changed allowlisted object fields; filenames and byte formatting are irrelevant. In either mode exit 2 means one or both inputs refused, independent of the flag. Without the flag, `CHANGED` continues to return `0` for backward compatibility. This is a *change-detection* signal, **not** evidence of authentic provenance, an authorized baseline, permission to collect, or a safe-to-execute verdict. Callers must treat exit 2 and 3 as review-required and may not infer approval from exit 0. No network or writes.
## Opt-in manifest-only directory review (2026-10-18)

For a clean reviewer intake directory that **must not contain unexamined auxiliary files**, run `python3 ops/t5b0/c0_manifest_preflight.py --directory ./manifests --require-json-only`. This adds a fail-closed shape check **before opening any manifest**: any immediate directory entry whose name does not end in `.json` (including nested directories, hidden files, foreign metadata, and symlinks with a non-JSON name) causes `REFUSED` / exit 2, `errors=["directory contains non-json entry"]`, `results=[]` and `audit_sha256=null`. A `.json` symlink/special file still fails the pre-existing descriptor-anchored regular-file validation. `--require-json-only` is supported with `--compare-directories BEFORE AFTER` (on both directories) and `--compare-stdin-to-directory BEFORE_DIR` (only on the baseline directory); optional `--fail-on-change` is compatible with either comparison mode. A refusal prevents any partial semantic object inventory (`object_diff=UNAVAILABLE`). It is rejected when used with single-file, `--json` single-file, or `--batch` modes.

Without the flag, the existing behavior remains: small auxiliary files and nested directories are **ignored** (subject to the 64-total-entry resource budget shared by strict and default modes); output field names, status markers and exit codes of all existing invocation modes are unchanged. A clean directory or unchanged comparison is **not** source authenticity, trust-root verification, independent time evidence, execution-environment admission or operator authorization. Nothing is downloaded, written, executed or approved by this option; `C0_COLLECT_HOLD`, `NO_NETWORK` and all five `UNVERIFIED` evidence gaps remain in force.

## Total-entry scan budget and safety (2026-10-18)

The directory/compare reviewer caps enumeration at **64 total immediate entries**, including ordinary `.json` files, other files, symlinks and nested directories. Within that budget, non-JSON entries remain ignored exactly as before. On the 65th entry, it stops consuming `scandir` and returns `REFUSED` / exit 2, `errors=["directory must contain at most 64 total entries"]`, `results=[]`, `audit_sha256=null` without opening even a known manifest. The pre-existing 17th `.json` rule likewise refuses before opening input manifests. For `--compare-directories`, either side's scan-budget refusal suppresses the entire `object_diff` (`UNAVAILABLE/DIRECTORY_AUDIT_REFUSED`), including with `--fail-on-change`.

Operator reproduction without network: create one valid C0 test manifest and 63 unrelated `.txt` entries in a disposable directory: structure-only directory audit remains allowed; add a 64th `.txt` entry to make 65 total and re-run `python3 ops/t5b0/c0_manifest_preflight.py --directory ./manifests`: it must report `REFUSED`. The 64-entry cap is a resource/DoS limit, not an authenticity or authorization gate. `STRUCTURE_ONLY_PASS` is never permission to download or execute candidate bytes; evidence gaps remain `UNVERIFIED`, and no source, signer, time, runtime or consent policy is selected.

## Explicit bounded stdin C0 manifest preflight (2026-10-18)

For a purely offline command pipeline, `cat manifest.json | python3 ops/t5b0/c0_manifest_preflight.py --stdin --json` validates the exact piped input without creating a temporary manifest file. The `--stdin` flag must be explicit; the tool reads **at most 16,385 bytes** from standard input and refuses any payload longer than 16 KiB, malformed/duplicate-key JSON, invalid structures, or invalid UTF-8 with `REFUSED`/exit 2. Empty input is refused. Stdin is decoded as strict UTF-8 (an optional UTF-8 BOM is accepted) before JSON parsing; UTF-16/UTF-32 encoding autodetection is not permitted. It applies the same existing `parse_manifest` and `validate` shape rules as a regular manifest, returning the same stable machine-readable `status/errors/error_codes` and invariant `NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, `NO_NETWORK` markers. Without `--json`, the legacy `STRUCTURE_ONLY_PASS` or `REFUSED:` text contract remains. `--stdin` is exclusive with positional manifest, `--batch`, `--directory` and `--compare-directories` and mixed modes fail before reading input.

The stream is an **operator-supplied untrusted proposal**, not an authenticated or sealed file, and may block while the producer has not closed its end. No stdin approval field can ever authorize collection, signature verification or execution. This path is structure-only with no hostname contact, package download, file creation, installer, privileged host or new root policy. Existing descriptor-anchored file and directory modes remain unchanged. All C0/T5B evidence and consent gates stay HOLD.

## Bounded NDJSON stdin batch audit (2026-10-18)

For offline build/reviewer pipelines that need cross-manifest consistency checks without creating files, pipe **1–16 newline-delimited JSON C0 proposals** into `python3 ops/t5b0/c0_manifest_preflight.py --stdin-batch` (optional `--json` is redundant: batch always returns JSON). Each record must be a complete manifest under the existing C0 structural schema. Input is **untrusted** and may block until the producer closes the stream. The reader consumes at most **262,161 bytes** (one byte past the **262,160-byte** total maximum: 16 × (16,384-byte record + one newline)); any overflow refuses the whole batch *before parsing* with no partial results. More than 16 records, an empty batch, or a record over 16 KiB similarly refuses without partial results. A missing terminal newline is allowed; blank records are invalid.

Each parsed item is identified only by deterministic `stdin:1`, `stdin:2`, … order. The tool reuses the exact duplicate-key/nonfinite UTF-8 parser, strict structure validator and cross-record duplicate-ID/URL/digest-size checks from directory audits. Individual malformed/invalid records refuse the aggregate; cross-record conflict reason strings are deliberately generic and do **not** echo untrusted URLs, digest values or raw stream data. Exit 0 means only structural consistency; exit 2 means refusal. `--stdin-batch` rejects other input modes, `--require-json-only`, and `--fail-on-change` **before consuming stdin**; legacy single-file, `--stdin`, `--batch`, directory and compare behavior remains unchanged. No network calls, filesystem reads/writes, collection, authorization, host probes or external verifier execution occur. All five evidence gaps are still `UNVERIFIED`; `NO_AUTHORIZATION` and `C0_COLLECT_HOLD` remain invariant. The NDJSON stream is **not** a source-authenticated input and has no consent power.

For `--stdin-batch`, each bounded record is decoded as strict UTF-8 before JSON parsing; an optional UTF-8 BOM is accepted. UTF-16/UTF-32 records are refused with `INVALID_MANIFEST`, without JSON encoding autodetection. File-based input modes retain their existing behavior.

## C0 streamed successor versus offline baseline comparison (2026-10-18)

**Implemented reviewer function (non-authorizing):** `--compare-stdin-to-directory BEFORE_DIR` consumes a bounded 1–16-line NDJSON *successor* from stdin and compares its validated object-ID semantic inventory with the existing bounded, descriptor-anchored offline directory *baseline*. Both are untrusted independent snapshots, neither a trust root. `--fail-on-change` returns exit 3 only for a valid changed successor, exit 0 for unchanged, exit 2 for any refusal. `--require-json-only` applies only to the baseline directory. The command emits one JSON object with `before`, `after`, `object_diff` and aggregate `UNCHANGED`/`CHANGED`/`REFUSED` status. Added/removed IDs and names of changed fields may be shown, but never their raw URLs or SHA256 values. On either-side refusal, semantic inventory is `UNAVAILABLE` and never a partial diff. The new combined report also sanitizes baseline `before.results[].errors`: cross-file URL and SHA-size conflicts use fixed generic diagnostics, never untrusted URL/digest values. Existing standalone `--directory` and `--compare-directories` output formats remain unchanged.

**Hard invariants:** reuse existing at-most-64 directory entries, at-most-16 JSON manifests, safe no-follow reads, 16 KiB/line and 262,160-byte stdin total, cross-manifest duplicate/conflict refusal, strict UTF-8 for NDJSON, deterministic stdin:N labels, and CLI exclusivity before stdin consumption. No writes, downloads, host probes, root/source/clock adoption, collector, installer, real privileged Mac/UID502/APFS or Linux C activity. `NO_AUTHORIZATION`, `C0_COLLECT_HOLD` and `NO_NETWORK` remain invariant; C0/T5B execution and material admission remain HOLD. Semantic equality is not byte identity, cryptographic provenance or consent.

**TDD plan:** RED subprocess tests for unchanged and changed semantic inventories, add/remove/change-field reporting, exit-3 opt-in, malformed/oversize stdin, invalid or over-64-entry/symlink directory, strict mixed non-JSON rejection and mode-conflict pre-read, then smallest shared-parser/semantic-diff implementation, focused GREEN + regression, docs parity and exact-head CI. This is one externally runnable reviewer workflow, not a new admission gate.

**Usage (offline operator example):** keep a previous bounded manifest set as an untrusted directory baseline. Feed one JSON C0 proposal per NDJSON line from a closed producer:

~~~sh
cat successor-proposals.ndjson | python3 ops/t5b0/c0_manifest_preflight.py \
  --compare-stdin-to-directory ./before-manifests --fail-on-change --require-json-only
~~~

The result always includes JSON keys status, before, after, object_diff, evidence, authorization, collection, network. Exit 0 / UNCHANGED means only the declared object-ID inventory and url/sha256/bytes/max_bytes fields are equal; filenames, JSON formatting, and exact source bytes need not match. Exit 3 / CHANGED is returned only with --fail-on-change and a valid semantic difference. Exit 2 / REFUSED means baseline or stream failed and object_diff.status is UNAVAILABLE, never a partial admission. Without the change gate, valid CHANGED exits 0 as in the prior directory semantic reviewer. Neither side is an authenticated reference.

## C0 race-aware regular-file observation (2026-10-18)

**Bounded behavior:** when a C0 manifest is already held open via no-follow/nonblocking regular-file descriptor, compare the opened inode's device, inode number, type/mode, size, mtime_ns and ctime_ns before and after the existing bounded single read. Refuse (INVALID_MANIFEST/exit 2) when any differ, even if the byte count and resulting JSON are valid. Final digest, structure-only success and object inventory MUST derive from a checked stable read, never from observed in-place mutation.

**TDD and independent observability proof:** the original deterministic same-inode/same-length in-place rewrite tests proved false STRUCTURE_ONLY_PASS before the production fix. Additional reviewed regression fixtures for both single-file and directory audit perform a same-length valid-JSON rewrite, restore the original mtime, and use paired synthetic same-FD fstat observations where **only ctime_ns differs**; the complete report must REFUSE with INVALID_MANIFEST and no accepted digest/inventory. A separate paired observation where **only atime_ns differs** must retain STRUCTURE_ONLY_PASS. The harness uses controlled timestamp observations to avoid filesystem time granularity/flakiness. Mutation-test evidence: temporarily removing ctime_ns comparison causes two ctime fixture failures; temporarily including atime_ns causes two atime fixture failures. Production source was restored and both normal fixtures passed afterward. The 16 KiB manifest cap, 64 directory entries, no-follow/nonblocking reads and stdin modes are unchanged. This is metadata-drift detection, not proof of an atomic snapshot.

**Limit:** metadata rechecking reduces race windows but does NOT prove atomic snapshot consistency against a privileged attacker, immutable source provenance, or authenticity of any artifact. STRUCTURE_ONLY_PASS is non-authorizing. C0 collection, T5B admission, verifier, real Mac/UID502/APFS and Linux C remain HOLD.

The verifier compares same-opened-file identity, mode, size, mtime_ns, and ctime_ns both before and after read; an observed same-length in-place rewrite returns REFUSED with INVALID_MANIFEST and no accepted object inventory. It deliberately ignores access time because normal reads may update it. Test coverage includes stable positive inputs, same-size mutation REFUSED, restored-mtime/ctime-only REFUSED and atime-only PASS for single-file and directory paths. This cannot detect all races or privileged timestamp manipulation and does not grant provenance or admission authority.

## C0 intra-manifest object identity and digest-size consistency (2026-10-18)

The bounded offline C0 structural validator now rejects **within one manifest** any URL reused for more than one object ID, including identical declarations, and any repeated SHA-256 claim with inconsistent declared byte length. Distinct URLs with the same SHA-256 and identical byte length remain permitted as untrusted mirror claims; this does not authenticate either origin. The existing strict URL, known ID, positive cap, 16 KiB and aggregate/directory bounds remain. Cross-manifest consistency rules are additive and unchanged.

Both contradictions return INVALID_STRUCTURE and REFUSED/exit 2 across file, --stdin, --batch, --stdin-batch, --directory and streamed comparison. The latter suppresses the semantic object inventory (UNAVAILABLE). Errors name only the object index and collision type, never echo the conflicting URL or digest. This is a **non-authorizing** consistency observation, not an admission verdict. NO_AUTHORIZATION / C0_COLLECT_HOLD / NO_NETWORK and all UNVERIFIED evidence gaps persist; no material collection, trust-root adoption, verifier execution, privileged Mac/UID502/APFS or Linux C actions.

## C0 opened-directory namespace drift refusal (2026-10-19)

An offline directory audit can otherwise observe a valid manifest and return a misleading stable result when another process changes the directory namespace after enumeration. The bounded auditor now compares the **same open directory FD** before and after its scan and manifest reads using device, inode, mode, `mtime_ns` and `ctime_ns`. If these differ, the entire directory report returns `REFUSED` / exit 2 with fixed `directory changed during audit` diagnostic, no partial `results`, `audit_sha256=null`, and no accepted object inventory. Two-directory and streamed-successor comparisons automatically return `object_diff=UNAVAILABLE` when the baseline side refuses. Atime is excluded because a normal directory read can update it.

The tests mutate a real bounded input directory after a valid manifest read (direct directory, two-directory, stream-to-directory), and separately inject identical pre/post metadata except for ctime (must REFUSE) and except for atime (must PASS). Ordinary stable behavior, no-follow directory/file reads, 64 total entries/16 JSON entry and 16 KiB file budgets remain unchanged.

This check reduces observed namespace races, but cannot guarantee atomic snapshots, privileged attacker resistance, source authenticity or consent. `NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, `NO_NETWORK` and five `UNVERIFIED` evidence gaps are unchanged. No material collection, verifier execution, trust admission, privileged Mac/UID502/APFS or Linux C work is authorized.

## 2026-10-19 C0 offline directory cross-file diagnostic redaction

The directory auditor historically included raw candidate URLs or SHA-256 claims in cross-file conflict `errors`. A synthetic two-manifest probe independently reproduced this exposure in `--directory` and `--compare-directories` JSON/stdout; existing streamed comparisons already redacted the diagnostic. To avoid exposing untrusted candidate metadata in reviewer output or CI logs, all directory report paths now reuse the existing fixed `DUPLICATE_OBJECT_ID` / `CROSS_FILE_CONFLICT` diagnostic sanitizer. Both default and `--require-json-only` directory and comparison modes are covered, including URL disagreement and same-SHA/different-size conflicts. No raw URL or digest is echoed from these diagnostics. Legacy JSON field structure, error codes, statuses, exit codes and non-conflicting success reports are unchanged; conflicting error message *content* intentionally changes for confidentiality.

This is **only** suppression of raw values in error diagnostics, not source authentication or secrecy of original files. SHA-256 exact-file audit fingerprints remain diagnostic and unauthenticated. `NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, `NO_NETWORK`, `UNVERIFIED` evidence gaps, 64 directory entries, 16 manifests/16 KiB each, same-FD file and directory race protections remain unchanged. No material collection, tool/root admission, verifier invocation or privileged Mac/UID502/APFS or Linux C action is authorized.

## 2026-10-19 Refused directory: no partial internal object inventory

Offline C0 `inspect_directory(..., capture_inventory=True)` and the derived `directory_report` previously retained raw object metadata from already-valid individual manifests even when another manifest was invalid, cross-file duplicate IDs were detected, or cross-file URL/SHA inconsistency made the **aggregate REFUSED**. This internal inventory is currently discarded by comparisons when refused, but returning a partial accepted-like inventory creates a future fail-open interface risk. The directory auditor now clears this inventory for **any** directory-wide or per-item refusal, while preserving diagnostic `results`, `error_codes`, `status`, `audit_sha256`, exit behavior and unchanged positive results. Both comparison modes continue to report `object_diff=UNAVAILABLE` for refused inputs.

Deterministic TDD RED/GREEN fixtures cover duplicate cross-file object ID, conflicting cross-file URL/SHA and invalid subsequent manifest. They explicitly verify no partial internal object inventory is retained, plus unchanged valid-directory semantic inventory. The 64-entry, 16-manifest, 16 KiB, no-follow/same-FD race and sanitized diagnostics boundaries remain unchanged. This is structural review, **not** an atomic snapshot, proven origin, material collection or source/root/tool approval; `NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, `NO_NETWORK`, five `UNVERIFIED` gaps, privileged Mac UID502/APFS, T5B and Linux C remain HOLD.

## 2026-10-19 Direct directory-inspection diagnostic confidentiality

The lower-level offline `inspect_directory` interface previously returned untrusted cross-file conflict diagnostics with literal candidate URLs or SHA-256 values; the higher-level `directory_report`/CLI already sanitized those messages. A caller that reused the direct results could therefore inadvertently log the raw candidate metadata. The directory inspector now applies the same fixed cross-manifest diagnostic redaction **before returning**, for both inventory and non-inventory callers, default and strict directory modes. This applies to duplicate IDs, colliding URLs and declared-digest versus size conflicts.

TDD regression confirms twelve original leak cases (three conflict types × default/strict × with/without captured inventory) and keeps an unchanged accepted-directory control. Diagnostic *contents* at the lower-level API are intentionally fixed, but codes, status, ordering, digest/fingerprint, inventory suppression on aggregate refusal, public JSON/CLI output shape, and exit semantics stay unchanged. The existing outer sanitizer remains idempotent defense-in-depth.

This only protects offline error-message confidentiality. Neither the structure-only verdict nor file SHA-256 fingerprints prove source authenticity, atomic snapshot, trust-root, execution approval or collection permission. No network/material acquisition, candidate verifier/root admission, privileged Mac UID502/APFS or Linux C capability was added. 64 entry / 16 JSON / 16KiB file caps, NO_AUTHORIZATION, C0_COLLECT_HOLD, NO_NETWORK and all five UNVERIFIED evidence gaps persist.

## 2026-10-19 C0 canonical HTTPS hostname syntax refusal (offline)

The inert C0 structural validator previously accepted hostnames with percent escapes, empty DNS labels, a leading/trailing dot, underscore labels, leading/trailing label hyphens, label length over 63, or total hostname length over 253. Python's URL authority parser can parse these spellings, but parsing alone does not make them a single canonical DNS-host spelling. The validator now refuses these under the **existing** `INVALID_STRUCTURE` / `URL not pinned to a single HTTPS object path` diagnostic, using a lower-case ASCII LDH label check (1–63 characters per label, bounded total 253). Existing accepted simple lowercase DNS, punycode spellings, IPv4 literal text and single-label hosts remain syntactically eligible. This **does not** validate DNS existence, IP literal identity, whether punycode is a permitted source, endpoint provenance or source authorization.

Nine adversarial invalid hosts were observed as structure-only PASS before the fix (TDD RED) and now refuse; valid controls pass. Existing input modes use the shared validator; representative `--stdin` text and JSON refusal paths are verified. No DNS lookup, network interaction, package acquisition, trust root/tool, candidate admission, privileged Mac UID502/APFS or Linux C behavior is enabled. `NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, `NO_NETWORK`, the five `UNVERIFIED` evidence gaps, 64 directory names, 16 JSON manifests and 16 KiB each remain unchanged.

## 2026-10-19 Offline C0 numeric IPv4 hostname alias refusal

The canonical DNS-label syntax gate did not eliminate legacy numeric IPv4 aliases. The untrusted C0 manifest preflight previously reported structural PASS for shortened dotted IPv4, zero-prefixed, hexadecimal, and integer-form hosts; these spellings can be interpreted as IPv4 addresses differently from their literal string representations by network clients. The offline validator now recognizes wholly numeric/hex-prefixed dotted hosts and requires the **strict canonical four-component dotted decimal** spelling via Python's `ipaddress.IPv4Address`, otherwise reusing existing `INVALID_STRUCTURE` and fixed URL-not-pinned diagnostics. Ordinary DNS labels (including numeric *interior* labels), lowercase punycode text, and valid IPv4 dotted decimal remain structurally eligible.

Deterministic regression covers noncanonical IPv4 aliases and ordinary host controls as well as the existing stdin JSON refusal flow. This check neither performs DNS lookups nor uses a socket, never authenticates an endpoint or grants a material-download permission. It changes no public JSON keys/exit code classifications, no C0 directory (64 immediate entries), 16 manifest, 16 KiB-per-file, nofollow/race budgets, and no T5B source/root/tool or privileged Mac UID502/APFS/Linux C HOLD boundary. `NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, `NO_NETWORK` and all five evidence gaps `UNVERIFIED` persist.

## 2026-10-19 Offline C0 numeric final DNS-label refusal

A noncanonical URL hostname may contain ordinary alphabetic labels but end in a numeric or hex-IPv4 label, such as `example.123`, `abc.127.1`, or `a.0x7f`. Offline C0 structural preflight formerly accepted these while WHATWG-style URL parsing rejects/handles them as candidate IPv4 rather than ordinary DNS. The existing numeric-host spelling check now **also refuses numeric/hex-only rightmost labels** on mixed-label hosts, preserving strictly canonical four-component IPv4, ordinary lowercase DNS and numeric *interior* DNS labels (e.g. `a.1.example`).

Five deterministic RED→GREEN examples demonstrate this gap at the shared C0 validator; good controls remain eligible. This is a strictly lexical, offline check: **no** DNS resolution, endpoint identity proof, downloads, collector action, signer trust or authority changes. Reuses `INVALID_STRUCTURE` and the fixed URL diagnostic; all modes, 16 KiB/file, 16 JSON/64-entry bounds, FD/race checks and `NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, `NO_NETWORK` with five `UNVERIFIED` gaps remain. T5B trust/root/tool and Mac UID502/APFS/Linux C HOLD remain.

## 2026-10-19 Empty `0x` terminal host-label regression (PR #300 review P2)

Independent review exposed the special terminal label `0x` with no following hex digit (e.g. `example.0x`, `a.0x`, also bare `0x`). The numeric-tail checker previously matched only `0x` followed by at least one hex digit, so the offline structure-only validator accepted these URL-parser-incompatible proposals. The shared, strictly lexical numeric IPv4 helper now explicitly refuses an empty `0x` tail under existing `INVALID_STRUCTURE` diagnostics. TDD RED reproduced refusal misses in each of seven entrypoints (single file, stdin, batch, NDJSON, directory, two-directory comparison and streamed successor comparison), for all three examples; GREEN verifies exit 2, the refusal statuses, and `object_diff=UNAVAILABLE` for both comparisons. `example.0xg`, numeric *interior* DNS labels and canonical dotted IPv4 remain valid controls. This neither resolves DNS nor confers network/material/installer/root/tool privileges. `NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, `NO_NETWORK`, five `UNVERIFIED` gaps, and T5B/Mac UID502/APFS/Linux Slice C HOLD remain unchanged.

## 2026-10-19 C0 empty URL query/fragment delimiter refusal

Offline C0 structural preflight previously accepted an untrusted URL ending with an empty question-mark or fragment delimiter (`https://host/pinned.whl?`, `https://host/pinned.whl#`, `https://host/pinned.whl?#`). Python `urlsplit` reports empty `query` and `fragment` strings in these cases, so a truthiness-only check did not reject the delimiters despite the documented no-query/no-fragment canonical URL policy. The shared validator now rejects literal `?` and `#` URL delimiters even when their corresponding fields are empty, reusing fixed `INVALID_STRUCTURE` / URL-not-pinned diagnostics. Existing nonempty query/fragment refusals and canonical pinned HTTPS object-path success remain unchanged.

TDD RED verified the three old false structural passes; GREEN tests 3 delimiters × 7 CLI input/compare modes (single manifest file, stdin, batch, NDJSON, directory, two-directory comparison and streamed successor comparison) for exit 2, status REFUSED, unchanged `NO_AUTHORIZATION`/`C0_COLLECT_HOLD`/`NO_NETWORK` and `object_diff.status=UNAVAILABLE` on comparison refusal. No DNS/network/material acquisition, root/tool admission or host privilege changes. Existing 64 total directory entries, 16 JSON, 16KiB/file and race/no-follow limits, five UNVERIFIED evidence gaps, T5B source/root/tool and Mac UID502/APFS/Linux C HOLD are unchanged.

## 2026-10-19 C0 canonical literal lowercase HTTPS scheme

Python `urlsplit` lowercases the scheme value, so the offline structural preflight previously treated uppercase and mixed-case HTTPS scheme spellings (`HTTPS://`, `Https://`, `hTTps://`) as identical to literal canonical `https://` and incorrectly returned structure-only PASS. The shared C0 URL validator now requires the raw untrusted URL to begin exactly with lowercase `https://` in addition to its existing parsed scheme check; the existing `INVALID_STRUCTURE` and fixed URL-not-pinned diagnostic remain. No change to lowercase canonical URLs or existing non-HTTPS rejection.

TDD RED proved three mixed-case scheme variants were misaccepted; GREEN verifies all three across the seven file/stdin/batch/NDJSON/directory/two-directory comparison/streamed successor modes, checking fail-closed status, exit 2, existing safety markers and unavailable semantic diff on refused comparisons. This is strictly offline lexical hardening; no DNS, network, downloaded material, root/tool/source admission, privileged Mac UID502/APFS or Linux Slice C. The 64 directory-entry/16-manifest/16KiB limits, no-follow and race checks, NO_AUTHORIZATION, C0_COLLECT_HOLD, NO_NETWORK and five UNVERIFIED gaps remain unchanged.

## 2026-10-19 C0 malformed percent-escape URL path refusal

The inert C0 canonical pinned HTTPS URL policy already refused valid percent encodings that `urllib.parse.unquote` changes; however malformed encodings (such as `/pkg%GG.whl`, `/pkg%.whl`, `/pkg%2.whl` and `/pkg%zz.whl`) are left unchanged by `unquote` and were erroneously accepted as `STRUCTURE_ONLY_PASS`. The shared validator now refuses any literal `%` in the URL path, including malformed encodings, using existing fixed `INVALID_STRUCTURE`/URL-not-pinned diagnostics; valid unescaped ASCII paths are unchanged. This is a lexical offline syntax check, not URL fetching, endpoint authentication, DNS or material execution.

TDD RED reproduced four false-valid path spellings; GREEN covered those in the seven single-file, stdin, batch, NDJSON, directory, two-directory comparison and streamed comparison CLI paths. Expected refusal remains exit 2/REFUSED, comparison `object_diff=UNAVAILABLE`, and markers `NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, `NO_NETWORK`. The unchanged 64 immediate names, 16 JSON, 16KiB/file and no-follow/race resource controls and all five `UNVERIFIED` evidence gaps remain; no T5B roots/tools/source/material, privileged Mac UID502/APFS or Linux C HOLD is advanced.

## 2026-10-20 C0 WHATWG-reserialized raw path characters

The inert C0 pinned HTTPS URL checker previously accepted raw `<`, `>`, double quotation mark, `{`, `}` and backtick in a path even though WHATWG URL clients percent-serialize these characters (e.g. `<` to `%3C`, `{` to `%7B`). That can cause the lexical value in a structure-only candidate proposal to differ from the URL string a downstream client handles. The shared offline structural validator now refuses **only these six raw path characters** using existing `INVALID_STRUCTURE`/fixed URL-not-pinned diagnostics; no URL resolution, network access, download or trust assertion is added. Existing canonical ASCII paths and punctuation that is not reserialized in these positions (including `|`, `^`, apostrophe, brackets and semicolon) remain structurally eligible.

TDD RED reproduced six false structural passes. GREEN covers six raw character variants across seven real CLI file/stdin/batch/NDJSON/directory/two-directory comparison/streamed successor comparison entrypoints; refused comparisons expose `object_diff=UNAVAILABLE`, while safety markers/exit code/JSON shape stay unchanged. The existing caps (64 immediate names, 16 JSON, 16KiB each) and no-follow/race controls are untouched; `NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, `NO_NETWORK`, five `UNVERIFIED` gaps, T5B root/source/tool, real privileged Mac UID502/APFS and Linux Slice C HOLD remain.

## 2026-10-20 C0 reverse streamed baseline to directory successor (offline only)

The non-authorizing C0 reviewer now supports the symmetric `--compare-stdin-before-directory AFTER_DIR` workflow, treating bounded NDJSON provided on standard input as the **untrusted before snapshot** and an existing descriptor-anchored directory as the **untrusted after snapshot**. This complements but does not replace `--compare-stdin-to-directory BEFORE_DIR` (directory baseline, streamed successor). It does not persist streamed bytes and performs no network, DNS lookup or collection. The two directions reuse the same comparison report composer so both use `before`, `after`, `object_diff`, `evidence`, and unchanged safety markers.

Input budget: NDJSON baseline 1–16 records, up to 16 KiB each and bounded combined bytes, duplicate/conflict checks with sanitized diagnostics; directory successor 1–16 JSON files, no more than **64 total immediate entries**, exact-read FD/no-follow/race validation, optional `--require-json-only` **on the directory side**. `--fail-on-change` exits 3 for successful observed semantic change (otherwise 0), while **either-side refusal** dominates and exits 2 with `object_diff=UNAVAILABLE` even if changes were present. No raw URL or SHA256 object values appear in the semantic diff. Other intake modes cannot be combined with the reverse comparison; legacy single/batch/directory/compare behaviors remain unchanged.

Example (illustrative local proposal, not an authorization): `cat untrusted-before.ndjson | python3.13 ops/t5b0/c0_manifest_preflight.py --compare-stdin-before-directory ./untrusted-after --require-json-only --fail-on-change`. The output remains `NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, `NO_NETWORK` and five `UNVERIFIED` evidence gaps. Neither side is a trusted baseline, and status `UNCHANGED` does not authenticate artifacts or approve material collection. No T5B root/source/tool, original privileged Mac UID502/APFS or Linux Slice C gate changes.

TDD RED established missing reverse-mode behavior; GREEN covers identity, added/removed IDs, all four changed metadata fields, safe value-redacted comparisons, change gate, both refused sides, overlong/too-many NDJSON, duplicate ID, strict non-JSON refusal, 64/65 total entry boundary and CLI option mutual exclusion. This is a bounded reviewer feature, not a security authorization.

## 2026-10-20 C0 paired-stdin offline semantic reviewer (non-authorizing)

The new opt-in `--compare-stdin-batches` consumes exactly one bounded, in-memory input stream containing **two untrusted NDJSON snapshots**. A single line containing exactly `---` separates the before records from the after records. Each side must contain 1–16 manifest records, each UTF-8 line up to 16 KiB and an independent 262,160-byte stream budget; the aggregate reader caps input to `2 * 16 * 16385 + 5` bytes (plus one-byte overflow probe) before parsing. Framing must contain **exactly one** `LF---LF` separator; empty sides, extra/missing separators or byte overflow fail closed and never publish a partial semantic object inventory. This works directly in CI from two generated sets without an on-disk staging directory, no DNS/network access, and no persisted stream data.

Each side is audited by the same `inspect_stdin_batch` cross-record validation used by `--stdin-batch`; the shared compare composer returns the existing fixed `before`, `after`, `object_diff` (ID adds/removals and changed **field names**, not raw URLs/SHA256 values), `evidence`, `authorization`, `collection` and `network` keys. A valid comparison yields `UNCHANGED` or `CHANGED` and exits 0, or optionally exits 3 when `--fail-on-change` detects a valid difference. If *either side*, stream framing, or resource budget fails validation, `REFUSED` dominates, exit 2, and `object_diff=UNAVAILABLE`. The new flag cannot be combined with any other input mode or the directory-only `--require-json-only`.

Illustrative stdin stream (proposal metadata only, never a collection instruction): `<before NDJSON lines>\n---\n<after NDJSON lines>\n`. The full C0 schema, ID limits and cross-record consistency checks still apply separately to each side. The existing directory↔stream and two-directory review modes and their legacy reports/error messages remain unchanged; the P3 review finding on the `--fail-on-change` help now lists all four comparison modes.

This is structural review of untrusted proposals, **not source authenticity, signer verification, a safe downloader or operator authorization**. All outputs remain `NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, `NO_NETWORK`, with five independent evidence gaps `UNVERIFIED`. No T5B root/source/tool/material acceptance, protected Mac UID502/APFS operation, Linux Slice C authorization, or directory 64-entry/16-JSON/no-follow/race restriction is relaxed.


## Human-readable offline review (`--summary`, 2026-10-20)

Add `--summary` to any existing single-file, `--stdin`, `--batch`,
`--stdin-batch`, directory or comparison command to produce a concise text
report for a terminal or review discussion. `--summary` and `--json` are
mutually exclusive and their combination is rejected before input is read.
Without `--summary`, every existing JSON/text output contract is unchanged.

The report shows the final status, per-side status and observed record counts,
numbered refused records with fixed error categories, file-change counts for
directory comparisons, and semantic object additions/removals/changed field
names. All paths, filenames, raw diagnostics, URLs, digest values and declared
sizes are omitted. Record numbers refer to the original report's order (directory
entries are lexically sorted); they are not trusted object identity. Use the
existing JSON output locally when detailed path diagnostics are needed. A
pre-read refusal can show zero observed records; a refused directory's file
counts are explicitly partial diagnostics. Neither means complete inspection.
Semantic changes remain `UNAVAILABLE` if either input is refused.

Output is deterministic for the same observed input. This option changes only
presentation: existing 64-entry / 16-manifest / 16KiB budgets, regular-file,
no-follow, race detection and cross-record checks still apply. Exit codes stay
0 for structure-only success or a valid comparison, 2 for refusal, and 3 for a
valid change when `--fail-on-change` is selected. Every summary, including
single-file summaries, states `NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, `NO_NETWORK`
and all five `UNVERIFIED` evidence gaps. It never reads a previously generated
report as trusted input, writes a report file, fetches material or authorizes
collection or execution. T5B/source/root/tool, original Mac UID502/APFS and
Linux Slice C HOLD gates remain unchanged.

Reproducible positive/changed/refused acceptance with synthetic proposal text
only (no candidate material or network):

```sh
python3 - <<'PY_SAMPLE' | python3 ops/t5b0/c0_manifest_preflight.py --compare-stdin-batches --summary --fail-on-change
import copy
import json
before = {'schema': 'som-t5b0-c0-preflight-v1', 'approval': None,
          'objects': [{'id': 'C0-W1', 'url': 'https://example.org/sample.whl',
                       'sha256': 'a' * 64, 'bytes': 100, 'max_bytes': 100}]}
after = copy.deepcopy(before)
after['objects'][0]['max_bytes'] = 120
print(json.dumps(before))
print('---')
print(json.dumps(after))
PY_SAMPLE
# Expected: CHANGED; Changed C0-W1: max_bytes; process exit 3.
# Remove the max_bytes assignment for UNCHANGED and exit 0.
# Replace the final print with print('{') for REFUSED / UNAVAILABLE and exit 2.
```

Run `python3 -m unittest discover -s ops/t5b0 -p 'test_c0_summary.py' -v`
for runnable all-mode, output-privacy, terminal-injection, refusal-priority,
FIFO/size-limit, option-conflict and legacy-output acceptance coverage.

## Offline reviewer operator next-action guidance (2026-10-20)

Add `--summary --guidance` to **any of the existing nine** single, batch,
directory, stdin or comparison inspection modes to append deterministic,
privacy-safe **next-action hints**. Examples:

```sh
# A malformed local input: exit 2 with INVALID_MANIFEST guidance.
printf '{' | python3 ops/t5b0/c0_manifest_preflight.py --stdin --summary --guidance

# A valid but untrusted single proposal: exit 0, external evidence remains UNVERIFIED.
python3 - <<'PY_SAMPLE' | python3 ops/t5b0/c0_manifest_preflight.py --stdin --summary --guidance
import json
print(json.dumps({'schema': 'som-t5b0-c0-preflight-v1', 'approval': None,
                  'objects': [{'id': 'C0-W1',
                               'url': 'https://example.org/synthetic.whl',
                               'sha256': 'a'*64, 'bytes': 100, 'max_bytes': 100}]}))
PY_SAMPLE

# For any existing before/after reviewer, append --guidance to
# --summary --fail-on-change: exit 3 for a valid changed proposal.
```

The guidance is a fixed allowlisted mapping from stable error codes to safe
local corrective steps (invalid/oversized or malformed input, schema error,
duplicate IDs, cross-record disagreement, or bounded audit refusal). Refusal
takes precedence over any changed data and does not suggest accepting a partial
semantic inventory. A valid change calls for human review, **not approval**.
An unchanged/structurally valid observation says to gather independent
source, trust-root, trusted-time, execution-environment and operator evidence;
it never claims that these gaps are resolved.

No untrusted error text, path, filename, URL, digest, raw byte count or terminal
escape is copied into the hints. All existing `--summary` output remains an
exact prefix of guidance output; calls without `--guidance` are unchanged.
`--guidance` requires `--summary` and rejects `--json` *before input reads*.
Exit codes remain 0/2/3; existing 64 directory names / 16 manifests /
16 KiB per manifest / same-FD checks are unchanged. This opt-in tool
does **not** authenticate, download, run or authorize material; preserve
`NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, `NO_NETWORK`, all five `UNVERIFIED`
gaps and all T5B/Mac UID502/APFS/Linux C HOLDs.

## Direct two-manifest offline reviewer (`--compare-files`, 2026-10-20)

Use this mode when two individual proposal files already exist and an operator
needs an offline structural semantic diff without packaging each into a
one-entry directory or rewriting them into NDJSON. The files are independent,
untrusted observations, not a trusted baseline or approved software artifacts.

```sh
# Synthetic local examples; no network/material collection.
workdir=$(mktemp -d)
python3 - "$workdir" <<'PY_SAMPLE'
import copy, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
before = {'schema': 'som-t5b0-c0-preflight-v1', 'approval': None,
          'objects': [{'id': 'C0-W1', 'url': 'https://example.org/sample.whl',
                       'sha256': 'a'*64, 'bytes': 100, 'max_bytes': 100}]}
after = copy.deepcopy(before)
after['objects'][0]['max_bytes'] = 120
(root / 'before.json').write_text(json.dumps(before))
(root / 'after.json').write_text(json.dumps(after))
PY_SAMPLE
python3 ops/t5b0/c0_manifest_preflight.py --compare-files \
  "$workdir/before.json" "$workdir/after.json" --summary-json --fail-on-change
# Expected: CHANGED, exit 3, review_mode FILE_COMPARISON,
# object_change_counts.changed 1, never actual URL, path or SHA256.
# Make the two files identical => UNCHANGED/exit 0, counts all zero.
# Replace either file with malformed JSON => REFUSED/exit 2,
# object_changes UNAVAILABLE and object_change_counts null.
rm -rf "$workdir"
```

Both reads use the existing no-follow, race-aware regular-file reader with a
separate 16,384-byte ceiling. FIFO, directory, symlink and missing files refuse
without blocking or disclosing input paths in private summary output. Inputs are
not downloaded, written by the CLI, trusted, admitted or executed; the example
creates and removes only temporary *synthetic* files. CLI mutually excludes
other intake modes and `--require-json-only`, including checks **before any
input is read**. The legacy JSON report includes bounded object identifiers and
field *names* but never candidate URLs/digests; `--summary-json` omits even
identifiers and includes a fixed `FILE_COMPARISON` mode label. The `v1` envelope
remains a structural report-format identifier, not provenance or authorization.
T5B/Mac UID502/APFS/Linux C and all five evidence verification gates remain HOLD.

Test with `python3 -m unittest discover -s ops/t5b0 -p test_c0_compare_files.py -v`.

## Compare one regular manifest with piped single JSON (2026-10-20)

Two complementary offline C0 commands compare an existing untrusted local
manifest file with exactly one **unpersisted** JSON proposal streamed from
standard input. No NDJSON framing, staging directory or downloader is needed.

```sh
# First create two synthetic local test inputs, not candidate material.
workdir=$(mktemp -d)
python3 - "$workdir" <<'PY_SAMPLE'
import copy, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
old = {'schema': 'som-t5b0-c0-preflight-v1', 'approval': None,
       'objects': [{'id': 'C0-W1', 'url': 'https://example.org/synthetic.whl',
                    'sha256': 'a' * 64, 'bytes': 100, 'max_bytes': 100}]}
new = copy.deepcopy(old)
new['objects'][0]['max_bytes'] = 110
(root / 'old.json').write_text(json.dumps(old))
(root / 'new.json').write_text(json.dumps(new))
PY_SAMPLE
# File baseline -> piped successor: expected CHANGED, exit 3.
python3 ops/t5b0/c0_manifest_preflight.py --compare-file-to-stdin \
  "$workdir/old.json" --summary-json --fail-on-change < "$workdir/new.json"
# Piped baseline -> file successor: expected CHANGED, exit 3.
python3 ops/t5b0/c0_manifest_preflight.py --compare-stdin-to-file \
  "$workdir/new.json" --summary-json --fail-on-change < "$workdir/old.json"
# Replace piped JSON with a '{' for REFUSED, exit 2, semantic UNAVAILABLE.
rm -rf "$workdir"
```

Both directions enforce independent 16,384-byte ceilings. Local file reads use
the existing O_NOFOLLOW, nonblocking regular-file and same-FD race check; the
stdin reader caps bytes without storing content on disk. Either-side invalid,
missing, symlink, FIFO or oversized input fails closed; no partial inventory or
zero-change claim on refusal. Comparison direction affects added/removed IDs.
The `--summary-json` envelope uses fixed `FILE_TO_STDIN` or `STDIN_TO_FILE`
mode tags but never echoes the local path, user URL, hash or object ID; the
ordinary legacy report can include only already-allowlisted semantic IDs and
field names, not arbitrary raw source URLs or SHA values. The operation does
not verify trust, collect, download, approve or execute material; T5B/Mac
UID502/APFS/Linux C and all five independent evidence checks remain HOLD.

Run `python3 -m unittest discover -s ops/t5b0 -p test_c0_mixed_file_stdin.py -v`.

## Direct file and directory snapshot comparison (next offline slice)

These two commands compare one untrusted on-disk manifest and a bounded
collection of untrusted manifest files in a directory, without converting the
single input into NDJSON or staging a second directory. The specified BEFORE
side is the baseline for semantic object-ID additions/removals, **not a trusted
source**.

```sh
workdir=$(mktemp -d)
mkdir "$workdir/snapshot"
python3 - "$workdir" <<'PY_SAMPLE'
import copy, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
before = {'schema': 'som-t5b0-c0-preflight-v1', 'approval': None,
          'objects': [{'id': 'C0-W1', 'url': 'https://example.org/synthetic.whl',
                       'sha256': 'a'*64, 'bytes': 100, 'max_bytes': 100}]}
after = copy.deepcopy(before)
after['objects'][0]['max_bytes'] = 101
(root / 'single.json').write_text(json.dumps(before))
(root / 'snapshot' / 'new.json').write_text(json.dumps(after))
PY_SAMPLE
# Both examples are valid CHANGED; --fail-on-change returns exit 3.
python3 ops/t5b0/c0_manifest_preflight.py \
  --compare-file-to-directory "$workdir/single.json" "$workdir/snapshot" \
  --summary-json --fail-on-change
python3 ops/t5b0/c0_manifest_preflight.py \
  --compare-directory-to-file "$workdir/snapshot" "$workdir/single.json" \
  --summary-json --fail-on-change --require-json-only
# Make the two proposals equal: UNCHANGED/exit 0.
# Replace either proposal with '{': REFUSED/exit 2, changes unavailable/null.
rm -rf "$workdir"
```

The file uses the existing regular-only, O_NOFOLLOW, nonblocking, same-FD
race-aware max 16 KiB reader. The directory independently enforces a 64-total
entry bound, 1–16 `.json` manifest bound and 16 KiB per manifest with stable
refusal. Strict `--require-json-only` rejects even one extraneous entry. No
partial or zero-change object inventory is released on either-side refusal.
The versioned private `--summary-json` includes `FILE_TO_DIRECTORY` or
`DIRECTORY_TO_FILE`, allowlisted change counts and fixed triage codes; it
excludes paths, filenames, candidate URLs/digests, object IDs and raw errors.
The historical detailed JSON report may include local directory entry paths
and observed file-content digests as before; it is **not** the private report
format. The operation does not download, trust, admit or execute anything and
does not satisfy independent source, trust, time, environment or operator
verification. C0/T5B/Mac UID502/APFS/Linux C HOLD persists.

Run `python3 -m unittest discover -s ops/t5b0 -p test_c0_file_directory_compare.py -v`.

## Read-free machine capability discovery (next offline slice)

Automation can discover supported offline review modes and resource ceilings
*without* opening local proposal files, reading stdin, contacting a network
endpoint, trusting manifests or collecting material:

```sh
python3 ops/t5b0/c0_manifest_preflight.py --capabilities-json
```

The output is deterministic JSON with fixed code-defined keys: `schema`
(`som-t5b0-c0-capabilities-v1`), `review_schema`, alphabetically sorted
`review_modes`, `limits`, the three non-authorizing boundary markers and the
five UNVERIFIED evidence-gap IDs. The ceilings are 16 KiB per manifest,
64 total directory entries (including ignored names), 16 directory/NDJSON/batch
manifests and four objects per manifest. The command must not be mixed with
any input/comparison mode, output flag, strict-directory mode or
`--fail-on-change`; parser rejection occurs before data reads. No paths,
URLs, object IDs or raw diagnostics are exposed by this capability catalog.
A compatible report schema does **not** certify the source, manifest trust,
clock, execution environment or operator consent. All C0/T5B/Mac UID502/APFS
and Linux C HOLD boundaries remain in force.

Run `python3 -m unittest discover -s ops/t5b0 -p test_c0_capabilities.py -v`.

## Compare one manifest and one *local* NDJSON snapshot file (2026-10-20)

The operator can compare one bounded on-disk manifest to a bounded NDJSON
snapshot file without piping stdin or creating a second directory. Both inputs
remain untrusted and observation-only; BEFORE determines semantic ID direction,
not any privileged or approved baseline.

```sh
workdir=$(mktemp -d)
python3 - "$workdir" <<'PY_SAMPLE'
import copy, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
old = {'schema':'som-t5b0-c0-preflight-v1','approval':None,
       'objects':[{'id':'C0-W1','url':'https://example.org/synthetic.whl',
                   'sha256':'a'*64,'bytes':100,'max_bytes':100}]}
new = copy.deepcopy(old)
new['objects'][0]['max_bytes'] = 105
(root/'before.json').write_text(json.dumps(old))
(root/'after.ndjson').write_text(json.dumps(new) + '\n')
PY_SAMPLE
# CHANGED/exit 3; JSON contains no source paths/URLs/hashes/IDs.
python3 ops/t5b0/c0_manifest_preflight.py --compare-file-to-batch \
  "$workdir/before.json" "$workdir/after.ndjson" \
  --summary-json --fail-on-change
# Inverted baseline: same result counts but opposite ID addition/removal direction.
python3 ops/t5b0/c0_manifest_preflight.py --compare-batch-to-file \
  "$workdir/after.ndjson" "$workdir/before.json" \
  --summary-json --fail-on-change
rm -rf "$workdir"
```

The single manifest is bounded to 16,384 bytes; the entire NDJSON file to
`16 * 16385` = **262,160 bytes**; each of 1–16 lines must not exceed 16,384
bytes excluding its newline. Both files are read once with no-follow,
nonblocking regular-file and metadata/race protections. Invalid encoding,
malformed JSON, oversized input, symlink/FIFO/directory, duplicates or
cross-proposal metadata conflicts refuse without a partial inventory.
Refusal exits 2, valid unchanged exits 0, valid change exits 3 with
`--fail-on-change`. The machine envelope emits fixed `FILE_TO_BATCH` or
`BATCH_TO_FILE` review modes, static `review_schema` and triage codes, omits
input paths/filenames/URLs/digests/object IDs, and never authorizes collection,
trust, network access or privileged host operations. Other legacy output
formats remain available. All C0/T5B/Mac UID502/APFS/Linux C HOLD and five
UNVERIFIED evidence gaps continue.

Run `python3 -m unittest discover -s ops/t5b0 -p test_c0_local_ndjson_compare.py -v`.

## Offline comparison of two local NDJSON proposal snapshots

```sh
python3 ops/t5b0/c0_manifest_preflight.py --compare-batch-files \
  BEFORE.ndjson AFTER.ndjson --summary-json --fail-on-change
```

Both inputs are untrusted, independently audited bounded regular files
(no-follow, nonblocking, same-FD race-aware open/read) containing 1–16 UTF-8
NDJSON manifest records, each <=16,384 bytes, with a **262,160 byte** local
file cap. The shared validator rejects duplicate object IDs or cross-record
metadata conflicts. The baseline direction is purely for semantic comparison;
no provenance, trust or execution authority is inferred. Valid same content
returns `UNCHANGED`/0; valid changes `CHANGED`/3 with the flag; either-side
refusal `REFUSED`/2 and private diff counts `null`. Private JSON has the fixed
`LOCAL_BATCH_COMPARISON` mode label, no paths/URLs/hashes/object IDs, and
remains explicitly `NO_AUTHORIZATION`, `NO_NETWORK`, `C0_COLLECT_HOLD` with
five independent evidence gaps UNVERIFIED. C0/T5B, Mac UID502/APFS and Linux C
HOLDs persist.

Run `python3 -m unittest discover -s ops/t5b0 -p test_c0_two_local_ndjson.py -v`.

## Compare local NDJSON and directory proposals in both directions (next slice)

Two distinct offline routes use an untrusted local NDJSON snapshot and an
independently audited bounded directory snapshot. BEFORE is a **comparison
baseline only**, never a trusted source or authorization:

```sh
workdir=$(mktemp -d)
mkdir "$workdir/directory"
python3 - "$workdir" <<'PY_SAMPLE'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
a = {'schema': 'som-t5b0-c0-preflight-v1', 'approval': None,
     'objects': [{'id': 'C0-W1', 'url': 'https://example.org/synthetic.whl',
                  'sha256': 'a'*64, 'bytes': 100, 'max_bytes': 100}]}
b = {'schema': 'som-t5b0-c0-preflight-v1', 'approval': None,
     'objects': [{'id': 'C0-W1', 'url': 'https://example.org/synthetic.whl',
                  'sha256': 'a'*64, 'bytes': 100, 'max_bytes': 101}]}
(root / 'batch.ndjson').write_text(json.dumps(a) + '\n')
(root / 'directory' / 'proposal.json').write_text(json.dumps(b))
PY_SAMPLE
# CHANGED/exit 3, private object counts; no source path/URL/digest displayed.
python3 ops/t5b0/c0_manifest_preflight.py \
  --compare-batch-file-to-directory "$workdir/batch.ndjson" "$workdir/directory" \
  --summary-json --fail-on-change
python3 ops/t5b0/c0_manifest_preflight.py \
  --compare-directory-to-batch-file "$workdir/directory" "$workdir/batch.ndjson" \
  --summary-json --fail-on-change --require-json-only
rm -rf "$workdir"
```

The file remains regular-only/O_NOFOLLOW/nonblocking/race-aware and bounded to
262,160 bytes, 1–16 NDJSON manifests of ≤16,384 bytes per line. The directory
remains at most **64 total entries including ignored names**, 1–16 `.json`
files each ≤16,384 bytes, same no-follow metadata checks. Strict
`--require-json-only` constrains only the directory side. Either-side
malformed/unsafe/oversized/cross-record conflict refusal gives exit 2,
semantic `UNAVAILABLE` and JSON count `null`, without partial inventories;
valid unchanged exit 0, change exits 0 or 3 with `--fail-on-change`.
Private versioned `--summary-json` emits fixed `BATCH_FILE_TO_DIRECTORY` or
`DIRECTORY_TO_BATCH_FILE` and never echoes paths, filenames, candidate URLs,
digests, IDs or raw diagnostics. All C0/T5B/Mac UID502/APFS/Linux C HOLD and
five independent UNVERIFIED evidence gaps remain. No network, trust, material
collection or privileged host authorization is granted.

Run `python3 -m unittest discover -s ops/t5b0 -p test_c0_local_batch_directory.py -v`.

## Direct local NDJSON baseline versus piped NDJSON successor (next slice)

```sh
workdir=$(mktemp -d)
python3 - "$workdir" <<'PY_SAMPLE'
import copy, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
a = {'schema': 'som-t5b0-c0-preflight-v1', 'approval': None,
     'objects': [{'id':'C0-W1','url':'https://example.org/synthetic.whl',
                  'sha256':'a'*64,'bytes':100,'max_bytes':100}]}
b = copy.deepcopy(a)
b['objects'][0]['max_bytes'] = 101
(root/'before.ndjson').write_text(json.dumps(a)+'\n')
(root/'after.ndjson').write_text(json.dumps(b)+'\n')
PY_SAMPLE
# Both routes show private CHANGED with exit 3; no input source URL/hash leaks.
cat "$workdir/after.ndjson" | python3 ops/t5b0/c0_manifest_preflight.py \
  --compare-batch-file-to-stdin-batch "$workdir/before.ndjson" \
  --summary-json --fail-on-change
cat "$workdir/before.ndjson" | python3 ops/t5b0/c0_manifest_preflight.py \
  --compare-stdin-batch-to-batch-file "$workdir/after.ndjson" \
  --summary-json --fail-on-change
rm -rf "$workdir"
```

Both inputs remain untrusted and separately bounded to **262,160 bytes** total,
**1–16 UTF-8 NDJSON records** each ≤**16,384 bytes**. Disk uses the existing
nonblocking regular-only no-follow same-FD audited reader; stdin uses a
strict one-time bounded read. Unsafe/bad encoding, duplicates, metadata
conflicts, malformed or excessive data on either side refuses (`exit 2`,
semantic `UNAVAILABLE`, private count `null`), never partial success. Valid
unchanged exits 0; change exits 0/3 with `--fail-on-change`; BEFORE→AFTER
orients additions/removals. Option conflicts fail **before** file/stream reads;
`--require-json-only` is directory-only. The fixed private labels
`LOCAL_BATCH_TO_STDIN_BATCH` and `STDIN_BATCH_TO_LOCAL_BATCH` exclude raw
paths, URLs, digests and IDs. No privilege, trust root, source admission,
network or collection granted; all five independent UNVERIFIED evidence gaps
and C0/T5B/Mac UID502/APFS/Linux C HOLDs remain.

Run `python3 -m unittest discover -s ops/t5b0 -p test_c0_local_batch_stream_compare.py -v`.

## Direct manifest file vs NDJSON stdin batch (symmetric offline review)

```sh
workdir=$(mktemp -d)
python3 - "$workdir" <<'PY_SAMPLE'
import copy, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
old = {'schema': 'som-t5b0-c0-preflight-v1', 'approval': None,
       'objects': [{'id':'C0-W1','url':'https://example.org/synthetic.whl',
                    'sha256':'a'*64,'bytes':100,'max_bytes':100}]}
new = copy.deepcopy(old)
new['objects'][0]['max_bytes'] = 101
(root/'before.json').write_text(json.dumps(old))
(root/'after.json').write_text(json.dumps(new))
(root/'before.ndjson').write_text(json.dumps(old) + '\n')
(root/'after.ndjson').write_text(json.dumps(new) + '\n')
PY_SAMPLE
# Valid CHANGED/exit 3 in either direction, no paths/URLs/digests/IDs in private JSON.
cat "$workdir/after.ndjson" | python3 ops/t5b0/c0_manifest_preflight.py \
  --compare-file-to-stdin-batch "$workdir/before.json" \
  --summary-json --fail-on-change
cat "$workdir/before.ndjson" | python3 ops/t5b0/c0_manifest_preflight.py \
  --compare-stdin-batch-to-file "$workdir/after.json" \
  --summary-json --fail-on-change
rm -rf "$workdir"
```

The local single manifest has a hard 16,384-byte cap, regular-only no-follow,
nonblocking single-FD identity and race checks. Stdin NDJSON is independently
bounded to **262,160 bytes**, **1–16 UTF-8 records**, each ≤**16,384 bytes**.
Invalid encoding, duplicate or conflicting records, malformed JSON, unsafe or
oversized files/streams on either side => `REFUSED`, exit 2, semantic
`UNAVAILABLE`, private counts `null`, never partial diff. Valid unchanged 0,
changed 0/3 when `--fail-on-change`; input order is the semantic baseline.
Directory-only `--require-json-only`, any conflicting input mode or mixed
read-free capability discovery is rejected before consuming stdin or files.
Versioned private machine labels `FILE_TO_STDIN_BATCH` and
`STDIN_BATCH_TO_FILE` are allowlisted and omit source paths, URLs, digests
and IDs; all C0/T5B/Mac UID502/APFS/Linux C HOLD, no-network/no-authorization,
and five independently UNVERIFIED gaps remain. No privilege, trust, network
or material collection is granted.

Run `python3 -m unittest discover -s ops/t5b0 -p test_c0_file_stdin_batch_compare.py -v`.

## Direct local NDJSON batch versus piped single-manifest comparison (both directions)

These examples compare untrusted structural proposal snapshots only; they do **not**
authorize fetching, installing, signing, executing or collecting anything.

```sh
workdir=$(mktemp -d)
python3 - "$workdir" <<'PY_SAMPLE'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
old = {'schema': 'som-t5b0-c0-preflight-v1', 'approval': None,
       'objects': [{'id':'C0-W1','url':'https://example.org/synthetic.whl',
                    'sha256':'a'*64,'bytes':100,'max_bytes':100}]}
new = {**old, 'objects': [{**old['objects'][0], 'max_bytes': 101}]}
(root/'before.ndjson').write_text(json.dumps(old) + '\n')
(root/'after.ndjson').write_text(json.dumps(new) + '\n')
(root/'before.json').write_text(json.dumps(old))
(root/'after.json').write_text(json.dumps(new))
PY_SAMPLE
# Valid semantic CHANGED/exit 3; no paths/URLs/digests/object IDs in --summary-json.
cat "$workdir/after.json" | python3 ops/t5b0/c0_manifest_preflight.py \
  --compare-batch-file-to-stdin "$workdir/before.ndjson" \
  --summary-json --fail-on-change
cat "$workdir/before.json" | python3 ops/t5b0/c0_manifest_preflight.py \
  --compare-stdin-to-batch-file "$workdir/after.ndjson" \
  --summary-json --fail-on-change
rm -rf "$workdir"
```

The on-disk NDJSON batch uses existing `O_NOFOLLOW` nonblocking regular-file
same-FD race checks; at most **262,160 total bytes**, **1–16** lines, at most
**16,384 bytes** per line. The single stdin JSON is independently limited to
**16,384 bytes**. Unreadable/nonregular/oversized/invalid/duplicate/conflicting
inputs refuse (exit 2), semantic difference `UNAVAILABLE`, machine count `null`
for either-side failure (including both refused), with no partial success.
UNCHANGED exits 0; CHANGED exits 0 or 3 with `--fail-on-change`. The selected
order determines BEFORE→AFTER orientation. Conflicting input flags and
`--require-json-only` refuse before touching files or stdin. `--summary-json`
uses allowlisted fixed `LOCAL_BATCH_TO_STDIN` or `STDIN_TO_LOCAL_BATCH`, never
paths, names, URLs, digests, IDs or raw diagnostic strings. Static
`--capabilities-json` advertises both without reading input. The five
independent UNVERIFIED gaps, `NO_NETWORK`, `NO_AUTHORIZATION`,
`C0_COLLECT_HOLD`, and C0/T5B/Mac UID502/APFS/Linux C HOLD remain.

Run `python3 -m unittest discover -s ops/t5b0 -p test_c0_local_batch_stdin_manifest_compare.py -v`.

### Offline C0 machine field-change triage (2026-10-22; non-authorizing)

The opt-in `--summary-json` comparison report now includes the additive,
privacy-safe `object_field_change_counts` histogram with **exactly** four
fixed keys: `url`, `sha256`, `bytes`, and `max_bytes`. Counts measure how many
matched object IDs have that field changed; multiple changed fields on one ID
can yield a sum larger than `object_change_counts.changed`. Added and removed
IDs are **not** interpreted as four edited fields. A valid unchanged or
added/removed-only comparison gives four zeros; if either side refuses,
`object_field_change_counts` is JSON `null` alongside `object_changes:
UNAVAILABLE` and `object_change_counts:null`, never a false zero-delta.

For example:

```sh
python3 ops/t5b0/c0_manifest_preflight.py \
  --compare-files BEFORE.json AFTER.json --summary-json --fail-on-change
# With one matching ID changed only in SHA256, expected field counts:
# {"url":0,"sha256":1,"bytes":0,"max_bytes":0} (exit 3).
```

The field names are trusted static literals, not input. Private output never
contains object IDs, source paths, URLs, SHA256 values or raw diagnostics.
This is an additive optional field under `som-t5b0-c0-summary-json-v1`;
`--json`, human summary, guidance, fixed modes, capability discovery and
0/2/3 exit semantics remain intact. It is an offline observation only:
`NO_AUTHORIZATION`, `C0_COLLECT_HOLD`, `NO_NETWORK`, five independently
UNVERIFIED provenance/trust/time/environment/operator gaps, and all T5B,
Mac UID502/APFS and Linux C HOLDs remain in force.


## Opt-in cross-file consistency for individually named local manifests (2026-10-22)

Use `python3 ops/t5b0/c0_manifest_preflight.py --batch one.json two.json
--batch-consistency --summary-json` to audit 1–16 **individually named** local
manifest JSON files as one consistency set, without staging them in a directory
or copying to NDJSON. The opt-in flag runs existing strictly bounded (≤16,384
bytes each), nonblocking/no-follow/regular-only/same-FD metadata race-aware reads,
then reuses directory/NDJSON cross-manifest duplicate-ID, conflicting URL and
SHA256/declared-size checks **on the same already parsed objects**. No extra
file opens, network or write operations. An invalid input or any conflicting
metadata yields `REFUSED`/exit 2, never a structural PASS, and all inspected
items are included in the aggregate report. Over 16 paths refuse before any
file access. There are at most four distinct allowed object IDs; successful
strict batches cannot repeat IDs across files.

The default `--batch` continues its historical independent per-file inspection,
so repeating an individually valid file still passes absent the opt-in flag.
`--batch-consistency` requires `--batch` and rejects positional source,
other input modes, discovery, directory-only `--require-json-only`, or comparison
change gate before opening files or stdin. Private versioned `--summary-json`
uses the fixed, no-input-derived `FILE_BATCH_CONSISTENT` review mode advertised
by input-free `--capabilities-json` and fixed next-action codes. Legacy detailed
aggregate output retains its existing per-file path fields, while private JSON
and human summary exclude paths, proposal IDs, source URLs, SHA256 values,
metadata conflicts and arbitrary raw diagnostics. No semantic diff is claimed
for this inspection-only operation; `--fail-on-change` remains comparison-only.

This is offline **structural** and cross-file consistency only; it grants no
source authenticity, cryptographic trust, material collection, privileged host
execution, T5B admission or approval. `NO_NETWORK`, `NO_AUTHORIZATION`,
`C0_COLLECT_HOLD`, all five independently `UNVERIFIED` evidence gaps and
Mac UID502/APFS, T5B and Linux C HOLDs remain unchanged.
