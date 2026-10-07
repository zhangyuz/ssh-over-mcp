# Incident staging inspection: activation design

- Status: Draft for written review; no workflow activation or deletion approved
- Date: 2026-10-06
- Parent: ADR 0011, Inspect steps 1–6
- Prerequisites: merged dormant inventory (#142) and hardened marker reader (#143)

## Purpose and scope

Obtain a complete, bounded, read-only inventory of one of the two already-bound
incident staging roots. This supplies evidence for a later separately reviewed
apply contract. It does not establish deletion eligibility, clear the marker,
start a provider, execute target code, or close A1.

The existing collector is a metadata component, not proof of root provenance,
process absence, workflow authority, or an authenticated inspection receipt.
Activation must establish those bindings around it. Ship three independently
reviewable slices: canonical envelope, bounded native preflight, then fixed
manual workflow integration. The native-preflight slice additionally requires
the prior approved, already-main ADR amendment described below. The first two
remain dormant until the third is already trusted on main. No product/native
package capability is included.

## Fixed incident catalog and authority

Only these two literal selectors are supported:

| Selector | Basename | Device / inode | Expected commit |
| --- | --- | --- | --- |
| stale-target | ssh-over-mcp-e2e-i8ow1ni6 | 16777220 / 187176421 | 47531dadb58d365f74089dd5f52ce1b61bb0fdd1 |
| older-target | ssh-over-mcp-e2e-w_kn4rus | 16777220 / 186877220 | bf84c7aafa5c79d629fc04488b5e0bda1cd98cef |

Both roots must still be UID 502 and mode 0700. This is an incident-specific
catalog, not a configurable path or generic inventory API. No caller may
provide a path, inode, UID, target checkout, command, or inventory JSON.

The fixed provider marker must still have target
`47531dadb58d365f74089dd5f52ce1b61bb0fdd1` and owner PID 38013. Validate its
regular-file type, UID 502, mode 0600, bounded exact schema and no-follow open
identity. Pin the fixed /Users/gha-e2e-orchestrator/Library/Caches/ssh-over-mcp-e2e
parent chain with directory no-follow descriptors: system ancestors root-owned,
account ancestors UID 502, none group/world writable, final cache mode 0700.
Read active-run.json relative to the pinned cache descriptor with the hardened
reader semantics; an absolute-path re-open is not equivalent. No creation or
repair of missing/unsafe parents. Pin the initially observed marker device/inode
and re-read/revalidate it through the same cache descriptor after collection; the state and identity must match. No marker mutation.

The workflow is dispatch-only on refs/heads/main in zhangyuz/ssh-over-mcp,
contents:read, dedicated self-hosted macOS/X64 orchestrator runner, timeout
10 minutes, concurrency group live-local-e2e with cancel-in-progress:false.
Checkout exact GITHUB_SHA using the existing pinned checkout action without
persisted credentials; require matching HEAD and clean tracked/untracked state
before invoking trusted code. No PR target authority or reusable target input.
Require Darwin/x86_64, UID 502, account gha-e2e-orchestrator, fixed home, non-root,
and no admin primary or supplementary group. Reuse existing context checks but
add these activation-specific requirements without widening marker recovery.

## Root provenance

Derive the account temp parent from fixed `/usr/bin/getconf DARWIN_USER_TEMP_DIR`
with an empty environment except LC_ALL=C; never from TMPDIR, TEMP, caller text
or tempfile's environment-dependent fallback. Require exit status 0, empty
stderr and a 5-second wall deadline. Bound stdout and stderr separately to
1024 bytes and combined to 2048 bytes during collection; overflow refuses.
Successful stdout contains exactly one ASCII path with one final newline and no control bytes. Accept the
native `/var/folders/<two lowercase alphanumeric characters>/<lowercase
alphanumeric or underscore token>/T/` shape. Map only the known `/var` alias to
`/private/var`; do not resolve arbitrary symlinks or use Path.resolve.

Walk from the pinned `/` descriptor through `/private/var/folders`, the fixed
OS-returned components and `T`, opening every component with O_DIRECTORY and
O_NOFOLLOW, checking stat/open device/inode agreement. Shared ancestors must be
root-owned and not group/world writable; the per-account token directory must
be UID 502, mode 0700 or 0755;
T must be UID 502 and mode 0700. Reject unsupported ownership/layout instead of
falling back. Open the selected literal root relative to the temp parent and
match the catalog before any expected_commit read or collection. Hold all
necessary parent/root descriptors until verification is complete and close
owned descriptors on all paths. Immediately before receipt emission, after the
final process checks, revalidate **every parent-to-child namespace edge** of
both the marker-cache and temp/root chains: no-follow stat relative to each held
parent must match the held child's device/inode/type/UID/GID/mode and the required
ownership/permission constraints. Recheck the selected root's literal catalog.
Missing, replaced, unsafe or mismatched edges refuse, even if the originally
opened objects remain valid. Holding FDs alone is insufficient provenance.
These final checks remain observations under quiescence, not an atomic snapshot
or immunity to changes after the last check.

The initial live run must report the derived parent and safe metadata so this
macOS provisioning assumption can be checked. A mismatch is a failed inspection,
not permission to choose another path. Preserve the root provenance record in
the inventory payload, so later receipt review can identify the actual parent.

## Fresh bounded process preflight and quiescence

Before and after collection, require recorded owner PID 38013 absent. Treat
permission errors as live and ambiguous process errors as refusal. Run only the
fixed `/bin/ps -ww -U 502 -o pid=,comm=` with the diagnostic child's environment
restricted to LC_ALL=C. Bound combined output to 65536 bytes, nonempty process
rows to 256, each line to 4096 bytes and wall time to 10 seconds. Require exit
status 0 and empty stderr. Consume bounded chunks while the child runs; an unbounded capture followed by a size check is
insufficient. Malformed/control-bearing rows, duplicate/noncanonical PIDs,
unknown child status, unavailable inventory or deadline expiry refuse.

Reject runner-owned qemu-system-* or qemu-img processes. After bounding and
validating each process row, case-fold its basename and treat **every basename
starting with `python` or `pypy`** as an interpreter candidate; reject every such
PID except this exact inspection PID. That includes framework `Python`, all
version/ABI/debug/threading suffix combinations, and malformed or unrelated
prefix near-misses. No suffix parsing may classify a prefix candidate as an
ordinary process. Conservative over-blocking is intentional for this dedicated
account: `python3.13td`, `python3.7dm`, `pypy3.10dm`, `python3..13`,
`python3.13tdx`, and `python-tools` must all refuse. Require the inspection PID's
own row to have this recognized prefix as well. Do not claim detection of
arbitrarily renamed interpreters or unrelated non-prefix executables. Also reject
fixed E2E authority basenames run-live-local-e2e-orchestrator.py,
ssh-over-mcp-live-e2e-gate and recover_provider.py. No caller-selected patterns.
The running inspection process must itself appear exactly once. Other ordinary runner/OS processes are not an execution grant. This is a
bounded observational check under the trusted-account assumption, not detection
of malicious renamed processes. Operator activity on the roots must be stopped;
workflow concurrency cannot exclude a manual shell or all transient processes.

The bounded diagnostic helper may terminate/reap **only the child it just
spawned for fixed ps/getconf**, if needed to enforce output/time limits. It may
never signal a PID taken from the marker, process inventory, or caller. This
is a **proposed exception**, not authority granted by this design. ADR 0011's
current no-process-killing rule remains in force. Before any signal-capable
preflight code is implemented or merged, even dormant code, a separate ADR 0011
amendment must be explicitly approved in writing, reviewed, and merged to main.
No dormant label, passing CI, or approval of this design substitutes for that
prerequisite. The implementation plan must identify the exact already-main
commit containing the approved amendment, its fixed ADR path and content SHA-256;
the preflight implementation and final activation must bind to that reviewed
authority. A proposed/future merge SHA or ancestry alone is insufficient.
Until that prerequisite exists, only the signal-free envelope slice may proceed
under its own approved plan. No wrapper shell, command interpolation, generic
process-killing helper or arbitrary executable is accepted.

## Inventory and immutable envelope

Reuse collect_staging_inventory(root_fd, uid=502) and the fixed expected_commit
reader's no-follow, nonblocking, ownership/type/41-byte/ASCII validation. The
activating reader must return a value **and its pinned regular-file metadata**:
device/inode, UID/GID, mode, nlink, size and mtime_ns/ctime_ns. Compare metadata
before/after each bounded read, rejecting instability, and require value equal
to the selector's literal catalog SHA. The existing string-only reader API alone
does not establish this binding. Require that observation to equal the
collector's payload-content/expected_commit entry. After collection and final
process checks, reread and revalidate through pinned payload/root descriptors;
require identical value/metadata matching the collected entry, and validate its
parent-to-child namespace edges before emission. Replacement or a same-inode,
same-size content write at any observed stage refuses. Do not silently update
the binding or certify a later state with an earlier SHA. Malicious same-account
ABA changes are outside the promised guarantee, as are changes after the final
check. Regular data files are never opened or read except the already-approved
payload-content/expected_commit. Keep the collector's 4096 total entries,
depth 12, 4096-byte relative path, no-follow/type/UID/device/link/mode/identity
checks and 60-second checked monotonic deadline. The workflow bounds overall
invocation; no hard filesystem syscall cancellation guarantee is claimed.

### Exact wire schema and scalar representations

Every object has exactly the named fields below; extra/duplicate keys, nulls,
booleans and floating-point values are forbidden. JSON integers use decimal
integer tokens, never quoted numbers, leading zeros, exponents or negative zero.
JSON strings use the canonical escaping below; never coerce between types.

| Object / field | Exact JSON type and value |
| --- | --- |
| inventory | Object: schema_version, incident, parent, marker, staging, entries |
| envelope | Object: schema_version, inventory, inventory_sha256, inspection |
| parent | Object: path, ancestors |
| parent.ancestors | Array of ancestor objects, ordered from / through T |
| each ancestors element | Object: path, device, inode, uid, gid, mode |
| marker | Object: device, inode, target, owner_pid |
| staging | Object: basename, device, inode, uid, mode, expected_commit |
| inspection | Object: authority_sha, run_id, attempt |
| inventory.entries | Array of complete collector records, ordered by filesystem-encoded path bytes |
| each entries element | Object: path, kind, device, inode, uid, gid, mode, nlink, size, mtime_ns, ctime_ns |
| schema_version (inventory, envelope, receipt) | Integer, exactly 1 |
| inventory.incident | String, exactly "stale-target" or "older-target"; never an object |
| parent.path / ancestors[].path | String, pinned canonical absolute path; no trailing slash except root "/" |
| staging.basename | String, the selected catalog's exact basename |
| entries[].path | String, "." for root or the collector's canonical relative path |
| entries[].kind | String, exactly "directory" or "regular" |
| device, inode, uid, gid, mode, nlink, size | Nonnegative integers observed from pinned filesystem metadata; mode is stat.S_IMODE permission bits as an integer, not an octal string; existing UID/mode/link/type constraints still apply |
| mtime_ns, ctime_ns | Signed integers observed from filesystem metadata, nanoseconds; never generated invocation timestamps |
| marker.owner_pid | Integer, exactly 38013 |
| marker.target / staging.expected_commit | String, exactly the respective literal catalog SHA, 40 lowercase hexadecimal characters |
| inspection.authority_sha | String, exact trusted workflow authority SHA, 40 lowercase hexadecimal characters |
| inspection.run_id / inspection.attempt | Strings preserving positive canonical decimal trusted workflow environment values; ASCII digits, no sign/leading zero, at most 19 digits and numeric value at most 2^63-1; never JSON integers |
| inventory_sha256 / receipt.envelope_sha256 | Strings, exactly 64 lowercase hexadecimal characters, no prefix |
| receipt | Object: schema_version, envelope_bytes, chunks, envelope_sha256 |
| receipt.envelope_bytes | Integer, exact canonical envelope byte length, 1 through 2097152 |
| receipt.chunks | Integer, exact ceiling of envelope_bytes / 1024, 1 through 2048 |
| chunk | Object: index, data |
| chunk.index | Integer, consecutive from 0 through receipt.chunks - 1 |
| chunk.data | String, canonical standard RFC 4648 section 4 base64, as defined below |

Canonical JSON bytes are equivalent to
`json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")`.
There is no final newline in hashed JSON, whitespace outside strings, Unicode
normalization, optional slash escaping, or alternative number/string encoding.
The envelope contains no fresh invocation timestamp. Do not accept caller-supplied
provenance; fresh workflow provenance is outside inventory equality.
inventory_sha256 covers the exact canonical inventory bytes. The envelope
SHA-256 covers the exact canonical envelope bytes, not a recursive digest field.
Enforce 2 MiB on the **complete envelope** before retaining/emitting beyond the
budget; a collector-only size check is insufficient.

Base64 uses the standard `A-Z a-z 0-9 + /` alphabet, required `=` padding only
when needed, zero unused pad bits, no whitespace/line wrapping and no URL-safe
alphabet. Strict decoding followed by standard re-encoding must reproduce the
exact data string; permissive decoding alone is insufficient. See
[RFC 4648 sections 3–4](https://www.rfc-editor.org/rfc/rfc4648.html#section-3.5).
Split the canonical envelope bytes into consecutive chunks of at most 1024 raw
bytes, then encode **each chunk independently**. Every nonfinal chunk carries
exactly 1024 raw bytes; the final chunk is nonempty and carries the remainder.
Do not concatenate encoded strings before decoding: independently padded chunks
must be decoded separately, then their raw bytes concatenated.

Successful output uses literal `STAGING_RECEIPT ` (one ASCII space) followed by
the canonical receipt JSON and one LF, then consecutive `STAGING_CHUNK ` lines
with canonical chunk JSON and one LF. These framing LFs are outside all hashed
bytes. Emit no receipt or chunks until all filesystem/process/marker revalidation
succeeds. JSON-escape all metadata names; never print raw exceptions or file contents. Failed or truncated
logs are not a usable receipt. No local evidence/cache files are created by the
inspection command. Operator review must include the full reconstructed envelope,
not only hashes. GitHub transport/log overhead is not counted as envelope bytes.

Logs provide review evidence only. This design does not authorize an apply to
trust caller-supplied chunks, digests or a run tuple. Authenticated retrieval from
the successful trusted job, exact inspection authority compatibility, and receipt
retention/failure behavior remain the separately reviewed apply contract.

## Acceptance and sequencing

Each slice uses focused RED, minimal GREEN, real disposable files/processes,
full self-hosted Python 3.13/3.14 CI and fresh independent adversarial review.
Before the native-preflight slice, require the separately approved ADR amendment
already on main and its exact commit/path/content-digest binding in the plan.
No signal-capable code may be implemented or merged before that gate, even in a
dormant helper. Final activation must retain that binding and independently
verify all implementation authorities are already on main; neither this draft
nor a target's own revision can approve its signal authority.
Envelope RED tests must pin every scalar type above with hand-written literal
vectors, not expected bytes generated by the encoder under test. Include a
complete valid fixture containing all eleven direct staging names, the root
record and payload-content/expected_commit (at least 13 inventory records), with
literal canonical inventory/envelope bytes, byte lengths, lowercase digests,
receipt JSON and independently encoded chunk lines; a consumer using another JSON/base64 implementation must reproduce
those bytes. Also cover changed marker/staging bindings, deterministic provenance
separation, complete 2 MiB equality/overflow, chunk loss/duplication/truncation,
wrong scalar types, uppercase/prefixed digests, URL-safe/unpadded/whitespace or
nonzero-pad-bit encodings, and invalid trusted provenance values.

These literal primitive vectors supplement, and do not substitute for, the full
valid inventory/envelope fixture (neither JSON sample is a valid live envelope):

- ASCII bytes `{"incident":"stale-target","run_id":"37563415169","schema_version":1}`:
  length 69, SHA-256 `54213dd999af295227f6d96133908796a0586cd6ff4b5d4d3a44d66766804d5e`,
  base64 `eyJpbmNpZGVudCI6InN0YWxlLXRhcmdldCIsInJ1bl9pZCI6IjM3NTYzNDE1MTY5Iiwic2NoZW1hX3ZlcnNpb24iOjF9`.
- ASCII bytes `{"attempt":"1","authority_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","run_id":"37563415169"}`:
  length 97, SHA-256 `81e5746c2b075dadcbe423f9953bc705d47da0209c210b8913b9dd85ba56e6a8`.
  Numeric run_id/attempt instead of strings must not pass this vector.
- Raw hex `fbff` encodes as `+/8=`; URL-safe `-_8=` and unpadded `+/8` refuse.
  Raw hex `ff` encodes as `/w==`; `/x==` must refuse for nonzero unused pad bits.

Preflight RED must demonstrate refusal for other-PID candidates `Python`,
`python3.13td`, `python3.7dm`, `pypy3.10dm`, `python3..13`, `python3.13tdx`,
`python-tools`, and mixed-case variants; prefix near-misses never become ordinary
rows. The exact inspection PID is the sole prefix-candidate exception.
Preflight tests must cover environment-selected temp roots being ignored,
symlink/owner/mode/inode races, fixed command/child ownership, output/line/count/
time bounds for both fixed children, unsuccessful exit/nonempty stderr, framework
Python/versioned python/pypy detection, live owner/QEMU/other interpreter and
ambiguous process results.
Integration tests must exercise failed late revalidation producing no success
receipt; root/cache/ancestor replacement after collection and during the final
process check; expected_commit replacement or same-inode/same-size rewrite
between first read, collection and final reread; preserved borrowed/closed owned
descriptor semantics; unknown selector and
unknown recovery-root exclusion. Add full workflow authority/input/serialization
contracts and run disposable native macOS fixtures before activation.

After the integration authority is merged with exact-head and merge-main ordinary
CI evidence, dispatch from trusted main for each fixed selector. Require exact
workflow authority/run/attempt binding, unchanged marker/other roots, complete
successful receipts and fresh process checks. Record actual failures; do not
relax bounds/layout/security or rerun blindly. This recovery-only bootstrap gives
no Level-3 credit while stale state blocks Level-3.

Unknown ssh-over-mcp-e2e-recover.cc8Del is excluded: no recursive inspection,
content read, deletion, inferred attribution or reuse of either target binding.
Its provenance and disposal remain an independent operator boundary. Even two
successful standard-root inspections leave A1 open. Apply implementation and
marker clearance require their own evidence/contracts; A1 closes only after
current-main ordinary plus automatic exact-SHA Level-3/provider/VM cleanup pass.
