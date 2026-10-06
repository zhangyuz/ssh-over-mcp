# Offline native E2E toolchain design

**Status:** Written proposal; direction approved 2026-10-06, written design and
execution plan approval pending. No native authority activated.

**Purpose:** Unblock Phase 7B1's native canaries without changing the pinned
guest or weakening its trust boundary. [ADR 0010](../../decisions/0010-offline-native-e2e-toolchain.md)
records the new input authority. The parent [Ledger design](2026-10-05-phase-7b1-ledger-systemd-design.md)
and its sixteen acceptance criteria remain unchanged.

## 1. Baseline and evidence limits

Main `9e78f98dc55e1c28f0a57be2ac87324bb6a82f62` has completed the keyfile and
fresh split-layout provisioning prerequisites (PRs 124/125). Task 3's guest
inventory run [37459216524](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/37459216524)
found no executable `/usr/bin/cc`; no compile/link/run proof exists.

The public pinned-image manifest corroborates the absence of compiler
packages. Its digest is
`ea3f35e10b7f0b1c48edc42665ccd4d1974319d0fb28bd97762dbef7643acaaf`.
It describes systemd `259.5-0ubuntu3` and kernel package
`7.0.0-28.28`; these are published inventory hints, not live version evidence.
The actual fresh guest must attest all consumed files before target execution.

Keep Ubuntu image SHA256
`117816726abbdefc5ef3e38902e81a76f1c76c3610e709999d0885f9d5d9b477`,
QEMU 11.1.2/HVF, x86_64, no NIC, no host shares or host credentials. Ordinary CI
remains self-hosted and nonprivileged. Do not provision the Mac or production.

## 2. Source authentication and frozen metadata

The only new acquisition origin is `https://snapshot.ubuntu.com`, fixed path
prefix `/ubuntu/20261005T000000Z/`. No arbitrary mirror or cross-origin redirect.
Acquire resolute, resolute-updates and resolute-security **main binary-amd64**
metadata and their selected `pool/` package paths. Resolve no target arguments.
Package names/paths/versions and all digests belong to trusted main.

Use the fixed 2018 fingerprint from ADR 0010. The operator provisions GPG
verification capability and its version; the host preflight verifies a private
keyring containing only that approved public key and its pinned digest. Do not
install a verifier during a workflow. Use explicit private GPG home/keyring,
no ambient trust/config/network key retrieval; require successful verification,
the exact allowed signer and strong digest algorithm. Unknown/expired/revoked
key state, extra ambiguous signatures or verifier errors refuse acquisition.
The fingerprint's independent Ubuntu documentation establishes identity;
copying an existing keyring alone is not that proof.

Research verified these exact InRelease digests with that signer:

| Pocket | InRelease SHA256 | Signed Date (UTC) |
| --- | --- | --- |
| resolute | `45f95ce276cdba3e41870516a130e03c58b8b7a79e9546b0efe9e526d255740c` | 2026-04-23 17:07:15 |
| resolute-updates | `b01932d3a6c1796a9ee7428ed58300b6cc288e0dfc004337c408ae865007d19e` | 2026-10-04 13:26:37 |
| resolute-security | `578358f7b5e41ad069fc209bfa8ab45410f24d241be80255bdd94dbf3c11dc98` | 2026-10-04 11:12:38 |

Freeze these bytes and exact signed dates. Reject any mismatch, future Date,
wrong suite/component/architecture or absent/conflicting SHA256 records. All
three researched releases omit Valid-Until. This deliberately historical
snapshot uses explicit reviewed byte/date pins, not a claim of rolling freshness
or a blanket disabling of expiry for future inputs. On a refresh, review signed
Date/Valid-Until and current key status anew; an expired Valid-Until is rejected.
Metadata limits: 512 KiB per InRelease, 32 MiB per compressed index, 256 MiB
per decompressed index, 200,000 records per index and 64 KiB per record. Limit
each resource transfer to 60 seconds and the acquisition stage to 15 minutes.
Enforce these independently of package limits while streaming; oversize,
compressed-expansion or timeout refuses before excessive allocation/use.
No fallback to a newer/older snapshot on download failure. Package indexes and
debs must match signed size/hash before parsing/use; retain the signed chain in
the receipt and payload for independent guest hash verification.

## 3. One derived native manifest

`ops/live-e2e/native-toolchain-inputs.json` will be the single native input
manifest. It records schema, image digest, snapshot, signer/key digest,
InRelease/Packages bytes and dates, root compiler selection, every selected
package's version/architecture/path/size/hash, all Depends/Pre-Depends edges
and their chosen providers, plus a complete materialized file recipe.

Derive it from the authenticated indexes using Debian version semantics.
Resolve the chosen roots `gcc-15-x86-64-linux-gnu`,
`cpp-15-x86-64-linux-gnu`, `gcc-15-base` and `libgcc-15-dev` at
`15.2.0-16ubuntu1`. Every transitive dependency must be either a verified exact
declared base-image provider or an authenticated payload package. Record which;
do not confuse published-image hints with measured image files. Alternatives,
virtual providers, multiarch and version relations require explicit selected
providers and tests; unsupported syntax fails, never truncates a dependency.
No automatic highest-version choice during a run. The verifier regenerates and
compares the derivation; editing a digest or dropping an edge cannot pass.

The four root packages are candidates, not a complete approved payload. Root
package SHA256s already authenticated in research are respectively
`df0e5375c9e981b18e396c2e9ec1e359f226576a9b94a311bf07603f3ca6023a`,
`1649aa71c45b047feda5b9ca303c94799bdba5befa5c9de9735cbfc59c3ef93f`,
`5a302d705d562fb7e150415b00651c00fed58b633faadff0b332eac1b73fadb3`,
`32fa5bde1891f46fd4f422e466c863fb78e834b634e1aa08211c8eea68870af5`.
Enabling the feasibility preflight requires the full generated manifest,
reviewed declared composition/layout and supported-Linux controls. Authorizing
subsequent security-canary use additionally requires actual pinned-guest proof;
these four hashes cannot substitute for either gate.

The manifest explicitly assigns driver, cc1, collect2/link helpers when used,
assembler, linker, compiler/system headers, startup objects, linker scripts,
ELF interpreter and every shared library to exact payload or image files.
Record transitive ELF dependencies and actual search paths. Root must not use
ldd or execute binaries to discover them. Non-root controlled probes confirm
the declared composition; unresolved files or shadowing forbid activation.
N1 owns the bounded non-root host-side package-data parser used to generate
this recipe. Its image input is DeclaredImageBindings: exact pinned image
digest, published manifest bytes/digest, explicit component roles, canonical
paths and expected package versions. This permits a complete **declared**
composition without claiming that candidate file contents have been measured.
Expected per-file hashes require an actual authenticated byte source; do not
guess them from a version. An image role may instead rely on the already-
authenticated full image digest with mandatory fresh-guest reconciliation.

N1 is complete when signature/dependency derivation and every payload recipe
entry are reproducible, every image role/path/provider is explicit, and review
finds no undeclared component or implicit search fallback. It is not complete
live composition evidence. At N3 candidate proof, before _start_manager() or any other target
exec, trusted code measures the still-fresh image files, checks the declared
versions/metadata/paths and complete ELF/search composition, and binds their
actual hashes to the verified image and receipt. Unknown or mismatched image
files/dependencies fail; they cannot expand the manifest at runtime. Native
feasibility and later canary authorization remain blocked on reconciliation.
No second Python build-tool authority or package replacement in the guest OS.

## 4. Bounded data materialization and read-only tree

Extract package **data only**, never run maintainer scripts, dpkg installation
or ldconfig. Use a trusted non-root host-side bounded parser to produce the
reviewed normalized file recipe, then the stdlib trusted guest materializer
verifies and copies only recipe entries into
`/opt/ssh-over-mcp-e2e/native-toolchain`. Neither root path imports target code.

Limits: at most 64 packages, 256 MiB total compressed input, 768 MiB expanded
data, 32,768 entries, 4,096 bytes per path, 128 MiB per regular file and 40 link
hops. Enforce limits while streaming, before allocating/extracting oversized
data. Reject absolute/parent-escaping paths, duplicate normalized paths,
cross-package file collisions, special files, hardlinks, set-ID bits, file
capabilities or unknown extended metadata. Identical directory entries may
merge only with identical approved metadata. Symlinks require an explicit
recipe: no escape, cycle or unapproved base-file destination. Any required
link rewrite or image-file copy is a reviewed deterministic recipe, with both
source and resulting bytes/modes/destination recorded; never silently repair.

Require a fresh run-owned destination and pinned directory descriptors. Reject
pre-existing or replaced state; no overwrite or recursive unknown deletion.
After all materializer writers are quiescent, measure the complete tree,
require root ownership, no writable ancestor and no unexpected entry, and bind
it read-only. Verify mount identity/options and denied writes as the compiler
identity. Root ownership alone is not read-only evidence. Keep read-only input
media; work/output reside in a separate bounded run-owned cgroup/directory.
Cleanup failure fails the run; whole VM destruction remains mandatory.

## 5. Fixed non-root feasibility and source/output binding

First land the already-required guest no-core guard as a separate small slice.
It uses its own `GuestPreflightError`, independent of the not-yet-created
systemd profile module. Establish fixed non-pipe `kernel.core_pattern=core`
and hard/soft RLIMIT_CORE `(0, 0)` after verified fresh-guest/root context,
before any target execution. Every direct child verifies inherited zero limits
before exec. This breaks a circular dependency on Task 3's later profile.

The native helper uses existing fixed probe UID 2204 / GID 3204, no supplementary
groups, all capability sets zero, NoNewPrivs=1 and zero core limits. The trusted
controller attaches it to a fixed run-owned cgroup **before exec**. It receives
no sensitive descriptors. A private fixed environment rejects inherited GCC_EXEC_PREFIX, COMPILER_PATH,
LIBRARY_PATH, CPATH and loader hooks. Any necessary search/loader path is an
exact reviewed manifest constant, never inherited or target data; LD_PRELOAD
and arbitrary loader/module injection remain forbidden.
Commands, cwd and source/output paths are fixed. No caller flags, response
files, specs/plugin selection, shell or generic compiler RPC.

`ops/live-e2e/native_toolchain_probe.c` is a harmless trusted-main source: native
x86_64 Linux ABI guards, system headers and symbolic SYS_io_uring_* constants,
compile/link/run with bounded exit output. It grants no seccomp or kernel-denial
credit and contains no credential/canary secret. Actual compiler commands and
composition are frozen after inspection and successful supported-Linux
non-root controls in N2, before enabling N3 candidate feasibility. Those controls do not
claim pinned-guest compatibility; the N3 result permits N4 routing only;
N4 native-required gates authorize later security-canary use.

Stop and inventory all writers/descendants before sealing the output. Reject
escaped or surviving writers. Pin/measure the produced ELF and execute only
that sealed file after validating architecture, interpreter, dependencies and
source/authority bindings. No root executes it. Record actual compiler and
guest/kernel versions; do not infer ABI support from a package name. Later
Task 7's security canaries use the same certified inputs plus their already-main
source, fresh output binding, core and identity checks.

## 6. Candidate proof, mandatory use and authority repair

Separate first guest feasibility from mandatory native certification. The
existing `live-local-e2e.yml` remains a fixed **legacy-7a** authority-regression
route: all five fixtures and cleanup, with no native acquisition or preflight.
It is available for preparatory authority changes and bounded native-authority
repair; it cannot certify native compatibility or a native-dependent target.
No failure automatically retries through this route. Once N3 lands, every
legacy invocation applies the already-main bootstrap/repair scope check;
merge-main self-target runs have an empty diff. Normal native-dependent targets
use the required profile (which still includes all five legacy fixtures).

| Fixed main workflow | Evidence class | Permitted credit |
| --- | --- | --- |
| live-local-e2e.yml | legacy-7a | Scoped authority bootstrap/repair and five-fixture regression |
| live-native-toolchain-candidate.yml | native-candidate | Native feasibility plus five fixtures; prerequisite preparation |
| live-native-toolchain-e2e.yml | native-required | Native prerequisite certification plus five fixtures |

Only the later ledger-systemd-7b1 path can certify full Phase 7B1. Trusted
consumers require the specific expected class, not merely any successful run.

N3 adds `live-native-toolchain-candidate.yml` and its fixed trusted-main host
entrypoint `scripts/run-live-native-toolchain-candidate.py`. This path runs only
already-main materializer/helper/source inputs, reconciles the fresh image,
compiles/links/runs, then runs the complete legacy matrix. It shares the existing
provider account and `live-local-e2e` concurrency group with cancel-in-progress
false; it cannot overlap another QEMU run. It remains guest-only/no-network,
main-only and accepts only exact commit_sha. The root gate receives its fixed
profile from trusted host payload metadata, never target CLI/environment/data.
Candidate selection is selection of a reviewed workflow, not a target-selected
command, helper, unit, UID/GID, path or arbitrary acceptance mode.

The candidate path becomes executable authority only after N3 merges. If its
first or later native proof fails, legacy regression remains executable because
that route neither fetches native inputs nor imports/runs native modules.
Repair the native authority through a separate small PR using ordinary CI,
full exact-head legacy E2E and independent review before merge. Then require
exact merge-main ordinary/legacy gates and rerun candidate proof using the
newly-main repaired inputs. A failing candidate remains failed; the repair PR's
legacy PASS is only authority-bootstrap regression evidence. The prerequisite
stays open, and N4/product certification stay blocked, until the actual native
candidate proof and all cleanup pass. Correcting this open slice is allowed;
starting another capability while its gates are pending is not.

Legacy repair is restricted to native authority inputs/modules, their fixed
workflow/orchestrator/gate wiring, corresponding ops contracts and documentation.
N3 commits an exact path allowlist for these files; broad ops/ or docs/ prefixes
are insufficient. Renamed/new paths require separate authority review before
the repair target can use them.
It must not include production src/, target live fixtures/probes/support or
ordinary CI policy changes. Split any such changes into separately certified
PRs. Trusted-main scope checks inspect the target diff as bounded data, never
execute target code on the host, and reject mixed repair/product changes.
Scope checks plus fresh review cannot be supplied or relaxed by the repair
branch itself. A product PR cannot select this route to avoid native evidence.

N4 adds `live-native-toolchain-e2e.yml` and fixed main entrypoint
`scripts/run-live-native-toolchain-e2e.py`, using the same frozen runtime recipe
as the successful N3 candidate. It requires native preflight and the five
fixtures, before any target exec including _start_manager(). No native failure,
missing input or malformed receipt permits fallback to legacy. N4's exact-head
candidate proof must already PASS under trusted main before merge; its exact
merge-main run must then PASS through the native-required workflow. N4 changes
only fixed routing/evidence policy, not compiler algorithms, inputs or source.
A changed native runtime contract is a separate prerequisite needing fresh
candidate proof, not an untested addition hidden in activation.

Keep the legacy authority-repair route after N4. If native-required main fails,
the same bounded repair cycle remains usable. Later native-dependent Phase 7B1
PRs normally require the native-required workflow; a repair bootstrap exception
never declares native or product completion. After repair, repeat native-required
merge-main proof before resuming those PRs. Candidate failures and missing proof
remain fail closed for their own purpose; legacy execution is never a runtime
fallback for a native-required invocation.

## 7. Authority sequencing and evidence

Ship five slices: G1 no-core guard, N1 authenticated derivation, N2 dormant
materializer/helper, N3 bounded candidate authority/proof, N4 mandatory native
certification. Each requires focused RED/GREEN, relevant full regression, fresh
independent review, exact-head ordinary CI and full legacy E2E, then exact
merge-main CI/E2E and cleanup. The authority used for each head must already be
on main. N3 additionally requires actual candidate merge-main native proof.
N4 additionally requires exact-head candidate proof before merge and exact
merge-main native-required proof afterward. Legacy, candidate and required
receipts have distinct evidence classes; none is interchangeable.

Every native invocation uses fixed preflight before _start_manager() (which
currently executes target code during prepare()) or any other target execution,
as well as before the five-fixture probe. Task 6 stays wired and Task 7
STOP_MANAGER remains last. No later security-canary use or prerequisite
completion is authorized until N4's actual native proof, legacy matrix and
cleanup all pass. Later Task 8's ledger-systemd-7b1 mode must include mandatory
native preflight; neither legacy nor candidate nor native-required alone earns
full Ledger/systemd acceptance. Keep all sixteen criteria unchanged.

Native receipt fields: authority/target SHA, run/attempt, fixed workflow/profile,
evidence class (native-candidate or native-required), image/snapshot/signer,
signed metadata and manifest digests, package closure, image file bindings,
materialized tree/mount identity, source digest, identity/core/cgroup facts,
fixed command plan, actual component/kernel versions, sealed ELF digest,
compile/link/run conclusions and all cleanup results. Reconcile with trusted
run output, not target self-report. Guest serial remains bounded by ADR 0008.
A required consumer rejects candidate/legacy receipts even if they say PASS.
Scope check errors or unknown workflow/profile/evidence classes fail closed.

This prerequisite is complete only after N4's exact merge-main native-required
proof, ordinary CI, unchanged full legacy matrix and provider/guest/whole-VM
cleanup. It does not close Phase 7B1, replace installed-package-under-systemd
proof, count as io_uring enforcement, or remove any acceptance criterion.
Resume the remainder of parent Task 3 only then, using native-required head and
merge-main gates for native-dependent preparations. If a compatible tree cannot
be established within these constraints, stop for renewed design; no networking,
skipped criterion, apt repair or silent image refresh. The tested repair cycle
above resolves native authority defects without self-certification or bypass.
