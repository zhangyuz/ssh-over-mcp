# Protected native E2E staging design

Status: proposed written design; implementation and activation are not approved.
Date: 2026-10-13 (America/Toronto).
Baseline: main b39e08aa31355e8c0abc441a501e5546279ecb46; full hosted/native
CI 38466541180 passed. The October historical incident is already resolved.
Authority proposal: [ADR 0019](../../decisions/0019-protected-native-e2e-staging.md).

## Intent and success

The operator asked to continue the small-slice development loop after verified
recovery and project-wide review. The intended outcome is that future native
runs create disposable workspaces in one private namespace outside the system
tmp cleaner's selection, and startup/recovery cannot overlook supported legacy
residuals. This prepares reliable infrastructure for Phase 7B1 native inputs;
it does not implement the native compiler or Ledger sandbox.

The continuation approves preparing this proposal, not code that has not been
reviewed. Written-spec review precedes the written implementation plan and its
review/execution-method selection.

Success requires actual creation, guest use and explicit verified cleanup in
the proposed namespace on the dedicated non-admin Intel Mac, plus refusal of
new or legacy residual state. Local fixtures and source contracts alone cannot
satisfy that runtime acceptance.

## Observed defect and existing contracts

The orchestrator's _ensure_temp currently creates tempfile.TemporaryDirectory
without a fixed dir; recovery uses tempfile.gettempdir. The dormant historical
preflight instead derives DARWIN_USER_TEMP_DIR. Actual UID 502 inspection
reported different parents. Historical roots under /private/tmp lost regular
payloads; the installed midnight tmp_cleaner script supplies a consistent,
unproved historical explanation. Moving a future root is not historical proof.

Current live cleanup uses TemporaryDirectory.cleanup before marker unlink.
Implicit object finalization must not become an alternate cleanup attempt after
the explicit cleanup path reports uncertainty. A live root needs explicit
ownership/lifetime tracking; an orphan remains separately authorized work.

The marker retains its two-field target/owner_pid schema and fixed cache path.
QEMU/image/guest locks, all five legacy guest fixtures, serial result binding,
no NIC/no shares, and host-only trusted-main execution remain unchanged.

## Alternatives and decision

| Option | Benefit | Limitation |
| --- | --- | --- |
| Fixed private Application Support staging (recommended) | One namespace and explicit lifetime outside the known tmp-cleaner path; separate from cache eviction semantics | New provisioning/namespace contract needs review and actual Mac evidence |
| One native getconf temp parent | Smaller placement change | Still temporary OS-managed storage; does not solve evidence-retention risk |
| Environment/operator-selected staging | Flexible placement | Adds path/configuration authority and inconsistent recovery selection; rejected |

Use this literal new namespace:
`/Users/gha-e2e-orchestrator/Library/Application Support/ssh-over-mcp-e2e/staging-v1`.

The Ubuntu image and active-run.json remain beneath the existing literal
`/Users/gha-e2e-orchestrator/Library/Caches/ssh-over-mcp-e2e`.
Do not move existing cache objects, historical roots or the journal. This is
outside the observed /tmp cleaner, not a promise against root, disk failure,
backup/OS software, manual deletion or a compromised orchestrator identity.

## Trusted namespace and creation

A shared trusted internal module, proposed as ops/live-e2e/provider_namespace.py,
owns fixed paths, validation, legacy discovery and explicit live workspace
handles. Production entrypoints accept no root/path/UID/permission selector.
Fixture adapters may replace OS boundaries in tests; they are not CLI inputs.

Validate existing trusted-main workflow/repository/Intel Darwin/non-admin
account context before filesystem actions. The initial provider requires real/effective UID 502 and the fixed account
name/home. UID reassignment refuses and needs a separate reviewed migration;
it must not cause old UID-502 residuals to be skipped. Preserve the existing
non-admin group policy; record/pin observed group identities, never accept a
caller-selected identity or add memberships.

Pin each parent-to-child edge from / using descriptor-relative directory
opens with O_NOFOLLOW and O_CLOEXEC, comparing no-follow pre-open metadata with
fstat and rechecking held edges before use and before returning success.
For the protected path, root/system ancestors must be root-owned; account
ancestors must be owned by the dedicated account; group/world-writable ancestors
refuse. The separate legacy validator has the explicit sticky-parent exception
below; it cannot be used to admit a protected staging parent. Do not reject
normal APFS system/data-volume transitions solely because parent and child
devices differ; pin each actual edge, then require the run child and staging
parent to share a device. Symlink substitution and unexpected mount/device
changes after pinning refuse; do not resolve arbitrary aliases.

Library must already exist and validate. Only the literal descendants
Application Support, ssh-over-mcp-e2e and staging-v1 may be created, one level
at a time, after clean-state checks, as the existing non-root account.
New directories use mode `0700` at creation and are opened/validated immediately.
Existing Application Support may be `0700` or `0755` without group/world write;
existing provider-base and staging-v1 must be `0700`. Existing unsafe/missing
required ancestors refuse; no chmod/chown, recursive mkdir or permission repair.
A concurrent creation is reopened and validated, never treated as our object.

Mode bits do not establish an ACL-free boundary. Private provider-base,
staging-v1 and new run directories must have no extended ACL entries.
For existing ancestors, reject ACL grants of namespace mutation to other
non-root principals and inheritable access grants; restrictive deny entries
do not grant authority. Inspect through a supported bounded native metadata
operation, correlate it with pinned identity, and revalidate before use.
Unavailable/ambiguous ACL evidence refuses; no automatic ACL removal.
Real disposable Mac ACL cases are mandatory before activation. The plan must
choose and review the fixed native metadata interface, not silently omit this
requirement because Python stat lacks ACL fields.

One live workspace uses the existing ssh-over-mcp-e2e- prefix with a fresh
32-character lowercase hexadecimal nonce. Create it exclusively relative to
the pinned staging FD, with mode `0700`; retain its basename, device/inode,
owner/group/mode, parent FD/identity and root FD in an explicit handle.
No public caller chooses or supplies an existing workspace. The marker does
not gain workspace fields in this iteration and cannot authorize directory
deletion; absence of every relevant root remains required for marker recovery.

No new E2E workspace, provider descendant or marker may be created when a
marker, QEMU, protected residual or supported legacy residual blocks startup.
Native discovery has the explicit OS-managed directory side effect below; do
not describe that operation as strictly read-only. Once context and both namespace
observations are clean, claim the existing marker exclusively before creating
the run child. Recheck held edges and legacy cleanliness before guest startup.
Failures retain unknown state; no automatic orphan cleanup.

## Bounded legacy compatibility

Always inspect two supported legacy parents: literal /private/tmp and the
dedicated account's native DARWIN_USER_TEMP_DIR, normalized only by mapping the
literal /var prefix to /private/var. Deduplicate if identical. These are
compatibility detection paths, never candidates for automatic removal.
Do not call tempfile.gettempdir, _get_default_tempdir, gettempdirb or a
writability probe during compatibility admission: they can create/delete probe
files in an environment-selected location. Capture only TMPDIR, TEMP and TMP
and the exact tempfile.tempdir scalar if the stdlib module is already loaded.
Unset/empty overrides and an unset cache need no candidate; reject other cache
types except an exact str. Each present value must be exact ASCII str, <=4096
bytes, with no NUL or whitespace. Freeze this bounded tuple and compare it again
before accepting either clean observation; drift refuses.

Validate lexically before any candidate-path access. Accept only /tmp and
/private/tmp, or the exact OS-returned native T path and its literal /private/var
counterpart. At most one trailing slash is accepted. Map /tmp to /private/tmp
and only the native path's literal /var prefix to /private/var. Reject relative,
redundant-separator, dot/dotdot, other account-token, /var/tmp, /usr/tmp, cwd and
other override/cache paths, before opening them. Never use realpath, resolve or
an arbitrary candidate stat/access check to make an unsupported value pass.
This does not infer which location a past interpreter actually selected; it
refuses unsupported present configuration. Supported historical absence remains
limited to the two declared parents; it is not proof about arbitrary old paths
or past environment changes. No host-recursive discovery is authorized.

The legacy-only /private/tmp parent must be a literal root-owned directory with
sticky mode `1777`, opened from pinned /private without following /tmp. Its shared
write permission is expected and permits only metadata blocking inspection,
never workspace creation/removal. Do not apply the private-root ACL/mode rules
to this shared temporary parent. All other legacy ancestors must satisfy the
already documented native-temp chain rules: safe root-owned shared ancestors,
dedicated-owner account token mode `0700`/`0755`, T mode `0700`, no followed symlinks,
and pinned edges. Foreign access that defeats those native private boundaries
refuses. The protected-path validator never has a sticky writable exception.

Getconf discovery uses a new fixed trusted child under this ADR's authority:
only /usr/bin/getconf DARWIN_USER_TEMP_DIR, sanitized environment, closed
unrelated descriptors, captured stdout<=4096 bytes and stderr<=1024 bytes,
5-second total execution deadline, then at most 2 seconds bounded owned-child
termination/reap. Signal only that positively owned child if required; never
discover/signal unrelated processes. A cleanup-uncertain child refuses the
whole check. Existing incident-pinned diagnostic bytes are not rewritten or
implicitly extended to this new authority.

The provider's installed confstr(3) manual and [Apple's published Libc manual source](https://github.com/apple-oss-distributions/Libc/blob/main/gen/confstr.3)
state that native temp discovery may create a missing OS-managed user temp
folder, and native temp files may also be cleaned after inactivity. This
proposal explicitly permits only that fixed non-root OS API side effect during
legacy discovery, even when E2E admission later refuses. It does not permit
Python probe-file writes, manual legacy-parent creation, E2E workspace creation
in that parent, removal or repair. Existing residuals are never relocated or
cleared. Missing/changed historical provenance is not reconstructed by an
OS-created empty parent; operator marker-recovery conditions still apply.
If native discovery cannot complete and its namespace cannot validate, refuse;
do not manually mkdir the returned path or omit that compatibility parent.

Require one canonical ASCII native path with the existing reviewed lexical
shape; validate the returned account-owned namespace through pinned edges.
Malformed, truncated, missing, inaccessible, unsafe, over-budget or drifted
parents refuse rather than disappearing from the supported-root set.

After native discovery, scan metadata only: at most 4,096 direct entries per legacy parent, at most 64
matching names and at most 16 dedicated-owner matches across both parents.
Any matching directory, regular file, symlink or special entry owned by the
dedicated account blocks. Never follow a link or read historical file content.
Foreign-owner matches in the shared legacy parent remain outside this account's
cleanup authority. In the private staging-v1 parent, any entry blocks a clean
check, including wrong names/owners/types; cap enumeration at 64 entries.
An aggregate 10-second metadata-scan deadline bounds all parents; every error
is refusal. Directory read-induced atime is not an identity field. No payload read is
authorized by these scans; native discovery itself is the documented exception
to calling the overall admission flow filesystem-read-only.

Use the same shared check for new-run admission, manual marker-only recovery
and trusted post-run namespace verification. It works even when no marker
exists, so a marker-free residual cannot silently become a healthy provider.
At least two observations and final parent-edge revalidation are required
before success. This is contemporaneous bounded evidence, not authenticated
historical provenance or proof of absence outside the declared locations.

## Explicit live cleanup and failure semantics

Replace implicit TemporaryDirectory finalization with explicit owned handles.
A destructor may close owned FDs; it must not unlink/rmdir or retry cleanup.
Stop and reap only the run's QEMU through the existing lifecycle first.
Before live workspace removal, verify every held namespace edge and original
run-root identity. A replacement, disappearance before our cleanup, lost FD,
ACL change or unknown cleanup result fails the run and retains the marker.

Ordinary recursive removal remains scoped to the exact freshly created
host-controlled run workspace owned by this invocation, after identity and
exclusive-writer checks. It is not a generic deletion API or stale recovery.
Preserve no-follow symlink handling and never traverse destinations. Require
removal/absence verification through the pinned staging parent. A descriptor
does not make POSIX stat followed by removal atomic; documented exclusive
account maintenance and no guest host-write path remain required assumptions.
The implementation plan must pin the removal primitive and its supported
platform attack resistance; it cannot use an absolute-path fallback after
a namespace mismatch.

Only after owned guest/workspace cleanup, repeated protected+legacy absence
checks, and unchanged owned marker identity/content may the existing live
cleanup clear its marker. Manual recovery still requires exact target/PID,
dead owner, no QEMU, repeated absence and unchanged marker; it never removes a
directory. Preserve failed/uncertain outcomes and do not add blind retries.

## Scope, frozen authority and rollout

Do not change ADRs 0011/0012 or their pinned historical spec bytes, incident
selectors/inventories, envelope/receipt schemas, or the exhausted ADR 0018
disposer/journal. The historical getconf-bound preflight stays historical.
Future observers must explicitly consume this new namespace contract;
this proposal does not activate them, B8 receipts or N1c.

After design and plan approval, stage two independently verified slices:
1. Dormant shared namespace/ownership/compatibility contracts with disposable
   fixtures and no workflow caller or production placement change.
2. Trusted-main activation for orchestrator, marker-only recovery and a fixed
   no-argument namespace-health check used by the E2E workflow.
   Already-main authority must judge a target; no PR target helper executes on
   the persistent host. Pre-merge legacy E2E does not prove the new placement;
   first actual new-placement proof is an additional post-merge gate.
A failed activation stays open for a separate narrow repair, not a fallback
to /tmp. No native toolchain or Ledger target certification is inferred.

Rollback stops new dispatches and preserves marker/workspace evidence.
The retained legacy route cannot silently resume while protected residuals
exist. Any rollback authority must continue scanning both namespaces; if it
cannot, the provider stays blocked for a separately reviewed repair.

## Required acceptance evidence

| Criterion | Required evidence |
| --- | --- |
| Selection independent of TMPDIR/environment | Fixture tests and shared production call-site contracts |
| Canonical FD-bound paths, identity/owner/mode/ACL refusal | Disposable Mac adversaries, including swaps after intention/before cleanup |
| Normal APFS volume transition handled | Actual Mac creation/open/use test; no global same-device shortcut |
| Bounded legacy scan and owned getconf lifecycle | Boundary/deadline/truncation/failure/reap tests; no payload reads or foreign signals |
| Residual blocks without a marker | Protected and both legacy locations, all entry kinds and unexpected private entries |
| Explicit lifetime | Abrupt interruption and cleanup-failure evidence; no destructor deletion or retry |
| Live cleanup only for owned original root | Replacement/symlink canaries, preserved foreign object and retained marker on ambiguity |
| Shared recovery/post-run behavior | Marker-only exact-target/PID tests, no-root-deletion contract, repeat observation drift |
| No target execution/host shares/network widening | Existing complete legacy fixture, workflow and guest trust regressions |
| Actual protected placement and complete cleanup | Final exact-main native run; layout-version and pinned-placement observation produced by trusted host authority, never guest/target text; no VM/marker/workspace remnants |

Baseline 86 focused current tests passed; this is existing behavior evidence,
not implementation of the proposed rows. Every behavior slice needs intended
RED→minimal GREEN, relevant/full regression, fresh independent review, full
exact-head Python 3.13/3.14 CI and applicable legacy/native gates, exact merge-main
verification and cleanup. Record earlier failed/refused attempts honestly.

The final tracked evidence protocol must not guess future head/main PASS.
Collect actual post-merge acceptance externally without another evidence-only
commit loop. N1c resumption additionally needs explicit reconciliation of its
A1/B8 pause conditions; this namespace change does not close them automatically.
