# Protected native E2E staging design

Status: written design approved 2026-10-13; first dormant-inspection plan approved for native execution 2026-10-13; no activation approved.
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

The operator approved this written design on 2026-10-13 at 20:21:38
America/Toronto after its Chinese explanation. The first
[implementation plan](../plans/2026-10-13-protected-staging-health-inspection.md)
delivers dormant namespace health inspection; owned lifetime and activation
follow in separately reviewed iterations. The operator approved the revised
written first plan and recommended native execution on 2026-10-13 at21:55:05
America/Toronto; this does not approve later lifetime/activation plans.

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

## Shared-parent drift rule

Use one strict drift rule for the protected and native private chains and the
inspection-only shared /private/tmp parent: device, inode, directory type,
owner/group, full mode, ACL snapshot, mtime_ns and ctime_ns must remain unchanged
across pinning, both observations and final edge revalidation. Atime is excluded
because our directory inspection can update it. Neither matching-prefix counts
nor a stable basename replace edge/identity/ACL evidence.

For /private/tmp, a foreign nonmatching create/remove can change mtime/ctime.
This deliberately refuses the current inspection even when both matching-prefix
scans are empty. The availability cost is explicit: unrelated host activity can
temporarily block admission, marker recovery or post-run acceptance. There is no
automatic quiet-period retry, timestamp reset, ignored drift or fallback parent.
Keep the two bounded scans and all owner/type/mode/ACL/edge checks; do not relax
this shared-parent rule during implementation. A future churn-tolerant design
would need separate review and evidence.

Required adversaries include a foreign nonmatching entry created between
observations, a foreign entry created then removed before the second scan, an
owned UID502 matching entry visible to either scan, and an owned matching entry
inserted then deleted between scans. The first two refuse as drift; a visible
owned match refuses as residual, and a between-scan insertion/deletion refuses
when its parent timestamp change is observed. Tests must establish that the
injected event changed recorded metadata, preserve foreign objects and prove
no payload reads or deletion. No finite sampling detects every transient event
outside its observations; unchanged evidence is contemporaneous bounded absence,
not a certificate that no past or future object exists.

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

After the applicable written-plan approval, stage three separately reviewed
and independently verified deliveries:
1. Dormant shared namespace health inspection with disposable fixtures and no
   workflow caller, creation/removal API or production placement change.
2. Dormant owned workspace lifetime: exclusive creation, original-root scoped
   cleanup and no deleting finalizer, with its own reviewed plan, removal
   primitive and adversarial evidence; no production caller activation.
3. Trusted-main activation for orchestrator, marker-only recovery and a fixed
   no-argument namespace-health check used by the E2E workflow. Its separate
   plan must satisfy the activation checklist below; do not combine lifetime
   implementation with activation.
   Already-main authority must judge a target; no PR target helper executes on
   the persistent host. Pre-merge legacy E2E does not prove the new placement;
   first actual new-placement proof is an additional post-merge gate.
A failed activation stays open for a separate narrow repair, not a fallback
to /tmp. No native toolchain or Ledger target certification is inferred.

## Required activation checklist

This checklist pins the current routes at baseline b39e08a. The activation
implementer must audit the then-current source too, replace each route below
and record every new equivalent call site. Adding inspect_namespace beside
an old tempfile route does not satisfy this contract. These are later activation
requirements, not permission to change callers in the first dormant delivery.

| Baseline route | Required replacement and gate |
| --- | --- |
| [orchestrator verify_host and _require_host_free_space](https://github.com/zhangyuz/ssh-over-mcp/blob/b39e08aa31355e8c0abc441a501e5546279ecb46/scripts/run-live-local-e2e-orchestrator.py#L490-L498), [both path calls](https://github.com/zhangyuz/ssh-over-mcp/blob/b39e08aa31355e8c0abc441a501e5546279ecb46/scripts/run-live-local-e2e-orchestrator.py#L603-L635) | Remove both the HOME path-based and gettempdir-based free-space checks from the pre-validation sequence. After trusted context and namespace pinning, use os.fstatvfs on the validated protected parent FD (or nearest existing fixed allowed ancestor if descendants are absent); compare f_bavail * f_frsize against the unchanged HOST_MIN_FREE_BYTES = 16 * 1024**3. Recheck the actual staging-parent FD before materializing run artifacts; no pathname/selector fallback. Unsupported/error/mismatched or changed FD evidence refuses. |
| [orchestrator _ensure_temp and callers](https://github.com/zhangyuz/ssh-over-mcp/blob/b39e08aa31355e8c0abc441a501e5546279ecb46/scripts/run-live-local-e2e-orchestrator.py#L699-L718) | Replace default TemporaryDirectory selection with the invocation's explicit owned handle from the separately reviewed lifetime deliverable. Check marker/QEMU/shared namespaces, claim the marker exclusively, then create only validated fixed descendants/fresh run child; recheck before guest startup. No parallel temp route, environment-selected workspace or finalizer cleanup. |
| [recovery inspect_recovery/recover](https://github.com/zhangyuz/ssh-over-mcp/blob/b39e08aa31355e8c0abc441a501e5546279ecb46/ops/live-e2e/recover_provider.py#L336-L394) | Replace gettempdir root discovery and the legacy-only _temp_dirs path with the bounded shared protected+both-legacy scanner. Retain exact target/PID, owner-death/no-QEMU, repeated observation and unchanged marker guards. A temp_root/uid test seam or historical diagnostic cannot choose a production scan root or authorize deletion. |
| [recovery inspect-only relation and main](https://github.com/zhangyuz/ssh-over-mcp/blob/b39e08aa31355e8c0abc441a501e5546279ecb46/ops/live-e2e/recover_provider.py#L397-L468) | Retire _inspect_temp_parent_relation from the activated recovery entrypoint; its gettempdir, realpath comparison and separate getconf are not shared-health evidence. Use only validated captured lexical selector/native evidence for any retained relation label; do not invoke the old _temp_diagnostics payload reader as part of new namespace health. Preserve historical evidence without extending frozen incident helpers. |
| [orchestrator provider_state_exists/startup and cleanup_host](https://github.com/zhangyuz/ssh-over-mcp/blob/b39e08aa31355e8c0abc441a501e5546279ecb46/scripts/run-live-local-e2e-orchestrator.py#L686-L705), [orchestration/cleanup](https://github.com/zhangyuz/ssh-over-mcp/blob/b39e08aa31355e8c0abc441a501e5546279ecb46/scripts/run-live-local-e2e-orchestrator.py#L916-L968) | Wire pre-claim startup and post-guest/post-workspace verification to the same scanner even without a marker. Owned cleanup retains QEMU reap, original-root/edge/ACL verification and uncertainty semantics. Clear only the unchanged owned marker after repeated shared absence; no parallel legacy-only success route. |
| [workflow always-run provider check](https://github.com/zhangyuz/ssh-over-mcp/blob/b39e08aa31355e8c0abc441a501e5546279ecb46/.github/workflows/live-local-e2e.yml#L81-L86) | Replace the marker-absence-only test with the fixed no-argument trusted-main namespace-health command plus the existing marker/process absence conditions. A skipped, failed or uncertain cleanup must fail the job; the check cannot erase residual state or infer success from marker absence. |

Activation tests must patch gettempdir, gettempdirb and _get_default_tempdir to
fail if reached through live startup/free-space/workspace allocation, normal
cleanup, marker-only recovery (including inspect-only diagnostics) or the
always-run workflow health route. Cover supported selector aliases and
unsupported TMPDIR/TEMP/TMP/cache values; these values may be lexically checked
but must never select a workspace, free-space object or replacement scan parent.
Unsupported candidates refuse before candidate stat/access/resolve/open or
probe-file writes. Pin all production call sites and the fixed command's
zero-argument surface, FD-based capacity/error/identity gates, shared drift
adversaries and absence when no marker exists. Frozen historical diagnostics
remain historical and cannot bypass these activation assertions.

The separate activation plan must retain exact-head/full legacy gates and
actual post-merge trusted-host protected-placement/guest/cleanup evidence.
Old-placement PASS does not close this checklist or certify the new root.

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
