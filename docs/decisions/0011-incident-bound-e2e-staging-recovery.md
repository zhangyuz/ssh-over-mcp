# ADR 0011: Incident-bound E2E staging recovery

- Status: Proposed; no cleanup authority approved or implemented
- Date: 2026-10-06

## Context

PR #140 merged as `1402b1addbdcfd4f7e740224ecaa014d9343163a`.
Its trusted-main inspect-only run
[37533378951](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/37533378951)
observed the stale marker target
`47531dadb58d365f74089dd5f52ce1b61bb0fdd1`, owner PID 38013, and three
runner-owned directories. No mutation occurred. The exact merge's ordinary
Linux validation passed, while its automatic Level-3 correctly refused stale
provider state; neither recovery nor A1 is closed.

The two standard staging roots have these observed identities:

| Root basename | Device / inode | Fixed expected_commit |
| --- | --- | --- |
| ssh-over-mcp-e2e-i8ow1ni6 | 16777220 / 187176421 | 47531dadb58d365f74089dd5f52ce1b61bb0fdd1 |
| ssh-over-mcp-e2e-w_kn4rus | 16777220 / 186877220 | bf84c7aafa5c79d629fc04488b5e0bda1cd98cef |

Both roots were UID 502, mode 0700. The latter binding is an older target,
not the stale marker target. Its target also has a successful historical E2E
run, but equal target SHAs do not attribute this directory to that run.
`ssh-over-mcp-e2e-recover.cc8Del` (device 16777220, inode 186815322) has no
expected_commit. It contains a runner archive, `clean/`, and empty `diff.txt`;
it remains unknown and MUST NOT be included in this proposal's cleanup.

An independent read-only host process snapshot found PID 38013 absent and no
UID-502 QEMU. Those observations are historical, not permission to mutate later.
The existing recovery authority only clears the marker after all runner-owned
blocking temp state is absent. Extending that authority to dispose of staging
requires a reviewed incident-specific contract first.

## Proposed decision

Create a separate manual, trusted-main, non-admin recovery workflow after
written approval. It shares the non-cancelling `live-local-e2e` concurrency
group. It performs no target execution, sudo, process killing, provisioning,
or normal-E2E automatic recovery. It never clears the provider marker.

Only the two exact roots above are eligible. Operator inputs choose one fixed
incident entry, not a path, glob, command, UID, or new target. Initial inspection
needs the expected stale target, but no input manifest digest: it creates that
evidence. Apply additionally requires the exact observed owner PID and reviewed
manifest digest to match freshly observed state.
Unknown, foreign-owned, or unbound roots stay untouched. A third incident entry
requires separate provenance, review and authorization; the unknown recovery
workspace cannot inherit either standard root's binding.

### Inspect phase

1. Validate the existing workflow/account/main context and fixed marker schema,
   ownership, mode and identity. Preserve that marker throughout.
2. Open the fixed temp parent and selected root using no-follow directory
   descriptors. Match the observed device/inode, UID and mode above, then read
   only the fixed expected_commit using PR #140's validated reader.
3. Require the recorded marker owner dead and no active runner-owned QEMU or
   orchestrator. Process inventory must be bounded and fail closed on ambiguous
   or unavailable results. Operator activity using these roots must be stopped;
   shared workflow concurrency alone cannot exclude a manual process.
4. Validate the exact eleven observed direct staging names/types:
   directories `bootstrap-wheels`, `payload-content`, `payload-iso`, `seed`,
   `target.git`, `wheels`; regular files `git-askpass`, `overlay.qcow2`,
   `payload.iso`, `seed.iso`, `target.bundle`. Any addition or mismatch refuses.
5. Build a data-only descriptor-pinned manifest of those trees. Read no other
   file contents, run no Git/package/application code, and follow no links.
   Require same device/UID, regular files or directories, no hardlinks, no
   group/world-writable entries, and no unexpected inode reuse. Enforce at most
   4096 total entries, depth 12, 4096-byte relative paths, a 2 MiB serialized
   manifest and a 60-second inspection deadline before accepting more input.
   These independent fixed bounds permit initial inspection. File contents are
   not allocated or read according to size; sizes are metadata observations.
   Apply's incident file/total-byte eligibility ceilings require the resulting
   complete evidence and review before its contract or code can be approved.
6. Record each relative name, kind, device/inode, UID/GID, mode, link count,
   size and change timestamps, with authority SHA, workflow run/attempt,
   marker identity/target/PID and selected staging identity/target. Emit bounded
   JSON and its canonical SHA-256. The operator reviews the complete manifest.
   A digest alone is not review or cleanup authorization.

### Apply phase

Only a separately dispatched operator-confirmed apply phase may mutate. Require
the exact reviewed manifest digest plus its inspect run/attempt and authority
binding. Re-inventory and compare the complete manifest and marker before any
mutation; a matching target string alone is insufficient.

Recheck process absence immediately before mutation. Keep all directory
descriptors pinned; revalidate directory-entry identities before each bounded
leaf unlink and bottom-up rmdir. Replaced, missing, newly added or ambiguous
state stops the operation. No generic recursive deletion or unknown-state
normalization is allowed. The protocol must state the residual same-account
concurrency assumption honestly: POSIX unlink is not an atomic conditional
unlink-by-inode. It cannot claim safety against a compromised runner account.

Before the first mutation, create a fresh exclusive no-follow mode-0600 journal
under a fixed runner-owned private recovery-evidence cache. Its lifecycle name
comes only from validated trusted workflow run/attempt and manifest binding.
No existing journal is overwritten, repaired or deleted. Bound projected
journal bytes before mutation; the exact limit belongs to the reviewed apply
contract. Write and fsync an intention record before each operation. After
unlink/rmdir, sync the pinned parent directory, verify absence, and write/fsync
a confirmation. Any write/sync/reporting failure stops with a failed result.
Successful sync calls are required; no stronger hardware power-loss guarantee
is claimed without separate evidence.

Termination between intention and confirmation means the operation **may have
completed**. Partial failure preserves the provider marker and must not claim
exact completed operations, rollback or success. Surviving evidence distinguishes
confirmed operations from uncertain intentions; missing/corrupt evidence is
itself uncertainty. Ordinary inspection still requires the original eleven
entries and MUST NOT silently accept a residual tree. A separately reviewed
residual-inspection/recovery contract is required before any retry; none is
approved by this ADR. No blind retry or guessed deletion from a journal.
After success, verify
the selected root and its run-owned files are absent, other roots unchanged,
and the marker unchanged. Cleanup evidence binds the exact apply run/attempt.

## Acceptance and sequencing

Use focused RED/GREEN with real disposable files/directories and adversarial
symlink, hardlink, special-file, ownership, bounds, replacement, process,
manifest-drift and partial-failure cases. Review the full trust boundary and
run self-hosted full Python 3.13/3.14 CI before merging any new authority.
Because stale state prevents Level-3, this is a separate recovery-only
authority prerequisite; it must not contain product/native changes or claim
Level-3 credit. Only already-main code may run on the persistent orchestrator.

Ship inspection first and obtain the missing full-layout/size evidence. Only
then specify and review bounded apply implementation. The unknown recovery
workspace still requires independent operator provenance and its own disposal
contract. Once every blocking root is resolved, use the existing separate
fixed-marker recovery with freshly verified PID/QEMU/marker/temp-state checks.
Finally rerun current-main CI so automatic exact-merge Level-3 and provider/
guest/whole-VM/artifact cleanup pass. Only then close A1, clean obsolete clean
branches/worktrees, and resume N1c. Preserve uncommitted work.

## Security impact and consequences

This proposal would add irreversible deletion of two specifically bound staging
trees by their existing non-admin owner. It does not grant generic deletion,
privilege escalation, host mounts/network/credentials to a guest, or a test
bypass. The fail-closed marker and production invariants remain unchanged.
Costs are an explicit incident record, manifest review, bounded layout proof,
partial-failure handling and independent authority activation. No implementation
or completion credit exists until those requirements are met.
