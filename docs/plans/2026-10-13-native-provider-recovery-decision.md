# Native provider recovery: exact operator decision

Status: exact disposition approved by the operator at 12:18:16 EDT;
implementation/test/review gates in progress. Native Level-3 remains blocked.
Date: 2026-10-13 (America/Toronto).

## Verified current state

Main is `f25117fbc46469a79e4d4b09d619323d8edbbea1` (PR #239 merged).
[Main CI 38425538261](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38425538261)
passed all eight hosted partitions and both Python aggregate gates. Native
Level-3 failed before QEMU launch with `stale E2E provider state detected`,
exit 70; marker-absence verification failed too. Hosted feedback completed
in approximately 7 minutes 21 seconds; native acceptance has not passed.
There were no open PRs when this investigation began.

The primary developer checkout was clean but 101 commits behind origin/main;
it was fast-forwarded without changing the two older dirty worktrees. The
initial worktree audit found 56 worktrees, with edits only in
`recovery-target-binding` and `e2e-observe-deep-metadata-oct13`. Their edits
remain preserved. Do not delete them as part of provider recovery.

## Complete residual metadata

[Root #1/#3 observation 38425575089](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38425575089)
and [repeat 38425760406](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38425760406)
have identical root inventories. [Root #2 observation 38399514982](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38399514982),
[repeat 38399515859](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38399515859)
and [fresh main observation 38427240585](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38427240585)
also have identical inventories and unchanged marker metadata.

All paths below are literal children of `/private/tmp`, device **16777220**,
UID **502**, root mode **0700**. Counts include the root itself.

| Exact basename | Root inode | Directories | Symlinks | Regular files | Maximum relative depth |
| --- | ---: | ---: | ---: | ---: | ---: |
| `ssh-over-mcp-e2e-i8ow1ni6` | 187176421 | 18 | 0 | 0 | 4 |
| `ssh-over-mcp-e2e-recover.cc8Del` | 186815322 | 1326 | 6 | 0 | 13 |
| `ssh-over-mcp-e2e-w_kn4rus` | 186877220 | 18 | 0 | 0 | 4 |

Total proposed removal envelope: **1362 directories and 6 symlink entries**.
Link targets were not read or followed. Complete per-entry identities remain
in the private workflow manifests, not in this public document.
Every observer explicitly reports `recovery_eligible=false`. Identical
snapshots do not establish exclusive process quiescence or lost-file provenance.

The fixed marker is
`/Users/gha-e2e-orchestrator/Library/Caches/ssh-over-mcp-e2e/active-run.json`:
UID502, mode0600, device16777220, inode187176420, nlink1, size75;
recorded owner PID **38013**, target
`47531dadb58d365f74089dd5f52ce1b61bb0fdd1`.
The developer account's process view did not show PID38013 or QEMU, but
this is not the UID502 exclusive-death proof required for mutation.

## Newly identified scheduled cleanup mechanism

Read-only inspection on this Mac found:

- `/System/Library/LaunchDaemons/com.apple.tmp_cleaner.plist` schedules
  `/usr/libexec/tmp_cleaner` at local hour **0**; launchctl reports the
  system service registered, 13 executions, latest exit0.
- The installed POSIX script scans `/tmp` (a symlink to `/private/tmp`)
  and deletes regular files matching all three `find` age predicates
  (`-atime +3 -mtime +3 -ctime +3`, with rounded-day semantics). It then deletes old empty directories. Its deletion selection
  excludes symlinks.
- Root #1 directory changes occurred at **2026-10-11 04:00 UTC**;
  root #3 changes at **2026-10-09 04:00 UTC**. Many root #2 directory
  changes also occurred at October9 midnight local time; six more directory
  changes occurred at **2026-10-13 04:00 UTC**. These times
  match the launchd schedule in Toronto.

This is a concrete mechanism consistent with lost regular payloads,
remaining directory skeletons and surviving symlinks. It is a **supported
causal hypothesis**, not an authenticated historical deletion record. It
neither proves the original cancellation cause nor reconstructs a commit
binding or deletion authority. Do not disable the system cleaner.

## Exact operator decision — approved

The operator explicitly approved this exact decision on October13 at
12:18:16 EDT: “Sounds good, let’s just fix it”. It covers whether these three exact residual
trees may be discarded despite incomplete historical provenance and the
loss of prior regular-file evidence. Approval applies only to the listed
root identities and the complete matching private per-entry manifests.
It does not authorize recovering deleted payload, accepting unknown
entries, trusting symlink destinations or classifying the old run as passed.

Approval of this document authorizes developing, reviewing, testing
and, only after its gates pass, executing the narrow disposition below.
Observation runs still grant no mutation authority. The separate approved
[ADR0018](../decisions/0018-approved-historical-residual-disposition.md) binds
the new implementation and dispatch to this incident. Permission repair,
process signals, generic deletion and quarantine rename remain excluded.

## Bounded implementation and execution sequence after approval

1. Implement a separate one-incident trusted-main manual UID502 workflow
   and independently review it. Keep the existing observers and marker-only
   recovery unchanged. First add a separately reviewed incident ADR:
   ADR0011 excludes root #2 and requires the original eleven-entry staging
   layout and depth12, so its existing apply contract cannot accept these
   depth13 skeletons. Do not relax or reuse it.
   Use pinned actions, exact authority SHA, read-only
   token, the shared non-cancelling `live-local-e2e` concurrency group,
   and a bounded private durable operation journal. Before first mutation,
   create it exclusively, no-follow, mode0600 beneath the pinned protected
   cache; write/fsync its initial record and fsync the cache directory.
   Record and sync intention before each mutation. Sync the mutated parent
   directory and verify absence before recording/syncing confirmation.
   Durability here covers process interruption with kernel/storage intact,
   not OS crash or power loss. Journal text alone cannot certify a failed
   sync; successful workflow completion and fresh state checks are required.
   Any uncertain durability stops the operation. Require disposable macOS
   evidence for journal creation/write/fsync, parent sync and confirmation
   failures, including crash recovery.
   No arbitrary input paths.
2. Use disposable fixture RED/GREEN evidence for exact identity mismatch,
   extra/missing entry, directory-to-symlink replacement, foreign owner or
   device, unsafe mode, live/reused owner PID, active QEMU/orchestration,
   partial operation failure and changed marker. Test that symlink target
   canaries remain untouched and an unexpected regular file blocks mutation.
3. Before any mutation, establish UID502 process quiescence and an explicit
   exclusivity/race model. Shared workflow concurrency alone is not a host
   lock and does not serialize the system tmp cleaner. Pin the literal
   root-owned sticky parent and protected marker cache with no-follow
   descriptors. Require exact marker bytes/metadata, exact root identities,
   and two complete matching inventories against the approved manifests.
   An operator maintenance window must exclude manual or other same-UID
   writers; workflow locking and snapshots do not supply this assumption.
   POSIX stat followed by unlink/rmdir is not inode-conditional: a
   replacement race remains if exclusive maintenance is not enforceable.
   Refuse apply when exclusivity cannot be established; do not describe
   descriptor-relative operations as race-free. Bound count, depth, path
   bytes, journal size, open descriptors and elapsed time.
   Refuse any added/removed/replaced object before side effects.
4. Delete only the **six exact symlink entries** through descriptor-relative
   unlink after no-follow metadata revalidation. Never resolve, read, open
   or traverse their destinations. Remove only the **1362 catalogued
   directories**, deepest first, through pinned directory descriptors and
   identity checks. Require empty-directory rmdir; refuse regular files,
   special files, hard links, cross-device entries and unlisted descendants.
   No `rm -rf`, `shutil.rmtree`, sudo, signals, chown, chmod or quarantine
   rename. Do not turn a changed basename into a new deletion candidate.
5. Metadata of ancestors naturally changes during removal; retain an
   explicit expected-operation ledger rather than blindly comparing their
   original size/timestamps/nlink after our own operations. Preserve the
   unchanged identity of every not-yet-removed node and parent-child edge.
   An error stops mutation and retains the marker. The journal distinguishes
   confirmed removals from unconfirmed intentions; a crash or sync failure
   can leave an explicitly unknown result. Do not infer completion or a safe
   retry from a missing confirmation. Deletion has no rollback. Never automatically
   resume against stale inventories; obtain a fresh reviewed disposition.
6. After every exact root is absent and fresh inspection finds **no** blocking
   E2E roots, invoke the existing marker-only recovery with the exact target
   and PID38013. Its dead-PID, no-QEMU, marker identity and repeat-inspection
   guards must all pass. Approval here covers this separate dispatch only
   after directory disposition and contemporaneous prerequisites succeed.
7. Run native no-network Level-3 against the reviewed exact main revision.
   Require product assertions, guest destruction, marker absence and host
   staging cleanup. Report hosted and native results separately. A new
   failure starts a fresh root-cause investigation.

The separate disposition tool/workflow and disposable fixture regressions
are now being verified. Approval is not evidence that technical gates passed.
See [the implementation checklist](2026-10-13-approved-residual-disposition-implementation.md).

## Follow-on defect prevention

A separate reviewed change must align future orchestration, recovery and
forensic temp-root selection. Current runtime Python temp selection and
native getconf selection differ under UID502. A protected owner-specific
staging root outside the system cleaner's namespace is a candidate, but
must preserve no-follow ancestry, identity, no-host-sharing and historical
root blocking. Moving roots must never hide these historical residuals
or bypass the marker. Do not mix that architectural change into disposal.

If the operator needs historical reconstruction before discarding the
residuals, keep the current provider blocked. A fresh separately provisioned
non-admin provider is an alternative after its own isolation review; it
does not certify or clear the old incident.

## Verification in this investigation

The isolated plan worktree uses current main. Focused recovery/observer/
inventory tests passed (94 cases) using `PYTHONPATH=src` and the existing
developer virtual environment. The first attempt without PYTHONPATH failed
at import before collection; no product failure was inferred from it.
No duplicate full local suite or live guest was launched.

No provider directory, link or marker was mutated. No process was signalled
and no account/permission/system cleaner configuration changed.

## Independent review

A separate reviewer checked all five private manifests, the actual system
cleaner script/schedule, and the applicable ADRs without mutation or tests.
Their blockers are incorporated above: separate incident ADR rather than
ADR0011 reuse, explicit maintenance/exclusivity assumptions and POSIX
replacement-race limits, durable intention/confirmation journal with failure
tests, and separate guarded marker recovery. This is evidence/plan review,
not approval of a future implementation or historical provenance.
