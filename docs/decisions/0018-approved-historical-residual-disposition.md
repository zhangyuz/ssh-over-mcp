# ADR 0018: Approved disposal of three exact historical residual inventories

- Status: implemented; exact incident disposed and native E2E/cleanup verified on main 53868a7
- Date: 2026-10-13 (America/Toronto)
- Approval: after reviewing the exact decision in PR #240, the operator replied
  at 12:18:16 EDT: “Sounds good, let’s just fix it”.

## Authority and scope

This approval covers the three named roots, full matching inventories, separate
guarded marker recovery and a native E2E retry described in
[the operator decision](../plans/2026-10-13-native-provider-recovery-decision.md).
It accepts disposal despite incomplete historical provenance. It does not
reconstruct the old commit binding or declare the old run successful.

This is a separate incident contract. ADR0011 excludes root #2 and requires
the original staging layout/depth12; neither that contract, its strict
inventory, nor its dormant apply mechanism changes. Read-only observers
continue to report recovery_eligible=false. Their results alone grant no
mutation authority.

The new script has no caller-selected paths or catalogs. It accepts only no
arguments (inspection) or --apply. It must run as the dedicated non-admin UID 502
Intel macOS account, workflow_dispatch from exact trusted main under the fixed
workflow identity. Main must already contain the independently reviewed tool.
There is no PR-triggered disposal and no host target checkout.

The fixed /private/tmp root tuples and canonical full-inventory SHA256 pins are:

| Basename | Device | Inode | Entries | Inventory SHA256 |
| --- | ---: | ---: | ---: | --- |
| ssh-over-mcp-e2e-i8ow1ni6 | 16777220 | 187176421 | 18 | baf242d5bd2e9dc363bb1e0cbbc38d8f205b1b632afba952c02b695dc5283153 |
| ssh-over-mcp-e2e-recover.cc8Del | 16777220 | 186815322 | 1332 | b331202dbc23cec8341b3f7946df680e730446238968775f7ea84d8007f2a9d1 |
| ssh-over-mcp-e2e-w_kn4rus | 16777220 | 186877220 | 18 | 008891ec4dfc438809dadac6b64d826498dfac5d39a8c06947382d5272e7d4a8 |

Every root is UID 502 mode0700. Digests cover canonical ensure_ascii JSON,
sorted keys, compact separators, ordered entries from the approved private
observations. Hash equality binds exact metadata; approval comes from the
operator and reviewed trusted-main authority, not from hashes.

Marker metadata and bytes must match the fixed observed target 47531dad,
ownerPID 38013, device16777220/inode187176420/UID 502/mode0600/size75 and both
nanosecond timestamps1791315629879589515, gid20, nlink1. The existing protected
cache/marker no-follow helpers and root-owned sticky /private/tmp pin are reused.

## Read-only preparation and bounded apply

All three roots must have two complete matching metadata snapshots whose
counts/digests equal the approved inventories before any journal creation.
Regular files, unlisted entries, mismatched nodes and changed marker refuse.
Symlink targets and regular payloads are never read.

The script uses existing bounded process snapshots and fixed owner-presence
checks before inventories, after them, before each root and after removal.
Owner PID reuse/presence or active QEMU/orchestration refuses. Before every
operation, recheck pinned parent/cache identity, marker bytes/metadata,
owner absence and the 420-second total deadline.

The operation requires an operator-exclusive maintenance window for UID 502.
Normal native runs remain blocked by the retained marker; shared workflow
concurrency serializes trusted jobs, but is not a host-wide lock. The script
refuses local hours23/0 and requires the registered system tmp_cleaner to be
not running, avoiding its midnight window. These observations cannot exclude
a malicious/manual same-UID writer. POSIX stat-then-unlink/rmdir is not
inode-conditional; a replacement race remains outside the maintenance
assumption. No claim of race-free deletion is made.

The separate observer retains depth64/path4096/4096-entry/60-second bounds per
pass. Approved actual depth is13, total1368 nodes. Apply holds three root
descriptors and only one ancestor chain per operation, not all1362 directory
descriptors. The private journal is bounded to2MiB, records to16KiB. The outer
workflow timeout is10 minutes.

Remove six exact symlinks first, then directories deepest first within each
root. Use FD-relative unlink for symlink leaves and empty rmdir for directories,
with no-follow stat/open and identity rechecks. After intention fsync and
process/marker checks, revalidate the live root basename and every held
ancestor edge again before the leaf syscall. Inspect-only and pre-journal
phases also recheck all three live root edges. Validate the current direct
children against the remaining catalog, including metadata. No arbitrary
recursive deletion, target traversal, permission repair, sudo, process signal
or quarantine rename occurs.

Own deletion changes immediate-parent size/timestamps/nlink. An explicit
remaining-operation ledger updates only that parent's expected metadata after
the observed removal; stable identity/mode/owner/group and expected nlink
change remain mandatory. On this Mac, APFS directory nlink counts all children,
so removing any child decrements nlink by1. Linux disposable CI fixtures use
the Linux subdirectory-only nlink rule. This platform distinction was
reproduced on a disposable Mac directory before GREEN; it does not relax
identity/mode/owner or child-set checks. Recheck remaining direct children
after each removal.
Any foreign drift stops further mutation.

## Durable journal and uncertainty

Before mutation, exclusively create fixed
incident-disposition-20261013.jsonl under the pinned protected cache, mode0600,
no-follow, single-link, runner-owned. Write/fsync the initial authority/approval/
digest/marker record, then fsync the cache directory. An existing journal
always blocks replay; no automatic resumption or log replacement is available.
The journal FD and fixed basename are revalidated before/after every append
and at each operation check; replacement, external metadata/size drift or
a detached journal refuses before the next side effect.

For every operation, write/fsync intention with private path/metadata before
side effects. After unlink/rmdir, fsync its parent, verify the name absent and
record/fsync confirmation. Failed writes/syncs/closes halt the operation.
A crash can leave an unconfirmed intention whose outcome is unknown.
These fsync barriers cover process interruption while the kernel and storage
remain functioning. They do not promise OS-crash/power-loss ordering;
[Apple fsync documentation](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html)
describes drive-cache reordering and stronger F_FULLFSYNC semantics.
A failed run may leave a syntactically complete confirmation buffered even
if its fsync failed; journal text alone never certifies durability. Require
successful workflow completion plus fresh state verification. After any
uncertain failure, maintain unknown outcome and refuse replay.
Confirmed removal has no rollback. Retain marker and journal; a new
disposition requires freshly reviewed residual state, not blind retry.

The workflow retains the protected private journal on apply failure as well
as success. Its original cache copy survives artifact expiration. Logs contain
only fixed phase labels and counts; exception text and private paths are not
printed. A missing artifact is not proof of no side effects.

## Integration and acceptance

The cleanup tool never unlinks the provider marker. After all roots are absent,
run existing exact-PID marker-only recovery, which still requires dead owner,
no QEMU and no blocking temp roots. Then exact-main native Level3 must prove
product assertions, guest destruction, marker absence and host cleanup.

Ruling: this authority cannot certify itself through the blocked guest gate.
Require full hosted Python3.13/3.14 exact-head CI, fresh independent source/
security/doc review and disposable Mac operation/sync-failure evidence before
merge. Only merged authority may inspect/apply; native acceptance follows
disposition and remains open until the real guest passes. This does not weaken
product security gates or confer native success from hosted tests.

Future temp-root alignment stays separate. Do not hide historical roots by
moving staging or disabling the OS cleaner.

## Recorded metadata consistency correction

Exact-head Linux stress exposed the shared special-metadata collector
rejecting directory reads that changed only access time. A controlled
strictatime filesystem reproduced the same guard with stable mtime/ctime and
identity. The collector now compares its existing published _record fields
at directory-open, child-edge and final-directory stability checks. This
keeps kind/device/inode/UID/GID/mode/nlink/size and exact nanosecond mtime/ctime
pinned, excludes unrecorded read-induced atime, and catches nanosecond drift
that raw stat_result tuple equality can miss. No schema, canonical digests,
path/depth/budget, owner/mode checks, strict staging collector or observer
non-authority changes. The Linux O_NOATIME fixture workaround is removed;
real strictatime stress must pass with the production comparison. Two RED
tests prove atime-only acceptance and one-nanosecond ctime rejection.

## Exact incident acceptance

[Acceptance evidence](../evidence/2026-10-13-native-provider-recovery-acceptance.md)
records PR #240 hosted exact-head PASS, trusted-main inspection and approved
disposition PASS, separate guarded marker recovery PASS, and exact-main
CI 38437463320 attempt 2/native cleanup PASS on 53868a7. The private complete
journal confirms all 1368 approved operations. This one-incident authority
is exhausted and refuses replay; do not reuse it for a future orphan.
Historical unknown provenance was accepted for disposal, not reconstructed.
Future temp-root alignment and A1/B8/N1c remain separate.
