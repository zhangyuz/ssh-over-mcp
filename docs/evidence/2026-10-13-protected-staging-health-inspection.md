# Protected staging health inspection — slice evidence

Status: implemented dormant; pre-merge external gates and final review remain required.
Date: 2026-10-14 UTC.
Plan: [approved first plan](../superpowers/plans/2026-10-13-protected-staging-health-inspection.md).
Spec: [approved design](../superpowers/specs/2026-10-13-protected-native-e2e-staging-design.md).

## Delivered boundary

The internal zero-argument inspect_namespace() validates fixed trusted-main
provider context, freezes bounded lexical selectors, completes fixed owned
getconf discovery, pins protected and both declared legacy chains, acquires
FD-bound Darwin/APFS ACL snapshots and requires two bounded clean metadata
observations plus strict edge/ACL/context/selector checks. It returns detached
evidence only after settled owned-resource close and final edge checks.

This is not protected-placement acceptance. No production caller, workflow,
CLI, workspace creation/removal, marker/QEMU judgement, receipt/schema change,
permission repair or historical disposer authority is added. Existing runtime
placement remains legacy. Later callers must independently validate exact
trusted-main checkout and marker/process state at each lifecycle boundary.
Owned lifetime and already-main activation remain separately reviewed plans.

## Actual pre-merge evidence

Baseline main14b989f6de7b0564e78b2e189c289969c2b3c902 came from PR242;
exact-main CI38499323414 and actual native job115643397267 passed with
marker absence and checkout cleanup. This baseline gate certifies legacy
placement only. Fresh relevant baseline127 tests passed before implementation.

Task1: missing-interface RED75FAIL, GREEN75PASS, ruff and independent review
PASS, commit55c9d363f6ba9cf81edc23e80e6f1176dde95d04.
Task2: missing-interface RED162FAIL with26 previous tests PASS; fixture error
distinguished and corrected. Meaningful review found three Important
ownership/no-follow/uncertainty issues, all reproduced before fixing:
six review regressions, one cleanup-allocation regression and two analogous
interrupted-open regressions. Fresh253PASS including selectors, independent
fix review PASS, commit3bb0adb53db42bc7446d4a94a9003f6d1c2080fc.
Task2 completion command independently ran204PASS in14.05s.

Task3: missing-interface RED54FAIL with264 contracts/previous tests PASS.
Initial feature GREEN318PASS in15.90s; six additional integration checks cover
ACL/cache/ancestor/missing-suffix drift, detached absence-only evidence and
last-close replacement. New plus required existing regressions447PASS
in17.43s; full src/tests/operator-tool ruff and compileall PASS.
Documentation regression independently observed missing-evidence RED.
Full suite, exact PR-head hosted/legacy E2E, final independent review and
merge-main gates are recorded subsequently in ignored progress/private
handoff, never inferred from these pre-merge results.

These are actual developer-platform/portable fixtures, not UID502 provider
admission or new-placement acceptance. UID/group/workflow adversaries use
private fixture adapters. No candidate helper ran as UID502 on the persistent
provider. No provider directory, account, permission or marker was modified.

## Real Mac ACL acceptance

Actual non-root Intel macOS15.8.1 (24H32), supported Python3.13, APFS:
all five actual disposable ACL cases passed: no ACL, explicit empty ACL,
everyone deny delete, everyone allow write, and inheritable allow.
The reader binds original directory FDs, distinguishes returned NULL/ENOENT,
preserves ACE order/exported bytes, observes ACL changes while FD-held and
continues identifying renamed original directories rather than replacements.
Deny delete really blocked rename; the fixture explicitly asserted denial,
then removed/reapplied only its own ACL and removed it in finally. The exact
failed empty fixture was also cleaned. These operations affected only freshly
created pytest-owned developer trees, with no sudo or provider repair.

The native adapter lazily loads fixed /usr/lib/libSystem.B.dylib, declares
all ctypes signatures and requires the Darwin64 fstatfs$INODE64 APFS ABI
(size2168, filesystem-name offset72). ACL export is capped at16384 bytes,
128 ACEs; fixed magic/count/size/kind checks correlate serialized data with
Darwin FIRST0/NEXT-1 iteration and exact end -1/EINVAL. Unknown symbols,
metadata, tags, results, free failure or uncaptured acquisition refuse.
Ancestors accept only empty/deny-only ACLs; provider-base/staging-v1 require
zero ACEs. Shared sticky /private/tmp has inspection-only ACL/mode policy.

Primary source checks: Apple Libc71bbe350ab79eef58113991d817ccc6165061a64,
acl_translate.c blob57cb01f1b1fa410b0ce0207f083c3551a829dc88;
[XNU mount.h](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/mount.h)
blob30b3ec78119098197cf0f6b25266fb71e077e854 and
[kauth.h](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/kauth.h)
blobedacab116517febf14edb87e2c7bb776efec447a.

## Resource, drift and availability decisions

Every directory edge retains full mode, owner/group, device/inode,
mtime_ns/ctime_ns and exact ACL evidence; atime alone is excluded.
Foreign unrelated shared-parent churn refuses as drift, including observed
create/remove transients. No quiet-period retry or timestamp exception exists.
Any protected entry and any dedicated-owner legacy prefix object blocks
without payload read; foreign shared-parent matches remain untouched.
Bounds cover4096 legacy entries per parent,64 aggregate prefix matches,
16 owned matches,64 protected entries and one10-second metadata budget.
Early residual refusal avoids enumerating an unnecessary inventory.

Ruling: fixed Darwin64 APFS guard and serialized-count/tag correlation narrow
NULL/ENOENT acceptance to supported observed evidence. Cost if wrong:
conservative refusal on a supported Mac; real fixtures mitigate that cost.

Ruling: private root/stat/owner fixture adapters follow existing reviewed
preflight practice so non-root disposable trees can test fixed policies.
Cost if wrong: fixture evidence misses actual provider context; provider
activation/admission remains separately gated and unclaimed.

Ruling: replace joined-path post-close checks with reverse single-basename
checks through original still-held parents. Intermediate links can otherwise
be followed despite follow_symlinks=False. Cost if wrong: finite observations
still cannot certify future atomic absence; per-edge checks and no-traversal
canaries mitigate that cost.

Ruling: each observation opens fixed dot relative to its original parent,
verifies identity/ACL and closes once, obtaining an independent directory
cursor. Cost if wrong: extra read-only FD operations; the64stable foreign
prefix test requires128metadata observations across both passes.

Pre-registration FD guards, reverse allocation-free close walks and attempted
uncaptured ACL/open acquisition preserve cleanup uncertainty. Ambiguous close
or free is never retried. No deleting destructor, foreign signalling,
unbounded capture, tempfile probe or candidate-selected filesystem access is
available.

POSIX observations are finite and not atomic. Root or compromised same-account
concurrent writers remain outside these guarantees. Healthy evidence is
contemporaneous, not a persistent certificate or historical provenance.
Historical exhausted journals, incident helpers, receipts and A1/B8/N1c
remain unchanged. Next delivery is separately reviewed owned lifetime.
