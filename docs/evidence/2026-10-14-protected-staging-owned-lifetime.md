# ADR 0019 Slice 2A — Dormant workspace primitives evidence

**Status:** First scoped implementation candidate for independent review, NOT production activation. Based on the now-merged [PR #248 plan](../superpowers/plans/2026-10-14-adr19-owned-protected-workspace-lifetime.md).

## Implemented boundary

The public `create_owned_workspace()` always refuses with `NamespaceError('unbound')`. The public live `OwnedWorkspace.dispose(receipt)` also refuses, including truthy Boolean input. No production claim or QEMU completion issuer exists.

A **private disposable-fixture-only** adapter tests `O_CREAT|O_EXCL` claim creation (at a different test-only marker), fixed three-literal descendants, fresh 32-hex run directory, original held FD/device/inode/mode, `0700` and APFS ACL checks, exactly-one-owned-child scan, bounded no-follow descriptor-relative cleanup, failed unlink retention and close-only finalization. It is **not** integrated with the production `_PinnedNamespaces` authenticated selector/QEMU/two-pass protected/legacy scan. The production orchestrator, live marker, protected staging root, recovery and CI workflows are untouched.

TDD evidence: missing module, fixture claim, fixture deletion and close-failure uncertainty tests each failed before fixes. Two final hardening tests reproduced a leaked FD on post-claim fsync failure and missing staging ACL revalidation; both passed after fixes. Older protected namespace baseline: **288 passed**. New + existing focused suite before formatting-only change: **312 passed, 1 skipped in 16.05s** (original feature HEAD; revised review-fix regression below). Reverify before treating latest code as green.

## Real-host limitations

Yuz.local command account is UID **501**. Dedicated `gha-e2e-orchestrator` is UID **502**, but passwordless `sudo -n -u gha-e2e-orchestrator` is denied. Disposable Darwin/APFS native smoke executes as UID501; the UID502-specific test is **SKIPPED**, not proof of real protected UID502 operations. Do not treat historical legacy Level-3 E2E as protected placement acceptance.

## Remaining separate gates

1. **Incomplete 2A integration:** the private fixture adapter is not bound to the current trusted protected/legacy namespace and QEMU admission scanner. This must be independently reviewed before claiming a complete 2A lifetime component.
2. **Slice 2B:** trusted-original `O_EXCL` provider marker claim handoff, not same-PID JSON re-read; a one-shot run-bound real QEMU wait/reap receipt, not a Boolean or never-started fixture token.
3. **Slice 3:** production protected root placement, recovery and actual UID502 guest/cleanup evidence.
4. POSIX check-then-unlink is not atomic against a malicious concurrent same-UID writer. Fixture creation and cleanup assume a disposable single-writer test root.
5. Exact-head full CI, independent project-wide security review and real native acceptance are required before merge. Independent review is requested **as soon as code self-review completes**, not after CI.

No production filesystem activation, marker deletion, broad cleanup, statuses writing or PR-native dispatch is authorized by this change.


## Independent reviewer findings and corrective TDD (PR #249)

The [independent project-wide review](https://github.com/zhangyuz/ssh-over-mcp/pull/249#issuecomment-6174210019) found **3 Important and 1 Minor** issues in the fixture-backed primitives; none were reachable through the permanently unbound production entrypoint. The review changes below are **only to the disposable fixture** and still do not authorize protected staging.

- Original exclusive fixture marker **FD identity, inode, owner, mode and directory entry**, and the complete held original Library → Application Support → provider base → staging edge/ACL/mtime/ctime chain, are now rechecked **before first unlink and while verifying the sole owned child**. Separate negative tests remove/recreate the marker or rename/replace an ancestor and prove no cleanup happens.
- FD ownership is recorded as soon as each no-follow child FD opens. All child/root/claim FD ownership is explicitly transferred only after final successful validation, otherwise deterministically closed exactly once. Tests inject ACL failure immediately after child FD open and post-construction drift; no leaked FD remains. An injected uncertain marker FD close also closes every other held descriptor, with no retry.
- All previously unbounded `os.listdir(fd)` and `list(scandir)` paths now use streaming, capped enumeration. An adversarial directory containing 140 test files proves enumeration stops at entry **129** for a per-level cap of 128, returns a refusal and leaves all foreign entries unchanged.
- The real macOS smoke now explicitly invokes the existing Darwin64 `fstatfs$INODE64` ABI and verifies `fstypename=apfs`, matching the held root and parent device. Observed fixture device **16777220**, mount **/System/Volumes/Data**, in the current UID501 shell. **UID502 remains SKIPPED**; no denial/allow-ACL or production placement UID502 matrix has run.

Final revised feature HEAD regression and GitHub-hosted CI should be referenced only after the actual new revision is tested. POSIX same-UID interleaving remains a documented non-atomic limit, and original real-run claim/reap issuance remains **future Slice 2B**.
