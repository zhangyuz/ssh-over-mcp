# Approved historical residual disposition implementation plan

> Execute inline with superpowers:executing-plans; fresh independent review before merge.

**Goal:** Dispose only the approved exact incident, preserve a durable journal and
marker, then restore native E2E through the existing guarded recovery.

**Architecture:** Reuse strict no-follow parent/cache/process helpers and the
separate metadata observer. Bind all three full inventories to fixed approved
digests. A private durable intent/confirmation log precedes each bounded FD
operation. Keep marker recovery separate.

**Spec:** 2026-10-13-native-provider-recovery-decision.md and ADR0018.

## Constraints and review focus

- Fixed UID502, root tuples, full inventory hashes and marker only; no path input.
- Inspection default; apply only on exact trusted main/manual workflow.
- Refuse changed entries, regular files, owner/PID/marker drift and uncertain I/O.
- Test symlink destinations remain untouched, late swaps refuse, journal/sync
  failures preserve uncertainty, and existing journals prohibit replay.
- POSIX removal relies on approved exclusive maintenance; no atomicity claim.
- 420s, 4096 entries/pass, depth64, path4096, journal2MiB, bounded descriptors.

## Task 1: Guarded incident tool and workflow

Files: ops/live-e2e/dispose_historical_residuals.py,
.github/workflows/live-local-e2e-dispose-historical.yml,
tests/ops/test_dispose_historical_residuals.py, ADR0018 and linked operator docs.

- [x] Write failing fixture and workflow tests; missing implementation/workflow RED.
- [x] Implement Journal(cache_fd, header), _remove_root(FDs, entries, journal,
  check, deadline), fixed context and inspect/apply composition.
- [x] All131 focused tests GREEN on disposable Mac fixtures; Ruff/compile/diff PASS.
  Incident-sized1332-entry depth13 stress fixture passed in21s with bounded journal.
- [x] Fresh independent complete code/security/doc review; Important findings
  fixed via failing root/ancestor/inspection regressions and real I/O/crash tests.
  Journal-name replacement was additionally reproduced RED and fixed GREEN.
- [ ] Update existing PR240 around final implemented scope; exact-head full hosted CI.
- [ ] Merge reviewed authority; trusted-main inspect-only must match all pins.
- [ ] Apply approved disposition once; verify journal, exact absence and marker retained.
- [ ] Existing exact-PID marker recovery; exact-main native E2E + host/guest cleanup.
- [ ] Record exact evidence and preserve older dirty worktrees.
