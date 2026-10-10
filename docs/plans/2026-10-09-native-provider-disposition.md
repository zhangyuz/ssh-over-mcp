# Native Level-3 provider disposition: evidence and safety gates

**Status (2026-10-09 local / 2026-10-10 UTC): BLOCKED — No cleanup authorized.**
This is an operator evidence plan, not authorization to delete provider state,
temp directories, or processes. Native Level-3 remains FAIL-CLOSED.

## Source-backed evidence

- [Trusted-main CI 38015831978](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38015831978), main `9e5b94d7`: Python 3.13 and 3.14 complete suites PASS; native Level-3 FAIL on stale provider state (exit 70). PR-only E2E SKIPPED is not native acceptance.
- [Trusted-main recovery inspection 38017034795](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38017034795): `RECOVERY_MODE=inspect-only` SUCCESS; fixed marker target `47531dadb58d365f74089dd5f52ce1b61bb0fdd1`, owner PID `38013`; **3 E2E temp directories** remain, owned by UID 502.

| Directory | Read-only observation | Current decision |
| --- | --- | --- |
| `ssh-over-mcp-e2e-i8ow1ni6` | Source `expected_commit` matches target; overlay, media and checkout artifacts present | Unresolved; do not remove |
| `ssh-over-mcp-e2e-recover.cc8Del` | No `expected_commit`; recovery staging `clean` directory remains | Unbound; do not remove |
| `ssh-over-mcp-e2e-w_kn4rus` | No `expected_commit` in latest inspection; partial directory tree remains | Unbound; do not remove |

A successful inspect-only job proves bounded metadata was readable; it
**does not establish whether the owner PID or QEMU is still alive**,
which artifacts are disposable, or whether prior interrupted work had effects.
Missing source metadata does not authorize disposal. This is not a live
process-inventory attestation or cleanup authority.

## Operator-reviewed disposition sequence — no destructive action authorized

1. Preserve marker target, owner PID, device/inode, mode, UID, and all three directory identities. Obtain a fresh inspect-only snapshot on trusted `main`; compare before making any decision. Changed metadata, symlinks, unexpected owners or inaccessible paths mean stop. Do not copy or disclose payload secrets.
2. Independently verify the exact owner PID is dead and no runner-owned QEMU or active orchestration/recovery remains. Inspect-only does not perform that proof. PID reuse, incomplete inventory or ambiguity means stop.
3. Independently classify the target-bound directory and **both unbound directories** using provenance, ownership, bounded contents and live dependencies. Prefix, age, missing `expected_commit`, and historical target matching alone do not justify deletion.
4. Obtain **explicit operator authorization** for any later separately reviewed, exact-identity directory disposition. No recursive arbitrary-path cleanup, symlink traversal, privilege escalation, process signals or automatic marker clearing is approved by this document or by CI. **Do not remove** the three directories or marker based on this plan.
5. The existing `Live Local E2E Provider Recovery` workflow uses owner PID `0` for inspection only. A separate exact nonzero PID recovery dispatch requires unchanged marker identity, dead owner, no QEMU and **no E2E temp directories remain**. It unlinks only the fixed marker; any failed precondition must stop without change. This document does not authorize that dispatch.
6. Only after separately approved disposition and fresh verification, run trusted-main no-network Level-3 with independently reviewed product assertions and complete cleanup evidence. Recovery success alone is not native acceptance.

## Open work and boundaries

A1 authority binding, B8 provenance/receipt, N1c native input authentication,
UID-502 dedicated read-only preflight, and native N1/Task 3 remain OPEN.
Even a successful provider disposition does not close them. No runtime,
workflow, marker, host, or privileged account is changed by this plan.

Implementation contracts: [`ops/live-e2e/README.md`](../../ops/live-e2e/README.md),
[`recover_provider.py`](../../ops/live-e2e/recover_provider.py), and the
[trusted-main recovery workflow](../../.github/workflows/live-local-e2e-recovery.yml).
