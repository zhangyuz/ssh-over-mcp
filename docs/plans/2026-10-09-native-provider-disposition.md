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


## 2026-10-12 trusted-main reinspection — **still blocked; evidence changed**

This update is read-only evidence for an **explicit subsequent operator decision**,
not approval to delete, archive or otherwise change any provider artifact.

- [Trusted-main CI 38304470006](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38304470006)
  on exact main `2a00db8165e5a96ec70f779a3e8925938e1dc462`:
  GitHub-hosted Python 3.13 and 3.14 both PASS; the native no-network
  Level-3 stage **FAIL-CLOSED** before QEMU launch on `stale E2E provider
  state detected` (exit 70). Its postcondition also fails because
  `active-run.json` is still present. This is a pre-existing host-state
  blocker, not evidence that native Level-3 passed.
- [Trusted-main inspect-only workflow 38308355924](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38308355924)
  ran `workflow_dispatch` on trusted main with **exact stale target**
  `47531dadb58d365f74089dd5f52ce1b61bb0fdd1`, owner PID
  **`38013`**, and `expected_owner_pid=0` (inspect only).
  `RECOVERY_MODE=inspect-only` succeeded with **three UID-502 directories**
  still present:
  - `ssh-over-mcp-e2e-i8ow1ni6` (device 16777220, inode 187176421):
    `bootstrap-wheels`, `payload-content`, `payload-iso`, `seed`,
    `target.git`, `wheels`. **`expected_commit=null`**.
  - `ssh-over-mcp-e2e-recover.cc8Del` (device 16777220, inode 186815322):
    only a `clean` directory reported. **`expected_commit=null`**.
  - `ssh-over-mcp-e2e-w_kn4rus` (device 16777220, inode 186877220):
    analogous wheel/payload/seed/checkout directories.
    **`expected_commit=null`**.
- The previous 2026-10-10 inspection recorded a valid target-bound
  `expected_commit` in the first directory; **that value is no longer observed by the same bounded inspector, a
  material change in the observations**. It does not authorize reassigning the
  tree, assuming it is disposable, or reconstructing a trusted binding
  from its name or age. Stop any cleanup pending independent provenance
  review.
- A read-only host-wide `ps` scan from the separate developer account
  did not show a running `qemu-system-x86_64` or E2E orchestrator child,
  but this **does not establish quiescence** of UID 502 and does not rule
  out PID reuse. The UID-502 marker is `0600` and cannot be read from
  the developer account; do not attempt privilege escalation, change
  permissions, or access provider payload contents to get around it.
- The existing recovery workflow refuses marker unlink while **any**
  E2E temp directory remains. Current conditions do not permit recovery.
  **No marker or directory was deleted, no process signalled, no sudo,
  no new guest launched, and no recovery with nonzero PID authorized.**

### Independent disposition gates required before any later action

1. Reinspect exact marker and three device/inode identities under the
   trusted non-admin UID-502 account, with bounded metadata only.
2. Establish contemporaneous PID identity/death and absence of QEMU or
   active runner-owned orchestrator, without relying only on historical
   PID or a different user's process view.
3. Obtain immutable provenance/ownership for each of the **three**
   directories. Investigate why the first directory's prior
   `expected_commit` value is no longer observed by the same bounded
   inspector, and bound the two unbound trees. Do not infer the cause or
   nested-file identity continuity from root inode equality.
   Unknown or changed contents mean **refuse disposition**.
4. Produce a separately reviewed, *per exact path/identity* action plan
   with failure/rollback behavior and obtain **explicit human operator
   authorization** for every destructive step. The existing recovery
   workflow cannot perform directory cleanup and must not be extended
   implicitly.
5. Only after safely resolving **all** orphan state, run fresh
   trusted-main inspect, invoke marker-only recovery with exact owner
   PID if its guards allow it, then run exact-main native no-network
   Level-3 and verify provider-state absence and host/guest cleanup.
   Until then native Level-3 is **BLOCKED / FAIL-CLOSED**, regardless of
   GitHub-hosted CI performance.

The hosted six-way CI later merged to main in PR #220 is orthogonal: it
has verified fast dual-Python test coverage, but neither asserts nor
repairs host-level native E2E provenance.


## 2026-10-12 23:17 UTC current-main inspection and dormant acceptance

Fresh trusted-main [inspect-only run 38321349471](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38321349471)
on exact main `39a4f868bb77b0391dbeeee5fb56d3cdb4ae3128` completed
successfully with owner PID input **0** and `RECOVERY_MODE=inspect-only`.
It reports the same marker target/owner and the same three device/inode
identities as run 38308355924. All three again report
`expected_commit=null`; the bounded direct-child inventories are unchanged
between these two October 12 observations. This establishes no owner-death,
QEMU-quiescence, provenance, accepted receipt or disposition permission.

Independent source review confirms that both the October 10 authority
`9e5b94d7` and the October 12 authority inspect the same fixed relative
`payload-content/expected_commit` path. The first directory's prior valid
value is no longer observed; regular direct-child artifacts previously
reported (`git-askpass`, `overlay.qcow2`, `payload.iso`, `seed.iso`,
`target.bundle`) also no longer appear. The reason and nested-file identity
continuity are unknown. Do not reconstruct a binding or relax the fixed
catalog to accept the current partial trees.

The composition plan's old A1 acceptance note needs to be read alongside
later component evidence: PR #161 already added
`test_real_pinned_authority_byte_tamper_blocks_getconf_before_capture`,
parameterized over all three pinned authority documents. Its disposable
fixtures verify authentic copies, change one byte without changing length,
call the production dormant getconf adapter and prove zero capture calls.
Current-main verification of the full fixed-getconf test module plus
`test_binding_matches_exact_main_blobs` passed **41 checks** on the developer
account. No existing incident staging or actual UID-502 capture was invoked.

This is narrow authority-byte-before-capture evidence only. **Incident
recovery A1, B8 trusted-main workflow/receipts, actual UID-502 compatibility,
changed-state provenance, per-directory human disposition and native
Level-3/cleanup remain OPEN.** The next live-observation workflow needs its
separate reviewed integration contract; fixture success cannot activate it.
No pinned authority document, recovery code, workflow or provider resource
was changed by this update.

## 2026-10-13 Mac temp-root divergence investigation

Trusted-main forensic run [38338824514](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38338824514)
refused with `catalog-open-1-missing` when using the strictly pinned native
getconf temp root. Minutes later, trusted-main inspect-only
[38338908394](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38338908394)
reported **all three** catalog identities still present under Python's
`tempfile.gettempdir()`, unchanged device/inode and missing expected_commit.
The observations do not prove a race or deletion. The developer UID-501
Mac shell reproduces a discrepancy between `getconf DARWIN_USER_TEMP_DIR`
and `tempfile.gettempdir()` when `TMPDIR` is unset. UID-502 runner
environment comparison is still needed before attributing the incident
to two temp roots.

The recovery inspector now reports a fixed non-authorizing
`RECOVERY_TEMP_PARENT_RELATION` (`same`, `different`, `unavailable`)
only for owner PID input zero, after the existing inspection. This does
not normalize paths, relocate state, change temp creation, treat missing
roots as valid forensic evidence, or grant marker/directory cleanup.
No provider mutation should occur until independent UID-502 observations,
per-identity reconciliation, and explicit operator authorization.


## 2026-10-13 trusted-main UID-502 root divergence confirmed

[Main inspection 38341134143](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38341134143)
used the already-merged PR #229 read-only probe under the dedicated non-admin
UID-502 runner at exact main
`2df644a34dd5eb83ed056898799d74b894c03dc0`. It returned:

```text
RECOVERY_TEMP_PARENT_RELATION=different
RECOVERY_INSPECT ... owner_pid=38013 temp_dirs=3
RECOVERY_MODE=inspect-only
```

The fixed native `getconf DARWIN_USER_TEMP_DIR` parent and the Python
`tempfile.gettempdir()` parent therefore **differ under the actual runner**,
not just on the separate developer account. Python's recovery inspector
still reported all three catalog roots with unchanged recorded device/inode,
mode 0700, UID 502 and `expected_commit=null`. Native forensic
[38338824514](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38338824514)
returned `catalog-open-1-missing` from the *other* parent. This explains
why those two inspections disagreed; it **does not** establish whether the
historical removed regular files were deleted, transferred or changed,
whether all nested content is harmless, or why the older provider run was
interrupted. Neither report is a manifest, disposition receipt or
authorization to clear state.

### Reviewed next steps (NOT cleanup authorization)

1. Align **future** orchestrator temporary root selection and native
   preflight to one explicitly validated source: current orchestrator
   `tempfile.TemporaryDirectory(prefix="ssh-over-mcp-e2e-")` uses Python's
   selected temp parent, while the pinned forensic authority derives its
   root exclusively from `getconf`. Design and test a single-parent contract
   before changing production creation, runner environment or diagnostic
   trust. Do not solve this by loosening no-follow ancestry checks.
2. Design a separate fixed-identity, read-only residual inventory of the
   actual Python-selected parent, with its own trusted ancestry,
   symlink/owner/device/mode checks and a bounded private artifact.
   Do not silently redirect ADR 0014's approved getconf-catalog to a
   caller-chosen path, and do not treat earlier root equality as continuity
   of nested contents. Obtain design/authority review before activation.
3. Establish fresh owner PID 38013 death and no runner-owned QEMU or
   active orchestration under the right account. Then independently classify
   and review **each of the three** exact surviving root identities, including
   the unbound recovery directory, before proposing per-identity disposition.
4. Obtain **separate explicit operator approval** for any identity-bound
   destructive operation. Existing recovery is marker-only and refuses as
   long as any E2E temp root remains. Do not use sudo, broad deletion,
   privilege/permission repair, process signals, or bypass flags.
5. After authorized and verified disposition, run the existing exact-PID
   marker-only recovery **only if all preconditions pass**, followed by
   exact-main no-network Level-3 with complete host/guest cleanup evidence.
   Hosted Python PASS and forensic success alone are not acceptance.

**State:** host/provider recovery remains BLOCKED / FAIL-CLOSED. No
provider marker, QEMU, residual tree, or privileged account was modified
by the UID-502 comparison.
