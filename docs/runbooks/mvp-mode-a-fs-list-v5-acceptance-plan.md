# Mode A `fs_list` v5 — isolated acceptance plan (PROPOSED, NOT AUTHORIZED, NOT EXECUTED)

**Status: a plan for operator review. No command in this document has been run.
Nothing here authorizes touching the live pilot VM, its Compose project, its
LaunchAgent, its images, keys or data.** Execution needs a separate, explicit
operator approval that names the target, the window and the rollback condition.

Related: [ADR0026](../decisions/0026-proposed-fs-visibility-v5-first.md),
[ADR0027](../decisions/0027-proposed-fs-list-control-plane-adapter.md),
[ADR0028](../decisions/0028-mode-a-fs-list-immutable-rotation.md),
[live operations](mvp-mode-a-yuz-local-live-operations.md),
[ADR0025](../decisions/0025-mode-a-fs-only-operator-pilot-release.md).

## 1. What this proves, and what it does not

**User outcome:** an authenticated MCP client lists bounded directories on both
independent Mode A nodes, with denied subtrees hidden, and a policy change is
applied only through a verified stop → drain → rotate → verify → resume.

It does **not** prove Mode B, `fs_search`, the other FS tools, production key
custody beyond this pilot, or protection against a compromised guest. A pass
is evidence for a decision, not a release; Native Level-3 on trusted main and
the operator's deployment and merge approvals remain separate gates.

## 2. Target: a second, isolated guest — never the live pilot

The live pilot (`som-mode-a-netpilot-oct27`, tunnel `127.0.0.1:18801`) must not
be stopped, rotated, re-imaged or have files added. Acceptance runs on a
**separate** Lima VM created for this purpose with its own name, its own Compose
project name, its own loopback tunnel port and its own freshly generated
keys. If a second VM is not authorized, the acceptance does not run; there is
no "briefly use the live one" variant.

Preconditions (all must hold before any step):
1. Written operator approval naming the VM, a time window and the rollback rule.
2. The exact image digests under test are the CI-attested ones; none is built
   or pulled ad hoc.
3. The live pilot's health is recorded first with the existing read-only script
   (`ops/mvp/mode_a_host_loopback_acceptance.py`) and again at the end; any
   difference is a failure of the acceptance.
4. `progress.md` records the approvals, the SHA under test and every host action.

## 3. The capability-boundary reconciliation (must be decided first)

| Surface | `CapBnd` | Source |
|---|---|---|
| Source launcher `ops/mvp/ssh-over-mcp-fs-only-launcher.py` (`_kernel_identity`) | must be `0` (all five sets zero) | code, line 69 |
| CI-only native review variant | exactly `0x401c0`, other sets zero, `Seccomp=2` | `ops/mvp/mode_a_hosted_native_review.py` |
| Live v1 pilot (ADR0025) | `0x401c0` (SETUID, SETGID, SETPCAP, SYS_CHROOT), accepted for the pilot only | measured, ADR0025 |

Consequences:
- The v2 launcher as written would refuse to start in an image that matches the
  live pilot's capability boundary, and a CI PASS of the review variant proves
  functional compatibility only.
- **Do not edit the all-five-zero gate to make this work.** Two honest options
  exist and the operator must choose one (a new ADR records it):
  1. Run the isolated acceptance with the same operator-accepted `0x401c0`
     boundary as the live v1 pilot, using an explicitly named launcher variant
     (never a silent loosening of the generic gate), or
  2. Prove a zero-bounding-set start path in the real remapped OCI.
- Either way the measured `/proc/<sshd-session pid>/status` capability fields
  are recorded verbatim as evidence.

## 4. Steps (each: command class, expected evidence, stop condition)

Stop at the first unexpected result and fence ingress; never improvise.

1. **Create the isolated VM and Compose project** (privileged; needs approval).
   Evidence: distinct VM name, Docker `userns-remap` shown, no published ports.
2. **Provision the generation** (privileged; root-owned, not group/other
   writable): per-host `host-visibility.json` and 32-byte CSPRNG verifier key in
   a trust directory separate from the nonce/epoch volume. Evidence: owner,
   mode, parent chain, mount flags, and that the Host Agent UID cannot write.
3. **Baseline read:** MCP tools list shows `fs_list` only in the isolated
   instance; for both nodes a visible root lists exactly the fixture files, a
   denied subtree and its root name are absent, and counts do not change with the
   number of denied siblings. Evidence: bounded JSON, audit events, no key bytes.
4. **Refusals** (each must be refused, with the audit class shown):
   unauthorized host/profile, approval-required policy (no Ledger approval
   created), over-bound visible entries, non-canonical names, stale epoch,
   replayed snapshot, v1/v2 downgrade, unknown SSH command, ancestor renamed or
   bind-mounted during a listing (the case unprivileged CI cannot create).
5. **Anti-rollback:** stop the node, replace the nonce volume with a blank one,
   start it, and show the host refuses (the durable epoch floor must not be
   resettable by swapping storage). Restore the original volume afterwards.
6. **Rotation** with the maintenance primitives and attestation, in order:
   freeze (service absent + disabled + port refused) → drain (zero established
   sockets on MCP and both SSH ports) → stop control → stop nodes → install the
   next generation → start nodes → `attest_v5` on each node and the control
   report for a fresh nonce, requiring **equal proofs** and manifest-equal
   fields → start control → re-attest → operator confirmation → reopen. Evidence:
   every proof comparison and every observed state.
7. **Failure recovery:** inject a mismatch (wrong key on one node, stale epoch,
   one node left stopped, drain that never reaches zero). Each must leave
   ingress fenced and the sequencer failed; nothing may reopen by itself.
8. **Restart persistence:** reboot the isolated VM; verify the fence and the
   anti-rollback floor still hold, then reopen deliberately.
9. **Teardown** of only the isolated VM and its volumes; confirm the live pilot
   is byte-for-byte unchanged by the same read-only script.

## 5. Explicit limits and open items

- `install` (staging the root-owned generation and how the controller learns
  each host's expected `config_sha256`) and the adapter wiring of
  `attest_host`/`attest_control` are **not implemented yet**; steps 2 and 6 need
  them. The current primitives deliberately cannot be passed to `run_rotation`.
- "Zero established sockets" is the defined drain criterion, not a proof that no
  request is in flight in memory; access paths other than the LaunchAgent
  tunnel (operator `limactl shell`) must be quiesced by the operator.
- The durable nonce/epoch floor is not part of the attestation report; step 5
  covers it by test.
- A single successful run is evidence, not a guarantee for later reboots or
  upgrades; failures are recorded, not retried until green.
