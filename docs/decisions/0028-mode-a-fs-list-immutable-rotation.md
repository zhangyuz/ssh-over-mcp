# ADR 0028: Mode A fs_list v5 uses stop/drain/rotate/verify/resume

**Decision: APPROVED by operator on 2026-10-28 for design and development only.**
**Runtime activation: NOT APPROVED. No new ForceCommand, secret, container,
filesystem privilege or network exposure is authorized by this ADR.**
Supersedes the need to construct a *continuously running* central epoch
notification service for the narrow Mode A v5 pilot; does not waive
revocation, identity, authentication, or correct verification.

## First principles

Two real SSH nodes must never execute `fs_list` under an outdated permission.
For this small pilot, operator-controlled downtime at policy updates is acceptable.
Use existing private MCP/SSH deployment and its narrowly scoped stop/start path,
not a new distributed policy service. Exposing `fs_list` only after a verified
complete policy generation is installed on **both** independently pinned nodes
is the user-visible outcome. Acknowledgement is an observable trusted state
transition, not a returned string, a synthetic fixture, or an exit code.

## Release protocol (single immutable generation)

1. Prepare an immutable generation manifest outside untrusted data: distinct
   host IDs, authoritative RFC4253 hostkey SHA256 pins, new monotonically
   increasing epoch and central policy digest, host-specific signer/key IDs
   and artifact fingerprints. Never commit, echo, or log secrets.
2. **Fence all ingress durably**, including the live loopback MCP forwarding
   and any authenticated internal alternate path; no traffic can start through
   an unfenced control instance or stale rollback container.
3. Confirm **zero active work across control and both Host Agents**, including
   requests already admitted over SSH. A timeout, partition, unknown process
   or ambiguous cancellation is a failed drain. Existing Ledger outcome-UNKNOWN
   and operation audits must remain intact; never auto-retry mutations.
4. Stop control then both SSH nodes and verify containers/processes are absent
   (not just command success). Keep ingress closed across any controller crash.
5. Install separately provisioned, immutable v5 Host Policy and HMAC verifier
   key for **each** node, matching central signer identity and inventory hostkey.
   Keep signer and verifier authorization materials out of the Host Agent's
   writable ownership domain; read-only mounts alone must be backed by an
   appropriate ownership, capability and mount privilege boundary. Keep the
   durable nonce+epoch floor in a *different* owned persistent volume. Verify
   an epoch rollback cannot be caused by replacing that volume with a blank DB.
6. Start both hosts in constrained v2 read-only mode. Through independent
   SSH hostkey-verified checks, obtain each node's actual hostkey, generation
   digest, epoch, Host Policy state and key identity; the controller must not
   trust a receipt that merely echoes the expected parameters.
7. Start control in the prepared generation but keep ingress fenced. Verify
   its signer, central policy digest, runtime epoch, pinned node inventory,
   Ledger and audit availability. Check both host receipts still match. Only
   after this full post-start evidence can the operator **explicitly**
   unfreeze the authenticated MCP ingress.
8. On any failure, uncertain result or loss of one host: **do not resume**.
   Do not silently restore an older policy (durable epoch floor rejects it).
   Maintain an operator-verifiable closed ingress state and reconcile the
   failed generation before a new attempt. No "best effort" partial roll.

## Code/evidence boundary

`ssh_over_mcp.ops.mode_a_v5_rotation.run_rotation` is an *inactive* sequencing
candidate. It accepts a separately implemented trusted adapter that must
enforce and prove all the operating-system/container preconditions above. A
`bool` alone is not cryptographic evidence or a durable fence. Neither a
production adapter nor an automatic release trigger is installed. The unit
tests cover ordering, both distinct host identities, aborts on each stage,
spoofed/different digests, and mutation of a release manifest. Step 7 is
sequenced too (review P3): after `start_control` the adapter must return a
`ControlReceipt` whose epoch, central policy digest, generation, pinned host
keys, per-host **signer key IDs** and Ledger/audit availability match the
approved release, and both host receipts are re-attested, before
`open_ingress` may run. The release spec carries one distinct signer key
fingerprint per host (never key bytes, never equal to a host-key pin), and
each `HostReceipt` must report the matching verifier key ID (step 6). Any
mismatch keeps ingress closed.

The host's local persistent epoch+digest floor is necessary defense against
rollback but is **not** distributed revocation proof. A live policy update must
use this full stop/drain/rotate path, never hot-reload. This decision is
applicable to low-frequency Mode A changes; if the product requires immediate
revocation of already-running operations, either fail-closed synchronous
admission/cancellation or a separately approved online epoch/ACK design is
needed.

## Maintenance primitives (2026-10-29, source only, no CLI, not executed live)

`ssh_over_mcp.ops.mode_a_v5_lima_primitives.LimaDockerPrimitives` implements
only the steps of the protocol whose mechanism is already approved in the
[live operations runbook](../runbooks/mvp-mode-a-yuz-local-live-operations.md):
- **Fence (steps 2, 7):** `launchctl disable` then `bootout` of
  `com.som.modea.loopback`, accepted only after observing the service absent
  (`launchctl print` = 113), marked disabled (survives login/reboot), and
  `127.0.0.1:18801` actively refused. A timeout or unreachable port proves
  nothing and fails.
- **Drain (step 3):** zero ESTABLISHED sockets on the MCP port and on both
  nodes' SSH port, read from `/proc/net/tcp` and `/proc/net/tcp6` inside each
  container. Unreadable or malformed tables, or work that never ends, fail.
- **Stop/start (steps 4, 6, 7):** `docker stop` / `start` through the Lima
  guest, accepted only after `inspect` shows `exited` / `running`; control
  stops before nodes and the Ledger starts before MCP.
- **Reopen (step 7):** every container observed running, then a mandatory
  injected operator confirmation, then `enable` + `bootstrap` and a
  listening check; any failure fences again.

All commands are fixed argv lists built from a validated configuration and run
without a shell. Stages enforce their order and refuse to run unless the
previous proof exists. The class deliberately has **no** `install`/`attest_*`,
so it cannot be passed to `run_rotation` and strand the pilot half-rotated.
Limits: zero established sockets is a defined drain criterion, not a proof of
no in-memory work; alternate ingress paths other than the LaunchAgent tunnel
(operator `limactl shell`) are out of scope and must be quiesced by the
operator; tests use a recording fake runner, so no real launchd, Lima or
Docker behaviour is proven.

**Ruling (operator-selected 2026-10-29): host and control state is attested by a
read-only operator-side `docker exec`, not by a new SMCP operation.**
- *Decision:* step 6 is implemented as a read-only entrypoint run inside the
  running node container (`python -m ssh_over_mcp.host_agent.attest_v5`) plus a
  matching control-side report from the central authority, both executed by the
  operator through the already-approved `limactl shell ... docker exec`
  path. No SMCP operation, ForceCommand, port or privilege is added. The SSH
  host-key pin is still checked (below); only the *transport* of the state
  differs from the written step.
- *Contract:* each side prints one JSON object with `version`, `host`,
  `host_key_sha256`, `profile`, `policy_epoch`, `central_policy_sha256`,
  `verifier_key_id`, the controller's fresh 128-bit `nonce`, and
  `proof = HMAC-SHA256(key, b"ssh-over-mcp/v5/attestation/v1\x00" ||
  canonical_json(those fields))`. The host derives every field from its
  protected config and key files (the same loaders verification uses) and also
  reports `config_sha256` (not part of the proof, since the central side cannot
  know it). The central authority computes the same proof per host from the
  keys it holds. The controller never sees a key: it requires the host proof to
  **equal** the control proof for the same nonce and every shared field to equal
  the approved manifest. Equal proofs under a fresh nonce can only come from two
  parties holding the same key bytes; a replayed, echoed or stale report fails
  because the nonce is new.
- *Why safe enough:* the entrypoint is read-only, opens no network socket and
  prints no key material; the operator already has this privileged path for
  stop/start; the compared proofs defeat echoing.
- *Cost if wrong:* `docker exec` trusts the container runtime and the image
  code that produces the report, so a compromised host image could lie
  consistently with a stolen key. A pinned-SSH state operation would not remove
  that (the same code would answer), but it would exercise the production
  path; the live pilot remains protected by the separate image-attestation and
  Native Level-3 gates.
- *Mitigation:* the live SSH host-key pin handshake is still verified
  independently of the container; attestation proves *state*, not image
  provenance; a compromise of the guest is out of scope for this pilot's
  threat model (ADR0025).
- *Still open:* `install` (staging the root-owned generation, including how the
  controller learns the per-host config hash it expects) and wiring
  `attest_host` / `attest_control` into the adapter; the durable nonce/epoch
  floor is not part of this report and stays a real-OCI acceptance item.

## Real acceptance gates before PR #347 Ready

- Independent whole-change security review of trustworthy freeze, read-only
  trust material ownership, Host Agent privilege and actual attestation path.
- Real two-independent-OpenSSH E2E for true MCP HTTP -> Ledger -> pinned SSH
  -> bounded `fs_list` -> central recheck/audit, including denied names,
  request spoofing, policy rotation, stale epoch, interruption between stages,
  restart and both-host independent confirmations.
- Exact-head Linux CI; trusted-main Native Level-3 with verified cleanup.
- Separate operator approval for the actual Mode A deployment/restart, and
  separate approval for PR merge. Mode B remains out of this decision.
- **Signer key ID and non-echo attestation (review round 3, N3):**
  *Derivation is now specified and implemented:* a key ID is
  `SHA-256(b"ssh-over-mcp/v5/hmac-key-id/v1\x00" || key)` from
  `host_agent.visibility_snapshot_v5.visibility_key_id`, used by
  `ImmutableVisibilityAuthority.signer_key_ids()` (central side) and
  `visibility_runtime_v5.local_verifier_key_id(path)` (host side, which reads
  the key only through the protected loader and accepts no expected value).
  *Still OPEN and a **Ready blocker** (not merely an activation item):* the
  production `TrustedRotationOps` adapter and an authenticated host attestation
  path that returns `local_verifier_key_id` plus the running epoch, policy
  digest and generation from the host itself over the pinned SSH identity.
  Until it exists, the sequencer's comparison is only as strong as the
  adapter, and an adapter that echoes the expected spec would still pass. The
  adapter needs its own design review.
  A key ID is an identifier, **not proof of possession**: it is not secret, so
  an adapter that is handed the expected ID can echo it. The production
  attestation must be nonce-bound (for example an HMAC over a fresh verifier
  nonce computed with the verifier key) and keys must come from a CSPRNG.

**2026-10-28 candidate improvement:** v5 config and HMAC verifier-key
loaders now require files and their immediate directory to be owned by
administrator UID 0, with no group/other writes; the only accepted file modes
are 0400/0440. An unprivileged Host Agent is not trusted to own these files.
The nonce/epoch store still requires its separate 0700 Agent-owned directory,
and the runtime config rejects sharing the trust parent with the nonce parent.
TDD demonstrated the former vulnerability (agent-owned key accepted), then
verified refusal and independent nonce storage. Unit tests model administrator
ownership via an explicit **test-only** patch; they are not Linux container
ownership/mount or secure-ancestor proof.

**Still not safe to activate:** verify actual UID/GID/mount mappings, immutable
root-owned ancestor traversal, key group readability and no writable alternate
mount, unprivileged code provenance, separate per-host secret rotation,
failure/recovery behavior, and authentic two-node acceptance before enabling
the candidate Host Agent.


## 2026-10-28: source-only fixed SMCP v2 SSH admission candidate

The existing **test-only**, non-sudo FS-only launcher source can select either
literal `mcp-v1` or `mcp-v2`, with *all* pre-existing isolated Linux
UID/GID/NNP/zero-capability, trusted full source/import-tree and exact v3
FS-only policy checks retained before dispatch. No shell, custom command,
PTY, group privilege or fallback is allowed. For v2 it additionally requires
the root-owned fixed `/etc/ssh-over-mcp/v5/host-visibility.json`,
validates the dedicated v5 policy and restricts every declared visibility
allow root to `/srv/data` or its strict descendants. Missing v5 trust
material refuses before filesystem access, and v1 remains unchanged.

The current `ops/mvp/ssh-over-mcp-fs-only-launcher.py` is a proposed
source-review launcher, **not** the running digest-pinned Mode A image.
Changing its source did not alter the approved live ForceCommand, Compose
overlay or guest. TDD covered strict command selection, broadened roots and
legacy launcher/source tests. A fresh trusted-image build, real root-owned
config/key/nonce mount proof, exact-host OpenSSH/NNP evidence and separately
approved promotion are required before it can be installed.


## Disposable fs_list v2 real-OpenSSH test (CI ONLY; not yet accepted)

An isolated, same-repository pull-request GitHub-hosted (workflow
`mvp-fs-list-v2-two-openssh-ci.yml`, formerly PR #347-only)
Ubuntu 26.04 workflow builds the review-only OpenSSH image from the
pinned-source/signed-APT Dockerfile and invokes two actual independent
OpenSSH nodes under Docker `--network none`, with no published ports.
Each gets a fresh per-node Ed25519 host/client identity, 32-byte test-only
HMAC key, root-owned v5 policy/key read-only bind and separate 0700
Agent-owned temporary nonce/epoch store. The source-only test covers
signed SMCP v2 `fs_list`, denied child names, replay, stale epoch,
fixed-SSH-command downgrade refusal and distinct host-key proof;
the cleanup removes only its own unique containers/files. No image,
keys or attestation are exported or promoted.

**Evidence status:** workflow source alone is not runtime proof. Require
a completed, successful exact-HEAD job and inspect actual container
logs/exit status before claiming that real SSH test passed. This
first stage signs its snapshot inside the disposable node. A second stage
(`mode_a_hosted_v2_central_e2e.py`) runs the real central MCP HTTP server,
Security Ledger and `ImmutableVisibilityAuthority` with per-host test-only
keys against two OpenSSH nodes on internal networks, checking a positive
listing and a denied subtree on each node. Exact-head run 40805225509
(`09a5803`) logged `PR347_REAL_CENTRAL_MCP_LEDGER_TWO_OPENSSH_V2_E2E_PASS`
(markers were later renamed to the PR-neutral
`FS_LIST_V2_REAL_CENTRAL_MCP_LEDGER_TWO_OPENSSH_E2E_PASS` family).
This is still CI-only: it does **not** prove protected production signer
identity, the durable freeze/attest adapter, live Mode A acceptance, or
exact-HEAD Native Level-3, all of which remain mandatory. This workflow does not touch
Yuz.local's live Mode A VM or its SSH/image/key supply.
