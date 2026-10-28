# Mode A OCI privilege and network proof matrix (review candidate)

**Status:** PROPOSED / OFFLINE REVIEW ONLY, PR #342. **runtime privilege exception not approved**. The current render-only Compose retains `cap_drop: ALL` and `no-new-privileges:true`. This document does not authorize starting or editing a VM, Docker daemon, image, keys, firewall or cgroups. No real A01–A03 runtime proof exists.

**Source hierarchy:** accepted ADR0004 (manager separated), ADR0005 (irreversible workload identity), ADR0007 (fixed no argv launcher), proposed ADR0022 (unresolved OCI gap). If an OCI proposal contradicts an accepted ADR, revise it through independent review rather than silently replacing the accepted invariant.

## Proposed process/FD/identity matrix

Values are **roles**, not invented live UID numbers. Before runtime, the operator must pin numeric UID/GID, namespace maps, exact OCI capability/bounding/permitted/inheritable/ambient sets, read-only mount/FD ownership, delegated cgroup v2 controllers and process residency. No implicit shared UID or supplementary group.

| Role | Required UID/GID and authority | NNP and capability boundary | FD and cgroup v2 boundary | Offline/real evidence |
| --- | --- | --- | --- | --- |
| sshd master | reviewed admission-domain service, root only if explicitly justified and bounded by namespace; **not** the host agent | NNP exception **not approved**; no ambient or inheritable drift | Only its SSH host-key read FD and listening TCP/22; stays **outside** delegated workload tree | exact source/image signature, effective `sshd -G`, /proc UID/caps/fds |
| SSH login | fixed non-root `ssh-over-mcp-e2e-host`; no server-chosen arbitrary caller UID | no general sudo, PTY, TCP/Unix forwarding, shell, user RC or environment | authorized-key read-only FD; no manager socket or writable cgroup ancestor | refused wrong key/command/PTY/forward and enforced ForceCommand |
| fixed launcher | root-owned, nonwritable, **exact digest**, **no argv**; root phase is tiny trusted binary/script integrity boundary | if sudo requires an admission-side NNP exception, stop for independent review; sanitize Python/import env, drop identity **before** app import | join exact source cgroup then verify /proc unified membership; close any unwanted inherited FD | exact sudoers policy, root ownership, digest, preimport trace and transitions |
| trusted host agent | fixed **distinct** non-root UID/GID; optional manager-client group only; its CAP_SETUID/CAP_SETGID can impersonate root in same user namespace | CAP_SETUID and CAP_SETGID only, no ambient/inheritable; treat all code until child drop as trusted security-critical | exact authorized manager socket FD, no sibling keys or writable cgroup subtree; source scope not target scope | capget, FSUID/FSGID, supplementary groups, SO_PEERCRED, no manager FD leak |
| containment manager | distinct fixed UID/GID, socket ACL plus SO_PEERCRED authenticated peer | no generic exec or shell; only reviewed narrow cgroup authority | owns **only** independently delegated node-local cgroup v2 root; operations create/attach/kill/stats/close; no ancestors or sibling node | actual write-authority and denied ancestor/sibling/self-migration proofs |
| workload | fixed request-selected, non-root **distinct** UID/GID; empty groups | `NoNewPrivs=1`, zero effective/permitted/inheritable/ambient caps; saved + fs IDs verified | inherit only close-on-exec reviewed request FDs; no manager or writable cgroup FD; attached to request subtree before release | positive pinned exec and denied cgroup self-migration/identity change |
| typed filesystem | presently host-agent calls may bypass manager-backed `ssh_exec` containment; separate design gate | cannot claim workload properties until typed FS operations use an independently reviewed privilege boundary | rooted FD/no-follow policy, mutation audit-before-effect, no privileged direct mutation outside accepted manager flow | cannot enable full RW M2 from this Mode A render-only PR |

All UID/GID transitions must verify real/effective/saved and filesystem IDs. File modes, ownership, mount source and inherited FDs are security-critical **even if a process prints a non-root UID**.

## Startup and fail-closed invariant

1. Verify approved immutable base + project SSH OCI digest and source/signer, exact host/authorized keys and trusted launcher/sudoers manifest. Unknown digests or test-only keys without approved provenance stop.
2. Validate live kernel namespace UID mappings, cgroup v2 delegation and manager socket ACL/peer identity before permitting any untrusted session. **No** root-equivalent host mounts, Docker socket, host PID/network, `privileged`, generic `CAP_SYS_ADMIN` or writable ancestor cgroup tree.
3. Evaluate a concrete narrowly scoped process-level OCI NNP/capability plan **before** a sudo attempt. A global NNP removal is not approved; no claim that an all-caps-dropped NNP container can use ADR0007 fixed sudo handoff.
4. Root launcher performs a bounded untrusted-environment sanitation, exact `SSH_ORIGINAL_COMMAND=mcp-v1`, no PTY/argv, fixed source-cgroup membership check, UID/GID/group drop, capability readback. No application imports during root phase.
5. Manager authenticates over SO_PEERCRED plus socket ACL, creates request scope and confirms attach before release. Workload clears group and all cap sets, sets `NoNewPrivs`, validates filesystem IDs and closes manager FDs before pinned native exec.
6. Rejected/missing evidence aborts before side effects; audit-before-effect and bounded cleanup must preserve UNKNOWN outcomes without retry. Only the Linux runtime test on the exact source/image can prove these properties.

## Bidirectional private bridge — proposed network policy matrix

Docker `internal: true` private bridge is **not** an unidirectional ACL. In current overlay MCP shares `node01_ssh` and `node02_ssh` with the SSH nodes and listens on `0.0.0.0`, so an SSH node can initiate MCP TCP/8000. A node can also use same-bridge broadcasts/addresses; do not trust alias names alone.

| Source → destination | Required behavior | Enforcement / runtime evidence |
| --- | --- | --- |
| MCP → node01 TCP/22 | allow authenticated **NEW**, then `ESTABLISHED` replies | immutable sshd and pinned node01 key, observe real connection |
| MCP → node02 TCP/22 | allow authenticated **NEW**, then `ESTABLISHED` replies | separately pinned node02 identity |
| node01 / node02 → MCP TCP/8000 | deny node-originated **NEW** even if application has origin authentication; permit only `ESTABLISHED` replies to valid MCP-originated requests | separately approved stateful per-interface ACL; negative TCP handshake and HTTP auth spoof probes from each node |
| node01 → node02, node02 → node01 | deny **NEW** for all management and workload ports | packet-level denial and independent bridge / socket verification |
| each node → host/LAN, public internet | deny outbound **NEW** except separately justified ephemeral bootstrap if authorized | guest/host boundary independent of Compose; host/LAN and external egress failure evidence |
| public/LAN → node TCP/22, MCP TCP/8000 | deny unsolicited **NEW** (Cloudflare origin has its separate audited channel) | firewall/routing proof, not `expose:` or lack of `ports:` alone |

**Origin authentication** is mandatory defense in depth: peer identity, not headers or IP supplied by a compromised node, must bind authorized Portal requests. Test valid/invalid tokens, spoofed identity, replay and request flood. Any missing stateful ACL, untrusted source binding or unsupported route must **fail closed** before an SSH session is accepted. Authentication alone does not satisfy packet-level node→MCP denial.


## Required approval packet before host/Docker actions

- Independent architecture review of root/sudo transition vs NNP, UID/GID maps, cap bounding/ambient/inheritable sets, FD closure, delegated cgroup subtree and typed FS exception. Freeze the exact accepted OCI manifest for **each** SSH node.
- B environment: the stopped Ubuntu 26.04 VM on `yuz.local` is an untrusted candidate; Lima 2.2 default user-mode networking provides host/LAN egress, so offline YAML inspection does not permit boot. Propose an externally verifiable no-NIC/offline-media guest or equally isolated network boundary. No broad host firewall operation; no probing production.
- C source: Docker Hub `library/ubuntu` 26.04 is a **candidate** Official Image (Canonical), not an approved OCI image; obtain full platform-specific digest, publish chain and separate project SSH Dockerfile, pinned packages, SBOM, reproducible binary/image digest and signer checks before any pull/use. Per-node host and authorized keys must be operator-approved fresh nonproduction assets.
- D candidate evidence: authorized Linux Docker **A01–A03** positive and hostile probes (all matrix negatives), exact-HEAD ordinary CI + trusted Native Level-3 PASS and fresh independent whole-diff review. Mode B A15–A18 and M2 remain separately HOLD.

**runtime proof required**: none of the above may be marked PASS using a render-only Compose graph, an offline VM configuration check or a fake attestation JSON.
