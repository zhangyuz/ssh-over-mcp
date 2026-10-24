# ADR 0022: Proposed minimal-privilege Compose SSH runtime

- **Status:** PROPOSED, not accepted, not deployable
- **Date:** 2026-10-24
- **Scope:** PR #342 Mode A, with separate Mode B gate
- **Depends on:** ADR 0005, ADR 0007, ADR 0021 and docs/security-model.md

## Problem and decision boundary

Both current SSH nodes explicitly declare `cap_drop: [ALL]` and `no-new-privileges:true`, a read-only root filesystem and no tested image/bootstrap. ADR 0007, in contrast, requires sshd to authenticate a fixed non-root account, invoke exactly one root-owned no-argument sudo launcher, join a delegated cgroup and hand off only `CAP_SETUID|CAP_SETGID` to a distinct non-root host-agent. Container-wide NNP prevents that sudo elevation, while dropping all capabilities denies the required credential transitions. A syntactically correct Compose render cannot validate this mechanism. Do not add capabilities, remove NNP or mount the host cgroup root as an implicit fix.

The current host-agent also handles typed `fs_stat/read/mkdir/write` before reaching its `ssh_exec` containment-manager path, so full typed filesystem safety needs a distinct audited, restricted execution plan. **A non-root UID does not make the host-agent unprivileged:** `CAP_SETUID` can impersonate UID 0 (within the same user namespace), and `CAP_SETGID` permits group impersonation. Per accepted methodology/ADR0005 this is trusted, security-critical code. Any container bootstrap must explicitly account for its effective file/identity authority, not infer an absence of root-equivalent risk from a non-root `id -u`.

## Proposed privilege separation (subject to independent security approval)

**SSH admission domain:** minimal, source-attested sshd master and a server-owned fixed non-root SSH identity; no password, PTY, user RC, environment, TCP, Unix-socket forwarding or arbitrary shell; only the exact ADR 0007 sudo launcher target, never a generic sudo rule. A container-specific launcher must match a separately reviewed SSH account, UID/GID and strict startup integrity manifest. The present `sshd_config.proposed` uses an *E2E-only* identity and must not be treated as production configuration.

**Containment domain:** separately authenticated manager Unix socket and separately delegated *per-node cgroup v2 subtree*, with fixed manager UID and manager-client GID. No workload, SSH identity, MCP process or sibling node may access the manager authority, ancestors or other node's keys/data. The launcher must prove exact process membership, drop to a distinct non-root **trusted** host-agent, retain only SETUID/SETGID and zero ambient/inheritable rights *before importing application code*. Any path processing caller-controlled data before dropping these capabilities remains in the privileged trust domain; the workload must never inherit them.

The current fixed sudo approach would require a narrowly scoped exception to **container admission-process** NNP, while the per-request **workload still requires `NoNewPrivs=1`, zero capabilities and an irreversible drop**. This exception is **not approved**, nor is the alternative of a privileged IPC broker avoiding sudo. If safe namespace/delegation cannot be proven with bounded OCI capabilities, halt rather than turn on `privileged`, `SYS_ADMIN`, general sudo, Docker socket or host-cgroup-root mounts.

## Required exact runtime proofs

| Process | Required positive proof | Required negative proof |
| --- | --- | --- |
| sshd master | Attested image, fixed UID, bounded capabilities | No broad rootfs, host net/PID, unreviewed ports or shell |
| SSH login | Fixed, read-only authorized keys, independently pinned host key | Wrong/rotated key, PTY, TCP/Unix forwarding, `ssh -N` |
| Fixed launcher | Root-owned exact digest, sole sudoers command, no argv, exact `mcp-v1` | Other commands, environment and sudo targets denied |
| Host agent | Distinct UID/GID/group, exactly two identity capabilities; trusted code only until drop | No unexpected capabilities, UID 0 impersonation by untrusted code, ambient caps or leaked manager FD |
| Manager | Authenticated socket, only assigned node cgroup controllers | No sibling, workload or ancestor cgroup control |
| Workload | Non-root, zero capabilities, `NoNewPrivs=1`, bounded resources | Cannot migrate cgroup, touch keys or invoke manager |
| Typed FS worker | **Separate design gate** for bounded UID/cgroup/audit | No privileged direct mutation or unreviewed append/replace |

This is a proof checklist, **not** a claim that these processes exist in either current Compose target. **Network blind spot:** each node and MCP share a Docker bridge, and MCP listens on `0.0.0.0`. A node-initiated connection to the MCP listener is therefore not excluded by the YAML; `internal: true` does not create a directional firewall rule. The live negative plan must attempt node→MCP TCP/8000 (including origin authentication bypass and resource-exhaustion probes), plus cross-node and external-egress attempts. A separately authorized network ACL/proxy must enforce the intended directionality if that is a required guarantee. Existing `network_acl_verified=false` stays correct.

## Trust and acceptance sequence

1. Independently review this ADR, the exact trust split, OCI startup/identity table, and cgroup-v2 delegation evidence plan; obtain explicit operator design approval.
2. Operator identifies a specific **disposable Linux Docker Engine**, permitted Docker API boundary, private nonproduction networks/keys, acceptable SSH/control immutable image source, signer/digests, base OS and OpenSSH package provenance, and safe cleanup.
3. Only then implement and validate the image/build/install manifest, fixed sshd/launcher/sudoers, manager process/IPC, authorized-key and per-node host-key provisioning. Fail startup if any trusted asset, socket ACL, controller, UID, digest or SSH restrictions are missing.
4. Real Mode A A01-A03: two actually running, independent host-key-pinned SSH nodes; positive MCP→SSH/ForceCommand/manager requests, host-/central-policy and Ledger audit-before-effect; hostile wrong key, `ssh -N`, port/Unix forwarding, PTY, bad sudo/manager, cross-node network and volume access, failed delegation, restart and cleanup. Record source SHA, image digest, host/network provenance and observed process identities.
5. Real authorized Level-2, independently reviewed exact candidate SHA and required trusted-main **premerge** Native Level-3 PASS must all exist before PR #342 is Ready; new main requires postmerge 11/11. Three distinct Linux Engines and A15–A18 for Mode B are separate, not inherited.

## Rejected shortcuts / release state

No `privileged: true`, host Docker socket, rootfs, host PID/net, writable cgroup root, generic `NOPASSWD: ALL`, `CAP_SYS_ADMIN`, auto host-key acceptance, broad shell fallback, or pretending native-VM evidence proves Docker namespaces. No unverified `@sha256` string is a trusted image signature. No new full RW tools before SMCP v2, Host Policy v5, exact approval binding, durable mutation journal and independent acceptance.

**Decision is unapproved.** The existing Mode A overlay must remain render-only, `deployment_ready=false` and PR #342 Draft until a reviewed minimal privilege mechanism plus *real authorized* positive/negative runtime evidence can satisfy those gates.
