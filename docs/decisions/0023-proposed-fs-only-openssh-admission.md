# ADR 0023 (proposed): minimal OpenSSH FS-only admission

- **Status:** PROPOSED / TEST-ONLY / NOT DEPLOYABLE
- **Date:** 2026-10-27
- **Scope:** #342 Mode A filesystem MVP only; does not revise managed-host ADR 0007.
- **Reason:** The rootless sshd and filesystem agent share UID 2201; the agent
  can then read the sshd host private key. This is a release-blocking P1
  even if publickey and filesystem roundtrips pass.

## Smallest candidate

Use normal **OpenSSH** privilege separation with a root master in a *private*
container user namespace and a fixed login account 2201:3201. Never mount a
host Docker socket, host root/cgroups, or host PID/network namespace.

- Root sshd master reads its own node-specific root-owned 0600 host private
  key. No session, agent or sibling node may open that key.
- OpenSSH remains publickey-only, ForceCommand-only, no user environment,
  shell escape, PTY, forwarding, PAM, password or generic sudo.
- The *only* permitted sudoers command is a fixed root-owned
  `/usr/bin/setpriv` with **exact argv**: clear the capability bounding set,
  set `NoNewPrivs=1`, clear supplementary groups, set all real/effective/
  saved/fs IDs to 2201:3201, then launch fixed `python3 -I -S` FS-only
  Host Agent. `SSH_ORIGINAL_COMMAND=mcp-v1` is checked by the existing
  immutable launcher *before app import*. No argument from the SSH client
  is interpreted as command, path, UID or policy.
- Candidate sshd container admission must be *separately* verified with
  `NoNewPrivileges=false` only during admission and **no broader** than
  SETUID/SETGID/SETPCAP/SYS_CHROOT in the bounding set, subject to exact
  Linux syscall proof. It must not receive SYS_ADMIN, DAC_OVERRIDE,
  privileged mode or cgroup mounts. The **FS agent** must end with
  `NoNewPrivs=1`, all five capability sets **zero**, fixed UID/GID,
  and /srv/data bound to per-node 0700 owner 2201:3201.
- This version is **FS v3 only**: stat/read/create-only mkdir/write,
  max 4096 bytes, central ACL + one-use Ledger for mutations, no exec,
  no arbitrary process child, no manager/cgroup/sudo access from model tools.
  Full execution and multi-request resource isolation remain TODO.

## Failure gates before ANY deployment

1. Independent review of the actual root-owned sudoers/ForceCommand code,
   exact sudo/setpriv privilege order and kernel identity; prove that
   `NoNewPrivs=1` and **all CapInh/Prm/Eff/Bnd/Amb are zero** inside the
   actual FS launcher under Ubuntu 26.04. If setpriv cannot drop bounding
   caps *before* UID transition, **STOP**. Deny every other sudo invocation.
2. Verify Docker private user-namespace UID/GID maps and bounded sshd
   capabilities. Show agent is unable to read root-only host keys or sshd
   credentials, send signals, ptrace, or access sibling node volumes.
   Record namespace/FD evidence; fail if not isolated. No host privileges.
3. Immutable signed Ubuntu/OpenSSH image, exact source/lock hashes, pinned
   host keys/authorized keys, real two-node SSH + MCP read, approved
   create-only mkdir/write/readback, wrong-key/forwarding/ACL/replay
   negatives and directional bridge rule proof on a disposable no-NIC
   Linux guest. Zero-cap source checks alone are NOT this proof.
4. Existing Compose and image `ENTRYPOINT` STOP78 stay unchanged until
   native Level-2/Level-3 verification, whole-PR security review,
   operator release approval and rollback/cleanup evidence. No production
   secrets or privileged changes to existing Yuz.local CI runners.

## Artifacts and alternatives

Review-only configuration:
`deploy/ssh-target/sshd_config.fs-privsep-review-candidate`;
`deploy/ssh-target/sudoers.fs-privsep-review-candidate`.
They are not installed, built, merged or wired. The original rootless
candidate remains for transport testing, **not** as a deployable
same-UID hostkey architecture. No replacement SSH daemon or new privileged
manager is introduced. This decision needs real Linux and independent review
before changing any runtime privilege envelope.
