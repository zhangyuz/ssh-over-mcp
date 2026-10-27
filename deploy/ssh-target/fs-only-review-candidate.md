# Mode A minimal FS-only, zero-capability SSH candidate

**Status: REVIEW CANDIDATE / NOT DEPLOYABLE / PR #342 remains Draft.**
This is a deliberately reduced acceptance **proposal**, not a revision of accepted
ADR0007 or permission to run Docker, alter host privileges or consume new keys.

- `sshd_config.fs-only-review-candidate` differs from the existing candidate
  only in `ForceCommand`: it runs the pinned `python3 -I -S` filesystem
  entrypoint **without sudo**; all authentication, no-PTY, no-password and
  forwarding-denial directives stay unchanged. No generic shell fallback.
- `ops/mvp/ssh-over-mcp-fs-only-launcher.py` does **not** request root,
  cgroup mutation, manager sockets or Linux capabilities. Before application
  imports, it refuses unless Linux UID/FSUID=2201 and GID/FSGID=3201 for all
  real/effective/saved IDs, groups are restricted, `NoNewPrivs=1`, every
  Linux capability set (including bounding) is zero, `python3 -I -S` is in
  use, **all files in the source and site-package import trees** are root-owned,
  non-writable, non-symlinked (no cached bytecode or setuid files), and
  `/srv/data` is a nonsymlink mode0700 directory owned by 2201:3201.
  It loads the existing root-owned v3 Host Policy, checks its *exact*
  `rw-operator` filesystem roots and 4096-byte bounds, as well as the
  non-executable command placeholder, empty environment allowlist and fixed
  process/time/input/output bounds, then delegates
  `mcp-v1` to existing Host Agent. The v3 command path is non-executing.
- An actual FS-only image would need its *separate* signed, immutable
  runtime packaging, root-owned trust assets, postdrop dependencies and data
  owner **2201:3201** (the existing privileged SSH candidate uses
  **2202:3202**, and therefore must NOT be reused unchanged). The current
  `Dockerfile.review-candidate`, manager image, Compose and all EXIT78
  gates deliberately remain untouched.
- **P1 still open:** OpenSSH's root master/login credential transition may
  itself require bounded setuid/setgid privileges. `cap_drop: ALL` +
  container-wide NNP does **not** prove sshd can authenticate and establish
  UID2201. Removing `sudo` solves only the post-login ForceCommand
  conflict, **not** the sshd admission boundary. A separately reviewed
  process-specific admission plan or rootless authenticated transport, with
  real userns and Linux identity evidence, is mandatory before enabling.
- **MVP validation** (not yet performed): independently approved disposable
  no-NIC Linux guest; attested image, exact SSH identity/UID/FSUID/NNP/caps;
  node-local mount owners and directional ACL; two pinned SSH host keys;
  real MCP `hosts_list → fs_stat/read → separately approved create-only
  fs_mkdir/fs_write → readback` on node01 and node02; negative SSH
  forwarding, cross-node and replay tests. Whole-PR security review/Native
  Level-3 remain required for Ready. Workload execution, manager-backed
  process containment, concurrency and extra FS operations stay out of this
  reduced test scope (TODO, independent architecture review).


## 2026-10-27: OpenSSH-only nonroot feasibility, MVP direction (source-only)

OpenSSH upstream explicitly supports running its **normal privilege-separation
path as a non-root user** (Darren Tucker, 2022:
https://lists.mindrot.org/pipermail/openssh-unix-dev/2022-February/039973.html).
Thus **do not** require a root master, `CAP_SETUID`, sudo, manager, or
`UsePrivilegeSeparation no` *by default* for the bounded FS-only MVP.
The separate FS-only candidate now listens on unprivileged internal TCP
**2222**, uses `UsePAM no`, publickey-only authentication, the original
deny-forwarding restrictions and the fixed no-sudo Python ForceCommand.
Its app identity remains the single SSH user **2201:3201**, NNP=1, all
capabilities (including bounding) zero. **No substitute SSH daemon.**

**P1 proof remains:** real Ubuntu 26.04 OpenSSH login/session with the
final OCI `USER 2201:3201`, `cap_drop: ALL`, `no-new-privileges:true`,
and per-node isolated keys; prove sshd's preauth/privsep/session identity,
`/proc` capabilities, `ForceCommand` and SSH denial probes. An OpenSSH
process running under the same UID as the session may expose its *private host
key* to the agent. Before deployment, demonstrate that per-node host-key
signing/key access cannot be abused by the session (or **STOP** and request
an independently reviewed narrow signer/isolated domain). Never grant a
private host key or trust override to MCP/agent input. The existing FS-only
image is not built, Compose still points to port 22 and STOP78, and no
runtime/guest was executed. Align the SSH target's service port and the
server-owned inventory **only after** Linux rootless verification and
separate explicit deployment approval. Process containment/ssh_exec and
manager-backed arbitrary child execution stay TODO.
