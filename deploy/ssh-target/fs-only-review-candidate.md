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
