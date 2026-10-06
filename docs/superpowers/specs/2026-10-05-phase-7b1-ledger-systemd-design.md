# Phase 7B1: Security Ledger systemd sandbox

- Status: Proposed written design; scope approved, implementation not yet approved
- Date: 2026-10-05
- Baseline: `a37747291894ac7b01ae5483af83d0dd89821015` (Phase 7A closed)
- Related decision: [ADR 0009](../../decisions/0009-ledger-systemd-sandbox.md)

## 1. Intent and first slice

Provide a reviewable Linux systemd reference deployment for the existing
Security Ledger daemon, and demonstrate that its sandbox is effective without
breaking durable audit, peer authentication, or approval semantics.

The user requested continued small iterations with quality and security as the
focus and approved Ledger-first hardening. This design covers one service.
MCP-origin units, containment-manager units, host-agent sandboxing, AppArmor,
SELinux, general egress profiles, SSH CA, and secret-manager integration remain
later independently designed slices. No new MCP operation or ledger protocol
operation is introduced.

Three approaches were considered:

1. **Ledger first (selected):** an existing foreground service with AF_UNIX-only
   communication, exact identities, and durable storage provides a narrow proof.
2. All service units together: increases the interaction surface, particularly
   SSH egress and writable cgroup authority, before one profile has live proof.
3. Containment manager first: immediately intersects cgroup delegation and
   workload identity; those privileges need their own design and evidence.

## 2. Existing contracts remain authoritative

- `approvals/main.py` runs the daemon in the foreground, handles SIGTERM/SIGINT,
  and closes both listeners and the database.
- `approvals/runtime.py` checks the configured service identity and the exact
  extra group set derived from execution/admin socket GIDs.
- Storage validates canonical service-owned paths and ancestors, a regular
  32-byte key with mode 0400/0600, and a database with mode 0600. SQLite retains
  WAL, synchronous FULL, and its existing transactions.
- Execution/admin directories have distinct group ownership and are not
  group/world writable. Socket creation and cleanup preserve inode checks.
  An existing endpoint is rejected, never silently removed before startup.
- Execution peers can ping, append audit, inspect/ensure approvals and consume;
  only the separately authenticated admin peer can grant/deny. Grant authority
  remains the real `ssh-over-mcp-approvalctl` process outside MCP.
- Policy deny remains terminal. Required audit failure blocks transport;
  consumed approvals and mutation/audit uncertainty do not become safe retries.

The proposed deployment MUST adapt to these contracts rather than change them
to fit systemd defaults. Initial implementation changes are deployment,
documentation, and tests; a demonstrated production defect needs its own RED
and reviewed fix.

## 3. Deployment ownership and process identities

The reference uses static operator-provisioned Linux accounts. `User=` and
`Group=` select the dedicated non-root Ledger identity; `SupplementaryGroups=`
contains exactly the two endpoint groups, with the primary group excluded when
checking the runtime identity. The account MUST have no other group memberships.
`DynamicUser=` is disabled because peer UID/GID and storage ownership must remain
stable across restarts.

The execution-client identity, admin identity, Ledger identity, and workload
identity MUST be distinct non-root users. Numeric IDs are operator-resolved
settings, not hardcoded portable host IDs or request inputs. The Ledger's extra
groups do not grant it capabilities or sudo. The daemon has no SSH key, origin
bearer, Tunnel token, Docker socket, or writable cgroup delegation.

Production preparation is an explicit operator action. The reference provides
an account/path/configuration checklist; this slice does not install a generic
privileged provisioning daemon or change the authorized Mac host.

## 4. Reference layout

| Purpose | Reference path | Ownership and mode | Service access |
| --- | --- | --- | --- |
| Installed runtime | `/opt/ssh-over-mcp/venv` | Root-owned; not service/client writable | Read/execute |
| Non-secret configuration | `/etc/ssh-over-mcp/ledger.env` | Root:root 0600; trusted parents | Read by systemd before identity drop |
| HMAC key directory | `/etc/ssh-over-mcp/ledger-key` | Ledger:Ledger 0700; root-owned outer parent | Read-only in sandbox |
| HMAC key | `/etc/ssh-over-mcp/ledger-key/hmac.key` | Ledger:Ledger 0400; exactly 32 bytes | Read-only; never environment/argv |
| Database directory | `/var/lib/ssh-over-mcp-ledger` | Ledger:Ledger 0700 | Writable DB/WAL/SHM only |
| Execution socket directory | `/run/ssh-over-mcp-ledger-exec` | Ledger:execution-group 0750 | Writable for Ledger; client traverse |
| Admin socket directory | `/run/ssh-over-mcp-ledger-admin` | Ledger:admin-group 0750 | Writable for Ledger; admin traverse |
| Two endpoint sockets | Each directory's `ledger.sock` | Ledger:corresponding-group 0660 | Filesystem permission plus exact SO_PEERCRED |

The root-owned environment file contains only the existing
`SSH_OVER_MCP_LEDGER_*` settings. Numeric identities and paths must match the
provisioned layout. Secret key bytes, loader hooks, source paths, and client
identity assertions are not environment-file contents. Fixed private paths
remain below the Linux AF_UNIX length ceiling.

No `LoadCredential=` migration is included: the current key-parent ownership
contract must remain intact. A systemd-created credential directory must not be
assumed compatible without a separate design.

Writable directories are provisioned and checked independently, with their
different groups. The unit does not use directory management which recursively
changes existing ownership or deletes endpoint directories on stop. In
particular, systemd must not erase a replaced/stale endpoint and thereby mask
the application's fail-closed cleanup/startup checks. Operator recovery first
verifies there is no active owner; unknown state is never automatically erased.

## 5. Unit contract

Create `ops/systemd/ssh-over-mcp-ledger.service` and an operator README plus a
non-secret configuration example. The production command is exactly the
installed interpreter with isolated mode and bytecode disabled:
`/opt/ssh-over-mcp/venv/bin/python -I -B -m ssh_over_mcp.approvals.main`.
There is no shell, root command prefix, application `ExecStartPre=`, inherited
socket activation, caller-selected interpreter, or request-selected profile.

The initial profile requires:

| Boundary | Required configuration/evidence |
| --- | --- |
| Privilege | Non-root static identity; empty `CapabilityBoundingSet=` and `AmbientCapabilities=`; `NoNewPrivileges=yes` |
| Filesystem | `ProtectSystem=strict`, `ProtectHome=yes`; writable exceptions exactly the database and two socket directories; key/runtime remain read-only |
| Device/kernel | `PrivateDevices=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes` |
| Network | `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`; no inherited network socket or socket unit |
| Other namespaces | `RestrictNamespaces=yes`; no namespace creation or network namespace reassociation |
| Execution | `SystemCallArchitectures=native`; `RestrictSUIDSGID=yes`, `LockPersonality=yes`, `RestrictRealtime=yes`; bytecode writes disabled |
| Async syscall bypass | Explicitly deny `io_uring_setup`, `io_uring_enter`, and `io_uring_register` through `SystemCallFilter=` |
| Lifecycle | `Type=exec`, `Restart=no`, `KillMode=control-group`, SIGTERM, `TimeoutStopSec=10s`, final SIGKILL enabled |
| Private temporary files | `PrivateTmp=yes`; no credential or persistence authority in the private temporary directory |

`Restart=no` preserves operator-visible failure and prevents a retry loop from
erasing or hiding stale endpoints. An explicit restart after a clean stop is
supported; forced termination leaves normal fail-closed recovery requirements.
The daemon's two-second timeout is per socket operation, not a total connection
deadline. A paused partial frame permits graceful shutdown after timeout; an
authorized peer trickling bytes can keep the receive loop occupied despite
SIGTERM. That case must exercise systemd's ten-second stop deadline and final
SIGKILL, with explicit forced-stop evidence and stale endpoints preserved. The
unit does not claim every client permits graceful shutdown and this slice does
not change framing/timeouts to conceal the distinction. `Type=exec` means
successful process exec, not application readiness;
readiness still requires the existing authenticated Ledger ping.

AF_UNIX remains reachable through filesystem paths by the authorized client
identities. This is intentional local IPC, not a general claim of zero possible
data transfer from a compromised Ledger. No socket activation or generic
descriptor transfer is added. Address-family filtering alone is insufficient:
its inherited-socket and io_uring caveats are addressed explicitly. Unsupported
mandatory directives or ineffective kernel enforcement fail deployment
validation; they are not silently omitted to improve a security score.

The installed unit and configuration are root-owned and not writable by any
service/client/workload. A security score is diagnostic only; effective
properties, process state, allowed behavior, and denied operations determine
acceptance. AppArmor/SELinux and additional syscall restrictions are deferred
until this profile has real compatibility evidence.

## 6. Trusted E2E separation

The current no-network QEMU provider and self-hosted runners remain unchanged.
All service-manager/root setup runs inside the disposable guest, never on the
persistent Mac or ordinary CI runner.

The existing five-fixture probe stays in its fixed order. Its final
STOP_MANAGER scenario remains last. The existing exact `STOP_MANAGER\n` /
`OK\n` control protocol is not expanded with systemctl commands.

The current trusted gate cannot certify new systemd behavior without new setup.
Ship a separate **authority prerequisite** first: fixed Ledger identities,
paths, lifecycle phases, canonical profile snapshot, and bounded result checks.
That prerequisite must be reviewed and merged to main before the target
reference/profile and live probe are certified. It must keep the existing full
five-fixture E2E working and must not declare the new sandbox already certified.

The trusted guest setup compares the target reference unit bytes against its
already-merged canonical profile snapshot before installation. Unknown text,
extra directives, command prefixes, alternate users, or mismatched bytes fail
closed before systemd starts anything. It never evaluates arbitrary target unit
directives as root. Changing the expected profile later requires another
separate trusted-main authority update. This intentional duplication trades
maintenance convenience for a small, auditable root setup interface.

File equality alone is insufficient: after daemon-reload and **before start**,
trusted setup must check the effective loaded unit, including fragment path,
drop-ins, aliases, all Exec command phases/prefixes, environment sources, identity,
capabilities and sandbox properties. Unexpected merged configuration or an
already-running/pre-existing fixture unit fails closed. Guest entrypoint
adaptation is the sole fixed allowed override and is part of that expected
effective configuration. No target root command may execute before these checks.

The production unit assumes a preinstalled application package. The source-only
guest instead uses a fixed trusted ExecStart adapter that imports the exact
checkout only after systemd has dropped to the Ledger identity. No target build
backend, package installer, application module, or target helper executes as
root. Only that fixed entrypoint adaptation differs; sandbox properties and
candidate profile equality must be checked. A guest result does not claim to
test production package installation, which retains separate packaging proof.

Trusted setup orchestrates start, client phases, stop, restart and cleanup with
fixed unit/path names. A non-root target client probe receives no systemctl
authority. Separate sandbox test processes use the same profile and fixed test
paths to attempt forbidden operations; production Ledger gains no diagnostic
opcode. Root setup accepts no arbitrary privileged RPC or target-selected
unit, command, path, UID/GID, or directive. An absent target 7B1 probe during
authority bootstrap is explicitly legacy-only evidence; after activation the
7B1 target acceptance run must require it, not conditionally skip it.

Read-only guest storage is not tamperproof against the accepted guest-root
equivalent target authority. Review and contracts establish product coverage;
trusted setup establishes lifecycle and commit binding. The independent outer
boundary remains the fresh QEMU VM with no NIC, shares, host credentials, or
production secrets, followed by whole-VM destruction.

## 7. Acceptance evidence

| Criterion | RED/contract and integration evidence | Real guest evidence |
| --- | --- | --- |
| Exact non-root identity/groups/caps | Alter unit identity/group/capability fields; mismatch rejected | UID/GID/groups, zero capability sets, NoNewPrivs=1 |
| Safe unit loading | Modified bytes, duplicate directives, root prefixes, symlinks, unexpected drop-ins/aliases/command phases rejected before start | Trusted snapshot/copy integrity plus effective loaded configuration verified before any start |
| Allowed persistence | Existing Ledger storage/restart/concurrency tests unchanged | WAL/FULL audit + approval grant/consume survives clean restart |
| Execution/admin separation | Wrong peer and cross-operation regressions | Separate real client/approvalctl identities; unauthorized grant/consume rejected |
| Network restriction | Missing restriction or allowed INET/INET6 rejected | IPv4/IPv6 socket creation, raw socket, and namespace bypass attempts denied |
| Syscall bypass restriction | Removing any io_uring denial or native-architecture restriction rejected | Explicit `io_uring_setup`, `io_uring_enter`, and `io_uring_register` attempts denied, with differential controls; kernel/process ABI attested as pinned x86_64/native |
| Read-only runtime/key | Wider write exception rejected | Runtime/key write and outside-root write fail under same sandbox; allowed DB write succeeds |
| Kernel/cgroup protection | Weakened protected paths rejected | Device/kernel/cgroup write attempts denied; zero capabilities |
| Normal shutdown | Existing close/restart checks retained | SIGTERM with a paused partial frame closes within the stop deadline; no process/socket leak; clean restart works |
| Forced-stop/stale state | No recovery deletion code or automatic restart; per-operation timeout distinguished from total deadline | Authorized slow-trickle frame causes bounded final SIGKILL; no remaining service processes, stale endpoints preserved and restart refused; replacement socket survives; only verified run-owned state cleaned |
| Approval invariants and secrets | Exact binding, consume/replay, policy deny, retention regressions | Real CLI pending→grant→consume; replay/binding rejection; scans of transcript/journal/storage |
| Existing Phase 7A | Fixed five-fixture order contracts unchanged | Full five-fixture PASS with STOP_MANAGER last |
| Exact revision and cleanup | Trusted-main workflow/bundle contracts retained | Exact head/merge CI + E2E; provider absence, guest/VM destruction |

Denial probes compare allowed and forbidden operations under the same effective
profile. A failure caused by an unrelated file permission or missing syscall is
not evidence that the intended sandbox layer works. Client readiness checks are
bounded and non-blocking; no arbitrary delay, skipped probe, relaxed assertion,
or retry of approval consumption is permitted.

The io_uring probes must use the attested native syscall ABI and valid arguments
or established kernel error controls, not unexplained magic syscall numbers.
For each syscall, a fixed trusted comparison profile changes only the relevant
filter boundary and establishes that the call reaches the kernel there. Compare
the restricted result against that control and inspect effective seccomp state.
Kernel-wide io_uring disablement, unavailable calls, invalid argument failures,
or other sandbox layers do not count as proof of the explicit filter. If the
pinned image cannot provide the required discriminating evidence, acceptance is
blocked until a specific alternative proof is reviewed; no test is silently
skipped and no production/guest kernel policy is relaxed to manufacture a pass.
The native-only claim requires recorded kernel/process x86_64 attestation;
compatibility ABIs and other architectures are not supported by this slice.

Effective systemd/kernel versions and supported mandatory properties must be
recorded from the pinned guest, not inferred from current upstream documentation.
No new supported distribution is claimed. The initial validated deployment is
the existing Ubuntu 26.04 x86_64 guest.

## 8. Delivery and completion

The written implementation plan must separate: design/ADR approval, the trusted
authority prerequisite, the target reference/probe, and final evidence/cleanup.
Each implementation slice follows RED → minimal GREEN → targeted tests → fresh
independent security review → full ordinary regression → required exact-head
Level-3 → merge → exact merge-main CI/Level-3 → cleanup.

Authority bootstrap has an explicit exception only for unavailable **new**
target evidence: existing exact-head Level-3 must remain green before its merge;
the merged authority is then verified and only later certifies the 7B1 target.
No authority merge is counted as target sandbox proof. Phase 7B1 is not complete
until the target's new mandatory matrix and existing five fixtures pass on exact
head and merge-main, with no Critical/Important review finding or cleanup debt.

Rollback disables the new reference service, verifies stop, and preserves the
database/key. It does not switch to a less restricted service automatically or
re-create approvals. Local durable storage remains trusted service authority,
not protection against root or a compromised Ledger itself.

## 9. Design preparation evidence

- Main/worktree baseline clean; supported Linux CI `37399768171` succeeded at
  baseline `a37747291894ac7b01ae5483af83d0dd89821015`.
- Eight runtime/Phase-7A evidence tests pass locally with short
  `--basetemp=/tmp/som7b1-design-baseline`. The initial Mac default temporary path
  exceeded the Linux AF_UNIX limit; only the harness temporary path changed.
- No runtime, systemd unit, production identity, guest authority, or secret has
  been changed by this design preparation.

## 10. References

- [Development methodology](../../development-methodology.md)
- [Security model](../../security-model.md)
- [Audit and approvals](../../audit-and-approvals.md)
- [Phase 5 Ledger design](2026-10-01-phase-5-security-ledger-design.md)
- [ADR 0008](../../decisions/0008-level3-e2e-no-network-guest.md)
- [systemd execution settings, upstream source](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)

Upstream documentation informs the proposed settings and caveats. Installed
guest properties and behavior, not upstream version assumptions, prove them.
