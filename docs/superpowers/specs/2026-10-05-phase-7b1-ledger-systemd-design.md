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
to fit systemd defaults. Product scope is deployment, documentation and tests;
any selected behavior-preserving provisioning-primitive extraction is a separate
preparatory RED/GREEN slice. A demonstrated production defect needs its own RED
and reviewed fix.

## 3. Deployment ownership and process identities

The reference uses static operator-provisioned Linux accounts. `User=` and
`Group=` select the dedicated non-root Ledger identity; `SupplementaryGroups=`
contains exactly the two endpoint groups, with the primary group excluded when
checking the runtime identity. Ledger primary GID, execution endpoint GID and
admin endpoint GID MUST be pairwise distinct, so the Ledger has exactly two
supplementary groups. The execution client MUST NOT belong to the admin endpoint
group, and the admin client MUST NOT belong to the execution endpoint group.
None may have unexpected account memberships. Preflight checks configured IDs
and account-database memberships; the exact runtime group check still applies.
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
| Configuration parent | `/etc/ssh-over-mcp` | Root:root 0755; trusted ancestors | Traverse to private key directory |
| Non-secret configuration | `/etc/ssh-over-mcp/ledger.env` | Root:root 0600; trusted parents | Read by systemd before identity drop |
| HMAC key directory | `/etc/ssh-over-mcp/ledger-key` | Ledger:Ledger 0700; root-owned outer parent | Read-only in sandbox |
| HMAC key | `/etc/ssh-over-mcp/ledger-key/hmac.key` | Ledger:Ledger 0400; exactly 32 bytes | Read-only; never environment/argv |
| Database directory | `/var/lib/ssh-over-mcp-ledger` | Ledger:Ledger 0700 | Writable DB/WAL/SHM only |
| Execution socket directory | `/run/ssh-over-mcp-ledger-exec` | Ledger:execution-group 0750 | Writable for Ledger; client traverse |
| Admin socket directory | `/run/ssh-over-mcp-ledger-admin` | Ledger:admin-group 0750 | Writable for Ledger; admin traverse |
| Two endpoint sockets | Each directory's `ledger.sock` | Ledger:corresponding-group 0660 | Filesystem permission plus exact SO_PEERCRED |

This is a fresh-install reference. The existing `ssh-over-mcp-ledger-init`
bootstrap requires key and database to share one parent directory and therefore
cannot provision this split layout unchanged. The operator checklist must
explicitly provision/check these paths and a new 32-byte key without printing
key bytes or overwriting an existing key. Existing container/bootstrap behavior
is unchanged; bootstrap redesign, moving an existing key/database, and key
rotation remain separate work.

### HMAC key provisioning contract

The fresh-install key operation MUST:

- Generate exactly 32 bytes with a CSPRNG equivalent to `secrets.token_bytes(32)`.
- Before generation, apply zero hard/soft core limits and verify the no-core
  host condition for every key-handling provisioning/helper process, not just
  the later Ledger service; no helper may first generate a key and only then
  disable crash-memory collection.
- Validate canonical non-symlink trusted parent/ancestors, exact Ledger UID/GID
  and private directory permissions before creation, with no active Ledger
  instance using/changing that provisioning state.
- Use `O_CREAT|O_EXCL`, `O_NOFOLLOW` and close-on-exec. Any existing path makes
  new-key creation fail, even an apparently valid key; never repair or replace it.
- Establish a private mode at creation, set/verify exact Ledger UID/GID and final
  mode 0400 through the open descriptor, and reject unexpected type, inode/path
  replacement, owner, mode or ancestor state.
- Complete all 32 bytes despite short writes; fsync file and parent directory
  before reporting success. Write/chown/chmod/fsync/validation failure is failure,
  never ordinary success. A partially created run-owned file needs explicit
  verified recovery; unknown existing state is never normalized or overwritten.
- Keep key bytes out of argv, environment, stdout/stderr, logs, exception text,
  review artifacts and temporary shell files. Verify secure metadata, exact
  length and readability by Ledger before first service use.

The implementation plan must first evaluate extracting/reusing the reviewed
exclusive-create/complete-write primitive in `approvals/bootstrap.py` rather
than introduce an independent shell recipe. Preserve current bootstrap's
validated-existing-key behavior for its existing layout; strict new-key refusal
is a separate operation. Any shared-primitive refactor is a small reviewed
RED/GREEN slice proving unchanged legacy behavior. Guest root uses only an
already-merged trusted helper with fixed fixture paths/identities, never the
same target's bootstrap/helper code imported as root.

The root-owned environment file contains only the existing
`SSH_OVER_MCP_LEDGER_*` settings. Numeric identities and paths must match the
provisioned layout. The configured `EXEC_PEER_UID/GID` and `ADMIN_PEER_UID/GID`
are trusted server-side peer policies, not client-supplied identity assertions.
Secret key bytes, loader hooks, source paths, and request-supplied identity
assertions are not environment-file contents. Fixed private paths
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
| Filesystem | `ProtectSystem=strict`, `ProtectHome=yes`; persistent/shared writable exceptions exactly the database and two socket directories; key/runtime remain read-only |
| Device/kernel | `PrivateDevices=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes` |
| Network | `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`; no inherited network socket or socket unit |
| Other namespaces | `RestrictNamespaces=yes`; no namespace creation or network namespace reassociation |
| Execution | `SystemCallArchitectures=native`; `RestrictSUIDSGID=yes`, `LockPersonality=yes`, `RestrictRealtime=yes`; bytecode writes disabled |
| Async syscall bypass | `SystemCallFilter=~io_uring_setup io_uring_enter io_uring_register`; `SystemCallErrorNumber=kill` explicitly preserves SIGSYS denial |
| Crash memory retention | `LimitCORE=0:0` plus verified non-pipe `kernel.core_pattern`; core policy checked before service or denial helpers start |
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

### Verified recovery after forced stop

Acceptance must prove this complete fixed sequence:

1. Before the fault, trusted bookkeeping records run-owned endpoint
   device/inode/type/ownership, key identity and committed audit/approval state.
   An authorized slow-trickle client then forces final SIGKILL. Verify stopped
   unit, empty service cgroup and no process of the dedicated Ledger identity;
   preserve stale sockets.
2. An explicit start attempt refuses the stale endpoints and leaves no service
   process. `Restart=no` prevents an automatic restart/recovery loop.
3. Trusted operator/test recovery independently proves no active socket owner
   using bounded process/socket checks across relevant guest namespaces. Failed
   or inconclusive ownership checks block recovery. Match the fixed path and
   metadata to the pre-fault run-owned record and revalidate parent identity;
   replaced inode/type/owner is preserved and reported, never silently deleted.
4. Exclude concurrent starts and remove only the verified original stale
   endpoint through a pinned trusted parent, rechecking identity at removal.
   No glob, directory/database/key deletion or target-selected path is allowed.
5. Restart the fixed unit and require authenticated ping, clean real database
   open with unchanged HMAC key, preserved committed audit and approval states.
   Natural Ledger-owned expiry may advance; recovery cannot extend TTL, resurrect
   consumed grants or fabricate audit/approval state.
6. Cleanly stop and verify listener/process cleanup. Negative recovery cases
   with an active owner, replaced endpoint or inconclusive inventory must refuse
   removal and preserve state.

Recovery remains fixed, bounded, trusted test/operator action, never automatic
production recovery, an `ExecStopPost=` deletion hook or a target-accessible
privileged RPC. Unit failure alone does not authorize socket deletion. Production
instructions require the same owner/provenance checks; database/key repair and
unknown-state recovery are outside this procedure.

### Crash collection is a deployment precondition

The first reference supports only an effective non-pipe `kernel.core_pattern`
and hard/soft core limits of zero. Linux ignores RLIMIT_CORE for a pipe collector,
so the unit setting alone is insufficient. A pipe collector, including apport
or systemd-coredump, makes this initial deployment ineligible; an exception needs
separate reviewed proof covering memory processing, temporary/unlinked writes,
backtraces and journal retention. No collector exception is silently accepted.

Preflight verifies the effective kernel setting and service limits before the
Ledger can load its key and before any SIGSYS-producing helper. The operator
must provision this host condition explicitly; this slice does not install a
generic host-global policy mutator. The separate trusted authority may establish
and verify a fixed non-pipe core policy inside its fresh disposable guest only,
before starting target processes. It must not change the persistent Mac or an
operator's production host. A changed condition requires deployment revalidation.

Separate same-profile canary processes hold a memory-only secret sentinel and
exercise SIGABRT/SIGSEGV as well as the SIGSYS denial path. Verify termination,
effective no-core policy and absence of core bodies/backtraces/sentinel bytes
in run-owned paths and applicable journal/crash locations. Scans supplement the
effective-policy proof; absence after cleanup does not prove that a collector
never processed or temporarily stored memory. Keep core limits zero for other
target guest children too when establishing a guest-wide core-pattern policy.
Forced/fault termination does not authorize automatic socket removal or restart.

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
capabilities, core limits and sandbox properties, along with the no-core host
precondition. Unexpected merged configuration or an
already-running/pre-existing fixture unit fails closed. Only an explicitly
selected diagnostic phase may use the fixed trusted entrypoint adapter; its
effective configuration is checked separately. Mandatory installed-runtime
acceptance permits no entrypoint override. No target root command may execute
before these checks.

The production unit assumes a preinstalled application package. A source-only
adapter may provide intermediate diagnostics after identity drop, but cannot
satisfy final reference-deployment acceptance. The mandatory 7B1 guest proof
runs a real installed non-editable artifact at `/opt/ssh-over-mcp/venv` with the
exact production command/profile, actual imports, identity/groups and immutable
runtime permissions. Separate source-adapter and unsandboxed-wheel successes
cannot substitute for this composition proof.

Trusted guest setup provisions the fixed construction prefix and a distinct
non-root builder identity. As that identity, build the exact target wheel and
install it non-editably into a clean venv **at its final fixed prefix**, offline
with already-trusted locked dependencies/build inputs. No target build backend,
installer, application module or helper executes as root. No download, host
mount or production secret enters the guest.
Before any target backend/installer call, trusted setup applies the existing
exact-identity/groups drop, zero effective/permitted/inheritable/ambient
capabilities and NoNewPrivileges contract to the builder and descendants.
The authority prerequisite must already contain the hash-locked build-tool
inputs and offline payload preparation; the persistent orchestrator may fetch
those trusted wheels but never executes the target build/backend itself.

Before start, trusted setup quiesces the run-owned builder and descendants,
verifies no writer remains, attests artifact/dependency manifests, interpreter
lineage, venv configuration, module origins and absence of editable/source hooks,
and seals the runtime root-owned/non-writable by builder, Ledger or clients.
Dependency expectations come from already-trusted hash-locked wheelhouse inputs;
a candidate-generated RECORD/manifest alone is not attestation. The target wheel
and installed tree are bound to the exact target input/build provenance and
trustedly measured content, without treating their code as root authority.
Sealing is filesystem handling only, never root execution of an artifact or
target validation script. Check regular files/directories and reject special
files, hard-link aliases, unexpected setuid/setgid or file-capability metadata,
unsafe symlinks and ancestor changes; retain only
explicitly trusted interpreter/runtime links. A surviving writer, race or
attestation mismatch fails closed instead of recursively repairing untrusted
paths. Construction/runtime state is fixed, run-owned and disposable; no
relocated-prefix compatibility assumption is allowed.

Start the exact production ExecStart under the canonical profile with no
entrypoint override. Require authenticated ping, normal stop, restart, sandbox
enforcement and the complete forced-stop/recovery sequence. Module-origin checks
run after identity drop and source paths cannot assist application imports.
Source-adapter evidence is recorded separately, never as installed-runtime PASS.

Trusted setup orchestrates start, client phases, stop, restart and cleanup with
fixed unit/path names. A non-root target client probe receives no systemctl
authority. Separate sandbox test processes use the same profile and fixed test
paths to attempt forbidden operations; production Ledger gains no diagnostic
opcode. Root setup accepts no arbitrary privileged RPC or target-selected
unit, command, path, UID/GID, or directive. An absent target 7B1 probe during
authority bootstrap is explicitly legacy-only evidence; after activation the
7B1 target acceptance run must require it, not conditionally skip it.

The trusted host workflow/gate selects and records `legacy-7a` versus
`ledger-systemd-7b1` acceptance mode. A target file's presence, contents, exit
code or environment cannot choose or downgrade that mode. Exact-head/merge-main
7B1 certification explicitly requires the latter mode and its complete fixed
matrix in the commit-bound result; a deleted, renamed, missing or failing probe
must fail. Legacy bootstrap results cannot be presented as 7B1 acceptance.

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
| Installed-package/systemd composition | Exact-head non-root wheel build/install; editable hooks, mutable runtime or unsafe sealing rejected | Exact production command at fixed venv prefix under canonical profile; module origins, ping, stop/restart and sandbox matrix PASS |
| HMAC provisioning | CSPRNG exclusive create; short-write/durability failures, existing paths, symlinks and metadata races rejected; legacy bootstrap preserved | Trusted fixed provisioning, exact private owner/mode/length, durable create and no key bytes in outputs |
| Execution/admin separation | Pairwise-distinct GIDs, cross-membership and unexpected memberships rejected; wrong-peer/cross-operation regressions | Independent DAC denial in both cross-directions; real client/approvalctl identities; separate SO_PEERCRED rejection with controlled DAC reachability |
| Network restriction | Missing restriction or allowed INET/INET6 rejected | IPv4/IPv6 socket creation, raw socket, and namespace bypass attempts denied |
| Syscall bypass restriction | Removing any io_uring denial or native-architecture restriction rejected | One isolated helper per `io_uring_setup`, `io_uring_enter`, and `io_uring_register`: restricted SIGSYS versus documented kernel result in fixed differential control; kernel/process ABI attested as pinned x86_64/native |
| Read-only runtime/key | Wider write exception rejected; sacrificial-file differential controls | Actual runtime/key read-only mount state; service-writable canary fails only under read-only boundary; allowed DB write succeeds; non-private-temp outside-root writes denied |
| Kernel/cgroup protection | Weakened protected paths rejected; safe effective-state checks | Device exposure and kernel/cgroup mount restrictions attested, harmless denied operations and zero capabilities; DAC-only denial not mislabeled as per-layer proof |
| Normal shutdown | Existing close/restart checks retained | SIGTERM with a paused partial frame closes within the stop deadline; no process/socket leak; clean restart works |
| Forced-stop and verified recovery | No automatic deletion/restart; active-owner/replaced-inode/inconclusive checks refuse recovery | Slow-trickle→SIGKILL→no process→stale start refused→trusted owner/provenance check→only original socket removed→restart/ping; key, committed audit and approval states preserved |
| Approval invariants and secrets | Exact binding, consume/replay, policy deny, retention regressions | Real CLI pending→grant→consume; replay/binding rejection; scans of transcript/journal/storage |
| Crash secret retention | Hard/soft core limits and non-pipe host precondition mandatory; pipe collectors rejected before start | SIGABRT/SIGSEGV/SIGSYS same-profile memory canaries; no core body/backtrace/sentinel retention; effective-policy proof before crashes |
| Existing Phase 7A | Fixed five-fixture order contracts unchanged | Full five-fixture PASS with STOP_MANAGER last |
| Exact revision and cleanup | Trusted-main workflow/bundle contracts retained; probe removal cannot downgrade acceptance mode | Exact head/merge CI + mandatory 7B1 E2E mode/matrix; provider absence, guest/VM destruction |

Denial probes compare allowed and forbidden operations under the same effective
profile. A failure caused by an unrelated file permission or missing syscall is
not evidence that the intended sandbox layer works. Client readiness checks are
bounded and non-blocking; no arbitrary delay, skipped probe, relaxed assertion,
or retry of approval consumption is permitted.

Distinguish end-to-end denied operations from attribution to a particular layer.
For read-only filesystem proof, trusted setup provides a harmless service-owned
writeable canary in a protected mount and a fixed control changing only that
read-only boundary. Confirm the real runtime/key mount state separately; never
chmod, overwrite or weaken permissions on actual runtime/key material merely to
obtain a positive control. For device/kernel/cgroup protection, attest effective
device/mount state and use harmless established-return checks where possible.
Do not mutate live kernel controls or give the production Ledger writable cgroup
delegation to manufacture a test. If attribution cannot be proved, report that
limit and block that criterion rather than substituting an unrelated denial.

The unit deliberately has writable private `/tmp` and `/var/tmp` through
`PrivateTmp=yes`. They are excluded from the persistent/shared write-exception
count and outside-root write-denial criterion. Their isolation, non-persistence
and lack of credential contents must be verified. They are not database/key or
cross-service communication roots.

Packaging acceptance requires a wheel built from the exact head **as non-root**,
installed non-editably with the locked runtime dependencies into a fresh venv.
Remove its temporary source/build staging, clear import/loader hooks, use an
unrelated clean cwd and isolated interpreter, and verify application and
installed third-party module origins reside inside that venv rather than the
source checkout. Standard-library, built-in and frozen modules may use the
trusted base interpreter's normal locations. Start the real installed
`-I -B -m ssh_over_mcp.approvals.main` process with safe temporary state, prove
authenticated ping and SIGTERM cleanup. Do not claim the whole ordinary runner
checkout is inaccessible merely because it is absent from import paths. This
proof is an early packaging regression and does not replace mandatory real
installed-artifact-under-systemd proof. Distinct-peer and sandbox proofs remain
the real guest matrix. No target build/install runs as root and no
privileged access is added to ordinary CI.

The io_uring probes must use the attested native syscall ABI and valid arguments
or established kernel error controls, not unexplained magic syscall numbers.
For each syscall, an isolated helper uses a fixed trusted comparison profile
which changes only that syscall's filter boundary and establishes kernel entry.
Compare restricted SIGSYS against the documented kernel result and inspect
effective seccomp state. The control need not create a working ring: an
established kernel EPERM (including kernel-wide io_uring disablement), EINVAL or
EBADF can discriminate against filter-produced SIGSYS. Missing syscall/ABI
support, unexplained argument errors, a control killed by another filter, or
identical results do not count as proof. Kernel-wide disablement alone is not
filter evidence. No-core preflight precedes these helpers. If the
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
head and merge-main using the actual installed artifact and production ExecStart
under the same systemd profile, including forced-stop/verified-recovery and
unchanged-key/audit/approval state. The early installed-wheel regression also
passes for those revisions on supported Linux. No Critical/Important review
finding or cleanup debt may remain.

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
- Review revisions also pass 31 existing runtime/bootstrap/storage/Phase-7A
  evidence tests with `--basetemp=/tmp/som7b1-review`. This is baseline evidence,
  not certification of the proposed systemd, provisioning or recovery matrix.
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
