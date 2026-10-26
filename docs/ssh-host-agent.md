# Remote SSH host agent

## Purpose

The host agent is the second enforcement boundary. It prevents a compromised or misconfigured control plane from converting a dedicated MCP SSH credential into an unrestricted shell credential.

## OpenSSH entry point

A dedicated account should be configured with an authorized key or SSH certificate principal that forces the host agent, for example:

```text
restrict,command="/usr/local/libexec/ssh-over-mcp-host-agent" ssh-ed25519 AAAA...
```

Equivalent `sshd_config` `Match User` / `ForceCommand` configuration may be used.

## Required SSH restrictions

Unless a capability explicitly needs otherwise:

- no agent forwarding;
- no local/remote TCP forwarding;
- no X11 forwarding;
- no tunnel device forwarding;
- no user-controlled SSH environment;
- no PTY for structured operations;
- no arbitrary `.ssh/rc` behavior.

The Phase 2 client additionally disables ambient SSH configuration, ssh-agent authentication, password authentication, keyboard-interactive authentication, host-based authentication, GSS authentication/key exchange, PTY allocation, X11 forwarding, and SSH environment forwarding for structured operations.

### Phase 7A planned capability handoff

ADR 0005 requires the production host agent to remain non-root while holding only `CAP_SETUID` and `CAP_SETGID` so its contained child can irreversibly transition to the distinct workload identity. Existing live probes establish that identity transition, but a plain sshd ForceCommand starts under the dedicated SSH account and does not itself supply those capabilities.

ADR 0007 defines the Phase 7A deployment bridge. A production managed host uses one fixed, operator-installed, root-owned, no-argument capability launcher as the exact ForceCommand sudo target. The Phase 7A E2E installs the exact target commit's launcher at that fixed path only inside the fresh disposable Linux guest defined by ADR 0006. In either case, the launcher may be root only during the bounded identity/capability transition. Before any `ssh_over_mcp` application module is imported or executed it must:

1. validate exact `SSH_ORIGINAL_COMMAND=mcp-v1` and reject PTY use;
2. while still root, move only the current ForceCommand launcher process into the fixed `host-agent-source` cgroup beneath the delegated root and verify the exact unified cgroup-v2 membership;
3. establish the exact host-agent UID/GID and manager-client supplementary group;
4. retain only `CAP_SETUID` and `CAP_SETGID` in effective/permitted sets;
5. require zero inheritable/ambient capabilities and no other Linux capability;
6. read back and verify the resulting state.

Only after those checks may it enter `ssh_over_mcp.host_agent.cli`.

The launcher accepts no argv and no caller-selected identity, capability, module path, policy path, or manager endpoint. On a production managed host its installed copy and sudo rule are operator-owned outside the writable application checkout. In Phase 7A E2E, target code is allowed to install/run this root-capability path only inside a disposable VM with no host mounts, GitHub token, or production secrets; the whole VM is destroyed after the run. This design is approved for Phase 7A but is not implemented until the corresponding 7A implementation slice lands.

## Host-key validation

The control plane connects to the server-owned inventory address while validating the host key against the inventory alias.

For each connection it constructs an in-memory `known_hosts` entry:

```text
<inventory-alias> <key-type> <base64-public-key>
```

and connects with that alias as the host-key lookup name. Unknown, malformed, or changed host keys fail closed.

Host aliases are restricted to letters, digits, `.`, `_`, and `-` so they cannot inject `known_hosts` patterns.

## Phase 2 host-agent wire protocol

Structured execution uses a fixed SSH exec command:

```text
mcp-v1
```

The executable, argv, cwd, environment, resource limits, and stdin are **not** embedded into that SSH command string.

Instead, stdin on the SSH channel contains:

```text
+----------------------+-----------------------------------------------+
| field                | encoding                                      |
+----------------------+-----------------------------------------------+
| magic                | 6 bytes: 53 4d 43 50 00 01 ("SMCP" + v1)      |
| metadata length      | 4-byte unsigned big-endian integer            |
| metadata             | UTF-8 JSON ExecEnvelope                       |
| application stdin    | remaining bytes                               |
+----------------------+-----------------------------------------------+
```

Metadata is limited to 64 KiB. The envelope defines bounded stdin, output, and execution time limits.

Conceptual metadata:

```json
{
  "version": 1,
  "request_id": "req_01...",
  "operation": "exec",
  "profile": "developer",
  "executable": "/usr/bin/git",
  "argv": ["status", "--short"],
  "cwd": "/srv/projects/app",
  "env": {},
  "limits": {
    "timeout_seconds": 60,
    "max_output_bytes": 1048576,
    "max_stdin_bytes": 1048576
  }
}
```

This framing has two important properties:

1. executable/argv/environment values are not shell-parsed by the SSH client path;
2. sensitive environment values are not placed in `SSH_ORIGINAL_COMMAND`.

The host agent MUST validate the fixed protocol command and parse the frame from stdin.

## Execution

Structured command execution MUST use an `execve`-equivalent path with a concrete executable and argv. The host agent MUST NOT turn structured execution into `sh -c`.

The central control plane MUST obtain an allow decision before opening the SSH connection for an operation.

## Resource handling

The Phase 2 client:

- shares one configured output-byte budget across stdout and stderr;
- closes the SSH channel when the output budget is exceeded;
- applies a wall-clock timeout;
- aborts the remote channel on caller cancellation;
- never requests a PTY for structured execution.

The remote host agent in Phase 3 MUST enforce its own limits independently. Client-side limits are not a substitute for server-side resource enforcement.

## Host-local policy

The host agent maintains a second policy boundary on each managed host. The default policy path is:

```text
/etc/ssh-over-mcp/host-policy.yaml
```

The policy file MUST be opened without following symlinks, MUST be a regular file, MUST be root-owned in production, and MUST NOT be group- or world-writable. The implementation bounds the policy file size and rejects duplicate YAML keys.

Phase 3c introduced host-policy schema version 2. Phase 3d2b2b1 upgrades the active host policy to **version 3**, retaining the per-command rules below and adding required child resource ceilings. Each command policy binds:

- an exact requested executable path;
- an expected canonical filesystem realpath;
- one or more token-based argv rules (`exact` or non-empty `prefix`);
- canonical allowed cwd roots, or an explicit no-cwd allowance;
- whether the resolved executable must be root-owned;
- whether group/world-writable executables may be accepted;
- whether setuid/setgid bits may be accepted;
- whether Linux file capabilities may be accepted.

Global host policy also constrains:

- exact allowed server-side profiles;
- allowed environment-variable names;
- hard-denied loader/runtime environment variables;
- maximum execution timeout requested by the control plane;
- maximum output budget requested by the control plane;
- maximum stdin budget requested by the control plane.

The host agent MUST apply metadata/resource checks before reading application stdin. A client cannot increase host limits by declaring larger limits in the request.

Executable authorization resolves the requested path and requires it to match the configured canonical target. The target MUST be a regular executable file and is root-owned/non-group-world-writable by default. Setuid/setgid binaries and executables carrying Linux file capabilities are also denied by default and require explicit policy opt-in. Working directories are resolved with symlinks and MUST remain beneath an explicitly configured canonical root.

`exact` argv rules are the safer default. A `prefix` rule authorizes every trailing token after the configured prefix and MUST only be used when that wider argument surface is intentionally acceptable; it does not interpret shell syntax or constrain command-specific path/helper semantics.

Authorization records canonical executable/cwd paths. Executable identity uses device+inode+ctime+mtime+size plus a SHA-256 content digest; cwd replacement identity uses device+inode because directory metadata changes during ordinary content updates.

### Phase 3d1 fd preparation

Before application stdin is accepted, the host agent re-runs host authorization and requires the filesystem identities to match the first authorization result. It then opens the canonical executable and cwd using no-follow/close-on-exec flags, validates the opened objects with `fstat()`, and keeps the descriptors pinned until the request completes.

The executable descriptor is independently rechecked for:

- the authorized device/inode/ctime identity;
- regular-file type;
- required ownership;
- group/world write restrictions;
- setuid/setgid restrictions;
- Linux file capabilities using the opened fd;
- executable mode bits.

The cwd descriptor is independently checked for the authorized device/inode identity and directory type. Directory ctime is intentionally not part of execution identity because legitimate creation/removal of children changes directory ctime without replacing the directory object.

This closes pathname replacement between authorization and later execution: a renamed or substituted pathname does not change the already opened object. Executable change identity combines device/inode/ctime/mtime/size with a SHA-256 digest captured from a securely opened descriptor. Fresh authorization and pinned-fd revalidation recompute that digest, so persistent same-inode content mutations are rejected even when size or timestamp metadata does not distinguish them. The child rehashes the pinned executable fd again immediately before native exec. This is still not an atomic immutability mechanism against a privileged writer racing mutations during the final verification/exec boundary; the execution profile must therefore retain trusted ownership and write restrictions.

The preparation layer records whether Python reports fd-based `os.execve()` support and classifies the opened file as ELF, shebang script, or other.

### Phase 3d2a native exec primitive

The first execution primitive is deliberately restricted to native ELF files. It consumes a `PreparedCommand` and:

1. requires fd-based `os.execve()` support;
2. requires the prepared executable format to be ELF;
3. requires a pinned cwd rather than inheriting the host-agent cwd;
4. revalidates executable device/inode/ctime/mtime/size and SHA-256 content immediately before exec;
5. revalidates cwd device/inode immediately before exec;
6. constructs `argv[0]` as descriptive metadata while selecting the executable solely by fd;
7. passes only the explicit, host-policy-authorized request environment and does not merge `os.environ`;
8. enters the pinned cwd using `fchdir()`;
9. invokes `os.execve(executable_fd, argv, env)` directly.

There is no shell, command-string parsing, PATH lookup, or executable pathname reopen in this primitive.

The primitive MUST only be called in a disposable child process because `fchdir()` mutates process state if exec subsequently fails. Phase 3d2a intentionally does not reset signal handlers/masks, umask, rlimits, groups, or unrelated inherited file descriptors, and it does not install stdin/stdout/stderr pipes. Those are supervisor responsibilities in Phase 3d2b.

Phase 3d2a is not wired into the ForceCommand CLI, so remote requests remain non-executing.

### Phase 3d2b1 child supervisor skeleton

The first supervisor increment requires parent fd 0/1/2 to already be open, validates the native exec spec before forking, then creates three `O_CLOEXEC` pipes and forks a disposable child. This precondition prevents pipe allocation from colliding with stdio target descriptors. The child:

1. creates a new session/process group with `setsid()`;
2. clears the blocked signal mask and resets catchable signals to default handling;
3. sets `umask 077`;
4. disables core dumps with `RLIMIT_CORE=0`;
5. wires stdin/stdout/stderr using `dup2()`;
6. closes unrelated file descriptors, preserving only fd 0/1/2 plus the pinned executable and cwd descriptors;
7. invokes the Phase 3d2a fd-exec primitive.

If child setup or exec fails, the child writes only a fixed generic diagnostic and exits with code 125; internal exception details are not written to the SSH-visible stderr stream.

The parent receives a PID and three parent-side pipe descriptors. This increment intentionally does not provide wall-clock timeout, output-byte accounting, process-group termination escalation, CPU/memory/process-count rlimits, or final request/response integration.

The supervisor is still not wired into the ForceCommand CLI, so remote requests remain non-executing.

### Phase 3d2b2a bounded parent loop

The bounded runner consumes a prepared command, application stdin, and the already-authorized `ExecutionLimits`. Before spawning it rejects stdin larger than `max_stdin_bytes`. It then uses nonblocking parent-side pipes and a selector loop to simultaneously feed stdin and drain stdout/stderr.

The parent enforces:

- a wall-clock deadline from `timeout_seconds`;
- one shared capture budget across stdout and stderr from `max_output_bytes`;
- capture truncation at exactly that combined budget;
- immediate stdin closure when timeout/output termination begins;
- SIGTERM to the child process group;
- SIGKILL after a short grace period;
- bounded post-kill drain/cleanup;
- nonblocking direct-child reaping within a cleanup deadline.

The runner never converts the cleanup deadline back into an unbounded blocking wait. If a SIGKILLed direct child still cannot be reaped within the cleanup window (for example, pathological uninterruptible kernel sleep), execution fails closed instead of indefinitely blocking the host agent.

The result records the process return code, captured stdout/stderr, whether the wall timeout fired, whether the output budget was exceeded, and elapsed duration.

Process-group termination is a cleanup boundary, not a full sandbox. A program which deliberately creates a new session/process group can escape later group signals. Before high-risk/arbitrary-code workloads are enabled, stronger OS containment such as a dedicated cgroup/systemd scope or equivalent sandbox remains required.

### Phase 3d2b2b1 host-local child rlimits

Host-policy version 3 requires an explicit `child_limits` block. These values are server-owned hard ceilings and are bound into the prepared command so the execution supervisor cannot accidentally omit them:

- `cpu_seconds` → `RLIMIT_CPU`;
- `address_space_bytes` → `RLIMIT_AS`;
- `max_processes` → `RLIMIT_NPROC`;
- `file_size_bytes` → `RLIMIT_FSIZE`;
- `open_files` → `RLIMIT_NOFILE`.

The child applies these limits after stdio setup and unrelated-fd cleanup, immediately before the fd-based exec primitive. For every resource, the effective value is the minimum of the configured host-policy ceiling and the inherited hard limit; the child never raises an inherited hard limit. Core dumps remain unconditionally disabled with `RLIMIT_CORE=0`.

These rlimits are defense-in-depth rather than complete isolation:

- `RLIMIT_NPROC` is scoped to the real UID and is not a per-request process container; privileged/root semantics can also weaken its usefulness;
- `RLIMIT_FSIZE` limits regular-file growth, not bytes written to stdout/stderr pipes;
- `RLIMIT_AS` limits virtual address space and may cause allocations or dynamic loading to fail before the configured number is fully consumed;
- rlimits do not stop descendants from deliberately escaping a process group.

The parent combined-output budget remains the stdout/stderr control. Strong descendant containment still requires a cgroup/systemd scope or equivalent sandbox before high-risk arbitrary-code profiles are enabled.

Phase 3d2b2b1 is not wired into the ForceCommand CLI.

### Phase 3d2b2b2a descendant-containment contract

Rlimits and process-group signaling are retained as defense-in-depth, but descendant containment is modeled as an independent mandatory execution boundary.

The backend-neutral contract defines one containment scope per request:

1. create a scope from a validated request and finite containment limits;
2. attach the initial child before it is released to exec;
3. allow descendants to inherit the same containment subtree;
4. provide a recursive `kill_all()` operation which kills the scope subtree rather than only one PID/process group;
5. expose best-effort memory/PID/CPU accounting;
6. clean up the empty scope deterministically.

Containment limits are deliberately separate from rlimits because their semantics differ. The current contract expresses finite memory, PID and CPU quota/period ceilings and does not invent implicit production defaults.

A read-only cgroup-v2 probe checks for a unified hierarchy and the `cpu`, `memory`, and `pids` controllers. This probe does **not** prove delegation/write access or `cgroup.kill` availability; the concrete backend must prove those properties when it creates a real scope.

### Phase 3d2b2b2b1 concrete cgroup-v2 backend

The first concrete containment backend operates only inside a server-configured,
already delegated, canonical cgroup-v2 subtree. It does not search for or write
outside that root.

Before creating a request scope it requires the `cpu`, `memory`, and `pids`
controllers to be available and enabled for child cgroups. If a required
controller is available but not yet enabled, the backend writes the
corresponding `+controller` tokens to the delegated root's
`cgroup.subtree_control` and verifies the result.

For each request it creates exactly one child cgroup named from the validated
request ID and configures:

- `memory.max` from `memory_max_bytes`;
- `pids.max` from `pids_max`;
- `cpu.max` from `cpu_quota_us cpu_period_us`.

The backend reads each configured limit back and fails closed if the kernel did
not apply the requested finite value. It also requires writable
`cgroup.procs` and `cgroup.kill` interfaces.

The handle:

- attaches one initial child by writing its PID to `cgroup.procs`;
- recursively terminates the request cgroup and descendants by writing `1` to
  `cgroup.kill`;
- reads memory, PID, CPU-usage and populated-state accounting;
- refuses cleanup while `cgroup.events` reports `populated 1`;
- removes the empty cgroup deterministically.

### Phase 3d2b2b2b2 containment start barrier

A separate contained-spawn path now connects the supervisor to any
`ContainmentBackend` without changing the existing uncontained internal spawn
primitive.

The contained path enforces this order:

1. validate the prepared native-exec specification;
2. require the containment request ID to equal the prepared command request ID;
3. create/configure the containment scope;
4. create stdio pipes plus a dedicated `O_CLOEXEC` start-barrier pipe;
5. fork;
6. in the child, close parent-owned pipe endpoints and block reading one barrier byte;
7. in the parent, attach the child PID to the containment scope;
8. only after successful attach, write the single release byte;
9. child continues with session/signal/stdio/rlimit setup and fd-based exec.

No untrusted executable runs before containment attachment succeeds.

If attach or barrier release fails, the parent never sends a valid release
byte. Cleanup closes the barrier, attempts recursive containment kill, falls
back to direct `SIGKILL` for pre-attachment failures, performs bounded reap,
and closes the containment scope. Unexpected backend cleanup exceptions do not
skip direct child SIGKILL, bounded reap, or the scope-close attempt; any such
exception makes cleanup fail rather than reporting success. The failed child
therefore cannot continue into the exec path.

For the proposed OCI-only `PidfdContainmentHandle`, the parent opens a live
child pidfd while the barrier remains closed, calls `attach_pinned(pidfd)`,
and closes its descriptor before release. Pin or adapter failure invokes the
same cleanup path; it must never fall back to integer-PID attach. This does
not supply an OCI cgroup writer or authorize deployment.

A successfully spawned child retains its containment handle.

### Phase 3d2b2b2b3 containment-aware bounded execution

The bounded execution loop now requires an explicit containment backend and
request and always enters through the contained-spawn path.

Timeout/output termination keeps a short graceful phase using process-group
`SIGTERM`. After the grace period, hard termination is containment-authoritative:
the runner invokes recursive `kill_all()` on the request scope and then attempts
process-group `SIGKILL` only as defense-in-depth. A process-group signaling
failure does not convert a successful containment kill into a false failure.

Normal direct-child exit does not imply request completion. Before returning,
the runner reads containment accounting. If the request scope is still
populated, it recursively kills remaining descendants, waits for the scope to
become empty within a bounded cleanup deadline, then removes it. The returned
execution result includes the final containment accounting snapshot.

This mechanism has an additional deployment invariant: untrusted workload code
MUST NOT have write access to an ancestor cgroup membership interface which
would let it migrate out of the request scope. In particular, a deployment
where the workload can write an ancestor `cgroup.procs` is not considered
escape-resistant containment. Production deployment must keep cgroup control
interfaces unavailable/read-only to the workload or separate the cgroup
manager from the workload privilege domain.

Kernel cgroup-v2 delegation contains a delegatee within its outer delegated
subtree, but the delegatee may reorganize processes inside that subtree.
Therefore request-scope containment is not sufficient when the executed
workload shares the manager's migration authority.

### Phase 3d2b2b2c0 containment privilege separation

Production hostile-workload execution MUST place writable cgroup management in
a separate containment-manager privilege domain. The existing
`CgroupV2Backend` remains the manager-side filesystem implementation, while
the host agent will consume a narrow typed manager/helper interface.

The workload MUST NOT inherit writable ancestor/sibling cgroup membership
controls or reusable manager authority. The existing start barrier remains in
place and the child is released only after manager-confirmed attachment.

Live validation MUST test descendant kill/resource limits and MUST attempt to
move the workload from its request scope into the delegated root. A successful
self-migration is a deployment failure even though the process remains inside
the outer delegated subtree.

### Phase 3d2b2b2c1 containment-manager protocol

The host-agent side now has a `ContainmentManagerClient` which implements the
existing `ContainmentBackend` contract over a narrow versioned protocol.

The protocol is length-bounded and exposes exactly five operations:

1. create a scope from a validated request ID and finite containment limits;
2. attach one positive PID;
3. recursively kill the scope;
4. read accounting;
5. close an empty scope.

It deliberately has no executable, argv, cwd, shell, arbitrary filesystem path,
or generic command field.

A successful create returns a manager-owned scope identifier plus an opaque
256-bit capability generated by the manager. Every subsequent scope operation
requires both values. Capabilities are compared in constant time and remain in
the parent-side handle only; they MUST NOT be copied into workload argv,
environment, audit output, or model-visible responses.

Each request has a message ID and the client rejects an uncorrelated response.
Protocol models use strict JSON types, unknown fields fail closed, frames are
bounded to 16 KiB, and server-side exception/path details are converted into
generic error codes.

Create is transactional: if a backend scope is created but a valid manager
response cannot be completed, the unpublished scope is closed instead of being
left orphaned.

The current `InMemoryContainmentManagerTransport` and dispatcher exist only to
validate framing, capability semantics and lifecycle behavior. They run in one
process and therefore do **not** satisfy ADR 0004 privilege separation.

The production local transport MUST establish a real manager boundary. Any
manager connection/control descriptor inherited across fork MUST be
close-on-exec and unavailable to the executed workload, and transport
authentication/authorization must prevent the workload from opening an
equivalent manager session.

### Phase 3d2b2b2c2a pre-connected Unix transport

The first real transport consumes an already connected
`AF_UNIX/SOCK_STREAM` socket. It intentionally does not accept a filesystem
path and cannot establish a new manager session.

The client:

- forces the socket descriptor non-inheritable;
- serializes manager round trips;
- enforces one total round-trip deadline across send and receive;
- reads exact bounded frames and tolerates normal partial stream reads;
- maps timeout, EOF, truncation, socket errors and invalid manager responses to
  fail-closed manager-unavailable errors;
- permanently closes/poisons the stream after any inbound framing or transport
  failure because the request/response frame boundary can no longer be trusted.

The manager-side connected-session loop consumes the same bounded frames and
terminates the session on malformed/truncated input. It does not create or
accept a socket endpoint.

This is still not the ADR 0004 authentication boundary. A pre-connected FD is
only a transport capability. The next phase must define who creates the
listening endpoint, which OS identity may connect, how Linux peer credentials
are verified, and how the executed workload is placed in a different privilege
domain so it cannot establish its own equivalent session.

The manager socket FD may exist in the forked blocked child before release, but
no untrusted code runs at that point. It is not part of the child keep-set, is
marked non-inheritable, and MUST be closed by the existing child FD sanitation
before `execve`.

### Phase 3d2b2b2c2b1 Linux peer-credential authentication

The pre-connected Unix transport and manager-side connected-session helper now
require an explicit Linux peer credential policy before any protocol traffic is
accepted.

Authentication uses the kernel's `SO_PEERCRED` value captured for the
connected Unix peer. The policy always requires an exact UID and may
additionally require an exact real GID. The peer PID is exposed only as
connection metadata; it is not a durable authorization key because process
lifetime/PID reuse are separate concerns.

A peer mismatch, unavailable `SO_PEERCRED`, malformed credential result or
disconnected socket fails closed. Client-side authentication failure closes the
manager socket immediately; manager-side authentication failure closes the
accepted connection before any request frame is read.

This does **not** by itself satisfy ADR 0004 if the host-agent and untrusted
workload run under the same UID. In that deployment, the workload would present
the same UID to a future manager endpoint. Production therefore MUST use
separate OS identities and endpoint permissions so the workload cannot create
an equivalent authenticated manager session.

### Phase 3d2b2b2c2b2a secure filesystem Unix endpoint

The manager-side endpoint owner creates one pathname AF_UNIX/SOCK_STREAM
listener under a pre-existing trusted parent directory.

The endpoint policy requires:

- an absolute, lexically canonical socket path within the Linux pathname
  `sockaddr_un.sun_path` limit;
- a parent directory which resolves to itself (no symlink/lexical alias), is a
  real directory, has the configured UID/GID, and is not group/world writable;
- every higher ancestor directory must be owned by root or the configured
  endpoint-directory owner; an ancestor which is group/world writable is
  accepted only when sticky-bit semantics protect directory-entry replacement;
- the endpoint pathname to be absent before bind;
- a configured socket owner/group and socket mode of exactly `0600` or
  `0660`;
- a bounded listen backlog.

An existing pathname is never automatically removed. This avoids treating an
active manager socket, attacker-created path, or split-brain endpoint as a
"stale" artifact.

After `bind()`, the listener sets socket ownership/mode and reads back the
socket type, owner/group, mode, device and inode **before** calling
`listen()`. The trusted parent plus ancestor-chain invariants prevent untrusted path
replacement during this setup window. A sticky writable ancestor such as
`/tmp` is permitted; a writable non-sticky ancestor is not.

The listening descriptor and every accepted descriptor are explicitly
non-inheritable.

Cleanup is identity-bound: the endpoint pathname is removed only when it still
names a socket with the same device/inode recorded after bind. If the pathname
has been removed and replaced, cleanup fails closed and preserves the
replacement instead of unlinking an unrelated object.

This phase owns only endpoint creation/accept/cleanup. It does not run a daemon,
spawn background sessions, choose production service accounts, or switch the
workload UID.

### Phase 3d2b2b2c2b2b1 Linux service identity contract

Production containment uses four OS identity concepts:

- a manager process identity;
- a host-agent process identity;
- an untrusted workload process identity;
- a dedicated manager-client group.

Manager, host-agent and workload UIDs MUST be pairwise distinct. Host-agent and
workload UID/GID MUST be non-root, and the manager-client GID MUST not be root
or the workload primary GID.

The manager and host-agent are the only identities which may hold the
manager-client group. The workload process policy has no supplementary groups.

Runtime process validation reads Linux real/effective/saved UID and GID plus
supplementary groups. All three UID values and all three GID values MUST match
the configured identity. Supplementary groups, after ignoring an optional
duplicate of the primary GID, MUST exactly match policy. This prevents a process
from appearing unprivileged while retaining a saved privileged identity or
unexpected powerful group.

A coherent endpoint layout is therefore:

```text
manager process:        manager UID/GID + manager-client supplementary GID
host-agent process:     host-agent UID/GID + manager-client supplementary GID
workload process:       workload UID/GID + no supplementary groups
endpoint directory:     manager UID : manager-client GID
endpoint socket:        manager UID : manager-client GID, mode 0660
```

The identity plan also derives manager-side expected host-agent SO_PEERCRED and
host-agent-side expected manager SO_PEERCRED policies.

This contract defines the target state but does not itself change UID/GID.
Manager service lifecycle enforcement is the next composition layer.

### Phase 3d2b2b2c2b2b2 containment-manager service lifecycle

The manager now has a foreground serial service lifecycle which composes the
existing identity, endpoint, peer-authentication, transport, and dispatcher
boundaries without duplicating them.

Service startup is ordered fail-closed:

1. validate the manager process real/effective/saved UID and GID plus exact
   supplementary groups;
2. only after identity validation succeeds, create the secure Unix listener;
3. accept one host-agent connection at a time;
4. authenticate the peer through the existing Linux `SO_PEERCRED` policy
   before manager protocol I/O;
5. serve the existing bounded manager protocol until clean EOF or a
   session-local failure;
6. return to the serial accept loop.

An unauthorized peer is session-local and closes only that connection.
Malformed/truncated protocol input is likewise contained to the connection by
the existing Unix session server. Listener/endpoint failures and unavailable
peer-credential infrastructure remain service-fatal rather than being hidden by
retry loops.

The foreground loop uses fixed 100 ms readiness polling on the listener fd. A
caller-owned stop predicate is checked before polling and again after readiness,
so shutdown cannot race a newly-ready connection into an unwanted accept. The
service installs no signal handler; an outer process supervisor may make its
handler set only the stop state.

Service `close()` is idempotent and delegates endpoint cleanup to
`UnixContainmentManagerListener`, which removes only the socket inode it
created. The service performs no independent pathname unlink.

This phase does not daemonize, add systemd packaging, introduce concurrent
sessions, switch manager/workload UID or GID, or garbage-collect every active
containment scope on shutdown.

### Phase 3d2b2b2c2b2b3 irreversible workload identity transition

Every supervisor spawn path which can reach native exec now crosses an explicit
Linux credential boundary after containment attachment/release and trusted child setup, but
before the pinned native ELF exec path. The host-agent service identity is
non-root and requires only `CAP_SETUID` and `CAP_SETGID` for this transition;
it does not receive `CAP_KILL`.

The child transition is ordered fail-closed:

1. containment attachment succeeds and the start barrier is released;
2. trusted child session/signal/stdio/fd setup and host-local rlimits complete;
3. `PR_SET_NO_NEW_PRIVS=1` is set and ambient capabilities are cleared;
4. supplementary groups are cleared to a literally empty set;
5. real/effective/saved GID are set to the workload GID;
6. real/effective/saved UID are set to the workload UID;
7. FSUID/FSGID are read back and must match the workload identity;
8. effective/permitted/inheritable capability sets are cleared and read back;
9. exact post-drop credentials, empty groups, zero capabilities, and
   `no_new_privs=1` are verified;
10. only then does final pinned cwd/executable revalidation and fd-based native
    ELF `execve` occur.

There is no optional workload policy, current-identity fallback, or bypass mode.
A transition failure takes the existing generic child-failure path and never
reaches native exec.

After the child changes UID, parent process-group/direct signaling can
legitimately fail with `EPERM`. The parent does not regain authority with
`CAP_KILL` or by switching identity. Timeout/output termination therefore
treats cross-UID signal denial as a cue to use the existing containment
`kill_all()` operation immediately. Recursive containment kill remains the
authoritative hard-cleanup mechanism; process-group/direct SIGKILL is only
defense-in-depth, and containment accounting still decides whether the request
scope is empty.

The dedicated disposable Linux live probe proves the real capability-bearing
transition, irreversibility, parent identity preservation, expected
`kill(child_pid, 0) -> EPERM`, and persistence of the dropped state through
the repository's pinned native ELF fd-exec path. Ordinary validation remains
unprivileged; the live proof is run explicitly with:

```bash
./scripts/run-live-workload-identity-probe.py
```

The containment-manager protocol is unchanged by this phase, and the
ForceCommand CLI remains non-executing.

### Phase 3d2b2b2c2c authenticated manager-client integration

The host agent now has one production composition entrypoint for the local
containment manager. `connect_authenticated_containment_manager()` accepts a
configured Unix endpoint path plus the server-owned
`ContainmentServiceIdentityPlan`.

Before opening any socket, the connector validates the current host-agent
real/effective/saved UID/GID and exact supplementary groups against the policy
derived from that identity plan. It also derives the expected manager
`SO_PEERCRED` policy from the same plan, so a caller cannot independently pair
a manager path with a weaker or unrelated peer identity policy.

The connector creates only an `AF_UNIX/SOCK_STREAM` socket, marks it
non-inheritable, applies a bounded connect timeout, connects to the lexically
validated endpoint path, authenticates the connected manager through the
existing Unix transport, and returns the existing `ContainmentManagerClient`.
That client continues to implement `ContainmentBackend`, so the established
start barrier and bounded runner are used without a second execution path.

The manager control descriptor can exist in the forked child only while the
child is trusted and blocked before exec. It is not in the child fd keep-set;
the existing child fd sanitation closes it before rlimits, workload credential
transition, and native ELF exec. A dedicated regression binds the concrete
manager transport fd to this invariant.

Client transport shutdown is explicit and idempotent. Once the client is
closed, later manager operations fail unavailable rather than reusing a test
transport which happens to remain callable.

This phase does not add a manager protocol operation, change cgroup filesystem
authority, alter containment attach/release ordering, or enable ForceCommand
execution.

### Phase 3d2b2b2c3 live delegated-cgroup validation

The separated containment design now has accepted real-kernel evidence on a
dedicated Ubuntu 26.04 x86_64 Linux fixture rather than Docker Desktop cgroup
simulation.

The live gate proves the full production ordering and authority split:

- the non-root manager owns only the delegated cgroup-management surfaces;
- the host agent enters through the authenticated Unix manager client;
- the execution child remains blocked until manager-confirmed attachment;
- the workload reaches native ELF exec only after irreversible UID/GID drop,
  empty supplementary groups, zero capabilities, and `no_new_privs=1`;
- self-migration to the delegated root and a sibling request scope is denied;
- PID, CPU, and memory limits produce real cgroup-v2 accounting/enforcement;
- request-scope OOM evidence is read from `memory.events`;
- recursive descendant cleanup is attributable to manager-backed
  `cgroup.kill`, not process-group SIGKILL;
- a sibling request survives recursive kill;
- request/source scopes are removed after success/failure while the delegated
  root itself is never targeted with `cgroup.kill`.

The accepted merged-main evidence is commit
`22e298fec42d92a963f093a6a073de622589dfc0` on kernel
`7.0.0-28-generic`: the non-root manager phase reports `2 passed` and the
production/resource/recursive-kill phase reports `4 passed`.

This closes Phase `3d2b2b2c3`.

### Phase 3d2c contained ForceCommand execution

Policy version 3 remains deliberately non-executing. Policy version 4 is the
first host-policy schema which may execute a structured ForceCommand request,
and it requires the server-owned containment block introduced for this phase.

The ForceCommand path reuses the already-validated execution composition rather
than adding a second runner:

1. validate the fixed `SSH_ORIGINAL_COMMAND=mcp-v1` context;
2. load and validate the root-owned host policy;
3. parse and authorize request metadata;
4. pin/revalidate the exact executable and cwd objects;
5. read application stdin within the already-authorized request bound;
6. for policy v4 only, derive the manager endpoint, service identity plan,
   workload identity, and cgroup limits exclusively from host policy;
7. open the authenticated containment-manager session;
8. run the prepared native ELF through the existing bounded runner,
   attach-before-exec barrier, workload identity transition, and manager-backed
   containment request;
9. close the manager session before returning captured output to the SSH peer;
10. deliver captured stdout/stderr through distinct nonblocking fds with one
    fixed five-second delivery deadline.

A manager/backend/supervisor failure returns only the generic
`execution failed` diagnostic. Internal exception details are never written to
the SSH channel. If the SSH peer stops draining result output, delivery fails
closed at the bounded deadline instead of blocking the host-agent indefinitely.
A signal-terminated workload maps to conventional SSH exit status
`128 + signal`; ordinary child exit statuses are forwarded directly.

SMCP v1 does not define a response-metadata frame. The control-plane
`SSHExecutionResult.timed_out` and `truncated` fields therefore report only
control-plane SSH collection guards. If the host-agent supervisor enforces its
own timeout or output ceiling first, the control plane receives only the
already-bounded stdout/stderr plus the resulting SSH exit semantics. It MUST
not infer a remote timeout or truncation flag from a status such as 137 or 143,
because a workload may legitimately produce the same status. A future response
protocol revision may add authenticated structured outcome metadata.

Request envelopes still cannot choose the manager endpoint, service identities,
workload identity, or cgroup resource limits. The manager protocol, cgroup
filesystem authority, attach-before-exec ordering, and workload transition are
unchanged by this wiring.

The dedicated Ubuntu 26.04 x86_64 real-kernel gate now exercises this wiring
end to end. At exact commit
`2857925800649f2ea89d9b123a7b2b19298a8dd6`, a real policy-v4
`mcp-v1` frame enters `cli.run()` under the host-agent identity, connects
to the real authenticated containment manager, executes the pinned native probe
under the workload identity, returns stdout through the real nonblocking output
path, and removes the request scope. The workload state proves request-cgroup
membership, empty supplementary groups, zero capabilities, `no_new_privs=1`,
and no inherited manager socket. The live gate reports `2 passed` for the
non-root manager phase and `5 passed` for the production/root-bootstrap
phase, with the delegated root absent after cleanup.

### Phase 3e read-only filesystem primitives

The first typed-filesystem host primitive is intentionally disconnected from
the ForceCommand request parser. It establishes the object-access boundary
before any wire operation is enabled.

For each approved absolute canonical path, bounded to fewer than 4096 encoded
bytes, the host agent starts from a pinned `/` directory descriptor and opens
every parent component with
`O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`. The final object is opened relative
to that pinned parent and is never resolved through a symlink.

The initial stat primitive accepts only regular files and directories. The
initial read primitive first pins the final object with `O_PATH|O_NOFOLLOW` and
rejects every non-regular inode before any data-capable open. A verified regular
inode is then reopened through `/proc/self/fd/<pinned-fd>` with a nonblocking
read descriptor and its identity is checked again. This avoids device/FIFO open
side effects and final-path replacement races. Reads enforce a caller bound plus
a 64 MiB hard ceiling and revalidate device/inode/change metadata and size
before returning bytes.

The next host-local layer is now defined without making the primitives remotely
reachable. Filesystem permissions are scoped per already-allowed SSH profile,
with independent absolute canonical `stat_roots` and `read_roots`. A
read-enabled profile also carries a strict server-owned `max_read_bytes` ceiling
bounded by the primitive's 64 MiB hard maximum.

Filesystem authorization is intentionally lexical-only: it validates canonical
paths, profile membership, root containment, and the requested read bound but
does not call `resolve()`, `stat()`, or `open()` on caller paths. This keeps the
policy decision free of pathname races and side effects. After authorization,
the descriptor-pinned primitive remains responsible for traversing and
revalidating the actual object without following symlinks.

The read-only primitives are now reachable through typed SMCP v1 operations.
The request metadata is a strict discriminated union: `fs_stat` carries only
request/profile/path fields and `fs_read` adds one strict positive
`max_bytes` field. Neither operation accepts application stdin; one trailing
byte is enough to reject the request before the pinned primitive runs.

The host agent authorizes filesystem metadata before object access and never
enters command preparation, containment-manager setup, or native execution for
these operations. `fs_stat` emits compact deterministic JSON containing path,
kind, size, mode, uid, gid, and mtime_ns. `fs_read` emits raw file bytes.
Policy denial and primitive failure are normalized to generic SSH-visible
diagnostics, and successful output reuses the existing bounded nonblocking
delivery path.

This is still below the MCP tool layer; Phase 4 must expose and parse the typed
MCP `fs_stat`/`fs_read` tools separately. OS filesystem permissions remain
the final access boundary.

Create-only directory mutation is now reachable through typed SMCP v1
`fs_mkdir`. The internal primitive performs exactly one pinned-parent
create-if-absent mutation. It opens and identity-checks a syncable descriptor
for the already-pinned parent, verifies pre-create fsync support, calls mkdirat,
and fsyncs the same parent after publication. Before-create sync failure leaves
no new entry. After-create sync failure is **committed/durability uncertain**:
the created directory is never removed, reopened or retried blindly. Host
policy supplies profile-scoped canonical `mkdir_roots`, authorized lexically
without touching the filesystem.

`fs_mkdir` is metadata-only. The envelope contains request ID, profile,
operation, and path; mode, owner, recursive, and overwrite semantics are not
represented and extra fields fail validation. The host agent authorizes first,
rejects any trailing body before mutation, then invokes only
`create_directory()`. Success returns SSH status 0 with empty stdout. Policy
denial and primitive failure are normalized to the existing generic filesystem
diagnostics. This is still below the MCP tool layer.

Create-only regular-file mutation is now reachable through typed SMCP v1
`fs_write`. The primitive pins the destination parent, creates an unnamed inode
with `O_TMPFILE`, writes an exact bounded byte body, fsyncs and verifies the
unnamed regular inode, then publishes it only if the final name is absent.
Existing destinations are never replaced and there is no named-temp fallback.

The envelope contains request ID, profile, operation, path, and one strict
non-negative `content_length`. Overwrite, append, mode, owner, and truncate
semantics are not represented. Host-local write-create authorization is applied
before reading the body. Only after authorization does the host agent read the
exact declared body plus EOF; underrun or overrun is a protocol error before
the primitive is called.

The publish link is the namespace commit point. Any failure before that point
uses the generic filesystem-operation failure and leaves no final pathname.
If the parent-directory fsync fails after publication, the host agent returns
dedicated `fs_write` status 74 and the fixed diagnostic
`filesystem write committed; durability uncertain; do not retry blindly`.
That status is not a workload exit code and the caller MUST NOT blindly retry.
The primitive never unlinks the final pathname in this state because another
authorized namespace writer could already have replaced it.

Each already-allowed profile may receive independent canonical
`write_create_roots` and a strict server-owned `max_write_bytes` ceiling no
larger than the primitive 64 MiB hard bound. Authorization is lexical-only and
does not resolve, open, create, or remove caller-selected filesystem objects.
This remains below the MCP tool layer.

Real Ubuntu 26.04 x86 validation additionally proves that concurrent
create-only writers racing the same destination yield exactly one published
complete body, the unnamed file is fsynced before the publish link becomes
visible, and the parent is fsynced afterward. Integrated host-agent tests also
prove that lexical policy approval cannot use an intermediate symlink to escape
the allowed root, existing destinations remain unchanged, policy denial and
body-length mismatch leave no object, and the real post-publish fsync-failure
path preserves the committed file while returning status 74.

The Phase 3e mutation boundary is closed at create-only semantics. The host
agent has no SMCP envelope or primitive for overwrite, append, truncate,
move/rename, delete/unlink/rmdir, recursive mutation, caller-selected chmod/
chown, or a generic privileged filesystem helper. Any future destructive
namespace mutation requires a separate authority design rather than widening
`fs_write` or `fs_mkdir`.

Linux/POSIX fd execution has a close-on-exec caveat for shebang scripts. Script execution remains disabled and requires a separate explicit design.

The central policy may be more expressive, but the host-local policy should preserve critical invariants if the central layer is bypassed.

## OS account model

Prefer separate accounts for materially different privilege levels, for example:

- `mcp-observer`;
- `mcp-developer`;
- `mcp-operator`.

Avoid a permanently available root SSH account for normal operations.

## Privileged helper

A root helper may expose narrow operations such as:

```text
service.restart(webapp.service)
package.install(approved-package)
host.reboot()
```

It MUST validate its own input and MUST NOT expose a generic command string. If `sudoers` is used, permit only fixed helper binaries/arguments rather than `NOPASSWD: ALL`.

## Sandboxing

Where available, commands can be launched via systemd transient units, namespaces, cgroups, seccomp, AppArmor/SELinux, or containers. Development commands that execute repository code SHOULD receive stronger filesystem/network confinement than simple inspection commands.
