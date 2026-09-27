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

Authorization records canonical executable/cwd paths. Executable identity uses device+inode+ctime; cwd replacement identity uses device+inode because directory ctime changes during ordinary content updates.

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

This closes pathname replacement between authorization and later execution: a renamed or substituted pathname does not change the already opened object. Including `ctime_ns` also detects ordinary in-place metadata/content changes which occur between authorization and fd preparation. It does **not** make a mutable inode immutable after the fd is pinned. If a policy permits an untrusted principal to modify the executable's contents in place, fd pinning cannot prevent those contents from changing; the initial execution profile must therefore retain trusted ownership/write restrictions.

The preparation layer records whether Python reports fd-based `os.execve()` support and classifies the opened file as ELF, shebang script, or other.

### Phase 3d2a native exec primitive

The first execution primitive is deliberately restricted to native ELF files. It consumes a `PreparedCommand` and:

1. requires fd-based `os.execve()` support;
2. requires the prepared executable format to be ELF;
3. requires a pinned cwd rather than inheriting the host-agent cwd;
4. revalidates executable device/inode/ctime immediately before exec;
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
and closes the containment scope. The failed child therefore cannot continue
into the exec path.

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

The ForceCommand CLI remains non-executing.

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
