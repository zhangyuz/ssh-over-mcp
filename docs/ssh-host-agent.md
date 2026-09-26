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

Phase 3c uses host-policy schema version 2. Each command policy binds:

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

Phase 3d2b2a still does not set CPU/address-space/process-count limits and is not wired into the ForceCommand CLI.

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
