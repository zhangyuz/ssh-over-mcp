# Development roadmap

## Phase 0 — specification baseline

Status: **complete**

Deliverables:

- source-of-truth docs;
- ADR baseline;
- repository skeleton;
- threat model;
- initial tool and policy schemas.

Exit criteria: security invariants and API semantics are reviewable before implementation.

## Phase 1 — policy core

Status: **complete; merged to main**

Implemented:

- typed configuration loader;
- host inventory schema;
- role/capability schema;
- allow/deny evaluator;
- command capability classification;
- filesystem path normalization helpers;
- risk classification;
- deterministic policy-explain output.

Tests:

- deny overrides allow;
- no-match denies;
- inheritance does not widen denied capability;
- host alias cannot escape inventory;
- executable canonicalization;
- environment allowlist;
- path traversal/symlink cases.

## Phase 2 — SSH execution core

Status: **complete; merged to main**

Implemented:

- AsyncSSH-based client transport;
- pinned host-key validation via inventory alias;
- no ambient SSH config/agent/password/GSS fallback;
- credential-provider abstraction;
- structured binary-framed remote envelope;
- fixed `mcp-v1` SSH command;
- no PTY / X11 / SSH environment forwarding for structured execution;
- bounded stdin and combined stdout/stderr;
- timeouts and cancellation cleanup;
- connection pooling with age limit;
- per-host session concurrency limit;
- policy decision before network access.

## Phase 3 — remote host agent

Status: **Through Phase 3d2c implemented; contained ForceCommand execution enabled for policy v4**

### Phase 3a — ForceCommand protocol entry

Implemented:

- installable `ssh-over-mcp-host-agent` entrypoint;
- exact `SSH_ORIGINAL_COMMAND=mcp-v1` validation;
- PTY rejection;
- bounded streaming SMCP v1 frame parser;
- metadata and stdin limits enforced before execution;
- fail-closed parse-only behavior: valid requests are not executed yet.

### Phase 3b — host-local request gate

Implemented:

- root-owned, no-symlink host-policy loader;
- duplicate-key and size validation;
- exact profile allowlist;
- exact executable allowlist;
- environment allowlist plus hard-denied loader variables;
- host-side timeout/output/stdin ceilings;
- metadata authorization before application-stdin read;
- fail-closed behavior after authorization; still no process execution.

### Phase 3c — canonical command authorization

Implemented:

- host-policy schema version 2 with per-command rules;
- exact/prefix argv token authorization;
- requested executable → expected realpath pinning;
- regular-file and execute-bit checks;
- root ownership and group/world-write controls;
- canonical cwd-root confinement;
- symlink retarget and cwd escape rejection;
- NUL-bearing argv/cwd/environment rejection;
- canonical resolved paths returned for the future execution stage;
- fail-closed behavior; still no process execution.

### Phase 3d1 — fd-pinned execution preparation

Implemented:

- authorization-time executable device+inode+ctime+mtime+size plus SHA-256 content binding, and cwd device+inode identity;
- host authorization repeated immediately before fd preparation;
- canonical executable opened with `O_NOFOLLOW|O_CLOEXEC`;
- canonical cwd opened as a directory fd with `O_NOFOLLOW|O_CLOEXEC`;
- fd identity revalidation using `fstat()`;
- executable ownership/writeability/setuid/setgid/capability revalidation on the pinned object;
- ELF/shebang/other format classification;
- fd-based `os.execve()` capability detection;
- deterministic descriptor cleanup;
- fail-closed behavior; still no process execution.

### Phase 3d2a — native fd-based exec primitive

Implemented:

- native ELF-only execution gate;
- fd-based `os.execve()` requirement;
- pinned cwd requirement; no ambient cwd inheritance;
- final executable identity revalidation using device+inode+ctime+mtime+size plus SHA-256 content binding;
- final cwd identity revalidation using device+inode;
- explicit argv construction;
- explicit request environment only; no ambient `os.environ`;
- `fchdir(cwd_fd)` followed by `execve(executable_fd, ...)`;
- no shell or PATH lookup;
- disposable-child real exec smoke test;
- primitive remains disconnected from the ForceCommand CLI;
- signal/fd/stdio/rlimit process-state sanitation explicitly deferred to the child supervisor.

### Phase 3d2b1 — forked child supervisor skeleton

Implemented:

- parent-side native exec spec validation before fork;
- atomic close-on-exec stdin/stdout/stderr pipes;
- disposable child created with `fork()`;
- independent child session/process group via `setsid()`;
- child signal mask cleared and catchable signals reset;
- `umask 077`;
- core dumps disabled;
- child stdio installed with `dup2()`;
- unrelated child descriptors closed before exec;
- generic child exec failure message with fixed exit code 125;
- parent-side PID/pipe handle with deterministic pipe cleanup and wait;
- real `cat` integration coverage;
- supervisor remains disconnected from the ForceCommand CLI.

### Phase 3d2b2a — bounded parent execution loop

Implemented:

- nonblocking selector-based stdin/stdout/stderr loop;
- pre-spawn stdin byte-limit enforcement;
- wall-clock timeout;
- shared stdout+stderr output byte budget;
- exact capture truncation at the combined budget;
- SIGTERM process-group termination;
- SIGKILL escalation after grace;
- cleanup deadline and direct-child reap;
- structured execution result with timeout/output flags and duration;
- tests for cat round-trip, sleep timeout, yes output overflow, stderr capture and pre-setsid signal fallback;
- runner remains disconnected from the ForceCommand CLI.

### Phase 3d2b2b1 — host-local child rlimits

Implemented:

- host-policy schema version 3;
- required server-owned child resource ceilings;
- CPU-time limit via `RLIMIT_CPU`;
- address-space limit via `RLIMIT_AS`;
- process-count limit via `RLIMIT_NPROC`;
- regular-file-size limit via `RLIMIT_FSIZE`;
- open-file limit via `RLIMIT_NOFILE`;
- prepared commands carry their host-local child limits;
- effective limits clamp to stricter inherited hard limits;
- rlimit setup failures remain generic child exit 125;
- rlimits explicitly documented as defense-in-depth, not descendant containment.

### Phase 3d2b2b2a — descendant-containment contract

Implemented:

- backend-neutral `ContainmentBackend` and per-request `ContainmentHandle`;
- explicit finite `memory_max_bytes`, `pids_max`, `cpu_quota_us`, and `cpu_period_us`;
- attach / recursive kill-all / accounting / cleanup lifecycle;
- read-only cgroup-v2 probe;
- required `cpu`, `memory`, and `pids` controller detection;
- invalid request identifiers and non-positive/absurd limit values fail closed;
- no default/no-op backend and no supervisor integration yet.

### Phase 3d2b2b2b1 — concrete cgroup-v2 backend

Implemented:

- canonical absolute delegated cgroup-v2 root;
- required controller availability check;
- required `cpu`, `memory`, and `pids` subtree enablement;
- unique per-request scope creation;
- finite `memory.max`, `pids.max`, and `cpu.max` configuration with read-back verification;
- PID attachment through `cgroup.procs`;
- recursive subtree kill through `cgroup.kill`;
- `memory.current`, `pids.current`, `cpu.stat usage_usec`, and `cgroup.events populated` accounting;
- populated-scope cleanup refusal and idempotent closed-handle behavior;
- no supervisor integration yet.

### Phase 3d2b2b2b2 — containment start barrier

Implemented:

- new explicit contained-spawn API; existing uncontained internal spawn remains unchanged;
- prepared-command/request ID binding before backend creation;
- containment scope creation before fork;
- dedicated close-on-exec barrier pipe;
- child closes parent pipe endpoints and blocks before session setup/exec;
- parent attaches child PID before releasing the barrier;
- attach/release failure keeps exec blocked and performs cgroup-kill/direct-kill bounded cleanup;
- successful spawned child retains the containment handle for later lifecycle integration;
- tests prove child code cannot run during attach and cannot run after attach failure.

### Phase 3d2b2b2b3 — containment-aware bounded execution

Implemented:

- bounded execution requires a containment backend/request;
- contained spawn replaces the older uncontained bounded-run path;
- timeout/output overflow retains graceful process-group SIGTERM first;
- hard termination uses recursive containment kill plus process-group defense-in-depth;
- process-group hard-kill failure does not override a successful containment kill;
- direct-child normal exit checks the containment populated state;
- lingering descendants are killed before result return;
- memory/PID/CPU accounting is returned with the execution result;
- containment empty-state wait and close are bounded;
- tests cover timeout containment kill, lingering descendants after direct-child exit, and process-group fallback semantics.

### Phase 3d2b2b2c0 — containment privilege separation decision

Implemented:

- identified request-scope self-migration as a distinct post-attach escape path;
- accepted ADR 0004;
- direct cgroup-v2 filesystem management is classified as manager-side only;
- hostile workload execution requires a separate containment-manager privilege domain;
- the child start barrier remains mandatory until manager-confirmed attachment;
- workload access to ancestor/sibling cgroup migration controls is prohibited;
- live validation must attempt self-migration and fail if it succeeds.

### Phase 3d2b2b2c1 — narrow containment-manager protocol

Implemented:

- versioned, bounded manager message framing;
- strict typed operations: create / attach / kill / stats / close;
- protocol contains no executable, argv, cwd, shell, generic path or command field;
- manager-generated 256-bit opaque scope capability;
- subsequent scope operations require scope ID plus capability;
- constant-time capability comparison;
- request/response message correlation;
- strict JSON types and extra-field rejection;
- generic error codes without backend exception details;
- transactional create: unpublished scopes are closed on response/setup failure;
- `ContainmentManagerClient` implements the existing `ContainmentBackend` interface;
- in-memory transport/dispatcher lifecycle tests;
- in-memory transport explicitly remains test-only and is not a privilege boundary.

### Phase 3d2b2b2c2a — pre-connected Unix manager transport

Implemented:

- AF_UNIX/SOCK_STREAM transport which rejects sockets that are not already connected;
- no socket path discovery/connect API;
- manager descriptor forced non-inheritable;
- serialized request/response round trips;
- one total client-side round-trip deadline;
- exact bounded frame receive with partial-read handling;
- timeout/EOF/truncation/OSError mapped to manager unavailable and the broken stream is poisoned;
- schema-invalid manager responses mapped to manager unavailable;
- manager-side connected-session loop which closes on malformed frames;
- socketpair lifecycle/timeout/truncation/schema-error tests;
- transport remains explicitly separate from peer authentication/endpoint policy.

### Phase 3d2b2b2c2b1 — Linux Unix peer credentials

Implemented:

- strict Linux `SO_PEERCRED` read for connected AF_UNIX/SOCK_STREAM peers;
- exact expected UID policy;
- optional exact expected real-GID policy;
- peer PID retained as metadata only, not a durable authorization key;
- Unix manager transport requires peer policy before protocol I/O;
- manager-side connected session requires peer policy before reading frames;
- peer-auth failure closes the connection immediately;
- missing `SO_PEERCRED`, malformed credential size, disconnected sockets and mismatched identity fail closed;
- tests cover exact UID/GID, UID-only mode, mismatch, unavailable kernel option and channel closure.

### Phase 3d2b2b2c2b2a — secure filesystem Unix endpoint

Implemented:

- absolute and lexically canonical pathname policy;
- Linux AF_UNIX pathname-length bound;
- explicit parent-directory UID/GID policy;
- canonical/non-symlink parent requirement;
- group/world-writable parent rejection;
- ancestor ownership validation and non-sticky writable-ancestor rejection;
- existing endpoint/file/socket/symlink rejection with no automatic stale unlink;
- socket UID/GID and 0600/0660 mode configuration before listen;
- socket ownership/mode/device/inode read-back verification;
- non-inheritable listening and accepted descriptors;
- endpoint cleanup only when the pathname still names the socket created by the listener;
- replacement-path preservation on cleanup mismatch;
- no daemon/background lifecycle or OS identity switching yet.

### Phase 3d2b2b2c2b2b1 — Linux service identity contract

Implemented:

- explicit manager / host-agent / workload identities;
- distinct manager, host-agent, and workload UIDs;
- non-root host-agent and workload UID/GID;
- non-root dedicated manager-client GID;
- exact real/effective/saved UID/GID process validation;
- exact supplementary-group validation;
- manager and host-agent both receive the manager-client group;
- workload receives no supplementary groups;
- bidirectional SO_PEERCRED policies derived from the identity plan;
- filesystem endpoint owner/group policy derived from the identity plan.

### Phase 3d2b2b2c2b2b2 — containment-manager service lifecycle

Implemented:

- exact manager process-identity validation before any endpoint side effect;
- foreground synchronous serial manager service;
- secure Unix listener creation only after identity validation succeeds;
- one authenticated host-agent session at a time;
- unauthorized peer failures bounded to the current session;
- malformed/truncated protocol input bounded by the existing Unix session server;
- listener/endpoint and peer-credential infrastructure failures remain service-fatal;
- fixed 100 ms listener-readiness polling with caller-owned stop predicate;
- stop recheck after readiness and before accept;
- idempotent service close delegated to the listener's inode-checked endpoint cleanup;
- no daemonization, concurrency, UID/GID switching, or ForceCommand execution.

### Phase 3d2b2b2c2b2b3 — irreversible workload identity transition

Implemented:

- every supervisor spawn path which can reach native exec requires an explicit workload identity policy;
- non-root host-agent child transition uses only `CAP_SETUID` and `CAP_SETGID`;
- `no_new_privs=1` is established before identity mutation;
- ambient and supplementary groups are cleared before UID/GID transition;
- real/effective/saved workload UID/GID plus FSUID/FSGID are verified;
- effective/permitted/inheritable capability sets are explicitly cleared and read back;
- post-drop supplementary groups must be literally empty;
- cross-UID signal `EPERM` escalates immediately to containment-authoritative kill;
- parent retains its original identity and does not receive `CAP_KILL`;
- dedicated disposable Linux live proof validates irreversibility and native ELF post-exec state;
- generic validation remains capability-free;
- containment-manager protocol is unchanged and ForceCommand execution remains disabled.

### Phase 3d2b2b2c2c — authenticated manager-client integration

Implemented:

- host-agent connector accepts one server-owned `ContainmentServiceIdentityPlan` plus a configured Unix endpoint path;
- endpoint path is validated through the existing endpoint-policy lexical/Linux AF_UNIX constraints before connection;
- exact host-agent real/effective/saved UID/GID and supplementary groups are validated before any manager socket is opened;
- client socket is AF_UNIX/SOCK_STREAM, explicitly non-inheritable, and uses the same bounded timeout for connect and manager round trips;
- expected manager `SO_PEERCRED` policy is derived from the same identity plan rather than supplied independently at the call site;
- authenticated `ContainmentManagerClient` remains the existing `ContainmentBackend` consumed unchanged by the start barrier and bounded runner;
- the manager control fd is not in the child keep-set and is closed by child fd sanitation before workload identity transition/native exec;
- client transport lifecycle is explicit and idempotent; calls after close fail unavailable;
- no manager protocol operation, supervisor ordering, cgroup filesystem authority, or ForceCommand execution surface was added.

### Phase 3d2b2b2c3 — live delegated-cgroup validation

Implemented:

- dedicated self-hosted Linux live gate separated from the generic Docker runner;
- operator-owned, root-owned zero-argument live helper with exact helper digest and exclusive sudo policy;
- exact-commit clean-checkout validation before privileged repository code runs;
- real unified cgroup-v2 delegated subtree with distinct manager, host-agent, and workload identities;
- attach-before-exec production composition through the authenticated manager client and start barrier;
- workload self-migration attempts to the delegated root and a sibling scope fail;
- finite `pids.max`, `cpu.max`, and `memory.max` enforcement with real kernel accounting;
- request-scope OOM attribution through `memory.events`;
- recursive descendant termination through manager-backed `cgroup.kill` with stable PID/start-time identity checks;
- sibling request survival during recursive kill;
- bounded success/failure cleanup which removes request/source scopes without calling `cgroup.kill` on the delegated root;
- exact merged-main evidence at `22e298fec42d92a963f093a6a073de622589dfc0` on Ubuntu 26.04 x86_64, kernel `7.0.0-28-generic`: manager phase `2 passed`, production/resource/recursive-kill phase `4 passed`;
- ForceCommand execution remains disabled through this phase.

### Phase 3d2c — contained ForceCommand execution wiring

Implemented:

- policy v3 remains non-executing;
- policy v4 requires server-owned containment configuration;
- ForceCommand v4 connects through the authenticated manager client and reuses
  the existing bounded supervised native runner;
- containment request limits and workload identity come only from host policy;
- manager protocol and attach-before-exec ordering are unchanged;
- manager/backend/supervisor failures are normalized to one generic SSH-visible
  error;
- signal exits map to `128 + signal`;
- captured stdout/stderr delivery is nonblocking with a fixed five-second
  deadline so a peer which stops reading cannot indefinitely block the host
  agent;
- `SSHExecutionResult.timed_out` and `.truncated` describe control-plane SSH
  collection guards only; SMCP v1 has no response-metadata frame, so a
  host-agent supervisor timeout/output overflow remains represented by bounded
  output plus the SSH process exit semantics rather than inferred flags.

Accepted real-kernel evidence at
`2857925800649f2ea89d9b123a7b2b19298a8dd6` on Ubuntu 26.04 x86_64,
kernel `7.0.0-28-generic`: manager phase `2 passed`; production/root phase
`5 passed`, including the real ForceCommand → authenticated manager →
contained workload path. The delegated root is absent after completion.

Phase `3d2c` is closed at this contract boundary. A future response-protocol
revision may add authenticated structured remote outcome metadata, but v1 does
not infer timeout/truncation from ambiguous child exit statuses.

### Phase 3e — typed filesystem operations

Tasks 1–3 implemented: read-only descriptor-pinned primitives,
filesystem-specific host-local authorization, and typed SMCP v1 read-only wire
operations.

- internal host-agent `stat_path()` and `read_file()` primitives only; no SMCP
  wire operation or MCP tool is enabled yet;
- absolute lexically canonical paths only, with a 4096-byte Linux pathname hard bound;
- every parent component is opened relative to a pinned directory fd with
  `O_NOFOLLOW`; intermediate symlinks fail closed;
- the final object is first pinned/classified with `O_PATH|O_NOFOLLOW`; read-capable open occurs only for a verified regular inode via `/proc/self/fd/<pinned-fd>`;
- `fs_stat` primitive scope is limited to regular files and directories;
- `fs_read` primitive scope is limited to regular files and uses both a
  caller-supplied limit and a 64 MiB hard ceiling;
- FIFO/socket/device/symlink objects are rejected;
- pinned reads verify stable device/inode/change metadata and size before
  returning;
- host-local filesystem policy is scoped per profile rather than shared across
  every globally allowed profile;
- `stat_roots` and `read_roots` are separate absolute canonical lexical roots;
- each read-enabled profile requires a strict server-owned `max_read_bytes`
  ceiling no larger than the primitive hard limit;
- filesystem authorization performs lexical root/ceiling checks only and does
  not resolve, stat, or open caller paths; descriptor pinning remains the object
  access boundary;
- OS DAC/ACL/MAC permissions remain authoritative.

The SMCP v1 metadata frame now uses a strict operation-discriminated request
union for `exec`, `fs_stat`, `fs_read`, `fs_mkdir`, and `fs_write`.
Filesystem requests are
metadata-only and any trailing application stdin is rejected before object
access. `fs_stat` returns compact canonical JSON metadata on stdout;
`fs_read` returns raw file bytes. Policy denial and object-access failure are
SSH-visible only as generic bounded diagnostics. The existing bounded
nonblocking result-delivery path is reused.

These host-agent wire operations are consumed by the separately reviewed Phase 4
MCP filesystem adapters when those adapters are enabled.

### Phase 3e mutation boundary — create-only v1 closed

The accepted mutation design is documented in
`docs/superpowers/specs/2026-09-30-typed-filesystem-mutations-design.md`.

The first mutation capability is create-only:

- one-level `fs_mkdir` for an absent destination;
- create-only `fs_write` for an absent regular-file destination.

Overwrite/replace, append, in-place truncate, move/rename, delete/unlink/rmdir,
recursive mutation, and caller-selected chmod/chown remain disabled. Descriptor
pinning alone does not make destructive pathname operations identity-atomic in
a concurrently writable POSIX directory.

Implementation follows
`docs/superpowers/plans/2026-09-30-typed-filesystem-mutations.md`.

Create-only mutation progress:

- Task 1 implemented: internal one-level `create_directory()` primitive using
  one pinned-parent `mkdirat`-style mutation, with no post-create pathname
  reopen/chmod/remove;
- Task 2 implemented: profile-scoped lexical `mkdir_roots` authorization;
- Task 3 implemented: typed metadata-only `fs_mkdir` SMCP v1 operation;
- `fs_mkdir` authorizes before mutation, rejects trailing stdin, accepts no
  mode/owner/recursive metadata, invokes only the create-only directory primitive,
  and returns status 0 with empty stdout on success;
- policy denial and primitive failure remain generic on the SSH-visible channel;
- the Phase 4 MCP layer now exposes this operation as strict create-only
  `fs_mkdir(host, path)` with no caller mode/owner/recursive/overwrite fields;
- Task 4 implemented internally: create-only regular-file publication through
  a pinned parent and unnamed `O_TMPFILE` inode, with fixed maximum mode
  `0600`, strict 64 MiB hard bound/exact length, file fsync before publication,
  create-if-absent publication, and parent-directory fsync afterward;
- every pre-publication failure leaves no final pathname, existing destinations
  are never replaced, and there is no named-temp fallback;
- publication is the namespace commit point. A later parent-directory fsync
  failure is reported as a distinct committed/durability-uncertain outcome and
  never triggers blind pathname cleanup;
- Task 5 implemented: filesystem host policy now has profile-scoped
  `write_create_roots` plus strict server-owned `max_write_bytes` bounded by
  the primitive 64 MiB hard ceiling;
- write-create authorization is lexical-only, accepts exact non-negative
  content lengths including zero, rejects sibling-prefix/root escapes, and
  performs no filesystem I/O or object creation;
- Task 6 implemented: typed create-only `fs_write` SMCP v1 wiring with strict
  declared `content_length`, exact raw-body acceptance, and no overwrite/mode/
  owner metadata;
- policy authorization occurs before body read, and object creation occurs only
  after the complete authorized body is received exactly;
- success returns status 0 with empty stdout; pre-publication failure remains
  generic; post-publication parent-fsync failure returns dedicated `fs_write`
  status 74 plus a fixed host-owned "committed; durability uncertain; do not
  retry blindly" diagnostic;
- the Phase 4 MCP layer now exposes strict create-only `fs_write(host, path,
  data_base64)`; content length is server-derived and overwrite/append/mode/
  owner metadata remain absent;
- Task 7 implemented on Ubuntu 26.04 x86 with real filesystem adversarial
  composition: concurrent create-if-absent races publish exactly one complete
  body, file fsync occurs before publish visibility, symlink escape/collision
  attempts fail closed, policy denial/body mismatch leave no object, and the
  real committed path preserves the published file while returning status 74;
- Task 8 review complete: the remote filesystem surface remains limited to
  read-only stat/read plus create-only mkdir/write. Overwrite, append, in-place
  truncate, move/rename, delete/unlink/rmdir, recursive mutation, arbitrary
  chmod/chown, and generic privileged filesystem helpers remain unavailable.

### Remaining Phase 3 work

- a separate future namespace-authority design before destructive filesystem
  mutation;
- optional privileged helper protocol.

Adversarial tests include malformed envelopes, command injection, env injection, PTY/forwarding attempts, and bypass through alternate executables.

## Phase 4 — MCP surface

Status: **complete; merged to main**

The read-only discovery/explanation slice is merged:

- official MCP Python SDK v2;
- stateless Streamable HTTP at `/mcp`;
- localhost-only packaged server while using the static principal provider;
- server-owned `StaticPrincipalProvider`; client tool arguments cannot select
  the trusted profile;
- `hosts_list` and `host_info` expose alias-only visible-host identity with
  empty labels/capabilities and indistinguishable missing/hidden errors;
- sanitized `policy_explain` with no SSH/network side effect;
- bounded `policy_explain` metadata (64 KiB aggregate plus field/count limits)
  and a 128 KiB Streamable HTTP request-body cap;
- `/healthz` and `/readyz` remain ordinary HTTP routes outside the MCP tool
  registry;
- real MCP SDK client round-trip coverage for Streamable HTTP.

The merged SSH runtime-composition slice added server-owned credential wiring
without adding an execution capability at that slice boundary:

- required `SSH_OVER_MCP_CREDENTIAL_MAP` points to strict operator-owned
  YAML/JSON mapping from inventory credential refs to absolute mounted key files;
- all inventory credential refs must be covered and all mapped key paths must
  already exist;
- startup composes the existing `FileCredentialProvider` and
  `SSHConnectionManager`, one shared `StructuredSSHTransport`, `SSHExecutor`,
  and the read-only `SSHFilesystemClient`;
- the shared transport owns the fixed `mcp-v1` channel plus bounded collection,
  timeout/output-overflow, cancellation, and cleanup mechanics without owning
  authorization;
- composition, `/healthz`, and `/readyz` do not resolve credentials or open
  network connections.

The MCP `ssh_exec` slice is implemented:

- strict closed-world MCP arguments contain only logical host, executable, argv,
  cwd, bounded environment, UTF-8 stdin, an optional tightening timeout, and an
  optional opaque `approval_id`;
- the static/trusted principal and fixed user privilege are injected server-side;
- central policy remains inside the existing `SSHExecutor` path and runs before
  SSH connection acquisition;
- denial never falls back to raw shell; approval-required execution also stays
  pre-network unless an exact, current, single-use grant is atomically consumed;
- client input cannot widen server-owned timeout/stdin/output limits;
- binary stdout/stderr are returned losslessly as explicit base64 fields;
- internal policy reasons, credential references, host keys, and raw SSH/library
  exceptions are normalized to stable public errors;
- application shutdown closes the pooled SSH connection manager;
- real Streamable HTTP coverage proves default-deny `ssh_exec` does not reach
  the SSH connection path.

The MCP read-only filesystem slice is implemented:

- `fs_stat` and `fs_read` use the same shared `StructuredSSHTransport`
  rather than introducing a second SSH process lifecycle;
- host visibility and central policy run before network access;
- only the centrally normalized path enters typed `FsStatEnvelope` /
  `FsReadEnvelope` requests;
- `fs_read` requires a strict positive byte bound with a 1 MiB MCP hard cap,
  and oversized files fail rather than truncate;
- `fs_stat` returns bounded structured metadata and `fs_read` returns
  lossless base64 bytes;
- host-agent policy denial, timeout, output overflow, malformed response,
  credential, host-key, and transport failures are normalized to stable public
  errors;
- real Streamable HTTP coverage proves default-deny filesystem calls do not
  reach the SSH connection path.

The MCP create-only directory slice is implemented:

- `fs_mkdir` accepts only logical host alias plus bounded path; profile,
  privilege, request ID, SSH coordinates, credentials, mode, owner, recursive,
  parents, and overwrite semantics remain server-owned or absent;
- central policy runs before network access and only its normalized path enters
  the typed `FsMkdirEnvelope`;
- the host agent independently applies `mkdir_roots` and the existing
  pinned-parent, one-level, create-if-absent primitive with maximum mode `0700`;
- a clean remote status 77 is a definite remote-policy denial, while channel
  open failure is a definite pre-request transport failure;
- once a mutation request may have been sent, timeout, collection/output
  failure, nonzero result other than clean policy denial, malformed success
  output, or foreign transport failure is surfaced as outcome-uncertain with
  an explicit do-not-retry-blindly contract;
- real Streamable HTTP coverage proves default-deny `fs_mkdir` does not reach
  the SSH connection path.

The MCP create-only file-write slice is implemented:

- `fs_write` accepts logical host alias, bounded path, and canonical strict
  base64 only; decoded content has a 64 KiB MCP hard cap chosen to stay within
  the existing 128 KiB Streamable HTTP request-body limit;
- trusted profile, user privilege, request ID, and `content_length` remain
  server-owned; content length is derived from the decoded bytes;
- central policy runs before network access and only its normalized path enters
  the typed `FsWriteEnvelope`;
- host-agent `write_create_roots`, `max_write_bytes`, exact-body validation,
  unnamed-`O_TMPFILE` create-if-absent publication, maximum mode `0600`, and
  fsync ordering remain independently authoritative;
- clean status 74 preserves the distinct committed/durability-uncertain public
  outcome; generic post-send ambiguity remains outcome-uncertain and both
  categories explicitly prohibit blind retry;
- real Streamable HTTP coverage exercises the maximum 64 KiB MCP payload and
  proves default-deny `fs_write` does not reach the SSH connection path.

The final Phase 4 whole-surface review is complete:

- exact implementation commit
  `79a3ebd6ed5e06b32ac1f152e3dc5b21e3ee9f5e`;
- authoritative hardened Ubuntu 26.04 x86 workflow run `36864606963` passed
  Ruff, cgroup-v2 probe, Python 3.13/3.14 compile, and both full pytest suites;
- the MCP registry contains only discovery/explain, structured exec, read-only
  stat/read, and create-only mkdir/write;
- health/readiness remain ordinary HTTP endpoints;
- client input cannot select the trusted profile, raw SSH coordinates, or
  credentials;
- central policy precedes every side-effecting SSH path and host-agent policy
  remains independently authoritative;
- destructive filesystem mutation and raw-shell MCP handlers remain absent;
- no Critical or Important finding remained.

Explicitly deferred beyond Phase 4:

- raw-shell enablement;
- OAuth/claim-to-profile mapping and Cloudflare identity integration;
- audit/approval persistence;
- destructive filesystem namespace mutation.

## Phase 5 — audit and approvals

Phase 5A domain/protocol infrastructure is implemented in this slice with no
runtime execution behavior change:

- trusted principals now carry server-owned `principal_id + profile`;
- `OperationContext` provides server-owned request identity for later lifecycle
  integration;
- strict audit/approval domain models contain only bounded, secret-safe fields;
- canonical approval binding fingerprints argv/env/stdin/fs_write payloads
  without placing raw sensitive values in ledger protocol/storage models;
- the versioned `SLED\x00\x01` Security Ledger protocol defines strict
  execution/admin request/response unions with a 64 KiB message cap;
- `ensure_approval` sends canonical binding + risk, not a duplicated safe
  summary; the ledger derives the operator-safe summary in Phase 5B;
- admin list responses use lightweight approval items while show/status may
  return the full safe `ApprovalStatus`.

Phase 5A does not add sockets, SQLite, approval handles to MCP, readiness
dependencies, policy changes, or SSH/network behavior.

Phase 5B local Security Ledger infrastructure is implemented:

- a dedicated foreground ledger process owns the SQLite database and 32-byte
  HMAC key;
- storage validates canonical service-owned paths, secure file ownership/modes,
  schema version, WAL + synchronous FULL settings, and a non-secret HMAC-key
  identity before serving requests;
- the approval state machine provides ledger-owned TTL, active-binding dedup,
  terminal grant/deny, expiry, atomic single-use consume, restart persistence,
  and same-transaction approval audit transitions;
- execution and admin authorities use separate pathname AF_UNIX/SOCK_STREAM
  endpoints with exact Linux SO_PEERCRED checks before frame read/dispatch;
- the execution authority exposes only ping/audit/ensure/status/consume while
  the admin authority exposes only list/show/grant/deny;
- operator identity is derived from authenticated admin peer credentials and
  cannot be supplied by protocol or CLI input;
- clients authenticate the ledger server before sending a request, use one
  bounded request/response per connection, and verify response correlation;
- `ssh-over-mcp-approvalctl` exposes only list/show/grant/deny and never opens
  the database or key directly;
- real Linux tests cover concurrent ensure/consume, wrong peer identities,
  dual-endpoint authority separation, inode-safe cleanup, service restart, and
  secret-retention boundaries.

Phase 5C mandatory audit lifecycle integration is implemented:

- runtime configuration now requires the execution-ledger Unix socket path plus
  the expected ledger service UID/GID; the MCP process authenticates the local
  ledger server with SO_PEERCRED;
- /healthz remains process liveness, while /readyz requires a successful local
  ledger ping and still performs no SSH/remote-host probe;
- every MCP invocation receives one server-owned OperationContext/request ID and
  records request_received before entering its domain operation;
- SSHExecutor and SSHFilesystemClient retain the authorization gate internally:
  central policy is evaluated once, its allow/deny/approval-required event is
  persisted, and execution_started is persisted before any structured SSH
  transport call;
- discovery/read-only completion audit failure is a stable audit-persistence
  error; an otherwise-successful side-effecting operation whose required
  completion audit cannot be persisted becomes non-retryable
  audit-persistence-outcome-uncertain;
- existing fs_mkdir mutation-outcome-uncertain and fs_write status-74
  committed/durability-uncertain classifications remain more specific even if
  their outcome audit also fails;
- cancellation records execution_cancelled without fabricating completion;
- audit rows retain bounded metadata/fingerprints only and never stdout/stderr
  bodies, stdin/file bodies, raw argv, secret environment values, credentials,
  or host keys;
- installed-package import-order regression tests keep the audit/approval/SSH
  domain layers free of circular initialization dependencies.

Phase 5D single-use `ssh_exec` approvals are implemented:

- `SSHExecutor` now uses `ExecutionAuthorizer`; filesystem tools deliberately
  retain the Phase 5C audit-only authorizer until Phase 5E;
- an approval-required `ssh_exec` call without a usable grant creates/reuses a
  ledger-owned approval and returns a public `request_id`, opaque `approval_id`,
  state, UTC expiry, and exact-retry instruction;
- `approval_status` is the only MCP approval tool and is read-only,
  principal-scoped, and oracle-resistant: unknown and other-principal handles
  return the same not-visible error; MCP exposes no grant/deny/TTL/binding
  authority;
- supplied grants are bound to trusted principal/profile, host, tool,
  privilege, policy version, normalized executable/cwd, argv fingerprint,
  environment value fingerprints, stdin fingerprint/length, and effective
  execution limits; changing any bound field prevents consumption;
- a successful exact retry atomically records `approval_required` then
  `approval_consumed` in the ledger before `execution_started` and before any SSH
  connection acquisition; the grant is single-use;
- an unusable, consumed, expired, foreign, or wrong-binding handle cannot act as
  an oracle: the current exact binding gets a safe replacement/reused approval
  status while network access remains zero;
- current central policy is re-evaluated on every retry: DENY remains terminal,
  current ALLOW does not consume a stale approval, and APPROVAL_REQUIRED requires
  the exact current binding;
- real Linux HTTP + Unix-socket ledger coverage proves approval-before-network,
  replay resistance, remote-failure-after-consume semantics, audit ordering, and
  that raw argv/environment values/stdin/credential material do not enter ledger
  frames.

Phase 5E filesystem approvals are implemented:

- `fs_stat`, `fs_read`, `fs_mkdir`, and `fs_write` now accept the same optional
  opaque `approval_id`; MCP still exposes no grant/deny/TTL/binding authority;
- all four tools use `ExecutionAuthorizer` inside `SSHFilesystemClient`, so
  current central policy is re-evaluated on every attempt and exact single-use
  consumption occurs before structured SSH transport;
- filesystem approval bindings include trusted principal/profile, host, tool,
  user privilege, current policy version, normalized path, and effective
  transport bounds; `fs_read` additionally binds its requested/effective byte
  limit, while `fs_write` binds decoded content length plus SHA-256 content
  fingerprint;
- changing only tool, path, `fs_read.max_bytes`, `fs_write` content, principal,
  or policy version invalidates an existing grant without opening SSH;
- a consumed grant is never refunded after cancellation, timeout, remote
  failure, mutation ambiguity, or committed/durability-uncertain status 74;
- read-only success/error schemas and the Phase 4 1 MiB read cap remain
  unchanged; create-only mkdir/write invariants, host-agent roots, 0700/0600
  modes, and no-overwrite semantics remain independently authoritative;
- real Linux HTTP + Unix-socket ledger coverage proves read replay resistance,
  mutation post-consume behavior, audit ordering, status-74 event
  classification, and that raw file bytes/base64 plus credential metadata do
  not enter ledger protocol frames, persistent audit/approval rows, or public
  errors.

The final Phase 5 whole-surface security review is complete:

- exact implementation commit `2fc7acb3611347a42315703db3c6fc98837fb996`;
- authoritative hardened Ubuntu 26.04 x86 workflow run `37009047426` passed runner
  hardening checks, Ruff, cgroup-v2 probe, Python 3.13/3.14 compile, and both
  full pytest suites;
- adversarial coverage spans approval restart state, five-tool concurrent
  single-use consumption, current-policy change, full material-binding
  mismatch, ledger/audit outage boundaries, post-consume mutation outcomes,
  authority separation, and secret retention;
- one Important review finding was fixed before closure: a clean-interpreter
  import cycle between approval authorization and the SSH package; a dedicated
  regression now pins the import boundary;
- the MCP registry exposes only `approval_status` for approval inspection and
  accepts opaque `approval_id` handles only on policy-gated execution tools;
  grant/deny authority remains isolated on the authenticated local admin
  endpoint;
- approval consumption remains one attempt rather than one successful
  execution, including execution-start audit failure, cancellation, timeout,
  remote policy denial, status 69, status 74, and transport uncertainty;
- host-agent policy, create-only mutation primitives, mode ceilings, and
  no-overwrite semantics remain independently authoritative;
- no raw-shell or destructive filesystem MCP capability was introduced;
- all 18 Phase 5 security invariants were reviewed against source structure and
  executable adversarial evidence, with no remaining Critical or Important
  finding.

Explicitly deferred beyond Phase 5:

- OAuth/user-claim principal IDs and remote approval UI;
- multi-node/reusable approval semantics;
- remote SIEM/audit export implementation;
- MCP audit-query authority;
- raw-shell break-glass enablement;
- destructive filesystem namespace mutation;
- privileged-helper approval;
- online HMAC-key rotation/migration.

## Phase 6 — Cloudflare reference deployment

Status: **Phase 6 closed.** Final Phase 6D merged as `a5c7c2d13c504f1e68beb0e7fc55db90539fbcc0`; PR-head CI run `37059153723` and merge-main push CI run `37059622970` passed on the configured self-hosted Ubuntu 26.04 x86 runner, and Phase 6 worktree/branch cleanup completed.

Delivered and verified:

- digest/hash-locked reproducible `linux/amd64` production image with two independent no-cache builds producing the same image ID/layers;
- non-root hardened container runtime and explicit loopback/private bind contract;
- Docker Compose reference with zero public MCP ports, separate MCP/Ledger/admin identities and mounts, restart persistence, and fail-closed outage/bootstrap behavior;
- pinned non-root `cloudflared` connector isolated to the origin and Cloudflare-egress networks with a file-only Tunnel token;
- private-hostname MCP Portal route guidance with origin bearer separation;
- Managed OAuth instructions for interactive clients and Access service-token instructions for headless clients;
- four-credential separation (Tunnel token, origin bearer, Access service token, optional Cloudflare API token);
- Gateway HTTP logging/DLP guidance with explicit limits and Security Ledger remaining the authoritative execution audit;
- separate-instance/static-profile guidance for materially different roles;
- full Phase 5 security/authority/secret-retention regressions and Phase 6A-6D static/live deployment probes.

The implementation workflow performed no live Cloudflare account mutation; live Cloudflare account provisioning remains an operator action. All Phase 6 closure gates are satisfied: exact PR-head CI, exact merge-main push CI, final review, and post-merge cleanup.

## Phase 7 — hardening

Status: **Phase 7A is closed.** Verified implementation merge `71243f2ac4fd4e60e76cdf7cf648f78081dff483` (PR #121) passed exact-head CI `37398372450` / no-network Level-3 `37398500863` and exact merge-main CI `37398919556` / Level-3 `37398928655`, including provider-state absence and checkout cleanup. Fresh independent review found no remaining Critical/Important issue. PR #119 Task 6/7 evidence, separate trusted-authority PR #120 evidence, the 25-criterion matrix, two-build reproducibility and 14 live deployment checks are recorded in the Phase 7A design spec. Superseded branches/worktrees are cleaned; staged Phase 7A1 work is preserved in a verified external recovery copy. The tiny closure-record PR has its own CI/Level-3 gates before final cleanup.

Planned sequence:
- 7A: real local E2E foundation and disposable-guest trust model: a dedicated non-admin Mac x86 orchestrator starts a fresh pinned Ubuntu 26.04 QEMU/HVF VM with `-nic none` for every run; capability-bearing target code executes only inside that no-network guest, while ADR 0007 bridges real sshd ForceCommand to the non-root host-agent `CAP_SETUID`/`CAP_SETGID` state and ADR 0008 prevents guest-root network reachability to the persistent host/LAN;
- 7B: systemd/AppArmor/SELinux and egress hardening;
- 7C: SSH CA and secret-manager integration;
- 7D: fuzz/property testing and Phase 7 final review.

Hardening backlog:
- systemd sandbox reference profiles;
- AppArmor/SELinux guidance;
- egress policy examples;
- SSH CA support;
- secret-manager integration;
- fuzz/property testing of policy and host-agent protocol;
- security review checklist.

Next slice: **Phase 7B1 — Security Ledger systemd sandbox**, written design
approved 2026-10-06;
[design](superpowers/specs/2026-10-05-phase-7b1-ledger-systemd-design.md) and
[ADR 0009](decisions/0009-ledger-systemd-sandbox.md) accepted. The
[small-slice implementation plan](superpowers/plans/2026-10-06-phase-7b1-ledger-systemd.md)
is approved 2026-10-06. Tasks 1–2 are complete through exact merge-main gates
(PRs 124/125). Task 3 has reached its required missing-tool prerequisite:
the pinned guest has no executable C compiler. The
[approved offline native design](superpowers/specs/2026-10-06-offline-native-e2e-toolchain-design.md),
[ADR 0010](decisions/0010-offline-native-e2e-toolchain.md) and
[approved prerequisite plan](superpowers/plans/2026-10-06-offline-native-e2e-toolchain.md)
are approved 2026-10-06. G1 is complete through PR #127 and exact merge-main
CI/Level-3 gates; N1 begins with a dormant bounded package-data reader.
No native authority is activated. No Phase 7B1
acceptance or closure is claimed.
The slice preserves existing
Ledger authority and first lands any necessary trusted guest setup separately before target
certification. Other Phase 7B hardening remains deferred to separate slices.

## Definition of done for v1

A v1 release must demonstrate:

1. at least two roles with materially different permissions;
2. multiple inventory-managed hosts;
3. structured exec and typed filesystem/service operations;
4. raw shell disabled for normal roles and approval-gated for admin;
5. pinned host-key failure behavior;
6. remote ForceCommand enforcement;
7. deny-overrides-allow policy tests;
8. audit trail for allow/deny/execution/approval;
9. private Cloudflare Portal deployment without public origin port;
10. adversarial tests for common policy bypasses.

### Phase 7 — dormant read-only evidence feature progress (2026-10-09)

The following **offline/dormant** capabilities have progressed on main,
independent of the blocked Phase 7B1 native toolchain and provider gates:

- **PR #174** — complete frozen one-pass joint observation from disposable
  pinned getconf/marker/ps A/inventory/ps B fixtures, with canonical temp
  ancestry, selected staging metadata and inventory; exact-head self-hosted
  Python 3.13/3.14 CI passed. This is a private fixture-only observation,
  **not** an authenticated UID-502 host inspection.
- **PR #175** — pure typed observation-to-canonical-inventory-v1 projection,
  byte-exact golden output, bounded validation and SHA-256. Its post-review
  fixes reject deceptive ancestor-path `str` subclasses and **fail closed on
  an uninitialized fixed inventory module cache without file loading**.
  Exact reviewed head `f7acb88743a934319090d17c6c3597915b5544ae`
  passed self-hosted CI `37916736461` and merged as
  `e241fee43fdebe56f42d8c6540fb4baf1328fce1`.
- **PR #176** — merged as `5610d94507a8120a68965878a755f33a5075e35e`
  after independent code/docs review corrected the distinction between
  paused native-input N1c and incident-workflow receipt integration
  (preflight plan B8). Delivered deterministic immutable *offline* drift
  reports comparing two separately projected, fixed-selector observations:
  added/removed paths, changed metadata, getconf ancestry/marker changes,
  payload digests, and strict fail-closed input behavior. Exact-head self-hosted
  Ubuntu Python 3.13/3.14 CI `37919751648` PASS; PR Level-3 SKIPPED.
- **PR #177** — merged as `f2c78878b6b10147de92a26eccf9f46418c822ea`
  after zero-actionable independent review, 89/89 focused tests and
  exact-head self-hosted Ubuntu 26.04 Python 3.13/3.14 CI
  `37920715971` PASS. Delivered strict bounded canonical v1 drift
  artifact JSON export/import, SHA-256 content validation, no-I/O
  round-trip, duplicate/noncanonical JSON and forged-path refusal.
  A checksum is **not** a trusted signature, receipt or provenance.
- **PR #178** — merged as `4b733e32fd9466aaceb7276146f1b40176009c61`
  from exact head `1b9eca642816a092f099b5745f89d9390278750e`
  after full regression, zero-actionable independent review and self-hosted
  Python 3.13/3.14 CI `37927015576` PASS. The *lossy v1*
  cross-binding verifies a portable drift artifact against two supplied
  observations, with strict checksum and independently recomputed report.
  Its **documented limit:** `marker_changed` does not encode raw non-wire
  metadata values or before/after direction. The original wire/API remains
  stable; Level-3 SKIPPED did not close its independent gate.
- **PR #179** — merged as `06b0bd2b811f89e7dd1d276c097437ee7ff5a8b1`
  after P2 repair at exact HEAD `dfbde0902a903991074e83f792aa689a6f8be3aa`,
  zero-actionable independent review and self-hosted Ubuntu Python
  3.13/3.14 CI `37929732642` PASS. Delivered a separately versioned,
  bounded, domain-separated ordered snapshot-pair content seal over
  canonical inventory and **all** checked marker/expected-file scalar
  metadata. It closes the v1 lossy timestamp/value-direction ambiguity
  for a fixed supplied tuple, with no trusted producer identity.
  P2 repair used the existing locally bounded integer wire codec for
  5001/10001-digit positive and negative signed timestamp values,
  preserving the global Python digit guard and ordinary canonical bytes.
  PR-only Level-3 SKIPPED is not native acceptance.
- **PR #180** — merged as `bc9fb95dfc36ad62174f30835b6535e0143d7587`
  from exact HEAD `48947ad2512da53e84ac11d38bf9f612c21da06b`.
  Delivered 2–17 ordered caller-supplied snapshots, 1–16 adjacent
  drift artifacts and complete pair seals, plus bounded canonical
  manifest and exact-hop recomputation. Two zero-actionable reviews,
  138 focused tests and exact-head self-hosted Ubuntu 26.04 x86
  CI `37930797706` PASS. PR Level-3 SKIPPED, not native acceptance.
  Post-merge main CI `37933406912`: Ubuntu 3.13/3.14 validation
  PASS, but merge-main Level-3 FAIL (exit 70: stale E2E provider
  state; cleanup absence gate also failed). Overall workflow FAIL,
  leaving provider disposition/native acceptance separately blocked.
- **PR #181** — merged as `13f1f9c91874ef4f8e22e01652064c88712ce647`
  from reviewed exact HEAD `053e9f379020fa6f227e4be71038e4fa03064efe`.
  Delivered a separate, path-free canonical v1 JSON timeline change summary
  (up to 16 KiB / 16 hops): ordered source/hop/seal fingerprints, changed
  categories and inventory path **counts** only. Independent fresh final
  review found zero actionable issues; the corrected >16-KiB input rejection
  adversary and related regression passed. Exact-head self-hosted Ubuntu
  26.04 x86 Python 3.13/3.14 CI `37934952379` SUCCESS; PR-only
  Level-3 SKIPPED, not native acceptance. Merge-main validation and
  stale-provider disposition are separately gated.
- **PR #182** — merged as `f130643b215f767de6565c18b886671f0a216e72`
  from reviewed exact HEAD `44665e67c95d04fc956393f4f2ffebbfdef3fc6a`.
  Delivered independently bounded private 128-KiB canonical path/field
  timeline audit with net first-vs-last full-content change, stable/changed
  hops and non-adjacent snapshot revisits; exact-source re-verification and
  full path-bearing confidentiality boundary. Independent deep review
  `6081989374`: 0 Critical / 0 Important / 1 Minor (PR metadata only,
  corrected before merge), 1,522 related tests and hostile forgery fixture
  PASS. Exact-head Ubuntu 26.04 Python 3.13/3.14 CI `37937065131`
  SUCCESS; PR native Level-3 SKIPPED. Merge-main CI `37938218143`:
  Ubuntu validation PASS, real no-network Level-3 FAIL-CLOSED on the
  pre-existing stale provider state. No provider recovery or A1/B8
  disposition claimed.
- **PR #183** — merged as `6f0d9deefc912965cf5e5908c2ea33c17e170f81`
  from exact HEAD `4f47b190fd579f07b2d93352c371c051ce5f74cc`.
  One-call path-free **public** manifest+count-summary casefile capped at
  32 KiB; separately opt-in private raw-path audit casefile capped at
  160 KiB and content-bound to the public SHA-256. Independent deep
  review `6082589824` found zero Critical/Important/Minor; 1,549 related
  tests and exact-head self-hosted Ubuntu 26.04 Python 3.13/3.14 CI
  `37939594908` PASS. PR Level-3 SKIPPED. Merge-main CI
  `37942814022` Python 3.13/3.14 PASS, but native Level-3 FAIL-CLOSED
  (exit 70: pre-existing stale E2E provider state). The privacy opt-in is
  intentional export handling, never trusted caller authorization.
- **PR #184** — merged as `2ec5ec1db940a61c76c2dd66872178419536826d`
  from exact HEAD `0d0c2e7baf16056d8d6b681c19eda6101768fd98`.
  Delivered bounded 64-KiB canonical path-free multi-segment series with
  2–8 segments, 128 source-sealed transitions, full-content cross-segment
  boundary checks, global changed/stable hop indices, aggregate counts,
  net-change and snapshot revisit classification. Independent deep review
  `6083111449`: 0 Critical/Important/Minor; 1,572 related tests PASS.
  Exact-head self-hosted Ubuntu 26.04 Python 3.13/3.14 CI `37944002739`
  SUCCESS. PR-only Level-3 SKIPPED, not native acceptance. Merge-main
  CI `37946298917`: Ubuntu 3.13/3.14 validation PASS, but no-network
  native Level-3 FAIL-CLOSED on pre-existing stale E2E provider state
  (exit 70). Real provider disposition remains separately blocked.
- **PR #185** — merged as `cdfc26af5021efc889b2c9c52a0af18955a1a23b`
  from exact HEAD `cdb703209c12e485f5721aba3d13eedd007d9017`.
  Delivered bounded canonical private opt-in multi-segment casefile
  audits (2–8 segments, ≤128 hops / 2 MiB), each privately linked to the
  verified public series and full source/seal/audit content. Independent
  deep reviews `6083652021` and `6083820365` found zero
  Critical/Important/Minor; 1,607 related tests passed. Exact-head
  self-hosted Ubuntu 26.04 Python 3.13/3.14 CI `37947379672` PASS;
  PR-only native Level-3 SKIPPED, not E2E approval. Merge-main CI
  `37951075646` Ubuntu validation PASS, but native no-network Level-3
  FAIL-CLOSED (exit 70: pre-existing stale E2E provider state).
- **PR #186** — merged as `459cb6622f609e8cb4f1eb9d094a0f22f317edab`
  from exact reviewed HEAD `df4c7ba756e074b1f63434fb2f0862aa6c5b1f38`.
  Delivered complete **two-series detached investigation comparison dossier**:
  128-KiB canonical path-free source/hop divergence and count summaries,
  separately opt-in 6-MiB raw path/field difference reports, independent
  source-bound public/private rebuild verifiers, 128-hop support and sanitized
  fail-closed rejection. Exact-head independent deep review `6085679812`
  found 0 Critical/Important/Minor; 1,646 relevant tests PASS and exact-head
  self-hosted Ubuntu 26.04 Python 3.13/3.14 CI `37962020041` SUCCESS.
  Prior CI attempts `37952154503` and `37959090921` were CANCELLED by the
  unchanged 20-minute job limit; source-validated **single-pass verified
  builders** removed redundant traversal without dropping any input, seal,
  continuity, audit or count checks. PR-only Level-3 SKIPPED, not native
  acceptance. Merge-main `37965175659`: Ubuntu 26.04 Python 3.13/3.14
  PASS; real no-network Level-3 FAIL-CLOSED on pre-existing stale E2E
  provider state (exit 70). No marker or provider state changed.
- **PR #187** — merged as `d12f19e6c352bcecd864485a852b67f9f4b8e22b`
  from reviewed exact HEAD `d1736b3a78d5226c53393b34c8ad747e606e3816`.
  Delivered canonical, independently original-source-verified **3–5-run
  cohort investigation portfolio**, one baseline plus 2–4 members, each
  with bounded 2–8 series segments (≤128 hops). Source clusters, the
  five-case hop-frequency partition (including absent-on-both), 768-KiB
  path-free public bundle and separate exact-True opt-in 24-MiB private
  path/field audit bundle. Independent full-diff reviews `6086065429`,
  `6086703132`: zero confirmed Critical/Important/Minor. 675 local relevant
  tests and adversarial five-run boundaries PASS, exact-head Ubuntu 26.04
  Python 3.13/3.14 CI `37967107396` SUCCESS. PR-native Level-3 SKIPPED.
  Merge-main CI `37973343853`: Ubuntu Python 3.13/3.14 validation PASS,
  real no-network Level-3 FAIL-CLOSED (stale E2E provider state, exit 70).
  Nothing cleared or changed in the real provider state.
- **PR #188** — merged as `ca382de725956252eeafba49d2c7c67806a5b896`
  from exact review HEAD `9444fe2263546c69011c5fda19b8830d37141b98`.
  Delivered bounded ≤256-KiB path-free quorum consensus from verified
  3–5-run source cohorts, strict floor(N/2)+1 of all runs and true
  unanimity, and distinct exact-True opt-in ≤24-MiB private effect-support
  report bound to original verified series and source portfolio. Exact
  source/wire rebuild rejection, 1,711 related local tests PASS, 65
  portfolio+consensus focused tests PASS. Independent global review
  `6087754626` found 0 Critical/Important/Minor; exact-head self-hosted
  Ubuntu Python 3.13/3.14 CI `37975594044` SUCCESS. PR Level-3 SKIPPED.
  Source verification now runs once per cohort member within a single
  construction call; no cross-call caches or removed checks. Timed CI:
  #187 8m08s/9m05s → #188 8m24s/8m51s (3.13/3.14), not a demonstrated
  total CI speedup. CI emits the 15 slowest pytest durations on trusted
  main. The standalone CI resilience PR #191 splits both primary and
  manually dispatched trusted-main validation into Python 3.13/3.14
  matrix jobs each retain a 20-minute hard limit, full unfiltered tests,
  non-root hardened ephemeral Ubuntu x86 runners and the native Level-3
  dependency on all validation jobs. The earlier combined single-job
  budget frequently exhausted before the second version completed.
  #188 merge-main CI `37980323392`: Ubuntu Python 3.13/3.14 full
  validation PASS; real no-network Level-3 FAIL-CLOSED on the existing
  stale E2E provider state (exit 70). No provider marker altered and no
  native acceptance or recovery implied.
- **PR #189** — merged as `9b9cc330441126001f4869d0d0f26cbc6d9ec294`
  from exact reviewed HEAD `69a0c1b750924008fe9ff2b398c077767c7fa3a1`.
  Delivered independently source-verified path-free canonical ≤64-KiB
  public consensus intervals, 3–5 caller-ordered series and source SHA
  anchor, per-hop unanimous/majority/disputed classification and half-open
  windows. Independent deep review `6088208724` found one Important
  **real disputed-partition information-loss bug**, fixed with canonical
  source-derived `agreement_groups` in the wire and interval merge key.
  Exact four-run/three-hop RED→GREEN proves disputed group transition
  `[0,1]/[2,3]` → `[0,2]/[1,3]` is preserved, rehashed forged
  partition rejected. Final author review `6088636090`: no outstanding
  actionable blockers; post-fix external Codex review rate-limited
  (**not** claimed independently completed). 21/21 focused and
  **1,732/1,732** complete local related regressions PASS; exact-head
  Ubuntu 26.04 Python 3.13/3.14 CI `37984107600` SUCCESS. PR-only
  native Level-3 SKIPPED; no provider state or marker changed.
  Merge-main run `37986652267` was CANCELLED at the 20-minute
  Ubuntu validation job limit during Python 3.14 after Python 3.13
  passed; dependent real no-network native Level-3 was SKIPPED.
  Neither native acceptance nor a provider disposition was established.
- **PR #191** — merged as `b4338153e9248256593605a333deca838ceb9453`;
  independent Python 3.13/3.14 complete-suite matrix jobs with
  `fail-fast: false`, each on a hardened ephemeral Ubuntu 26.04 x86
  runner with its own 20-minute limit. Exact-head CI `38008595926`
  SUCCESS; first trusted-main matrix CI `38010018993` validated both
  Python versions PASS, while dependent native Level-3 FAIL-CLOSED on
  stale provider state (exit 70). Matrix success is not E2E acceptance.

- **PR #190** — merged as `b7d7f86155fcacf8a8d1c57b7305de548c856ded`; bounded
  **public-only ranked disputed interval navigation index**.
  Independently recompute the just-merged #189 source-verified intervals
  from original caller tuples (3–5 source-series members, ≤128 hops).
  Keep only `disputed` windows with their half-open range, length,
  member agreement partitions and absent member indices. Rank by
  **length descending, start-hop ascending** for reproducible review;
  length is a navigation statistic, **not severity or chronology**.
  Emit canonical path-free ≤32-KiB ASCII with exact full original
  interval SHA-256, run/hop/window and total-disputed-hop counts.
  Standalone verifier validates type, size, SHA-256, canonical no-duplicate
  JSON and independently exact-rebuilds all bytes from source tuples,
  rejecting switched cohorts, rehashed modified rankings or member
  partitions. Empty fully agreed cohorts produce a valid empty index.
  Protect against oversized wire before parsing, private path/field
  disclosure and forbidden host/provider I/O. No authority upgrades,
  cross-request cache, UID-502, N1c/A1/B8 receipt or native recovery
  semantics. Exact-head Python 3.13/3.14 CI `38010044401` SUCCESS,
  focused dispute-index tests 14/14 PASS; PR-only Level-3 SKIPPED.
  Merge-main CI `38014354645` validated both full Python versions,
  but native Level-3 FAIL-CLOSED on stale provider state (exit 70).
- **PR #193** — merged as `9e5b94d7bfa74a533d5351fc2993c3793dae5478`;
  follow-up functional slice with bounded source-verified
  **public dispute navigation pages**. Accept
  original caller-ordered 3–5 source cohorts and strict integer offset
  and limit (1–16); rebuild the entire #190 index on every call.
  Emit path-free canonical ASCII ≤16 KiB, anchor the complete source
  index SHA-256, retain exact ranked disputed windows and stable
  continuation offset (or null at the end). Independent verifier checks
  wire canonicality, type/size/SHA and recomputes every byte against the
  original ordered sources. Reject oversize before parsing, forged
  pagination/groups/hash, changed source order and forbidden host/private
  I/O. No cache, severity/chronology inference, A1/B8/N1c/UID-502,
  native Level-3 authority or provider recovery.
  Focused pagination tests 33/33 PASS, Ruff/format PASS; exact-head
  self-hosted Python 3.13/3.14 CI `38014380038` SUCCESS. PR-only
  native Level-3 SKIPPED, not native acceptance.


**Native provider disposition evidence (2026-10-09):** trusted-main
[CI `38015831978`](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38015831978)
completed both full Python 3.13/3.14 matrix jobs PASS; native Level-3
FAIL-CLOSED on stale provider state (exit 70), **no native acceptance**.
Trusted-main manual [inspect-only `38017034795`](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38017034795)
confirmed marker target `47531dadb58d365f74089dd5f52ce1b61bb0fdd1`,
owner PID `38013`, and three remaining UID-502 temp directories. No
cleanup or marker recovery was authorized or performed. The evidence,
per-directory classification and hard-stop criteria are documented in
[`docs/plans/2026-10-09-native-provider-disposition.md`](plans/2026-10-09-native-provider-disposition.md).

**Roadmap / global consistency:** These primitives are test fixtures and
offline data transformations. The original Phase 7B1 Task 3 / N1 native
toolchain prerequisite remains blocked, as do the separately reviewed
trusted-main authority-file binding (A1), actual dedicated UID-502 read-only
preflight, separately reviewed incident-workflow provenance/receipt
integration (preflight plan B8), and real no-network Level-3 after stale
provider disposition. **N1c is a distinct paused native-input authentication
subtask; ADR 0011 requires recovery/A1 closure before N1c resumes.** These
acceptance criteria remain **open**, irrespective of PR-only Level-3 SKIPPED.
No real incident, provider cleanup, marker clear, process signal, or unknown
recovery workspace action has been authorized by this progress.


**#189 review correction (2026-10-09):** Exact source-derived public
agreement partitions `agreement_groups` (canonical member-index lists)
are included in each interval. Adjacent intervals merge only if their
classification, supporters, absent-members **and full member agreement
partition** remain the same. Thus changing disputed camps, such as
`[0,1]/[2,3]` to `[0,2]/[1,3]`, cannot be silently hidden even
though both hops have an empty strict-quorum support list. This is
path-free and does not reveal raw before/after fingerprints, raw
inventory paths, chronological authority or access rights. New real
3-hop four-member source-built and rehashed-tamper regressions protect
this invariant; the wire remains ≤64 KiB, canonical and source-bound.

**Completed offline functional slice — source-verified public dispute
hop lookup (PR #195 merged as `5185b61`):**
Given the original caller-ordered 3–5 source cohorts and one strict
zero-based hop index, independently rebuild the complete ranked public
dispute index and return a canonical ≤4-KiB path-free exact-match
window (or explicit no-dispute result). Bind the source index SHA-256,
window rank, public member agreement groups and hop range; verify
size/digest/canonicality and exact source-derived bytes. No detached
index trust, cache, host/provider/private I/O, severity/chronology
inference or native gate changes. RED→GREEN focused tests and exact-head
Python 3.13/3.14 exact-head CI `38062107045` SUCCESS;
PR-only native Level-3 SKIPPED. #194 is a separately merged
docs-only review-fix PR; neither PR CI run establishes native acceptance.

**Next incremental public-only functional slice — bounded dispute-hop
batch (PR #196 merged as `fb2dc8d`):**
1–16 strictly increasing, unique, exact integer hop positions,
snapshotted once before validation and index reconstruction; rebuild
the complete original-source public dispute index once per build/verify
call, return ≤16-KiB canonical ASCII with full index digest, selected
ranks/windows or explicit null for non-disputed hops. Fail closed on
invalid/duplicate/out-of-order/out-of-range hops, forged/rehashed or
noncanonical wire, changed source ordering, ambiguous overlap and
oversized input. No host/provider/private I/O, authority, chronology or
severity inference. New tests are RED-first; exact-head Python 3.13/3.14
CI `38065810745` SUCCESS and full staging regression 460/460 PASS.
Independent review identified a mutable-list snapshot Minor; fixed
with one tuple snapshot before validation/reconstruction, with
RED→GREEN mutation and real 16-hop source-derived boundary tests.
PR-only native Level-3 SKIPPED. Native provider
disposition, A1/B8/N1c/UID-502 and Level-3 acceptance remain OPEN.

**Completed public-only functional slice — ranked dispute window
lookup (PR #197 merged as `39fca38357deb816202a429793fd4f4633165873`):**
Given original ordered 3–5 verified source cohorts and strict integer
rank, rebuild the complete ranked dispute index, select its exact
ranked window or fail closed on empty/out-of-range index. Emit canonical
≤4-KiB path-free ASCII with full index SHA-256; independent verifier
rejects duplicate/noncanonical/oversized/rehashed/forged wire and
changed source order. RED-first 16 new rank tests and focused
dispute regression PASS; independent review found only a roadmap-state
Minor, corrected in commit `2b4b0da`. Exact-head self-hosted Ubuntu
26.04 Python 3.13/3.14 CI `38093223210` PASS, and PR #197 merged
into main as `39fca38357de`. PR-only Level-3 SKIPPED, not native
acceptance. No trusted time, severity, private path, host/provider I/O
or native authority; provider disposition, A1/B8/N1c/UID-502 and
real Level-3 remain OPEN.

**Completed public-only slice — sparse dispute-rank batch (PR #198
merged as `5239d10e7539d025c7083b8aa8d6a83dde17b690`):**
1–16 strict, unique, ascending exact-integer navigation ranks, with one
snapshot of caller input and one complete rebuild of the original-source
public dispute index per build/verify. Return bounded canonical ≤16-KiB
ASCII with full index digest and exact sparse selected windows; reject
empty/out-of-range/duplicate/noncanonical/oversized/forged/rehashed
input or changed source ordering. Distinct from contiguous page lookup
and per-rank single lookup. Independent review found two Minors,
both fixed: #197 merged status/CI documentation and real four-member
two-segment 16-disputed-window upper-bound build→verify. RED→GREEN
tests, focused dispute regression 119/119 PASS, Ruff/format PASS,
exact-head self-hosted Python 3.13/3.14 CI `38096587675` PASS,
review clear and PR #198 merged as `5239d10e`. PR-only Level-3
SKIPPED is not native acceptance. No host/provider/private I/O,
native recovery or authority change. A1/B8/N1c/UID-502/provider
disposition/real Level-3 remain OPEN.

**Completed public-only slice — exact disputed-window boundary lookup
(PR #199 merged as `383ad81193541962632e2a70c72b0384060ea5a2`):**
Strict integer half-open hop bounds rebuild the source-verified public
dispute index from original ordered 3–5 source cohorts, returning exact
window rank or null for valid nonmatching ranges. Reject invalid bounds,
oversized/noncanonical/duplicate-key wire, rehashed forged
query/rank/window/index digest and source reordering. Independent review's
Minor was resolved by a real-source build→verify regression proving a
later longer disputed window outranks an earlier shorter window.
Bounded canonical ≤4-KiB public ASCII; no private paths, host/provider I/O,
cache, trusted time, severity or native authority. RED→GREEN, focused
regression and Ruff PASS; pre-merge exact-head self-hosted Python
3.13/3.14 CI `38099287491` PASS and independent review cleared before
merge. PR-only Level-3 SKIPPED is not native acceptance;
A1/B8/N1c/UID-502/native Level-3 and stale provider disposition remain OPEN.

**Completed public-only slice — dispute overlap navigation
(PR #200 merged as `c5ff0dcccf13612514861284d8459fdac688ce58`):**
Given strict integer half-open hop bounds, rebuild the original-source
full ranked dispute index once per build/verify, return every
intersecting public disputed window in index rank order with its
clipped intersection **when the complete result fits ≤8 KiB**.
Larger complete results from otherwise valid original-source indexes
raise `DisputeOverlapCapacityError` (fixed nonsensitive text), never
silently truncate or return partial matches; callers can split the
hop query into smaller half-open ranges. The 32-KiB source-index limit
does not imply a global 16-window overlap ceiling; the 16-window sample
is a success regression, not an upper bound. Return an empty match list
for an empty index; reject invalid bounds and duplicate/noncanonical/
oversized/rehashed forged output and changed source order. Canonical
≤8-KiB ASCII binds full source index SHA-256. Real-source >16-window
capacity-refusal and 16-window all-matches build→verify regressions added.
Tests RED→GREEN and focused regression PASS; independent review's
Important capacity contract and Minor roadmap drift addressed. Exact-head
Ubuntu Python 3.13/3.14 CI `38103461194` PASS before merge; PR-only
Level-3 SKIPPED is not native acceptance. No host/provider/private I/O,
cache, native authority,
trusted chronology or severity. A1/B8/N1c/UID-502/stale provider/
real Level-3 remain OPEN.

**Merged public-only slice — bounded overlap pagination
(PR #201, branch `live-e2e-dispute-overlap-page`, merged to main as
`d9273a0583debdeb0fd029b31bae3776ebe374ff`):**
Add a separate deterministic source-verified page builder/verifier for
overlapping disputed windows, using exact integer hop bounds, matching
window offset 0..total and limit 1..16. Each public canonical ASCII page
fits ≤8 KiB; include complete clipped windows in length-first index rank
order, total matches, full rebuilt index digest and an advancing next
offset or terminal null. Automatically fit fewer than limit when required;
if one complete window cannot fit, reject with fixed sanitized typed
capacity error rather than silently truncate. Rebuild from original
ordered 3–5 source cohorts on every call and reject invalid, rehashed
forgery, reordered source and noncanonical output. TDD for multi-page
valid source overflow, cursor semantics, size, invalid inputs and
verifier. Independent review at `f8e4c0d` found 0 Critical/Important,
1 Minor: add source-verified later-longer rank-before-hop cross-page
`limit=1` build→verify test. Review Minor fixed by later-longer rank-before-hop across two `limit=1`
pages in `5ea3ad6`. Final main-base exact-head Python 3.13/3.14
workflow `38139789927` both PASS before merge. PR-only native
Level-3 SKIPPED is not native acceptance.
A1/B8/N1c/UID-502/provider disposition/native Level-3 remain OPEN.

**Merged public-only functional slice — disputed-overlap coverage
summary (PR #202, branch `live-e2e-dispute-overlap-coverage`,
merged to main as `5f340307b50ed467a458ed230777b8067f1129c8`):**
Provide a compact canonical ≤4-KiB ASCII source-verified coverage summary
for strict integer half-open hop queries. Report clipped disputed-window
intersection count, total disputed hops inside query and complementary
non-disputed query hops, along with full original index SHA-256.
Use original ordered 3–5 cohorts for every build/verify; never treat a
SHA-256 as authentication or infer severity/chronology/authority.
Fail closed on invalid bounds, oversized/noncanonical/duplicate/rehashed
wire and source reordering. Independent Review #202 (0 Critical/Important,
1 Minor) was addressed by real four-cohort mixed-coverage build→verify:
query [0,3) crosses two disputed windows and one unanimous gap,
returning 2 matched windows, 2 disputed hops and 1 unmatched hop,
with exact full index SHA-256. A real multi-segment >16-window index fixture
confirms the summary remains ≤4 KiB when full overlap output exceeds
8 KiB. This does not change #200's 8-KiB complete
overlap bound or #201's paginated retrieval; it enables bounded counts.
RED→GREEN focused regression, Ruff, docs consistency, independent review,
and exact-head Python 3.13/3.14 CI required before integration.
#201 merged as `d9273a0`; #202 passed exact-head dual Python
3.13/3.14 CI run `38141180265`, review Minor fixed, and merged
as `5f340307b50ed467a458ed230777b8067f1129c8`.
PR-only Level-3 SKIPPED is not native
acceptance; A1/B8/N1c/UID-502/provider disposition/native Level-3
remain OPEN.

**Merged public-only functional slice — batch dispute-overlap
coverage (PR #203, branch `live-e2e-dispute-overlap-coverages`,
merged to main as `0a17e0fe2d73420f44dd9380273ae6c463b35eb2`):**
Add canonical ≤8-KiB summary of 1–8 caller-ordered strict exact-int
half-open hop ranges. A single full index rebuild per build or verify
from original 3–5 ordered source cohorts serves all independent clipped
`matched_window_count`, `matched_disputed_hops` and `unmatched_hops`
results, including repeat/overlapping query pairs in caller order.
Never trust detached index or cached digest, reject oversized,
noncanonical/duplicate/rehashed forged wire, invalid/bool/out-of-range
pairs and reordered cohorts using fixed sanitized errors. TDD verifies
mixed-coverage source fixtures and that rebuild occurs once per call,
input refusal, wire tamper and preparse bound. Independent PR #203
review found 0 Critical/Important and 1 Minor: a list/list
validate-then-copy race. Fixed by bounded frozen outer and inner
snapshots before shape/value validation; added 8-pair upper-bound
build→verify and deterministic worker-thread mutation regressions. Production security
boundary unchanged: no private/host/provider I/O, authority, chronology,
severity or provenance. Run focused regression and Ruff, require an
independent security/docs review and exact-head dual Python 3.13/3.14
CI run `38144439187` Python 3.13/3.14 PASS on final main base;
#203 merged as `0a17e0fe2d73420f44dd9380273ae6c463b35eb2`.
Native Level-3 remains OPEN (PR-only skip is not acceptance), alongside
A1/B8/N1c/UID-502/provider disposition.

**Merged public-only functional slice — query-union disputed
coverage (PR #204, branch `live-e2e-dispute-overlap-union`, merged
to main as `30770c4a3652f9da0f74985bb929b695e1e03e05`):**
Extend navigation with an independent canonical ≤4-KiB union summary
over 1–8 strict exact-int caller-ordered half-open ranges. Freeze bounded
outer and inner inputs once; sorted merged intervals deduplicate all
overlaps, repetitions and touching endpoints. Report requested unique
hops, distinct intersecting disputed windows, clipped disputed unique
hops and complementary non-disputed hops, retaining original query
order and full source-index SHA. Rebuild full ranked index once from
original ordered 3–5 cohorts per build or verify; no detached index,
private host/provider I/O, trusted severity/time/provenance/authority.
TDD tests overlapping/duplicate union, mixed-gap coverage, disjoint
ranges, 8-range bound, malformed/oversized/duplicate/rehashed wire and
changed source order. Independent PR #204 review found 0 Critical,
0 Important, 2 Minor: added source-derived one long disputed window
split by two non-touching query clips, which must count 1 distinct
window/2 disputed hops, with build→verify; updated #201 merged status, #202 now merged status, #203 main-base
retarget and current #203→#204 stack and CI gates. Require independent
review and exact-head Ubuntu Python 3.13/3.14 CI run
`38149588161` both PASS on main-base, then #204 merged as `30770c4`.
PR-only Level-3 skip is not native approval.
A1/B8/N1c/UID-502/provider disposition/native Level-3 remain OPEN.


### CI architecture change — GitHub-hosted PR CI, self-hosted native E2E (2026-10-12, pending PR)

The staged CI throughput plan moves routine Python 3.13/3.14 PR/main-push
**full test suites** (including privileged-operator source tests, Ruff and
compile) to parallel GitHub-hosted Ubuntu 26.04 x86 VMs. Historical required
Python check names remain unchanged and fail closed. The PR workflow uses
`pull_request` instead of `pull_request_target` and does not provide
repository secrets or write token permissions. Strict Linux test identity
is retained through a non-root `setpriv` step that clears only GitHub-hosted
desktop supplementary groups. The manual trusted-main hardened
`self-hosted-security.yml` workflow remains separate and intact.

The **real, native no-network Level-3** E2E must still run after BOTH main-push
required checks succeed, on the dedicated non-admin macOS Intel QEMU
orchestrator with exact merged main SHA. It must not be represented as having
passed for a PR or while still queued. The optional second ephemeral Linux
Docker runner is capacity for dedicated security tests, **not** a prerequisite
to routine PR CI. The hosted full-suite canary
[38294820787](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38294820787)
is PASS for both Python versions, but required ~12m17s end-to-end; the
10-minute goal is **not yet established**. The four-VM hosted partition
experiment is pending [PR #216](https://github.com/zhangyuz/ssh-over-mcp/pull/216).
Rollout and post-merge acceptance require exact-head dual Python PASS,
no missing test nodes, no weakened security checks, trusted-main native
Level-3 PASS, and repeated end-to-end P95 under 10 minutes; see
`docs/ci-hosted-primary.md`.


### Six-way GitHub-hosted throughput milestone (2026-10-12, review pending)

Follow-up primary-CI migration integration retains Python 3.13/3.14
historical required check names as two independent fail-closed aggregate
gates, covering six parallel GitHub-hosted Ubuntu 26.04 shard jobs (3
disjoint partitions per Python). First separate six-way hosted
[Canary 38300258158](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38300258158)
fully PASSED 7/7 jobs in **7m02s end-to-end**. The 611 source-heavy module
tests split as exactly 4 selected hot IDs plus 607 other tests; all other
project tests remain in the rest partition, tested for both Python versions.
The earlier two full-suite hosted [Canary 38294820787](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38294820787)
PASSED in 12m17s, and four-way [Canary 38297317913](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38297317913)
PASSED in 10m08s. **One 7m02s sample is not verified P95 <10m.**
Only trusted main continues native no-network Level-3 on the dedicated
non-admin Intel Mac x86 QEMU runner, and manual hardened security workflow
is unchanged. Maintain source/docs/test consistency, exact-head green gates,
post-merge exact-main CI and native Level-3 PASS, and multiple genuine
performance samples before claiming final completion. GitHub branch
protection cannot be read on this private-repo plan (HTTP 403); manually
verify each required status and do not assume enforcement.


### Hosted CI latency acceptance (2026-10-12)

The unchanged production workflow and actual tested source/test/operator
Git objects now have **10/10 complete hosted successes**: median
**7m14s**, observed nearest-rank P95 and maximum
**7m22s**, all under 10m. Exact-main `db42a8e`
run `38323133514` passed the six shards and both historical gates in 7m12s.
See [the reproducible acceptance record](ci-production-acceptance-2026-10-12.md).
This closes the observed **ordinary hosted CI speed gate** only. Native
Level-3/provider cleanup, actual UID-502 provenance and manual hardened
security acceptance remain open; overall main workflow still fails on the
pre-existing native provider state. Future runtime is not guaranteed by ten
same-evening samples; retain all routine outcomes and review regressions.


**Next native CI blocker — read-only residual inspection (2026-10-12):**
CI speed is accepted; exact-main native run 38325534351 still fails closed on
stale provider state. Fresh inspect-only 38327646572 preserves the three
UID-502 partial/unbound directory identities. The user approved the separate
[ADR 0014](decisions/0014-exact-residual-forensic-inspection.md) forensic slice
to obtain complete bounded metadata evidence before a reviewed disposition.
Implementation/review/live observation remain pending. No deletion, marker
clearance, provenance recovery or native Level-3/A1/B8/N1c closure is claimed.

**In-review isolated public-only slice — source-verified
non-disputed gap pages (PR #205, branch `live-e2e-dispute-gap-page`,
now targeting main after #204 merged):** Add a separate bounded canonical ≤4-KiB ASCII API that
returns complement spans of disputed windows inside one strict exact-int
half-open hop query. The list is sorted by hop location, not by ranked
window position. `offset` identifies matching gap number (0..total),
`limit` is 1..8; each full-page gap has positive width and
`next_offset` advances until terminal null, with empty terminal
page when offset==total. Every build and independent verify rebuilds
the original ordered 3–5 source cohorts' full public dispute index;
no detached index, private I/O, cache or host/provider authority.
Strict preparse ≤4-KiB/digest/canonical checks and byte-for-byte
original-source verification refuse malformed/duplicated/oversized/
rehashed-forged output, invalid/bool hop/cursor/limit or reorder.
TDD includes mixed disputed/unanimous sources, real two-page gap cursor
fixture, empty-source/all-disputed cases, invalid inputs, and forgery
refusal. Independent PR #205 review (0 Critical/Important, 2 Minor)
requested original-source majority-not-unanimous gap and leading/trailing
clipped query coverage including the valid 8-gap limit, plus historic
roadmap repair. Added a 4-cohort, 2-segment 24-hop original source fixture
with eight majority gaps and independently verified build→verify; updated
#202 to Merged, #203 to merged commit `0a17e0f`, and #204 to
main-base. A gap is unanimous or majority, **not** certified safety
or native observation. Independent review and final exact-head Ubuntu Python
3.13/3.14 CI required on final HEAD/main-base; #204 merged,
#205 is retargeted to main and remains open.
A1/B8/N1c/UID-502/stale provider/native Level-3 remain OPEN;
PR-only Level-3 skip does not certify native acceptance.

**Next isolated public-only functional slice — three-class hop coverage
(branch `live-e2e-classified-hop-coverage`, stacked on PR #205):**
Add canonical ≤4-KiB ASCII original-source-verifiable count summary for
one strict exact-int half-open hop query: positive-width counts of
unanimous, majority, disputed hops, their sum and the non-disputed
(unanimous+majority) count. The return is navigation only, not trust.
Each build and independent verify reconstructs complete ordered 3–5
cohort `staging_consensus_intervals` once and clips their source
intervals. Include full original interval digest; SHA-256 provides
consistency only, not authenticated source provenance. Fail closed on
bool/invalid/out-of-bounds, oversize/digest-before-parse, duplicate-key,
noncanonical, rehashed forgery and source reorder. TDD exercises a
single real source fixture with majority, disputed and unanimous hops,
clipped subset, bad inputs/tamper, and one source interval rebuild per
call. Keep modules path-free and entirely offline: no host/provider/
private I/O, detached or cached summaries, native authorization,
severity, or trustworthy chronology. Independent PR #206 review
(0 Critical/Important, 2 Minor) requested cross-API parity from the
same original cohorts and roadmap gate correction: compare disputed hops
against #202 single-range coverage and exhaustive gap-page non-disputed
length against unanimous+majority, including clipped queries and majority
hops. PR #204 merged as `30770c4`; #205 must merge first, then retarget
#206 to main and verify exact final-head Python 3.13/3.14 CI and
independent review before merging. PR-only Level-3 SKIPPED
is not native acceptance; A1/B8/N1c/UID-502/provider native Level-3
remain OPEN.

**Next isolated public-only slice — source-verified classified-hop batches
(branch `live-e2e-classified-hop-coverages`, stacked on PR #206):**
Add a separate ≤8-KiB canonical ASCII builder/verifier for 1–8
caller-ordered (possibly duplicate/overlapping) strict exact-int
half-open queries. One complete original 3–5 cohort intervals rebuild
per build/verify call serves per-query clipped unanimous/majority/disputed
counts and non-disputed sum, with exact width identity and complete
source-interval SHA. Bounded caller-list capture must precede all
validation/use; reject malformed/boolean/out-of-range queries, oversize,
noncanonical/duplicate/rehashed forged wire, and reordered cohort
sources by fixed sanitized failures. Keep source fully public and
offline: no detached index/cache, host/provider/private I/O, trusted
time, severity, provenance or authorization inference. RED→GREEN tests
cover real mixed-class two-segment original cohorts, caller-order and
duplicates, legal eight-query upper bound, invalid shape/type/bounds,
one rebuilt full source per invocation, rehashed forgery/source
reordering and parsing size cap. Independent security/docs review and
**final exact-head dual Python 3.13/3.14 CI** after PR #205 and PR #206
have merged and this stacked branch retargets main are required.
PR-only Level-3 skipped is not native acceptance; A1/B8/N1c/UID-502/
stale provider/native Level-3 remain OPEN.

Independent PR #207 review (exact initial HEAD `f1bd728`, 0 Critical,
0 Important, 1 Minor) requested deterministic mutable-input snapshot
regression. A synchronized worker thread now mutates either an outer
8-pair list by appending a ninth query or one existing inner range's
boundary *during* original-source rebuild. For both build and verify,
the canonical payload and verified facts must stay bound to the eight
original frozen pairs. Production logic already freezes before source
I/O; this is a forward regression guard, not an observed runtime bug.
#205 and #206 remain upstream merge gates; the final exact-HEAD/main
Python 3.13/3.14 CI plus independent review remain required.

**Next isolated public-only slice — classified hop union coverage
(branch `live-e2e-classified-hop-union`, stacked on PR #207):**
Add bounded 1–8 original caller-ordered strict-int half-open hop queries
with sorted merged unique intervals (overlapping, duplicate and
touching segments coalesce). Return canonical ≤4-KiB ASCII one-shot
source-verified unique unanimous/majority/disputed and non-disputed
hop counts with the complete original source-interval SHA-256.
Independent build/verify each reconstruct the original ordered 3–5
cohort public intervals exactly once; never use detached/cached data.
Bounded frozen outer/inner input capture, original-query echo, disjoint
sorted merged ranges, strict sum=unique width and byte-for-byte
original-source verifier are mandatory. Invalid/bool/shape/oversized,
duplicate-key/noncanonical/rehashed forgery and reordered originals
fail with fixed sanitized errors. RED→GREEN focused tests include
real mixed-class source fixture, duplicates/touching queries, disjoint
8-input bound, one rebuild for build and verify, invalid shape/type/
bounds and tampered/reordered/oversized before parse. No host/provider/
private I/O, trusted time, provenance, severity or authority. Independent
security/docs review and final exact-head dual Python 3.13/3.14 CI are
required after #205→#206→#207 merge and final main retarget; PR-only
Level-3 SKIPPED is not native acceptance. A1/B8/N1c/UID-502/stale
provider/native Level-3 remain OPEN.

Independent PR #208 review at initial HEAD `4bb22cc` found
**0 Critical / 0 Important / 2 Minor**: requested a real
four-cohort, two-segment source fixture with disjoint union queries
cross-checked against original-source rebuilt disputed overlap union
and the per-merged-range one-query classified coverage; and deterministic
build/verify worker-thread mutation after the new batch's bounded freeze.
Two parametrized parity queries cover majority, unanimous and disputed
hop mixes and clipped gaps, asserting unique, disputed and non-disputed
counts are identical across API layers and summing every classified
merged range exactly reconstructs the union totals. Four deterministic
snapshot tests cover append-ninth outer mutation and a changed inner
hop boundary during source rebuild in both build and verify. No
production change: independent reviewer found existing algorithm and
security invariants sound. Exact final-head dual Python 3.13/3.14 CI,
independent final review and upstream #205→#206→#207 merges remain gates.

**New isolated public-only slice — source-verified classified hop interval
pages (branch `live-e2e-classified-hop-page`, stacked on PR #208):**
Add source-bound canonical ≤4-KiB ASCII per-page navigation of the
original `staging_consensus_intervals` rows clipped by one strict
exact-int half-open hop query. The public projection includes only
classification (unanimous/majority/disputed) and clipped start/end
bounds, not sensitive group or host metadata. Preserve original
interval boundaries and chronological **hop index navigation only**,
not verified time, security severity, provenance or authority.
`offset` counts clipped source segments (0..total) and `limit` is
1..8, with full positive-width segments, monotonic nonterminal cursor
and explicit empty terminal pages. Build/verify each rebuild complete
original ordered 3–5 cohorts' public intervals once, bind their full
SHA-256 and compare exact canonical bytes. Reject bool/invalid/
out-of-bounds query/cursor/limit, oversize/digest-before-parse,
duplicate-key/noncanonical/rehashed forgery and changed original order
with sanitized errors. TDD includes mixed real source segments and
multi-page cursor verification, valid 8-segment upper bound, query
clipping, empty terminal, invalid type/bound, tamper and one complete
source rebuild per call. Independent security/docs review and final
exact-head dual Python 3.13/3.14 CI required after #205→#206→#207→#208
merge and this branch retargets main. PR-only Level-3 skip does not
equal native acceptance; A1/B8/N1c/UID-502/stale provider/native
Level-3 remain OPEN.

Independent PR #209 review at initial HEAD `0ccbb46`: **0 Critical,
0 Important, 1 Minor**, concerning a test that asserted both-end
clipping although its query start was exactly at a source interval
boundary. Added real original four-cohort/two-segment source
build→verify parity: query endpoints strictly inside two *different*
underlying source intervals, `limit=1` traversal through all clipped
segments, preservation of full original intervals SHA and precise
unanimous/majority/disputed hop totals matching the original-source
#206 single-query classified summary. No production algorithm change.
Final exact-head dual Python 3.13/3.14 CI and independent review
remain mandatory after #205→#206→#207→#208 merge and main retarget.

**New isolated public-only slice — class-filtered classified hop interval
pages (branch `live-e2e-classified-filter-page`, stacked on PR #209):**
Add canonical ≤4-KiB ASCII per-page source-bound projection of
original classified intervals for one strict exact class selected from
`unanimous/majority/disputed` and one strict exact-int half-open hop
query. Filter *before* cursor navigation; `offset` counts only
matching clipped original interval rows (0..total); `limit` 1..8,
monotonic nonterminal cursor or terminal null, including zero-match
and explicit offset-total empty page. Preserve original source
agreement boundaries and stable hop ordering; do not treat majority or
unanimous as certified safe. Independently build/verify from the full
original ordered 3–5 cohorts' interval index exactly once per call,
bind complete source interval SHA and compare byte-exact canonical
bytes. Fail closed on malformed/bool/invalid class or bounds,
oversized/digest-before-parse, duplicate keys, noncanonical and
rehashed forgery, source reorder via fixed sanitized errors.
RED→GREEN tests cover all three real source classes, paging,
independent one-query class length parity, empty terminal,
strict invalid input, forged wire and one rebuild per invocation.
No host/provider/private I/O, cache/detached index, trustworthy time,
severity, authorization or authenticated provenance. Independent
security/docs review and final exact-head dual Python CI after
upstream #205→#206→#207→#208→#209 merge and #210 main retarget
remain mandatory. PR-only Level-3 skipped is not native acceptance;
A1/B8/N1c/UID-502/stale provider/native Level-3 remain OPEN.

Independent PR #210 review (original HEAD d2ed1c7, 0 Critical /
0 Important / 2 Minor) requested stronger source-derived pagination
tests, not a change to production algorithm. Added exact real
four-cohort/two-segment source regression with a filtered majority query
whose *both* boundaries fall strictly inside separate source intervals;
page cursor/length and full source SHA cross-check against independently
verified #206 classified coverage. Added a separate real eight-hop
disputed-only original source with changing agreement groups across
all eight adjacent same-category intervals; verified one legal
limit=8 page and complete limit=1 cursor traversal without
coalescing source identities. This is navigation evidence only,
not provenance/safety/host authority. Exact-head 3.13/3.14 CI
and upstream merges #205→#206→#207→#208→#209 remain gates.

**New isolated public-only slice — source-verified multi-class filtered
classified interval pages (branch live-e2e-classified-multifilter-page,
stacked on PR #210):** Allow 1–3 distinct exact selected public classes
(unanimous/majority/disputed), captured immutably from bounded
caller-owned tuples/lists. Return original-source hop-ordered matching
interval pages (offset=0..total, limit=1..8), preserving agreement-group
boundaries rather than coalescing equal-class rows. Output is canonical
≤4-KiB ASCII, binds full original source-interval SHA-256, and demands
independent byte-exact rebuild of the entire ordered 3–5 cohort intervals
once per build or verify. Strict exact-int query/cursor/limit and
category duplicate/type/unknown input refusal, preparse size+digest,
duplicate-key/noncanonical/rehashed forgery and source reordering
must fail closed with fixed sanitized errors. TDD covers original
mixed classes, selected category order and source order, full eight
segments, empty terminal page, independent one-query class sum parity,
invalid input/rehashed fraud/source reorder, and deterministic caller
list mutation during rebuild for both build and verify. Navigation
does not certify safety or privilege, chronology, severity, provenance
or host/provider/private authority. After upstream
#205→#206→#207→#208→#209→#210 merges, require retarget to main,
exact-final-head Python 3.13+3.14 CI and independent comprehensive
review. PR-only Level-3 SKIPPED is not native acceptance; A1/B8/N1c/
UID-502/stale provider/native Level-3 remain OPEN.

Independent #211 deep review (initial HEAD e9bb141, 0 Critical,
0 Important, 2 Minor) requested extra regression—not production
algorithm changes—for source-bound 1-class vs #210 paging and
2-class source-hop interleaving after strict interior clipping at both
query ends, including original interval SHA and #206 class-count
consistency. Added both real original cohort coverage and deterministic
3-to-4 category-list worker race during original interval rebuild
for build and verify, preserving the first immutable legal triple
and exactly one original rebuild per call. Final HEAD/source-specific
dual Python CI and independent review remain necessary; #205→#210
upstream stacked merges are still blocked.


### Classified hop public-only APIs — consolidated integration (2026-10-13)

Historical slices #205–#211 were independently reviewed, with all reported
Minor source-derived regression/doc corrections incorporated at their final
stacked heads. The seven PRs are being reconciled with the latest main
through a single consolidated integration candidate, not treated as seven
independent green merges. Each module is still offline public-only
projection over original ordered source cohorts; hashes prove content
equality and source reconstruction only, never host provenance, safety,
authorization, absence of tampering or native Level-3 acceptance.

The original pre-migration #205–#211 checks were incomplete/cancelled and
cannot authorize this integration. Require the consolidated exact-head
GitHub-hosted full six-shard Python 3.13/3.14 validation, both historical
required gates and fresh combined source/security/docs review before
integration. Preserve immutable main-source replay, bounded exact-integer
input, deterministic frozen caller parameters, at-most-4/8-KiB canonical
ASCII, digest/size-before-parse and fail-closed rejection contracts. The
original stacked PRs are superseded only after the consolidated patch is
verified on main and merged; do not claim earlier missing checks passed.

CI performance acceptance remains 10/10 under 10 minutes for the earlier
ordinary suite, but the additional projection tests require separate runtime
measurement. PRs #221, #224 and #225 have since merged on main; the
trusted-main read-only forensic run 38331323606 refused with exit 70
without evidence, and fresh marker-only inspection 38331933826
reconfirmed the same three UID-502 residual identities, all without valid
expected_commit. No directory deletion, marker clearance, process signal,
privilege escalation, E2E guest launch or disposition is authorized. Native
Level-3, A1/B8/N1c provenance and exact cleanup remain OPEN.


### Source-heavy CI rebalance during classified-stack integration (2026-10-13)

The first updated-main integration CI run 38333335954 proved that adding
#205–#211 source-bound regression cases can make Python 3.14 projection-rest
exceed the original under-ten-minute end-to-end budget, although the other
five partitions passed. This is a measured runtime regression, not a proven
assertion failure or native E2E clearance. To rebalance without changing
scope, move 15 exact nodes selected from the source-heavy Python 3.13
projection-rest hosted slowest-call evidence in run 38332697221 to the
existing projection-hot shard. Preserve all four original hot nodes and
all remaining projection tests; exact IDs are deselected from projection-rest
while every other test stays in its existing partition. Both historical
Python required checks still require all six hosted partitions to succeed.
The changed routing must be revalidated by new exact-head hosted CI for
both Python versions. Prior 10/10 speed acceptance remains historical and
does not imply this expanded suite has met the latency target.


### Complementary projection-rest hosted shards (2026-10-13)

Exact-node collection on the #227 integration checkout records **795**
projection parametrized nodes. The four original plus 15 additional
hosted-measured hot IDs select 19 unique nodes. Two complementary pytest
keyword filters applied to the remaining collection select **408**
'classified or dispute' and **368** 'not (classified or dispute)' nodes.
Disposable local --collect-only proof confirmed all **795 = 19 + 408 + 368**
nodes are covered once, with zero overlap or omissions. Neither source
tests nor assertions changed. The general rest partition continues to
exclude only the projection source module. The new workflow has eight
parallel hosted partitions (four per Python) and retains both historical
required check names; each aggregate fails closed unless all eight pass.
Only the native main-push Level-3 stage uses the non-admin Intel Mac runner.

The preceding six-partition integration run passed functional checks but
exceeded the 10-minute latency target due to expanded projection-rest work.
This eight-way layout is an improvement candidate, not a new speed PASS
before its exact-head hosted CI validation and measurement.


### Native provider investigation resumed — exact decision pending (2026-10-13)

Main f25117f (merged #239) passes all eight hosted partitions and both
Python aggregate gates in CI38425538261, but native Level3 fails before
QEMU because the historical provider marker remains. Reconciled private
observations cover all three exact roots: 1362 directories and six
symlinks, no regular files; fresh root #2 observation38427240585 matches
the earlier two inventories. The Mac's registered midnight tmp_cleaner
provides a concrete explanation consistent with lost old regular payloads
and surviving directory/link skeletons, but historical provenance remains
unproven. The [operator decision plan](plans/2026-10-13-native-provider-recovery-decision.md)
is proposed only. No disposal implementation, execution, marker recovery,
or native acceptance is authorized or complete. Future temp-root alignment
is a separate design task. Preserve both older dirty recovery worktrees.


### Approved exact historical disposition implementation (2026-10-13)

The operator approved the exact decision in PR #240 at12:18:16 EDT. ADR0018
and the separate incident tool/workflow bind three full private inventory
digests and the unchanged marker. Disposable Mac tests exercise opaque-link
removal, bottom-up directories, drift refusal, journal/replay and I/O
uncertainty. Actual native recovery and cleanup remain OPEN until fresh
review, exact-head hosted CI, trusted-main merge/inspection, approved
disposition, guarded marker recovery and actual exact-main Level3 succeed.
Future temp-root alignment remains separate. Earlier no-authorization
statements describe the historical state before this explicit approval.


### Historical native provider incident recovered and verified (2026-10-13)

PR #240 merged as main 53868a714308273e4f3292483ff3e33299193c1e. Approved
exact-root disposition 38437724175 and existing guarded marker recovery
38438738523 passed. Exact-main CI 38437463320 attempt 2 passed all eight
hosted partitions, both Python gates and actual no-network native E2E,
including guest-run and provider-state absence steps. The earlier first
native attempt correctly refused the not-yet-recovered marker; retain that
failure in evidence. The [acceptance record](evidence/2026-10-13-native-provider-recovery-acceptance.md)
binds the complete 1368-operation private journal and actual revisions.
The stale-provider blocker is RESOLVED. This does not reconstruct historical
provenance or automatically close A1/B8/N1c; future temp-root alignment is
a separate design task. The user's active progress.md handoff and both
older dirty worktrees remain preserved.


### Next Phase 7B1 infrastructure prerequisite — approved protected staging design (2026-10-13)

Verified main b39e08a (PR #241) passed full hosted CI and actual native E2E/cleanup
in run 38466541180. The historical provider incident is resolved. Future staging
retention/selector alignment remains a separate architectural change; see
[ADR 0019](decisions/0019-protected-native-e2e-staging.md) and
[written design](superpowers/specs/2026-10-13-protected-native-e2e-staging-design.md).
The approved design uses a fixed private Application Support namespace with
shared protected+legacy blocking checks and explicit owned lifetime. The first
implementation supplies dormant inspection only: existing runtime callers and
workspace placement are unchanged. It grants no activation, generic deletion
or historical receipt authority. The operator approved the written design on 2026-10-13; the
[first implementation plan](superpowers/plans/2026-10-13-protected-staging-health-inspection.md)
was approved by the operator on 2026-10-13 at 21:55:05 America/Toronto for
native execution with independent review and delivers only dormant shared
namespace health inspection. Three separate deliveries are required: dormant
inspection, dormant owned lifetime, then already-main activation. The design
pins all existing tempfile/free-space/recovery replacements and deliberately
refuses shared /private/tmp timestamp drift even from unrelated foreign activity;
see its activation checklist and shared-parent availability ruling. After verified activation, reconcile A1/B8 pause conditions before N1c, complete
N1–N4 native proof, then return to Ledger systemd Task 3. Do not claim the
remaining native toolchain/sandbox gates closed by incident recovery.

### First protected-staging delivery — dormant namespace inspection

The [slice evidence](evidence/2026-10-13-protected-staging-health-inspection.md) records selector/discovery, FD-bound Darwin/APFS ACL and fixed-chain inspection, and two metadata-only clean observations. This implementation has no production caller or workspace mutation. Pre-merge full/exact-head hosted and legacy E2E gates plus independent final review remain required. Next is a separately reviewed owned-workspace lifetime plan, followed by already-main activation and actual protected-placement acceptance. A1/B8/N1c and Ledger gates remain open.

### Proposed Local Live E2E vNext architecture (2026-10-14; design review only)

The [written design proposal](superpowers/specs/2026-10-14-local-live-e2e-vnext-design.md)
and [proposed ADR 0020](decisions/0020-trusted-pr-native-e2e-admission.md)
retain the trusted-main no-network native provider while proposing a separate
hosted completed-CI admission, exact-PR-head proof, bounded native queue and
post-clean PR status reporter. Current repository visibility is public.
The initial implementation candidate is **shadow admission only**: no native
dispatch or success status. The [vNext staged implementation roadmap]
(superpowers/plans/2026-10-14-local-live-e2e-vnext-rollout.md) and
[first detailed RED→GREEN plan]
(superpowers/plans/2026-10-14-pr-native-e2e-shadow-admission.md) are available
for joint operator review; neither is implementation authorization. Existing main-push/native CI is unchanged.
Owned staging lifetime, already-main protected placement activation, actual
UID-502 protected-path acceptance and A1/B8/N1c remain independent open gates
under ADR 0019. Neither this proposed design nor its draft PR authorizes an
automatic Mac run or required-check/ruleset change.


### PR #244 independent design review disposition — 2026-10-14

[Independent review comment 6166828549](https://github.com/zhangyuz/ssh-over-mcp/pull/244#issuecomment-6166828549)
identified three blocking proposed-design issues: (1) the live trusted Mac
orchestrator rejects `workflow_run` context; (2) ten green PR-CI job names are
not proof of the trusted-main test procedure because the PR can edit CI;
(3) a SHA-scoped status cannot enforce per-PR fork authorization.
The revised [vNext spec](superpowers/specs/2026-10-14-local-live-e2e-vnext-design.md),
[proposed ADR 0020](decisions/0020-trusted-pr-native-e2e-admission.md) and
[rollout](superpowers/plans/2026-10-14-local-live-e2e-vnext-rollout.md)
now require a metadata-only shadow verdict (never CI authority), a separately
pinned trusted-main hosted verification gate, a main-only `workflow_dispatch`
broker with fresh identity/proof checks (not a `workflow_run` direct caller),
separate informational SHA reporting, and a separately reviewed PR-bound merge
authorization with a two-PR/same-SHA fork refusal proof.
No native workflow, permission, status, branch-rule or provider behavior
has been changed or authorized. Existing main-push E2E is unchanged.

### Local Live E2E vNext — first implementation slice: metadata shadow

The reviewed design from PR #244 was merged at
`18baf09d31a2610c2ce4359bd04a9ebf85cbb62f`. The next isolated
feature branch implements only the
[Shadow Admission first-slice plan](superpowers/plans/2026-10-14-pr-native-e2e-shadow-admission.md)
using a pure PR/CI metadata observer, bounded read-only GitHub REST adapter,
informational-only CLI and hosted `workflow_run` YAML, with adversarial
TDD and [implementation evidence](evidence/2026-10-14-pr-native-e2e-shadow.md).
This slice **does not** attest trusted test execution because a PR may
alter the upstream CI, **does not** start a Mac E2E, and **does not** write
a merge status. Post-merge shadow canary and exact-main CI/native cleanup
remain separate acceptance evidence, not local-test assumptions.

### Local Live E2E vNext — Shadow Admission slice acceptance (2026-10-14)

[Implementation PR #245](https://github.com/zhangyuz/ssh-over-mcp/pull/245)
was independently reviewed with no Important/Critical findings, its two Minor
requests were addressed with 14 additional RED→GREEN event-identity cases,
and it was squash-merged at `7ec63ec7a39803518eda628b95021b46e666899e`.
[Exact merged-main CI #38580710142](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38580710142)
PASSED eight hosted partitions, both Python aggregates and real native Level-3
no-network E2E plus cleanup. The
[actual `workflow_run` shadow canary #38581841150](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38581841150)
PASSED on temporary non-draft
[PR #246](https://github.com/zhangyuz/ssh-over-mcp/pull/246)
with `METADATA_MATCH_SHADOW` and all proof/dispatch flags `false`. No extra
Mac dispatch or commit status write occurred; the canary was closed without
merging and its temporary branches/worktree cleaned. Exact evidence:
[shadow acceptance](evidence/2026-10-14-pr-native-e2e-shadow.md).

**Boundary remains unchanged:** Shadow output records Github-reported metadata
only; it does NOT prove a trusted-main regression manifest, authorize native
PR execution, require a SHA status, or provide a PR-bound merge gate. Next
independent work is ADR 0019 owned lifetime then protected-placement native
activation; subsequent hosted trusted-main suite verification and scoped
`workflow_dispatch` broker remain gated by separate plans and reviews.

### ADR 0019 — dormant protected workspace primitives (revised plan; awaiting approval)

[Independent security/design review #6172447419](https://github.com/zhangyuz/ssh-over-mcp/pull/248#issuecomment-6172447419)
found three Important authority/order gaps in the first
[owned-workspace plan](superpowers/plans/2026-10-14-adr19-owned-protected-workspace-lifetime.md):
re-reading a same-PID marker does NOT prove the original O_EXCL claim,
a guest-reaped Boolean is not a trusted QEMU completion receipt, and no
mkdir can occur before the marker/cleanliness gate. Two Minor findings
required distinct pre-create/owned-child/post-dispose scan phases and an
explicit single-writer assumption for timestamp attribution.

The revised **Slice 2A** plan is deliberately narrower: production
workspace entrypoints refuse as unbound, while test-owned disposable
marker permits exercise pinned FD-bound exclusive creation, exactly-one-owned
child observation, no-follow owned-only deletion, close-only finalization
and real UID-502/APFS fixture behavior. **This plan is proposed, not approved
or implemented. No live claim or QEMU completion authority is granted.**

A separate reviewed **Slice 2B** must bind the real trusted-main O_EXCL
marker-claim handoff and one-shot run-bound QEMU reap receipt before any
live provider directory creation or deletion. Only a later separately
approved **Slice 3** may activate protected placement, recovery and native
workflow changes. Current legacy E2E and marker wire formats remain
unchanged. After implementation code and author self-review finish, request
independent review **immediately**, in parallel with exact-head CI.

### ADR 0019 Slice 2A — dormant unbound FD primitives (implementation review)

A first [Slice 2A implementation evidence](evidence/2026-10-14-protected-staging-owned-lifetime.md)
candidate now targets `main` after the approved [plan PR #248](superpowers/plans/2026-10-14-adr19-owned-protected-workspace-lifetime.md) was squash-merged.
Only disposable fixture original-FD creation/owned-only cleanup is exercised;
production entrypoints always refuse as unbound. Real marker handoff, QEMU
reap proof, existing protected/legacy authenticated admission and production
placement are not implemented. Real Mac UID502 tests remain pending because
the command account is UID501 without passwordless switching authority.
Code-complete review is requested immediately, independent of CI status.

Independent review of this first feature PR found three Important fixture
safety defects (claim/ancestor drift, partial-open FD leaks, unbounded scans)
and one Minor macOS APFS evidence gap. The code was amended using negative
RED→GREEN tests: original marker/ancestor identity before fixture cleanup,
close-once FD transfer on every failed creation, fully bounded directory
enumeration, and explicit fstatfs APFS assertion. These changes **do not**
remove the earlier UID502/native or full protected/legacy scanner integration
gates; see the evidence document above.

**PR #251 security-frozen workflow exception.** The original trusted-main
workflow is byte-frozen under `test_protected_staging_dormant.py`. After
independently auditing the **only workflow diff** against its trusted base,
the finalizer's one command is deliberately replaced with a no-follow
verification helper; the **single corresponding SHA-256 freeze entry** is
updated. All other frozen authorities, triggers, SHA-pinned checkout,
shared concurrency, guest admission, runner permissions and recovery paths
remain unchanged. The helper hard-pins the same literal
`/Users/gha-e2e-orchestrator` as the original orchestrator, verifies the
dedicated UID502 account and current HOME match, and offers **no CLI
override** for its root. The pure Python check accepts disposable fixture
directories only as a directly imported test interface; production
workflow always invokes the fixed-root CLI.

### Native Level-3 cleanup guard — dangling-marker symlink hardening (review pending)

A small, separately reviewed security follow-up hardens the existing
Verify provider state is absent step in the native workflow
(.github/workflows/live-local-e2e.yml).
Previously a plain shell test ! -e followed the leaf link: a dangling
active-run.json symlink could be silently reported as an absent marker.
The new read-only postrun helper first verifies the dedicated UID502
account and HOME match its **fixed provider root**, then opens that fixed
home and three literal cache directories through
O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC FDs, and uses
os.stat(..., dir_fd=..., follow_symlinks=False) for the marker leaf. Only a genuinely missing leaf is accepted; a missing,
symlinked or inaccessible parent and every existing marker entry refuse.
The guard does not recover, delete, adopt or repair anything.

Local RED→GREEN contract tests exercise **the original importable
helper** against disposable filesystem roots (normal and missing marker,
valid/dangling leaf and ancestor links, permission/lookup failures).
A **separate real production YAML shell-step test** verifies refusal for
a divergent disposable HOME; it cannot perform a positive production
UID502 CLI test on the UID501 developer shell. The true postmerge
trusted-main native Level-3 run remains the positive host acceptance gate.
New adversarial tests rename/replace the held provider cache directory
after open and immediately after marker ENOENT, then plant a marker in
the canonical replacement: both must refuse on original FD/edge drift.
Checks compare original home + each pinned parent/child dev, inode,
uid, gid and full mode, before and after marker absence observation.
POSIX lookup is not atomic against hostile concurrent same-UID writers:
this acceptance assumes a serialized single-writer provider context,
not proof of unconditional race immunity. The helper is itself added to
the SHA-256 frozen native authority inventory. Any future executable
helper change requires a deliberate independent review and hash update.
Existing runner labels, checkout, trigger, no-network guest and
marker wire format remain unchanged.
This is not evidence of a passed protected UID502 staging fixture;
final exact-HEAD CI and independent review are required before merge.

### Phase 7 — ADR 0019 UID502 inert preflight contract (implementation iteration, 2026-10-14)

The jointly reviewed [design](superpowers/specs/2026-10-14-adr19-uid502-trusted-preflight-design.md)
and [TDD plan](superpowers/plans/2026-10-14-adr19-uid502-inert-preflight-contract.md)
were approved as **documentation only** and merged via
[PR #252](https://github.com/zhangyuz/ssh-over-mcp/pull/252), after independent
re-review cleared all previous findings. The exact merged documentation
baseline is `1c29ae8e8f8dfdb699d64e5f82285d46160473a6`.

A separate feature implementation now introduces an **inert, host-independent,
synthetic-only contract** in `ops/live-e2e/uid502_preflight_contract.py`.
Its two outputs, `CONTRACT_REFUSED` and
`CONTRACT_ELIGIBLE_FOR_HOST_PROBE`, are **not host admission,
authentication, fixture acceptance, workflow dispatch, CI status, or
production activation**. The accepted positive interpreter witness is a
**fictional test-only path**, not a real trusted Python installation.
The observed UID501/GID80 group-writable Homebrew ancestry remains
**refused pending a separately reviewed immutable interpreter and
operator/security trust decision**.

The trusted-main legacy no-network Level-3 and provider-marker postrun
verification succeeded in [main CI #38648215422](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38648215422),
but do **not** prove the ADR 0019 UID502/APFS original Slice 2A physical
nine-case matrix. Real UID502 acceptance, expected-forensic-quarantine
disposition, protected placement Slice 2B/3, any new persistent-Mac
workflow, and ADR 0020 automatic PR-native dispatch remain unapproved
or UNVERIFIED. See [contract evidence](evidence/2026-10-14-adr19-uid502-preflight-contract.md).

### Phase 7 — ADR0019 Gate A interpreter provenance consistency (2026-10-15)

The independently reviewed [design + plan PR #254](https://github.com/zhangyuz/ssh-over-mcp/pull/254)
was merged into main as ade5b33a7397c1f23844c29a2f61c88e5e6533f7.
This permits a separately reviewed implementation of **Gate A only**.

The standalone pure Python module ops/live-e2e/interpreter_provenance_contract.py
and adversarial tests tests/ops/test_interpreter_provenance_contract.py
implement bounded **synthetic, untrusted data consistency** checks for
declared package and canonical manifest SHA, manifest/node membership,
limited self-owned dependency graph/roles/ABI, Darwin x86_64 and
CPython 3.13.16 claims. The maximum 64 nodes/entries, 128 edges and
64 unique bounded module search paths are **schema budgets**, not proof
of macOS compatibility. The only states are PROVENANCE_REFUSED and
PROVENANCE_SCHEMA_CONSISTENT_UNATTESTED.

**Even self-consistent caller-supplied manifests/digests are not
authenticated.** Gate A performs no filesystem reads, package attestation,
code signing, runtime install, runner invocation, privilege use or physical
UID502/APFS fixture execution. It does not change the merged UID502
preflight interpreter default refusal, or authorize host execution.
The observed UID501/GID80 group-writable Homebrew Python remains **BLOCKED**.
Trusted Gate B interpreter selection/provisioning, original FD/APFS/ACL
and dyld/import resolution, operator approval, nine-case original UID502
fixture and protected placement remain **UNVERIFIED and OUT OF SCOPE**.

An independent source review identified two missing checks in the synthetic
witness schema: distinct nodes could share a claimed (dev, ino), and
unbounded st_mode/device/inode integers could pass permissive masks.
The Gate A validator now **refuses duplicated synthetic object identities**,
uses a unique positive fixture identity per declared node, and bounds full
POSIX st_mode to 0..0o177777 plus 64-bit positive device/inode
claims. Those checks do not authenticate actual host objects.

The subsequent independent review also required canonical paths to reject
embedded NUL bytes even if every synthetic digest is coherently recomputed,
and all reported POSIX file/directory modes to reject setuid, setgid, and
sticky privilege bits (mode & 0o7000), including root-owned interpreter
claims. These checks are explicitly fail-closed *synthetic schema* policies;
real host mode, package contents, signatures and loader behavior remain
unattested and belong to separately approved Gate B.

See [Gate A implementation evidence](evidence/2026-10-14-adr19-interpreter-provenance-contract.md)
for review/CI gates. A green synthetic schema fixture or old-path
trusted-main Level-3 run is NOT real UID502/APFS acceptance.

### Issue #256 — Proposed cross-platform provenance profile architecture (2026-10-15)

[Issue #256](https://github.com/zhangyuz/ssh-over-mcp/issues/256)
calls for portable **synthetic** evidence invariants and separate Darwin
and Linux ABI/loader profiles. Product/managed target, Ubuntu CI host,
macOS native E2E orchestrator and Ubuntu QEMU guest are distinct roles.
The merged [Gate A PR #255](https://github.com/zhangyuz/ssh-over-mcp/pull/255)
remains Darwin-specific and explicitly UNATTESTED; it is not a
SOM-wide Darwin requirement or a real UID502/APFS acceptance proof.

The current work is documentation-only:
[design](superpowers/specs/2026-10-15-issue256-cross-platform-provenance-profiles-design.md)
and [future **Slice B1 (Darwin-only router)** TDD plan](superpowers/plans/2026-10-15-issue256-portable-provenance-profile-slice-b.md).
[PR #257 independent review #6191154142](https://github.com/zhangyuz/ssh-over-mcp/pull/257#issuecomment-6191154142)
clarified that **B1 is only explicit static Darwin routing**, not the
promised portable shared invariant contract. **B2** is a separately reviewed
and explicitly approved future extraction of the pure OS-neutral
input/manifest/graph core, with direct-versus-routed Darwin status and
violations parity tests. **Slice C Linux synthetic ELF profile is blocked
on B2**; B1 must REFUSE all Linux selectors. Declared Linux/Darwin
selector-to-evidence contradictions can refuse, but perfectly forged
Darwin claims may remain **UNATTESTED**: no pure synthetic router
can identify unobserved real ELF or Mach-O bytes.

B1's caller-facing API must re-export the **same seven frozen
Gate A evidence constructor class objects** from the cached canonical
module. Evidence instantiated through separate module imports is
intentionally refused when routed; the original direct API remains
unchanged. The pre-existing Gate A source and tests are **immutable
in B1** (zero-diff requirement). Linux selector REFUSAL belongs to
prelaunch B1/B2 tests; positive Linux synthetic-profile tests are
**Slice C only**, following the Mac-first launch and B2 gates.

**Mac-first release sequence (operator decision, 2026-10-15):**
Prioritize completing and launching the approved macOS functionality.
**Do not begin Linux Slice C implementation until macOS full-feature
release/launch has been completed and confirmed by the operator AND
the B2 shared-core parity/refactor has separately passed review.**
Actual macOS release/UID502 physical acceptance and Gate B trust
evidence remain unverified here and require their own authorization;
CI or synthetic Gate A success is not macOS launch proof. B1/B2 may
remain future planning work, but should not displace the Mac release
critical path. Linux native E2E orchestration (D) stays separately
deferred.

B1, B2, C and future Linux native E2E orchestration/Runner (Slice D)
and Gate B actual interpreter trust all require separate operator and
independent security approvals. Green Ubuntu CI, or a synthetic
Darwin-positive, is never native host or source verification.

### ADR0019 macOS real-acceptance critical path — Gate B source selection (2026-10-15, proposal only)

Following merged [PR #257](https://github.com/zhangyuz/ssh-over-mcp/pull/257),
the next macOS-first blocker is not another synthetic profile router.
The existing Homebrew interpreter lives below a historically observed
UID501/GID80 **group-writable** /usr/local/Cellar ancestor and remains
**BLOCKED**. Merged Gate A only checks fabricated evidence.

The new [Gate B signed interpreter source design](superpowers/specs/2026-10-15-adr19-gate-b-macos-interpreter-source-decision-design.md)
evaluates Python.org CPython 3.13.16 macOS signed installer as a
**candidate only** and defines separate B0 source/signature verification,
B1 independently approved installation, B2 real at-use native FD/APFS/
Mach-O/dyld dependency attestation, and B3 original-code UID502 nine-row
physical acceptance. The [macOS blocker and release readiness matrix]
(evidence/2026-10-15-macos-native-release-blocker-inventory.md)
distinguishes already-merged inert contracts, old-path native Level-3
and still-UNVERIFIED physical gates. Gate B terminology here is
separate from Issue #256's portable-profile B1/B2 router/core slices.
Linux C remains deferred until operator-confirmed macOS full-feature
launch and separate portable B2 acceptance.

**This is a documentation-only design proposal**: no installer download,
package trust proof, root-owned path, permission change, host collector,
new workflow, persistent Mac run or UID502/APFS test has been performed
or authorized. The next step is joint design/security review and a
separate operator go-ahead before a B0 verification implementation plan.


### ADR0019 Gate B0 plan proposed — 2026-10-15

The [separate B0a/B0b plan](superpowers/plans/2026-10-15-adr19-gate-b0-offhost-package-verification.md) follows merged PR #258. It is documentation for independent operator/security review, not implementation authorization. B0a concerns independently verified offline digest and Sigstore evidence; B0b separately covers Apple Installer identity and package effects. The Python.org CPython 3.13.16 release remains a candidate only; B0 through B4 remain UNVERIFIED, with no download, installation, UID502 run or provider change. Linux Slice C remains deferred.


### ADR0019 B0 trusted signer policy research — 2026-10-15

A new [public-metadata-only B0 source trust dossier](evidence/2026-10-15-adr19-b0-signer-trust-policy-research.md) gathers independent primary-source signing and packaging references for **operator/security review**. The published CPython 3.13 Sigstore release-manager identity, the distinct Apple Installer Developer ID, and the offline trust-root freshness risk are **candidates and unresolved policy**, not measurements or granted authority. Exact signer/issuer, independent trust anchors, revocation/time rules, verifier provenance, byte-identity/custody join, installer effects and separate implementation/artifact/host approvals remain UNRESOLVED; **no source code, package download or Mac operation is authorized or changed**. B0–B4 and original UID502/APFS remain UNVERIFIED; Linux Slice C deferred.


### ADR0019 B0a digest-bound offline-verifier interface (design proposal, 2026-10-15)

A [digest-bound Sigstore interface design](superpowers/specs/2026-10-15-adr19-b0a-digest-bound-offline-verifier-interface-design.md) evaluates checking a SHA-256 **independently measured over an immutable sealed snapshot** rather than reopening an attacker-mutable pathname. **At the PR #262 design checkpoint, digest-only was UNSELECTED:** the governing [B0 plan](superpowers/plans/2026-10-15-adr19-gate-b0-offhost-package-verification.md) required the **same sealed FD** for the verifier, with `B0A_REFUSED` when impossible. The **separate plan amendment proposed below** is necessary to make a conditional digest-bound mode *eligible for independent selection* **only after** its own security review, exact-head CI, explicit operator approval and merge. Regardless of plan amendment, no digest mode, exact pinned CLI/verifier, signer, issuer, roots, offline freshness/revocation or artifact-source policy is selected without a **different, separately approved policy decision**. Future synthetic-positive pinned-verifier GREEN and wrong-digest RED tests cannot grant actual source approval; implementation, package handling, B0b inspection, UID502 and Mac release each require their own gate. All B0–B4 and original UID502/APFS physical acceptance remain UNVERIFIED; Linux Slice C stays deferred.


### ADR0019 B0a verifier handoff governing-plan amendment (PROPOSED, 2026-10-15)

A [separately reviewed proposed B0a plan amendment](superpowers/plans/2026-10-15-adr19-gate-b0-offhost-package-verification.md) would retain the existing same-sealed-FD verifier handoff as default and add a **conditional** digest-bound Sigstore interface with a trusted full sealed-byte SHA/length witness and exact signed-bundle binding; **it is not active before this PR's independent security review, exact-head CI, explicit operator approval and merge**. Any future digest-mode selection additionally requires independently approved exact signer/OIDC/roots/transparency/time/revocation/offline freshness, pinned verifier/hasher binaries and an explicit approved handoff mode; a synthetic GREEN proof with a real pinned CLI and paired different-digest RED is mandatory. Merger of this plan **does not** approve B0a implementation, real artifact/bundle retrieval, isolated Mac B0b inspection, provisioning, UID502/APFS original-code testing, staging or release. All T1–T9 remain UNRESOLVED, actual B0–B4 and UID502/APFS original physical acceptance UNVERIFIED, historic Homebrew path BLOCKED and Linux Slice C DEFERRED.


### ADR0019 B0a independent signer/root/verifier policy evidence checklist (PROPOSED, 2026-10-15)

A [T1–T5 evidence acceptance checklist](evidence/2026-10-15-adr19-b0a-artifact-trust-approval-checklist.md) documents what **separate independent approvals** would require for exact macOS binary signer/OIDC, expected full artifact digest+size, Sigstore trust roots/log and freshness/revocation policy, and exact pinned offline verifier runtime and signed-digest synthetic RED/GREEN proof. This is **not a selected signer, trust root, mode, tool or approved policy**, and no actual package/bundle/trust-root bytes have been retrieved or authenticated. Even if the proposed B0a plan amendment is merged, actual T1–T9 decisions, implementation, artifact use and B0b/UID502/macOS release remain distinct gates: **UNRESOLVED/UNVERIFIED**. Historic Homebrew source remains BLOCKED; Linux C deferred.


### ADR0019 Gate B0a T4/T5 Sigstore offline verifier compatibility (public research, 2026-10-15)

A [non-authorizing Sigstore offline verifier compatibility dossier](evidence/2026-10-15-adr19-b0a-sigstore-offline-verifier-compatibility.md) records official upstream constraints: Python.org's digest-only Sigstore interface has a **v3.3.0+ feature floor**, but upstream notes **Rekor v2 bundle verification requires sigstore-python 4+**; Sigstore offline mode may use stale embedded/cached trust roots, and signed-time evidentiary requirements vary with log generation. These published general facts **do not identify the current macOS `.pkg.sigstore` bundle format, signer or permitted verifier**. Exact T1–T5 signer/root/time/revocation/tool policy, synthetic executable tests, artifact-material access, B0b inspection and UID502/APFS acceptance all remain independently gated and **UNRESOLVED/UNVERIFIED**. No package, bundle or verifier was obtained or run in this docs-only slice; Linux C remains deferred.


### ADR0019 Gate B0a T5 exact-verifier version-specific compatibility gates (2026-10-15)

The [T5 public compatibility research](evidence/2026-10-15-adr19-b0a-sigstore-offline-verifier-compatibility.md) now records upstream **sigstore-python 4.2.0 bundle-declared digest consistency checking** (distinct from cryptographic signature verification, which was already over supplied real digest) and **4.3.0 Rekor v2 DSSE Hashedrekord format changes**. These version markers are **not an approved version floor, pinned binary, evidence of the actual macOS `.pkg.sigstore` format or permission to install/run a verifier**. A future operator-approved T5 policy must pin exact tool/roots, authorized bundle/log shape, verified time and revocation; require a pinned-verifier synthetic GREEN on a valid `message_signature` signed over the independently measured sealed-byte digest and a paired RED that alters **only** the bundle-declared `message_signature.message_digest.digest` while preserving the valid signature (specific digest-consistency rejection, not ordinary signature failure); separately test any authorized Rekor v2 DSSE/Hashedrekord format. T1–T9 unresolved; original B0–B4/UID502/APFS acceptance UNVERIFIED; Linux C deferred.


### ADR0019 Gate B0b Apple Installer inspection evidence boundaries (2026-10-15)

A new [public Apple Installer inspection evidence matrix](evidence/2026-10-15-adr19-b0b-apple-installer-independent-inspection-evidence.md) details the **separate** T6 immutable original-byte SHA/length/policy/custody join, T7 Developer ID **Installer** CMS chain and notarization/time/revocation, T8 bounded nested package/BOM/scripts/effects **plus file/directory/ancestor UID/GID, mode/setuid/setgid, effective ACL, xattr, filesystem flags and writability metadata** for every declared/conditional install effect (unknown or unprovable actual script/metadata effects → `B0_UNVERIFIED`, not implied safety from payload listings), and T9 distinct operator source-decision approval. Apple documents `pkgutil --check-signature` and notarization tickets, but neither proves safe installation effects; tools like `pkgutil --bom` write temporary files and extraction tools write decoded untrusted content. This docs-only research **does not authorize** a B0b Mac host, package/bundle retrieval, verifier/tool execution, package extraction, installer scripts, installation, UID502/APFS tests or release. All T1–T9 remain UNRESOLVED, actual B0–B4 and physical UID502/APFS nine-case acceptance UNVERIFIED, Homebrew source BLOCKED and Linux Slice C DEFERRED.

### 2026-10-17 Issue #259 T5B-0 concrete candidate admission checkpoint (non-authorizing)

The [exact-material admission dossier](evidence/2026-10-17-adr19-t5b0-exact-material-admission-dossier.md) records the published `sigstore-python==4.3.0` candidate wheel digest, PyPI publishing attestation's claimed workflow/commit, independently read GitHub release-tag ref, and Sigstore TUF root-bootstrap reference. **None is independently approved trust material.** A–F admission proofs remain absent: OOB initial root and independent trusted time/rollback, signed root/log/time/revocation closure, exact interpreter/loader/stdlib/native and candidate 31-wheel dependency closure, authenticated signer/fixture, one selected immutable-byte handoff and exact network-denied execution manifest, and separate operator approval. `T5B0_ADMISSION_REFUSED_INCOMPLETE`; full T5B-0 execution and T5B-1 Sigstore cryptographic verification remain HOLD. The [bounded candidate collection proposal](superpowers/plans/2026-10-17-adr19-t5b0-candidate-admission-next-gate.md) is **not itself consent** to download/import/run any candidate material or touch Mac/UID502/APFS. The current repository's PR #271 synthetic OpenSSL Ed25519 GREEN is not real Sigstore trust verification. Linux Slice C remains deferred.

### 2026-10-17 C0 inert-candidate collection preauthorization manifest (still HOLD)

The [finite C0 object allowlist and custody proposal](evidence/2026-10-17-adr19-t5b0-c0-inert-candidate-object-allowlist.md) restricts research candidates to a single `sigstore-python==4.3.0` wheel, its exact PyPI provenance metadata, and separately pinned Sigstore root-signing/TUF history metadata. **No URL wildcard, implicit dependency, actual CPython installer/bundle, downloader execution or candidate bytes acquisition is permitted.** Immutable per-object URLs/length caps, off-host image/downloader identity, independent OOB root/clock and explicit collection consent are still missing. `C0_COLLECT_HOLD_INCOMPLETE`; T5B-0 material admission and T5B-1 remain HOLD.

### 2026-10-17 C0 offline manifest structural preflight (non-authorizing)

A [strictly offline structural preflight](evidence/2026-10-17-adr19-t5b0-c0-offline-structure-preflight.md) with fail-closed negative fixtures rejects malformed C0 proposal objects, but explicitly does not validate authenticity or approve downloads. It does not replace independent exact URL/byte evidence, trusted source/time, isolated host/downloader admission, or separate operator consent. `C0_COLLECT_HOLD_INCOMPLETE` and T5B-0/T5B-1 HOLD persist.

### 2026-10-17 C0 offline preflight hosted coverage

An existing `tests/ops` pytest bridge runs `ops/t5b0` offline adversarial fixtures on Python 3.13 and 3.14 in `rest` shards, preserving the same non-root/no-supplementary-groups boundary and frozen CI workflow bytes. This is verification coverage only; `C0_COLLECT_HOLD_INCOMPLETE` and T5B-0/T5B-1 remain HOLD.

### 2026-10-17 C0 canonical URL syntax hardening

The offline C0 manifest structural checker refuses ambiguous URL spellings (percent-encoded components, dot/empty segments, backslashes, non-ASCII, malformed ports) with negative fixtures, without changing any trust or collection authority. `C0_COLLECT_HOLD_INCOMPLETE` remains in force.

### 2026-10-17 C0 offline machine-readable report

The bounded C0 preflight adds opt-in `--json` with a stable offline status/errors/safety-marker object, preserving legacy text and exit status. Valid/invalid/unreadable fixture tests run in the existing hosted dual-Python CI bridge. `STRUCTURE_ONLY_PASS` never authorizes collection or admission; `C0_COLLECT_HOLD_INCOMPLETE` and T5B-0/T5B-1 HOLD persist.

### 2026-10-17 C0 stable offline JSON error codes

The opt-in `--json` report now exposes `error_codes` (`INVALID_MANIFEST` for read/parse failures, `INVALID_STRUCTURE` for parsed invalid proposals, empty on structure-only pass). Existing text/JSON fields, exit codes and no-authorization safety markers remain unchanged. This does not approve C0 collection or T5B admission.

### 2026-10-17 C0 bounded offline batch preflight

Added `--batch` for 1–16 independent local manifest inspections with a single machine-readable aggregate status and per-file reports, fail-closed exit 2 on any refusal or count overflow. Single-file CLI output/exit behavior and all C0 authorization/collection/network HOLD markers remain unchanged; this is not permission for C0 collection or T5B admission.

### 2026-10-18 C0 offline directory audit (non-authorizing)

The bounded `--directory` workflow performs deterministic, nonrecursive 1–16 `.json` entry structural audits with per-file exact-read SHA256, pass/refusal counts and fail-closed handling of empty, overflow, symlink and special-file inputs. Existing single-file and batch behavior remains unchanged. Digest is only a reproducibility aid, not proof of authenticity or collection permission. C0_COLLECT_HOLD_INCOMPLETE, T5B-0/T5B-1, Mac/UID502/APFS and Linux Slice C remain HOLD.

### 2026-10-18 C0 cross-file audit and evidence handoff

The existing offline directory auditor now provides a complete non-authorizing handoff: cross-file duplicate object ID and contradictory URL/digest/declared-size checks, deterministic exact-read input fingerprint, final per-file refusal codes and aggregate counts, and explicit five-category external-evidence gap checklist. Legacy single/`--batch` contracts unchanged; no network or collection. The digest is not an authenticated seal. `C0_COLLECT_HOLD_INCOMPLETE`, T5B-0/T5B-1, real Mac/UID502/APFS remain HOLD and Linux Slice C deferred.

### 2026-10-18 C0 two-directory offline review diff

The non-authorizing `--compare-directories BEFORE AFTER` reviewer workflow reuses bounded directory audits to compare sorted filenames, exact-read digests and per-file pass-to-refusal regressions, with complete before/after reports and deterministic `UNCHANGED`/`CHANGED`/`REFUSED` status. Any refused side fails closed (exit 2) and partial delta is diagnostic only. Existing single-file, batch and directory output contracts unchanged; no network, collection, authorization, privileged host, CI workflow or Linux C change. `C0_COLLECT_HOLD_INCOMPLETE` and T5B-0/T5B-1 remain HOLD.

### 2026-10-18 C0 semantic object-level review delta

The offline two-directory reviewer now adds object-ID semantic `added`/`removed`/changed-field deltas, independent of filename moves, from already-read fully validated manifests. It refuses to publish a semantic inventory if either bounded directory audit refused. No raw URL/digest values are echoed in `object_diff`; no network, collection, policy admission, privilege or CI changes. C0, T5B and Mac/UID502/APFS HOLD remain; Linux C deferred.

### 2026-10-18 Opt-in C0 offline review change gate

`--compare-directories BEFORE AFTER --fail-on-change` adds a non-authorizing CI/reviewer exit-code gate (0 unchanged, 3 observed changed, 2 refused), while preserving byte-for-byte identical JSON reporting and default CLI exit codes. Refusal dominates change, and the flag is rejected outside compare mode. A matching untrusted pair is **not** an authorization or source authenticity proof; all evidence gaps remain `UNVERIFIED`. No CI workflow, collection, privileged Mac or Linux C changes; T5B holds persist.
### 2026-10-18 Optional C0 manifest-only directory intake

The offline C0 directory reviewer supports `--require-json-only` for directory audit and compare modes. Strict mode refuses unexpected immediate non-JSON entries before reading any manifest; both strict and default paths share a 64-total-entry resource cap; default mode preserves ignoring unrelated names, and single-file/batch invocations reject the option. Compare-mode refusal suppresses semantic object inventory. This adds no collection/admission authority, network, CI workflow, privileged Mac/UID502/APFS or Linux Slice C activity; all related gates remain HOLD.

### 2026-10-18 Bounded C0 directory enumeration resource gate

The offline directory and two-directory reviewer now bound **all** immediate entries (64 total) rather than only matching `.json` files. The 65th name refuses before any manifest is read, preventing unbounded iteration through ignored foreign names. Non-JSON files and nested directories remain ignored within the budget, preserving small-directory compatibility. Overflow yields `REFUSED`/exit 2 and no partial inventory; compare mode suppresses semantic object deltas on either-side refusal. No network, collection, authorizing trust proof, CI workflow, Mac/UID502/APFS or Linux Slice C change. All admission/collection gates remain HOLD.

### 2026-10-18 C0 offline stdin proposal preflight

Explicit `--stdin [--json]` lets offline automated pipelines validate one 16 KiB-capped untrusted proposal without writing temporary manifests. The exact existing parser/schema/refusal classification and default safety markers are reused; oversized, empty, malformed or unauthorized-approval forms refuse. Stdin is mutually exclusive with file/batch/directory/compare input modes. No filesystem, collector, network, trust admission, privileged Mac/UID502/APFS, CI or Linux C authority is introduced; C0 and T5B remains HOLD.

Test-harness integration: the hosted C0 stdlib bridge subprocess has a 45-second safety timeout rather than the previous 15 seconds, to accommodate the growing bounded offline fixture suite on slower developer hosts; this does not add a CI job, elevate privileges, or alter product execution timeouts.

### 2026-10-18 Bounded multi-manifest stdin proposal audit

Offline C0 reviewer `--stdin-batch` accepts at most sixteen newline-delimited untrusted proposal manifests, one at most 16 KiB and a bounded total (262,160 bytes), without temporary files. Shared schema and cross-record conflict checks refuse duplicate object IDs and inconsistent URL/SHA256 metadata; over-budget/empty/too-many inputs refuse before parsing with no partial results. Sanitized diagnostics do not echo raw URL or digest values. The option is mutually exclusive with other input modes and review/strict gates; the aggregate is structure-only, never approval or provenance. This function is useful for no-file CI/operator review and does not lift `C0_COLLECT_HOLD`, T5B material admission, trusted root/time, UID502/APFS or Linux C gates.

### 2026-10-18 Offline C0 streamed-successor semantic comparison (non-authorizing)

The C0 reviewer adds --compare-stdin-to-directory BEFORE_DIR: compare a bounded stdin NDJSON successor against a bounded descriptor-anchored directory baseline without persisting incoming proposals. The common object-ID semantic inventory reports added/removed IDs and changed field names only, never their URL or SHA256 values. Strict baseline --require-json-only retains the 64-total-entry limit; streamed records retain 1–16 lines, strict UTF-8 and 16 KiB per record / 262,160-byte total limits. Either-side refusal suppresses the semantic delta, and optional --fail-on-change returns exit 3 for a valid change (default valid change exits 0). The result remains NO_AUTHORIZATION, C0_COLLECT_HOLD, NO_NETWORK, with all independent source/clock/tool/privilege/host/Linux gates untouched.

### 2026-10-18 C0 race-aware same-FD manifest observation

The existing offline regular-manifest reader now compares opened-inode identity, mode, size, modification and change timestamps before/after its bounded read. An in-place same-size mutation that remains parseable refuses rather than producing an apparently stable structure-only pass or audit inventory. Existing O_NOFOLLOW/O_NONBLOCK, 16 KiB payload cap, 64-entry directory scan cap and stdin modes are unchanged; atime is excluded because reading may update it. This is best-effort race detection, not an atomic snapshot or source-trust proof. NO_AUTHORIZATION, C0_COLLECT_HOLD, NO_NETWORK and T5B/Mac/UID502/APFS/Linux C HOLD remain.

### 2026-10-18 C0 race-aware observer: timestamp discrimination regression

Independent review of #292 requires two deterministic additional regressions. Both single-manifest and directory audit now have controlled same-FD pre/post metadata fixtures: valid same-length in-place rewrite with restored mtime but ctime-only difference MUST refuse without an accepted digest/inventory, and atime-only difference MUST retain STRUCTURE_ONLY_PASS (normal reads may change atime). The fixtures are validated by temporary fault injections that remove ctime comparison (must fail) and add atime comparison (must fail), followed by restoring production source. No production behavior or privilege changes; existing NO_AUTHORIZATION, C0_COLLECT_HOLD, NO_NETWORK and T5B/Mac/UID502/APFS/Linux C restrictions remain.

### 2026-10-18 C0 single-manifest object collision refusal

The offline C0 reviewer now enforces that each object URL is unique **within** one valid proposal and that two objects declaring the same SHA-256 cannot disagree about the expected byte count. It deliberately permits two distinct URLs with the same declared digest and byte count for untrusted possible mirrors. New TDD regressions prove formerly false structure-only passes across existing single-file, stdin, batch, directory and streamed-comparison entrypoints, with sanitized diagnostics and REFUSED semantic inventory suppression. No new input/output mode, material acquisition, host authority or network use; NO_AUTHORIZATION / C0_COLLECT_HOLD / NO_NETWORK, T5B/Mac/UID502/APFS/Linux C remain HOLD.

### 2026-10-19 C0 offline directory namespace drift refusal

The existing directory auditor now measures opened-directory identity and namespace-change timestamps before and after scanning and reading. Observed drift refuses the aggregate without returning partial manifest results, audit digest or semantic inventory, even if already-read manifests independently passed. Deterministic tests include live directory mutation during read, ctime-only drift rejection and atime-only non-rejection for direct/compare paths; limits and no-follow protections remain. This is not an atomic snapshot, material provenance, network/collection authorization or T5B/Mac/UID502/APFS/Linux C release approval; all corresponding HOLD markers persist.
