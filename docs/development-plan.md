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
is approved 2026-10-06. Implementation is in progress, starting with Task 1's
shared key-write prerequisite; no Phase 7B1 acceptance or closure is claimed.
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
