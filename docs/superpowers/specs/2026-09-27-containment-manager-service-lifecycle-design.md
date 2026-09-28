# Containment Manager Service Lifecycle Design

Date: 2026-09-27

Status: proposed for implementation planning

## 1. Purpose

This design defines the first real Linux service lifecycle for the privileged containment manager.

The intended outcome is a foreground, fail-closed manager process which:

- verifies its configured Linux process identity before creating any endpoint;
- creates the already-defined secure Unix pathname listener only after identity validation succeeds;
- accepts one authenticated host-agent session at a time;
- uses the existing `SO_PEERCRED` policy before any manager protocol I/O;
- delegates request handling to the existing `ContainmentManagerDispatcher`;
- treats malformed or unauthorized sessions as session-local failures;
- treats listener/endpoint/manager-identity failures as service-fatal;
- shuts down deterministically without blindly deleting a pathname it no longer owns.

This phase does not enable ForceCommand execution and does not perform UID/GID switching.

## 2. Context

The repository already contains the security-sensitive pieces this service will compose:

- a real cgroup-v2 containment backend;
- a start barrier which prevents child execution before containment attachment;
- a containment-aware bounded runner;
- a narrow versioned manager protocol;
- `ContainmentManagerDispatcher`;
- authenticated pre-connected Unix manager transport;
- Linux `SO_PEERCRED` policy;
- secure filesystem Unix endpoint creation/validation;
- a Linux service identity contract covering manager, host-agent and workload identities.

The remaining gap is lifecycle composition. There is not yet one production service object which proves manager identity first, creates the endpoint second, accepts authenticated sessions, and shuts down with explicit ownership semantics.

## 3. Scope

### 3.1 In scope

This phase implements:

1. manager process-identity enforcement at service startup;
2. foreground synchronous service lifecycle;
3. serial accepted-session handling;
4. session-local vs service-fatal error semantics;
5. stop-request handling outside async signal-handler work;
6. composition with the listener's existing endpoint-ownership tracking;
7. safe, idempotent shutdown;
8. tests for ordering, session fault isolation and cleanup ownership.

### 3.2 Explicit non-goals

This phase does not implement:

- daemonization;
- systemd unit packaging;
- socket activation;
- threads or async session concurrency;
- manager UID/GID switching;
- workload UID/GID transition;
- ForceCommand execution wiring;
- raw shell or remote command enablement;
- containment-scope garbage collection after manager crash;
- backend-wide `kill_all` on service shutdown;
- generic retry loops for service-fatal errors.

## 4. Approaches considered

### 4.1 Selected: foreground serial manager service

One process owns one listener and serves one accepted host-agent connection at a time.

Flow:

```text
process start
  -> verify manager identity
  -> create secure Unix listener
  -> accept one connection
  -> authenticate SO_PEERCRED
  -> serve manager protocol until EOF/session failure
  -> close accepted connection
  -> return to accept
```

This is the selected approach because it introduces the smallest new trust surface and preserves the current non-thread-safe dispatcher semantics.

### 4.2 Deferred: thread-per-session manager

This would allow concurrent host-agent sessions, but it would require:

- locking or redesigning `ContainmentManagerDispatcher._scopes`;
- worker lifecycle management;
- shutdown joins;
- session ceilings;
- more complex error propagation.

That complexity is not required for the next safe milestone.

### 4.3 Deferred: systemd socket activation / process-per-session

This could provide a stronger deployment lifecycle later, but it couples this change to:

- systemd packaging;
- socket-activation semantics;
- process-per-session dispatcher ownership;
- service manager policy.

Those concerns are intentionally deferred.

## 5. Proposed component

Add:

```text
src/ssh_over_mcp/host_agent/containment_manager_service.py
```

with a narrow service API conceptually equivalent to:

```python
service = ContainmentManagerService.create(
    identity_policy=manager_process_policy,
    endpoint_policy=endpoint_policy,
    peer_policy=host_agent_peer_policy,
    dispatcher=dispatcher,
)

service.serve_one()
service.serve_forever(stop_requested=...)
service.close()
```

Exact implementation details may vary, but the observable lifecycle and invariants in this document are normative.

## 6. Startup ordering and identity boundary

Startup ordering is security-sensitive.

The required order is:

```text
validate manager process identity
  -> create secure endpoint
  -> listen
  -> accept sessions
```

The service MUST call the existing manager process-identity enforcement before any filesystem/socket side effect.

If the manager process does not match its configured:

- real UID;
- effective UID;
- saved UID;
- real GID;
- effective GID;
- saved GID;
- exact supplementary-group set;

then startup fails and endpoint creation MUST NOT be attempted.

This prevents a wrongly launched process from creating a seemingly valid privileged-manager endpoint.

The service does not switch identities in this phase. It only verifies the identity supplied by the surrounding service manager/operator.

## 7. Listener and endpoint ownership

The service composes the existing `UnixContainmentManagerListener` rather than duplicating endpoint-ownership logic.

The listener already records the socket's canonical policy path and device/inode identity and implements guarded cleanup. The service MUST treat the listener as the single ownership authority for the endpoint.

During shutdown the service calls the listener's idempotent `close()`. The listener then:

1. closes the listening descriptor;
2. inspects the pathname without following symlinks;
3. removes the pathname only if it still names the socket created by that listener instance;
4. preserves a replacement object and raises a cleanup error when the path now names a different object;
5. treats an already-absent endpoint as already cleaned.

The service MUST NOT add a second unconditional `unlink(path)` or a second independent socket-identity cache.

The following replacements are preserved:

- a different socket inode;
- a regular file;
- a directory;
- a symlink.

Repeated service `close()` calls are idempotent because listener `close()` is idempotent.

## 8. Session lifecycle

The first implementation is intentionally serial.

For each iteration:

1. accept exactly one connection;
2. ensure the accepted descriptor remains non-inheritable;
3. authenticate the host-agent with the existing Linux `SO_PEERCRED` policy;
4. call the existing `serve_containment_manager_connection(...)`;
5. ensure the accepted connection is closed;
6. return to the accept loop.

The service does not duplicate protocol framing, dispatcher logic or peer-credential validation.

The existing dispatcher remains the only manager-protocol operation owner.

## 9. Error model

Errors are divided into service-fatal and session-local categories.

### 9.1 Service-fatal

The service stops and propagates a fail-closed error for:

- manager startup identity mismatch;
- endpoint parent/ownership/mode invariant failure;
- listener creation failure;
- listener accept infrastructure failure;
- endpoint ownership mutation discovered during required service cleanup;
- explicit manager process-identity recheck failure, if a recheck point is added by implementation.

The service MUST NOT enter an unbounded retry loop for these states.

### 9.2 Session-local

The current accepted connection is closed, but the listener remains available for the next connection, for:

- wrong `SO_PEERCRED`;
- malformed or truncated manager frame;
- unsupported/invalid manager message;
- peer disconnect;
- protocol correlation/session framing failure;
- bounded backend operation failure which the existing dispatcher maps to a manager error response.

The service layer MUST NOT expose backend exception strings to the peer.

### 9.3 Existing dispatcher semantics remain authoritative

Scope operation semantics stay inside `ContainmentManagerDispatcher`.

The service does not reinterpret:

- create;
- attach;
- kill;
- stats;
- close;
- opaque scope capabilities.

## 10. Shutdown and signal semantics

The service remains a foreground synchronous process.

Signal integration is intentionally small.

A process-level signal handler may set a stop flag/event, but MUST NOT directly:

- unlink the endpoint;
- close arbitrary service objects;
- mutate dispatcher scope state;
- call backend containment operations;
- perform complex Python cleanup.

Normal control flow observes `stop_requested` and exits the accept lifecycle.

Required shutdown order:

```text
stop accepting new sessions
  -> finish/close current accepted session
  -> close listener descriptor
  -> remove only still-owned endpoint inode
  -> return/exit
```

The first implementation MUST use readiness polling on the listener file descriptor with a bounded polling interval. It checks `stop_requested` between polls and calls `listener.accept()` only when the descriptor is readable. This keeps stop observation out of the signal handler without exposing or mutating the listener's private socket timeout state.

## 11. Containment-scope ownership on shutdown

Service shutdown does not implicitly kill every scope held by the dispatcher.

Scope lifetime continues to follow the existing protocol:

```text
create
attach
stats / kill
close
```

A future crash-recovery/garbage-collection phase may define how orphaned cgroups are recovered after manager process death.

That concern is explicitly outside this phase because silently killing all scopes during ordinary service shutdown would change established containment lifetime semantics.

## 12. Security invariants

The implementation MUST preserve all of the following:

1. no endpoint side effect before successful manager process-identity validation;
2. no protocol bytes read before peer credential authentication;
3. accepted and listening descriptors remain non-inheritable;
4. malformed/unauthorized sessions cannot terminate the healthy listener;
5. service-fatal listener/endpoint failures are not hidden by retries;
6. service shutdown delegates endpoint cleanup to the existing identity-checked listener and never performs an independent unlink;
7. service lifecycle adds no shell, executable, argv, cwd or generic filesystem-operation surface;
8. no UID/GID switching is introduced;
9. no ForceCommand execution path is enabled;
10. no concurrency is introduced around the current dispatcher.

## 13. Expected implementation surface

The expected implementation diff is deliberately small:

```text
src/ssh_over_mcp/host_agent/containment_manager_service.py
tests/host_agent/test_containment_manager_service.py
docs/ssh-host-agent.md
docs/development-plan.md
remote/host_agent/README.md
```

Exports from `host_agent/__init__.py` may be added if required.

Unrelated refactors are out of scope.

## 14. Test matrix

The implementation plan MUST include at least the following tests.

| Case | Expected result |
| --- | --- |
| manager UID/GID mismatch | startup fails; endpoint creation not called |
| saved ID mismatch | startup fails; endpoint creation not called |
| supplementary groups mismatch | startup fails; endpoint creation not called |
| valid manager identity | listener creation proceeds |
| wrong peer UID/GID | accepted session rejected; service remains usable |
| malformed manager frame | session terminates; next valid session accepted |
| clean peer EOF | accepted connection closes; service remains usable |
| dispatcher/backend request failure | bounded to session/protocol response where existing dispatcher permits |
| listener accept infrastructure failure | service exits fail-closed |
| stop requested while readiness-polling for accept | loop exits without creating a new session |
| repeated `close()` | idempotent |
| original socket still present | listener close removes owned endpoint |
| endpoint replaced by different socket | listener close preserves replacement and propagates cleanup failure |
| endpoint replaced by regular file | replacement preserved |
| endpoint replaced by symlink | symlink preserved |
| endpoint already absent | no unsafe recreation/unlink side effect |

Tests MUST assert ordering, not only final state. In particular, failed identity validation must prove that endpoint creation was never attempted.

## 15. Success criteria

This phase is complete when:

1. a correctly launched manager can run as a foreground serial Unix service;
2. the manager refuses startup before endpoint creation under an incorrect process identity;
3. an unauthorized or malformed client cannot terminate the listener service;
4. accepted connections are always closed;
5. listener cleanup removes only the socket object created by the current service instance;
6. shutdown is idempotent and does not perform backend-wide scope destruction;
7. all new tests pass on the project's supported Python versions;
8. ForceCommand remote execution remains disabled.

## 16. Follow-on phases

After this phase, the roadmap continues with:

1. workload UID/GID transition before exec with no saved privilege;
2. authenticated manager-client integration through the existing start barrier and bounded runner;
3. live delegated-cgroup descendant-kill/resource-limit/self-migration tests;
4. ForceCommand execution wiring only after those boundaries are enforced.
