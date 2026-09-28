# Containment Manager Service Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a foreground serial containment-manager service which verifies its Linux process identity before creating the Unix endpoint, serves authenticated manager sessions, and shuts down through the existing identity-checked listener without enabling ForceCommand execution.

**Architecture:** Add one focused service module which composes the existing identity validator, secure Unix listener, peer-authenticated connection server, and dispatcher. Keep protocol, endpoint ownership, containment scope semantics, UID/GID switching, concurrency, and ForceCommand wiring outside this layer. Use fixed 100 ms listener-readiness polling so a caller-owned stop flag can end the foreground loop without signal-handler cleanup work.

**Tech Stack:** Python 3.13+, stdlib `select` / AF_UNIX sockets, pytest, existing ssh-over-mcp containment manager modules.

**Spec:** `docs/superpowers/specs/2026-09-27-containment-manager-service-lifecycle-design.md`

## Global Constraints

- Python package floor remains **Python 3.13 or newer**; validation runs on Python 3.13 and 3.14.
- Manager process identity MUST be validated before any endpoint filesystem/socket side effect.
- The service MUST reuse `UnixContainmentManagerListener` as the single endpoint-ownership authority; no second inode cache and no direct service-layer `unlink()`.
- Manager sessions remain strictly serial; do not add threads, asyncio, locks, or dispatcher concurrency.
- No protocol bytes may be read before the existing `SO_PEERCRED` authentication.
- Session-local peer/protocol failures must not terminate a healthy listener.
- Listener/readiness/endpoint failures remain service-fatal and must not be hidden by retry loops.
- The service does not switch UID/GID, daemonize, add a systemd unit, garbage-collect all scopes, or enable ForceCommand execution.

## Review Focus

- Stop becomes true after readiness is reported but before `accept()`: re-check stop and do not start a new session.
- Readiness polling is interrupted by a signal: treat `InterruptedError` as a poll miss so control returns to the stop check instead of failing the service.
- Unauthorized peer credentials: close only that accepted connection and keep the listener usable for the next session.
- Endpoint pathname is replaced before shutdown: delegate to listener close, preserve the replacement, and propagate cleanup failure.
- Startup identity mismatch: prove listener creation was never attempted, including saved-ID and supplementary-group mismatch paths.

---

### Task 1: Startup Identity Gate and Listener Ownership

**Files:**
- Create: `src/ssh_over_mcp/host_agent/containment_manager_service.py`
- Create: `tests/host_agent/test_containment_manager_service.py`

**Interfaces:**
- Consumes:
  - `require_linux_process_identity(policy: LinuxProcessIdentityPolicy) -> LinuxProcessIdentitySnapshot`
  - `UnixContainmentManagerListener.create(policy: UnixManagerEndpointPolicy) -> UnixContainmentManagerListener`
  - `LinuxPeerCredentialPolicy`
  - `ContainmentManagerDispatcher`
- Produces:
  - `class ContainmentManagerServiceError(ContainmentError)`
  - `ContainmentManagerService.create(*, identity_policy: LinuxProcessIdentityPolicy, endpoint_policy: UnixManagerEndpointPolicy, peer_policy: LinuxPeerCredentialPolicy, dispatcher: ContainmentManagerDispatcher) -> ContainmentManagerService`
  - `ContainmentManagerService.close() -> None`

- [ ] **Step 1: Write failing startup-order tests**

Add tests named:

```python
def test_identity_failure_happens_before_listener_creation(monkeypatch):
    # require_linux_process_identity raises LinuxProcessIdentityError
    # UnixContainmentManagerListener.create must not be called

def test_valid_identity_creates_listener_once(monkeypatch):
    # identity validation succeeds before listener factory call

def test_service_close_delegates_once_and_is_idempotent(monkeypatch):
    # two service.close() calls produce exactly one listener.close()
```

Also parameterize the first test with representative identity failures already modeled by the identity layer: wrong real/effective/saved IDs and supplementary groups. The service test may simulate these by making `require_linux_process_identity` raise; the detailed credential matching remains covered by `test_containment_manager_identity.py`.

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
python -m pytest -q tests/host_agent/test_containment_manager_service.py -k 'identity or close'
```

Expected: FAIL because `containment_manager_service` / `ContainmentManagerService` does not exist.

- [ ] **Step 3: Implement the minimal startup/close service**

In `containment_manager_service.py`:

```python
class ContainmentManagerServiceError(ContainmentError):
    ...

class ContainmentManagerService:
    @classmethod
    def create(
        cls,
        *,
        identity_policy: LinuxProcessIdentityPolicy,
        endpoint_policy: UnixManagerEndpointPolicy,
        peer_policy: LinuxPeerCredentialPolicy,
        dispatcher: ContainmentManagerDispatcher,
    ) -> "ContainmentManagerService":
        ...

    def close(self) -> None:
        ...
```

Required ordering inside `create()`:

1. call `require_linux_process_identity(identity_policy)`;
2. only after success call `UnixContainmentManagerListener.create(endpoint_policy)`;
3. store listener, peer policy, dispatcher;
4. do not duplicate listener endpoint identity.

`close()` sets the service closed state once and delegates cleanup to `listener.close()`. If listener cleanup raises because the pathname changed, propagate that failure; subsequent `close()` calls remain no-ops.

- [ ] **Step 4: Add real-listener cleanup integration tests**

Using a secure temporary parent and the current process UID/GID policy, assert:

```python
def test_service_close_removes_still_owned_socket(tmp_path):
    # endpoint exists after create; absent after close

@pytest.mark.parametrize("replacement_kind", ["regular_file", "symlink", "different_socket"])
def test_service_close_preserves_replacement_path(tmp_path, replacement_kind):
    # replace the owned socket path with the selected different object
    # close raises ContainmentManagerEndpointError
    # replacement object remains present and unchanged

def test_service_close_accepts_already_absent_endpoint(tmp_path):
    # unlink owned socket path before close
    # close returns without recreating/unlinking anything
```

- [ ] **Step 5: Run Task 1 tests**

Run:

```bash
python -m pytest -q   tests/host_agent/test_containment_manager_service.py   tests/host_agent/test_containment_manager_identity.py   tests/host_agent/test_containment_manager_endpoint.py
```

Expected: PASS.

- [ ] **Step 6: Commit Task 1**

```bash
git add   src/ssh_over_mcp/host_agent/containment_manager_service.py   tests/host_agent/test_containment_manager_service.py
git commit -m "feat: add containment manager service startup gate"
```

---

### Task 2: Serial Session Handling and Session Fault Isolation

**Files:**
- Modify: `src/ssh_over_mcp/host_agent/containment_manager_service.py`
- Modify: `tests/host_agent/test_containment_manager_service.py`

**Interfaces:**
- Consumes:
  - Task 1 `ContainmentManagerService`
  - `UnixContainmentManagerListener.accept() -> socket.socket`
  - `serve_containment_manager_connection(sock, dispatcher, *, peer_policy) -> None`
  - `ContainmentManagerPeerAuthError`
- Produces:
  - `ContainmentManagerService.serve_one() -> None`

- [ ] **Step 1: Write failing session-lifecycle tests**

Add:

```python
def test_serve_one_accepts_and_delegates_exactly_one_session(monkeypatch):
    # listener.accept called once
    # connection server receives accepted socket, dispatcher, peer_policy

def test_unauthorized_peer_is_session_local(monkeypatch):
    # connection server raises ContainmentManagerPeerAuthError
    # serve_one returns normally
    # second serve_one can accept/delegate another connection

def test_clean_peer_eof_is_session_local(monkeypatch):
    # connection server returns normally for EOF
    # a second serve_one still accepts/delegates another connection

def test_listener_accept_failure_is_service_fatal(monkeypatch):
    # listener.accept raises ContainmentManagerEndpointError
    # serve_one propagates; no retry

def test_non_auth_transport_failure_is_not_hidden(monkeypatch):
    # connection server raises ContainmentUnavailableError
    # serve_one propagates as service-fatal
```

- [ ] **Step 2: Run the new tests and verify failure**

Run:

```bash
python -m pytest -q tests/host_agent/test_containment_manager_service.py -k 'serve_one or unauthorized or accept_failure or transport_failure'
```

Expected: FAIL because `serve_one()` is missing.

- [ ] **Step 3: Implement `serve_one()`**

Signature:

```python
def serve_one(self) -> None:
    ...
```

Behavior:

1. fail with `ContainmentManagerServiceError` if service is already closed;
2. call `listener.accept()` exactly once;
3. call `serve_containment_manager_connection(connection, dispatcher, peer_policy=peer_policy)`;
4. catch only `ContainmentManagerPeerAuthError` as the service-layer session-local exception;
5. let endpoint, credential-API-unavailable, and other infrastructure failures propagate;
6. rely on the existing connection server's `finally` block to close the accepted socket.

Do not catch broad `ContainmentError` or `Exception`.

- [ ] **Step 4: Add real malformed-frame then valid-session integration test**

Use a real `UnixContainmentManagerListener`, current-UID/GID peer policy, and fake backend/dispatcher.

Test sequence:

```python
def test_malformed_session_does_not_poison_next_valid_session(tmp_path):
    # client 1 connects and sends malformed SCMG frame
    # service.serve_one() terminates only client 1
    # client 2 connects and sends one valid CreateRequest frame
    # service.serve_one() sends a valid CreateResponse
    # decode response and assert scope creation succeeded

def test_backend_operation_error_response_does_not_poison_next_session(tmp_path):
    # backend fails one CreateRequest with ContainmentError
    # first client receives ErrorResponse(code="operation_failed")
    # first client closes and serve_one returns
    # second client uses a healthy backend path and receives CreateResponse
```

Use bounded socket timeouts in both integration tests so a regression cannot hang the suite.

- [ ] **Step 5: Run manager session tests**

Run:

```bash
python -m pytest -q   tests/host_agent/test_containment_manager_service.py   tests/host_agent/test_containment_manager_unix.py   tests/host_agent/test_containment_manager_peer.py
```

Expected: PASS.

- [ ] **Step 6: Commit Task 2**

```bash
git add   src/ssh_over_mcp/host_agent/containment_manager_service.py   tests/host_agent/test_containment_manager_service.py
git commit -m "feat: isolate containment manager sessions"
```

---

### Task 3: Bounded Readiness Loop and Stop Semantics

**Files:**
- Modify: `src/ssh_over_mcp/host_agent/containment_manager_service.py`
- Modify: `tests/host_agent/test_containment_manager_service.py`

**Interfaces:**
- Consumes:
  - Task 2 `serve_one()`
  - `listener.fileno: int`
  - caller-owned `stop_requested: Callable[[], bool]`
- Produces:
  - module constant `ACCEPT_POLL_INTERVAL_SECONDS = 0.1`
  - private helper `_wait_listener_readable(fd: int) -> bool`
  - `ContainmentManagerService.serve_forever(*, stop_requested: Callable[[], bool]) -> None`

- [ ] **Step 1: Write failing readiness/stop tests**

Add:

```python
def test_serve_forever_stops_without_accept_when_stop_already_requested(monkeypatch):
    # stop is true before first poll; no readiness wait and no accept

def test_serve_forever_rechecks_stop_after_readiness(monkeypatch):
    # first stop check false
    # readiness reports true
    # second stop check true
    # serve_one/accept is not called

def test_interrupted_readiness_poll_retries_via_stop_check(monkeypatch):
    # select.select raises InterruptedError once
    # helper reports not-ready rather than service failure
    # loop rechecks stop and exits

def test_readiness_infrastructure_error_is_service_fatal(monkeypatch):
    # select.select raises OSError (not InterruptedError)
    # raise ContainmentManagerServiceError

def test_ready_listener_serves_one_then_returns_to_poll(monkeypatch):
    # readiness true, stop false -> serve_one exactly once
    # next stop check true -> clean return
```

- [ ] **Step 2: Run readiness tests and verify failure**

Run:

```bash
python -m pytest -q tests/host_agent/test_containment_manager_service.py -k 'serve_forever or readiness'
```

Expected: FAIL because readiness helper and `serve_forever()` are missing.

- [ ] **Step 3: Implement fixed readiness polling**

Implement:

```python
ACCEPT_POLL_INTERVAL_SECONDS = 0.1

def _wait_listener_readable(fd: int) -> bool:
    ...

def serve_forever(
    self,
    *,
    stop_requested: Callable[[], bool],
) -> None:
    ...
```

`_wait_listener_readable()` uses:

```python
select.select([fd], [], [], ACCEPT_POLL_INTERVAL_SECONDS)
```

Semantics:

- `InterruptedError` -> return `False`;
- other `OSError` or `ValueError` -> raise `ContainmentManagerServiceError("cannot poll containment manager listener")`;
- readable fd -> `True`;
- timeout -> `False`.

`serve_forever()` loop ordering:

1. if closed -> `ContainmentManagerServiceError`;
2. check `stop_requested()`; return if true;
3. readiness poll;
4. if not ready, loop;
5. check `stop_requested()` again; return if true;
6. call `serve_one()`;
7. repeat.

Do not install signal handlers in this module.

- [ ] **Step 4: Add real stop-while-idle timing test**

Create a service on a real temporary Unix listener, run `serve_forever()` in a test thread, set a `threading.Event` stop flag without making a client connection, and assert the thread exits within a bounded margin greater than one 100 ms poll interval (for example 1 second).

This test validates that foreground shutdown does not require a signal handler to mutate listener state.

- [ ] **Step 5: Run Task 3 tests**

Run:

```bash
python -m pytest -q tests/host_agent/test_containment_manager_service.py
```

Expected: PASS with no hanging threads.

- [ ] **Step 6: Commit Task 3**

```bash
git add   src/ssh_over_mcp/host_agent/containment_manager_service.py   tests/host_agent/test_containment_manager_service.py
git commit -m "feat: add stoppable manager accept loop"
```

---

### Task 4: Public Export, Source-of-Truth Docs, and Full Verification

**Files:**
- Modify: `src/ssh_over_mcp/host_agent/__init__.py`
- Modify: `docs/ssh-host-agent.md`
- Modify: `docs/development-plan.md`
- Modify: `remote/host_agent/README.md`
- Test: `tests/host_agent/test_containment_manager_service.py`

**Interfaces:**
- Consumes:
  - completed `ContainmentManagerService`
  - `ContainmentManagerServiceError`
- Produces:
  - stable package exports for the service/error
  - source-of-truth documentation marking Phase 3d2b2b2c2b2b2 implemented
  - next roadmap item remains workload UID/GID transition before exec

- [ ] **Step 1: Write failing public-export test**

Add:

```python
def test_host_agent_package_exports_manager_service():
    from ssh_over_mcp import host_agent

    assert host_agent.ContainmentManagerService is ContainmentManagerService
    assert host_agent.ContainmentManagerServiceError is ContainmentManagerServiceError
```

Run:

```bash
python -m pytest -q tests/host_agent/test_containment_manager_service.py -k package_exports
```

Expected: FAIL until `host_agent/__init__.py` exports the new symbols.

- [ ] **Step 2: Export the service API**

Modify `src/ssh_over_mcp/host_agent/__init__.py` to import and include in `__all__`:

```python
ContainmentManagerService
ContainmentManagerServiceError
```

Do not export private readiness helpers/constants unless another production module actually needs them.

- [ ] **Step 3: Update source-of-truth documentation**

Update `docs/ssh-host-agent.md` with the implemented service lifecycle:

- identity validation occurs before listener creation;
- serial foreground sessions;
- `SO_PEERCRED` remains inside existing connection serving;
- fixed readiness polling + caller-owned stop flag;
- session-local unauthorized/malformed clients;
- listener/endpoint infrastructure failures are service-fatal;
- endpoint cleanup remains listener-owned and identity-checked;
- no UID/GID switching and no ForceCommand execution yet.

Update `docs/development-plan.md`:

- mark Phase `3d2b2b2c2b2b2` implemented;
- next Phase is `3d2b2b2c2b2b3`: workload UID/GID transition before exec with no saved privilege.

Update `remote/host_agent/README.md` with the same current boundary in operator-facing form.

- [ ] **Step 4: Run focused host-agent manager tests**

Run:

```bash
python -m pytest -q   tests/host_agent/test_containment_manager_service.py   tests/host_agent/test_containment_manager_identity.py   tests/host_agent/test_containment_manager_endpoint.py   tests/host_agent/test_containment_manager_peer.py   tests/host_agent/test_containment_manager_unix.py   tests/host_agent/test_containment_manager.py
```

Expected: PASS.

- [ ] **Step 5: Run full supported-version verification**

On the repository validation environment:

```bash
python -m compileall -q src tests
python -m pytest -q
```

Run the self-hosted Docker validation workflow on the implementation branch so the complete suite executes under both Python 3.13 and Python 3.14.

Expected:

```text
Python 3.13 compile + full pytest: PASS
Python 3.14 compile + full pytest: PASS
```

ForceCommand execution must remain disabled after this verification.

- [ ] **Step 6: Commit Task 4**

```bash
git add   src/ssh_over_mcp/host_agent/__init__.py   tests/host_agent/test_containment_manager_service.py   docs/ssh-host-agent.md   docs/development-plan.md   remote/host_agent/README.md
git commit -m "docs: complete containment manager service lifecycle"
```

- [ ] **Step 7: Open the implementation PR with explicit security boundary**

PR summary must state:

- serial foreground service only;
- startup identity gate precedes endpoint side effects;
- session-local peer failures do not kill the listener;
- endpoint cleanup remains existing listener responsibility;
- no workload identity transition;
- no manager concurrency;
- ForceCommand execution remains disabled.

