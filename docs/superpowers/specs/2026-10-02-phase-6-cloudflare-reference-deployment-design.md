# Phase 6 Cloudflare Reference Deployment Design

Date: 2026-10-02

Status: **closed** — Phase 6D merged as `a5c7c2d13c504f1e68beb0e7fc55db90539fbcc0`; exact PR-head and merge-main self-hosted CI passed; Phase 6 worktrees/branches cleaned.

Base commit: `408f8ad1435f0a67eea20342b31c3a30ffe9a4ee`

## 1. Purpose

Phase 5 closed the Security Ledger, audit, and exact single-use approval
boundary. Phase 6 adds a reproducible deployment reference without weakening
that boundary.

The reference deployment must keep the MCP origin off public host ports,
preserve the separate Security Ledger authority, and provide a documented path
through Cloudflare Tunnel, Gateway, MCP Portal, Managed OAuth, and Access
service tokens.

The first implementation is intentionally local-first. It must be testable
without mutating a real Cloudflare account. Live Cloudflare provisioning is a
later operator-approved step after the local container and Compose security
contract is green.

## 2. User intent and success criteria

The intended result is a small, reviewable deployment stack which an operator
can build locally, verify adversarially, and then connect to Cloudflare without
redesigning the application security model.
Success means:

1. the origin has no Docker host-port publication;
2. the MCP process remains non-root and cannot access ledger admin authority;
3. the Security Ledger still owns its DB, HMAC key, and peer-authenticated
   Unix sockets;
4. Cloudflare acts as front door, routing, identity, and observability, not as
   the final SSH authorization boundary;
5. machine and interactive Cloudflare authentication are documented separately;
6. Portal-to-origin requests use an origin credential rather than relying only
   on private reachability;
7. Phase 5 security tests continue to pass unchanged;
8. deployment invariants are executable tests, not prose-only promises;
9. exact-head CI remains self-hosted Ubuntu 26.04 x86 on Python 3.13 and 3.14;
10. Phase 6 is split into small slices which can be reviewed and merged
    independently.

## 3. Non-goals

Phase 6 does not implement:

- per-user OAuth subject/claim to `principal_id` or profile mapping;
- automatic mutation of the operator's live Cloudflare account;
- Kubernetes;
- systemd, AppArmor, or SELinux hardening profiles;
- SSH CA support;
- external secret-manager integration;
- public-origin fallback;
- raw-shell enablement;
- destructive filesystem namespace tools;
- new privileged-helper authority;
- changes to approval replay, TTL, or single-use semantics.
A fully compromised MCP process remains outside the local control-plane
protection boundary, exactly as in Phase 5. Remote ForceCommand, host-agent
policy, OS identity, and containment remain independent enforcement layers.

## 4. Design principles

### 4.1 Preserve authority separation

Runtime authority comes from process identity, mounts, peer credentials, and
network placement. It must not depend on whether a binary happens to exist in
an OCI image.

One immutable application image may contain the MCP server, ledger server, and
approval CLI executables. Compose runs them as separate identities with
different mounts. Possessing the `approvalctl` binary does not confer admin
authority without the admin Unix socket and matching peer identity.

### 4.2 Default-safe outside Compose

A bare `ssh-over-mcp-server` process continues to bind only to
`127.0.0.1` by default.

Container-private binding is an explicit operator action, never a new global
default.

### 4.3 No public-origin escape hatch

The reference Compose file contains no `ports:` publication for the MCP
service. Cloudflare failure must make the remote path unavailable; it must not
cause a fallback listener on the host.

### 4.4 Cloudflare is not application authorization

Cloudflare decides who can reach the portal and can add routing, logging, and
DLP. `ssh-over-mcp` still owns profile, host, tool, command/path, risk,
approval, SSH host-key, and remote-host policy.
## 5. Reference topology

```text
Interactive client                 Headless client
      |                                  |
Managed OAuth                    Access service token
      +---------------+------------------+
                      |
                      v
             Cloudflare MCP Portal
                      |
                 Access policy
                      |
                      v
             Cloudflare Gateway
            HTTP logging / DLP
                      |
                private route
                      |
                      v
                 cloudflared
                      |
             origin_internal network
                      |
          +-----------v-----------+
          | ssh-over-mcp MCP      |
          | static server profile |
          | origin bearer auth    |
          +-----------+-----------+
                      |
           execution Unix socket
                      |
          +-----------v-----------+
          | Security Ledger       |
          | DB + HMAC key         |
          +-----------------------+
                      |
MCP -- pinned-key SSH -- managed hosts
```
The long-running process domains are:

- `mcp`: MCP HTTP service and outbound pinned-key SSH;
- `ledger`: local Security Ledger with no TCP listener;
- `cloudflared`: Cloudflare connector with no application/SSH/ledger secret
  mounts.

Two short-lived operator/bootstrap domains also exist:

- `ledger-init`: prepares secure ledger-owned volume roots and creates the
  initial HMAC key if and only if it is absent;
- `approvalctl`: operator-invoked admin client which mounts only the admin
  socket volume and runs under the exact configured admin peer identity.

## 6. Application image

Phase 6 provides one production OCI image for the Python application.

Required image properties:

- Python 3.13 runtime baseline;
- project installed from an immutable build stage;
- no compiler/build cache in the final stage;
- a non-root default user;
- no embedded policy, SSH private key, ledger HMAC key, Cloudflare credential,
  or environment-specific configuration;
- server, ledger, and approval CLI entry points available;
- deterministic health/version smoke commands where practical.

The image itself does not choose authority. Compose `user:`, mounts, socket
visibility, and environment select each runtime role.
The reference runtime uses:

- `read_only: true` where compatible with the role;
- `cap_drop: [ALL]` for long-running application services;
- `security_opt: ["no-new-privileges:true"]`;
- explicit writable volumes/tmpfs only where required;
- no Docker socket mount;
- no privileged container;
- no host PID/IPC namespace;
- no host network mode.

## 7. MCP bind contract

Add operator-owned runtime setting:

```text
SSH_OVER_MCP_BIND_HOST
```

Rules:

- default: `127.0.0.1`;
- allowed values: exactly `127.0.0.1` and `0.0.0.0`;
- malformed, hostname, wildcard-text, IPv6, or other values fail startup;
- the same validated value is passed to both Uvicorn and MCP SDK host
  validation;
- `SSH_OVER_MCP_PORT` retains its existing validation.

The reference Compose deployment explicitly sets
`SSH_OVER_MCP_BIND_HOST=0.0.0.0` because the listener must be reachable by
`cloudflared` on a private Docker bridge. This does not publish a host port.

## 8. Origin authentication
Phase 6 adds an upstream bearer credential for non-loopback MCP exposure.

Runtime configuration uses an optional absolute mounted secret-file path, not
the token value itself:

```text
SSH_OVER_MCP_ORIGIN_BEARER_TOKEN_FILE=/run/secrets/origin-bearer
```

The token file must:

- be a regular file;
- be read only at startup;
- have a bounded non-empty value;
- never be returned in errors, logs, tool output, or readiness output.

Binding rules are fail-safe:

- `127.0.0.1` with no token file preserves the current local-only behavior;
- `127.0.0.1` with a token file enforces bearer auth;
- `0.0.0.0` without a token file fails startup;
- the reference Compose stack always uses `0.0.0.0` plus the token file.

Whenever origin auth is configured, requests to the MCP endpoint require:

```text
Authorization: Bearer <origin credential>
```

Comparison uses constant-time byte comparison after strict header parsing.
Missing, duplicate, malformed, or incorrect authorization fails with a generic
HTTP authentication error before MCP request parsing.

`/healthz` and `/readyz` remain credential-free for local container health
checks and disclose only their existing bounded status values. No future
non-health route is implicitly exempt.

Cloudflare Portal registers the private upstream with `auth_type=bearer` and
stores the origin bearer as its upstream credential.
The origin bearer is distinct from a Cloudflare Access service token.

- origin bearer: Portal -> private ssh-over-mcp origin;
- Access service token: headless MCP client -> Portal/Access.

Neither credential selects the server-side `SSH_OVER_MCP_PROFILE`.

## 9. Runtime profile model

Phase 6 keeps the existing static trusted principal model.

One MCP service instance has one operator-owned
`SSH_OVER_MCP_PROFILE`. Request headers, query parameters, MCP arguments,
origin bearer contents, Cloudflare email, and service-token identity cannot
override it.

Operators who need materially different profiles deploy separate MCP service
instances with separate private upstream identities/credentials, rather than
multiplexing an unverified caller-selected role inside one process.

Per-user verified OAuth claim-to-profile mapping remains deferred.

## 10. Compose networks

The reference defines three logical networks:

1. `origin_internal`: `internal: true`; only `mcp` and `cloudflared`.
2. `ssh_egress`: non-internal; only `mcp`, for DNS and managed-host SSH.
3. `cloudflare_egress`: non-internal; only `cloudflared`, for Cloudflare
   connector egress.

`ledger`, `ledger-init`, and `approvalctl` use `network_mode: none`.
The MCP service has no `ports:` entry. Compose may use `expose: ["8000"]`
as documentation of the container-private port, but `expose` is not a host
publication.

The private origin receives a stable Docker network alias suitable for the
Cloudflare private-hostname route. The reference must not rely on a fixed
container IP.

## 11. Ledger volume and socket separation

Use three distinct persistent/runtime mounts:

- ledger data volume: DB + HMAC key; mounted only by `ledger` and
  `ledger-init`;
- ledger execution-socket volume: mounted by `ledger` and `mcp`;
- ledger admin-socket volume: mounted by `ledger` and ephemeral
  `approvalctl`.

The MCP container must not mount the admin-socket volume at all. Therefore an
MCP compromise cannot even name the ledger admin socket through its own mount
namespace.

The MCP container also must not mount the ledger data volume. It receives only
the execution socket path plus expected ledger service UID/GID, preserving the
Phase 5 execution-client authority model.

The `cloudflared` container mounts none of these three volumes.
## 12. Ledger bootstrap

Named Docker volumes begin with ownership which does not satisfy the existing
ledger storage/socket invariants. Phase 6 therefore provides one narrowly
scoped bootstrap command.

`ledger-init`:

- runs only before `ledger`;
- has no network;
- mounts only the three ledger volumes;
- runs as UID 0 only for initialization, with all capabilities dropped and
  only `CHOWN` plus `DAC_OVERRIDE` added;
- uses `no-new-privileges` and a read-only root filesystem;
- creates secure socket parent directories with the exact configured UID/GID;
- creates the ledger data directory as ledger-owned and non-group/world
  writable;
- if the HMAC key is absent, creates exactly 32 cryptographically random bytes
  with create-only semantics;
- sets key owner/group to the ledger service identity and mode to 0600;
- never replaces an existing HMAC key;
- never creates or rewrites an existing database;
- validates existing directory/key type, ownership, mode, and key length;
- exits non-zero on any mismatch;
- never prints key bytes.

After bootstrap, the existing Security Ledger remains authoritative for DB
creation, schema validation, HMAC key/database binding, socket ownership,
socket mode, and exact peer-credential checks.

Bootstrap convenience must not weaken the ledger's existing startup checks.

## 13. Runtime identities
Compose uses explicit numeric Linux UID/GID values. No security decision
depends on usernames.

The reference defines distinct identities for at least:

- MCP process UID/GID;
- ledger service UID/GID;
- ledger execution socket group;
- ledger admin peer UID/GID.

The ledger service receives only the execution/admin socket groups as explicit
supplementary groups. The MCP process uses the execution-socket group as its
primary GID, and `approvalctl` uses the admin-socket group as its primary GID.

The ledger execution peer policy must exactly match the MCP container's actual
peer UID/GID observed through `SO_PEERCRED`.

The admin peer policy must exactly match the ephemeral `approvalctl`
container identity.

User-namespace remapping and rootless Docker are not claimed safe by analogy.
They are supported only after a live peer-identity test demonstrates that the
kernel-visible UID/GID values match the configured policies.

## 14. Application configuration and secrets

MCP mounts read-only:

- combined inventory/policy configuration;
- credential-map file;
- referenced SSH private-key files;
- origin bearer token file;
- ledger execution-socket volume.

MCP does not receive:

- ledger DB;
- ledger HMAC key;
- ledger admin socket;
- Cloudflare tunnel token;
- Cloudflare Access service-token secret.
Ledger receives only its own data and Unix-socket mounts plus its runtime
identity configuration.

`cloudflared` receives only the tunnel connector credential and network
configuration. It does not receive application config, SSH keys, ledger data,
ledger sockets, or the origin bearer as a mounted secret. The origin bearer may
transit the local proxy request because Portal supplies it as upstream
authentication, but it is not a connector configuration secret.

The Access client service-token secret belongs to the headless caller, not to
the origin deployment stack.

No example file contains real secret bytes.

## 15. Cloudflare private route

The reference Cloudflare path uses a private hostname route, not a public
origin hostname and not a fixed Docker container IP.

Operator flow:

1. run the local reference stack and verify local deployment tests;
2. create/select a Cloudflare Tunnel connector;
3. run `cloudflared` attached to `origin_internal` and
   `cloudflare_egress`;
4. configure the private hostname route to the connector;
5. verify the connector can resolve/reach only the intended private MCP alias;
6. add the private MCP URL ending in `/mcp` to MCP Portal;
7. enable Gateway routing for that server before connection/capability sync;
8. configure upstream bearer authentication with the origin bearer;
9. verify server status becomes Ready.
The implementation documentation must state that current Cloudflare private MCP
support requires Gateway routing for private server registration/capability
synchronization.

Phase 6 does not invoke Cloudflare APIs or dashboard mutations automatically.

## 16. Portal authentication modes

### 16.1 Interactive users

Interactive MCP clients connect to the Portal endpoint using Cloudflare's
Managed OAuth flow and the portal Access application.

The origin does not trust or map the user's Cloudflare identity in Phase 6.
Cloudflare Access determines portal reachability; the selected private upstream
still runs one static server-owned profile.

### 16.2 Headless clients

Machine callers may use a Cloudflare Access service token.

Current Cloudflare Portal behavior requires a matching `Service Auth` policy
at both:

- the Portal Access application; and
- each linked MCP server Access application the token should reach.

For service-token sessions, the linked server mapping must not require per-user
upstream OAuth. Portal then uses the configured upstream admin credential,
which for this reference is the origin bearer.
The `CF-Access-Client-Secret` must never be written into repository config,
MCP tool arguments, model prompts, or application logs.

## 17. Gateway logging and DLP

Gateway routing is enabled for the private upstream.

The deployment guide explains:

- Portal real-time tool calls can appear in Gateway HTTP logs;
- HTTP/DLP policies can inspect or block matching data;
- DLP is defense-in-depth and not `ssh-over-mcp` authorization;
- Cloudflare background operations such as some credential/capability sync
  paths are not equivalent to real-time Gateway-inspected tool calls;
- no application security invariant depends on Gateway logging being available.

The application audit ledger remains the authoritative execution decision trail
for `ssh-over-mcp`.

## 18. Failure behavior

### 18.1 Ledger unavailable

MCP readiness returns 503 and Phase 5 execution/audit behavior remains
fail-closed. No SSH network side effect may begin through a missing ledger.

### 18.2 cloudflared unavailable

The origin and ledger may remain locally healthy, but remote Portal access
fails. No host port is opened and no alternate listener is started.
### 18.3 Portal/Gateway/Tunnel misconfiguration

Failure is unreachable/not-ready, not public fallback. A Cloudflare routing or
policy error cannot change the server-owned static profile or central policy.

### 18.4 Origin bearer missing or invalid

MCP endpoint requests fail before MCP parsing. Health/readiness behavior does
not disclose credential material.

### 18.5 Wrong ledger identities or filesystem state

Wrong UID/GID, socket directory ownership, key owner/mode/length, unsafe data
directory, stale endpoint path, or wrong peer credential causes startup or
connection failure. The reference never auto-chmods unknown existing state into
acceptance after the initial bootstrap contract.

### 18.6 Lost required audit persistence

Existing Phase 5 uncertainty/fail-closed semantics remain unchanged. Container
restart does not convert an uncertain execution into success.

## 19. Test strategy

Every implementation slice follows RED -> minimal GREEN -> targeted verification
-> full verification -> review -> commit.
Deployment tests must include:

| Invariant | Evidence |
| --- | --- |
| default runtime binds loopback | Python unit test |
| container bind requires explicit opt-in | runtime unit tests |
| non-loopback bind without origin bearer fails startup | runtime negative test |
| configured origin bearer required on `/mcp` | ASGI/API tests |
| malformed/duplicate bearer rejected safely | negative API tests |
| bearer absent from errors/tracebacks | secret-retention test |
| image default user is non-root | image smoke test |
| long-running containers have zero effective Linux caps | live probe |
| no-new-privileges is set | live probe |
| Compose publishes zero MCP host ports | parsed Compose contract test |
| ledger has no network namespace | Compose/runtime probe |
| MCP has no admin socket mount | mount inspection + path-negative probe |
| MCP cannot read DB/HMAC | mount/permission adversarial test |
| cloudflared has no SSH/ledger secret mounts | mount inspection |
| ledger execution peer is exact MCP UID/GID | live `SO_PEERCRED` test |
| wrong peer is rejected | live negative socket test |
| ledger down makes readiness 503 | live Compose test |
| ledger down blocks network execution | integration test |
| restart preserves approval/audit state | live Compose restart test |
| HMAC key create-only and exact 32 bytes | bootstrap tests |
| wrong key/dir ownership or mode fails | bootstrap + ledger negative tests |
| config/key mounts are read-only | write-attempt probe |
| killing cloudflared exposes no host listener | network/socket probe |
| existing MCP request-size behavior remains | API suite |
| Phase 5 adversarial matrix remains green | integration suite |
| Python 3.13 and 3.14 pass | self-hosted exact-head CI |

Compose contract tests parse the resolved configuration rather than searching
raw YAML text, so anchors/interpolation cannot hide a published port or secret
mount.

## 20. Implementation slices

### Phase 6A — hardened application image and origin boundary

Deliver:

- production Dockerfile;
- validated `SSH_OVER_MCP_BIND_HOST`;
- origin bearer middleware/configuration;
- image security contract tests;
- local image smoke tests.

No Compose stack or Cloudflare account configuration is required to merge 6A.

### Phase 6B — private local Compose reference

Deliver:

- `ledger-init`, `ledger`, `mcp`, and ephemeral `approvalctl`;
- separate data/execution/admin volumes;
- private origin + separate MCP SSH egress networks;
- no host ports;
- live readiness, restart, mount, UID/GID, capability, and secret-isolation
  tests.
### Phase 6C — Cloudflare connector reference

Deliver:

- `cloudflared` service/reference configuration;
- separate connector egress network;
- private-hostname route instructions;
- Portal upstream registration instructions using origin bearer;
- Gateway-routing validation checklist;
- no automatic Cloudflare account mutation.

### Phase 6D — Portal auth and operational guidance

Deliver:

- Managed OAuth client instructions;
- Access service-token instructions;
- Gateway logging/DLP guidance;
- explicit distinction between client service token and origin bearer;
- multi-profile deployment guidance;
- final Phase 6 adversarial deployment review and closure evidence.

Each slice gets its own branch/worktree, review gate, targeted/full tests,
exact-head self-hosted CI, merge, and cleanup.

## 21. Acceptance criteria

Phase 6 is complete only when all of the following are true:

1. production image builds reproducibly and runs non-root;
2. bare server default remains `127.0.0.1`;
3. Compose explicitly opts into container-private `0.0.0.0`;
4. resolved Compose config publishes zero MCP host ports;
5. ledger and MCP remain different process identities;
6. execution and admin sockets are separate mounts;
7. MCP cannot access ledger DB, HMAC key, or admin socket;
8. cloudflared cannot access SSH keys or ledger secrets;
9. origin bearer is required for `/mcp` and secret-safe;
10. Ledger failure makes MCP not-ready and blocks execution;
11. cloudflared failure does not expose the origin;
12. approval and audit state survive intended container restart;
13. unsafe ledger key/directory/peer configuration fails closed;
14. existing Phase 5 adversarial tests remain green;
15. deployment-specific negative tests remain green;
16. Ruff and the complete Python test suite pass;
17. Python 3.13 and 3.14 exact-head CI pass only on the configured self-hosted
    Ubuntu 26.04 x86 runner;
18. final whole-branch security review finds no remaining Critical or Important
    issue;
19. obsolete Phase 6 branches/worktrees are removed after merge;
20. live Cloudflare account changes remain a separate explicit operator action.

## 22. Security invariants carried from Phase 5

Phase 6 must not weaken any of the 18 Phase 5 final-review invariants. In
particular:

- the client cannot choose principal/profile;
- DENY remains non-overridable;
- approval-required operations cannot reach SSH before atomic consume;
- consumed approvals remain single-use across concurrency/restart;
- policy changes invalidate stale required grants;
- MCP cannot acquire ledger admin authority;
- MCP cannot read ledger DB/HMAC material;
- ledger/audit outage remains fail-closed;
- host-agent and OS policy remain independently authoritative;
- secret-retention rules still exclude credentials and raw sensitive payloads;
- mutation uncertainty and `fs_write` status-74 semantics remain distinct.
Any deployment change which makes one of these statements false requires a new
security design rather than a Compose workaround.

## 23. Cloudflare capability snapshot

This design was checked against Cloudflare documentation on 2026-10-02.

Current assumptions used by this spec:

- MCP server portals are generally available;
- private MCP servers may be reached through Cloudflare Tunnel or another
  Cloudflare One connector using a private hostname/CIDR route;
- private MCP server registration/capability synchronization requires Gateway
  routing;
- Portal supports stateless modern MCP and 2025 Streamable HTTP compatibility;
- Portal upstream authentication supports OAuth, static bearer/custom headers,
  and unauthenticated servers;
- Managed OAuth protects the portal-facing interactive client flow;
- Access service tokens support machine-to-machine Portal sessions;
- service-token Portal sessions require matching `Service Auth` policy at the
  Portal and linked MCP-server Access applications;
- Gateway routing exposes real-time Portal tool traffic to HTTP logging/DLP,
  but not every background operation follows that same path.

These are deployment-provider facts, not application invariants. If Cloudflare
changes them, documentation/configuration may change without weakening the
local security boundary.

## 24. External references

- Cloudflare MCP server portals:
  https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/
- Cloudflare private MCP support changelog, 2026-09-22:
  https://developers.cloudflare.com/changelog/post/2026-09-22-private-mcp-servers/
- Cloudflare MCP Portal GA changelog, 2026-09-24:
  https://developers.cloudflare.com/changelog/post/2026-09-24-mcp-portals-ga/
- Cloudflare private routes:
  https://developers.cloudflare.com/cloudflare-one/networks/routes/add-routes/
- Existing project deployment guidance: `docs/cloudflare-deployment.md`
- Cloudflare front-door ADR: `docs/decisions/0003-cloudflare-portal-front-door.md`

## 25. Review/implementation gate

The written-spec gate was satisfied before implementation. Phase 6A through 6D
were implemented through approved Superpowers plans, TDD, adversarial review,
and self-hosted exact-head CI gates. No live Cloudflare account mutation was
performed by repository code or by the implementation workflow.

Phase 6 is **closed**. PR #102 head `2e2486a3b536ad600be5e6439ede36268c08b06f` passed self-hosted CI run `37059153723`; the resulting merge-main commit `a5c7c2d13c504f1e68beb0e7fc55db90539fbcc0` passed push CI run `37059622970`. Both runs used the configured self-hosted Ubuntu 26.04 x86 validation job with Python 3.13 and 3.14. The merged Phase 6D worktree/branch and prior Phase 6 implementation worktrees/branches were cleaned after merge.

## 26. Phase 6 implementation evidence

### 26.1 Acceptance criteria 1-20

| # | Acceptance criterion | Executable/source evidence | State before final merge |
|---:|---|---|---|
| 1 | Production image builds reproducibly and runs non-root | `Dockerfile`; `tests/ops/test_container_reproducibility_contract.py`; `tests/live/test_reproducible_image.py::test_two_no_cache_builds_are_bit_reproducible`; `tests/live/test_container_image.py` | Green |
| 2 | Bare server default remains `127.0.0.1` | `src/ssh_over_mcp/api/runtime.py`; `tests/api/test_runtime.py::test_runtime_settings_default_to_loopback_without_origin_token` | Green |
| 3 | Compose explicitly opts into container-private `0.0.0.0` | `deploy/compose/compose.yaml`; `tests/ops/test_compose_contract.py::test_compose_pins_exact_runtime_environment_and_entrypoints` | Green |
| 4 | Resolved Compose publishes zero MCP host ports | `tests/ops/test_compose_contract.py::test_compose_has_exact_private_service_network_and_volume_surface`; `tests/live/test_compose_deployment.py`; `tests/live/test_cloudflare_connector_reference.py` | Green |
| 5 | Ledger and MCP remain different process identities | `tests/ops/test_compose_contract.py::test_compose_pins_exact_numeric_identities_and_capabilities`; live Compose identity assertions | Green |
| 6 | Execution and admin sockets are separate mounts | `tests/ops/test_compose_contract.py::test_compose_mount_visibility_preserves_ledger_authority_domains`; live Compose mount/isolation probe | Green |
| 7 | MCP cannot access ledger DB, HMAC key, or admin socket | `tests/integration/test_phase5_authority_separation.py::test_mcp_runtime_has_socket_identity_only_not_ledger_storage_authority`; Compose static/live mount tests | Green |
| 8 | cloudflared cannot access SSH keys or ledger secrets | `tests/ops/test_cloudflare_connector_contract.py::test_cloudflared_service_is_hardened_and_token_file_only`; `tests/live/test_cloudflare_connector_reference.py::test_created_connector_has_only_connector_authority` | Green |
| 9 | Origin bearer is required for `/mcp` and secret-safe | `tests/api/test_origin_auth.py` including invalid-header, secret-retention, auth-before-parser, and health/readiness cases | Green |
| 10 | Ledger failure makes MCP not-ready and blocks execution | `tests/live/test_compose_deployment.py` outage/recovery case; `tests/integration/test_phase5_security.py::test_approval_persistence_outages_block_transport` | Green |
| 11 | cloudflared failure does not expose origin | `tests/live/test_cloudflare_connector_reference.py::test_connector_failure_does_not_expose_origin` | Green |
| 12 | Approval and audit state survive intended restart | `tests/live/test_compose_deployment.py` restart-persistence case; `tests/integration/test_phase5_security.py::test_restart_matrix_preserves_terminal_states_and_expiry_once` | Green |
| 13 | Unsafe ledger key/directory/peer configuration fails closed | `tests/approvals/test_bootstrap.py`; wrong-UID/right-GID and stale-endpoint cases in `tests/live/test_compose_deployment.py` | Green |
| 14 | Existing Phase 5 adversarial tests remain green | `tests/integration/test_phase5_security.py`, `test_phase5_authority_separation.py`, and `test_phase5_secret_retention.py` rerun in the Phase 6D targeted gate | Green |
| 15 | Deployment-specific negative tests remain green | Phase 6A origin-auth negatives; Phase 6B Compose/live negatives; Phase 6C connector/live negatives; Phase 6D reproducibility/auth-guidance contracts | Green |
| 16 | Ruff and complete Python test suite pass | Linux/amd64 Phase 6D gate: Ruff + compileall + full pytest; closure-evidence tests intentionally RED until this section was written | Green after closure docs GREEN rerun |
| 17 | Python 3.13/3.14 exact-head CI passes only on configured self-hosted Ubuntu 26.04 x86 runner | `.github/workflows/ci.yml`; PR-head `2e2486a3...` → run `37059153723` success; merge-main `a5c7c2d...` → push run `37059622970` success | Green |
| 18 | Final whole-branch review has no Critical/Important issue | Fresh `408f8ad..2e2486a3` author security review plus source invariant checklist and post-PR-head review; no remaining Critical/Important finding | Green |
| 19 | Obsolete Phase 6 branches/worktrees removed after merge | Post-merge cleanup left root `main` as the only Phase 6 worktree/branch; refs pruned and `main == origin/main` at `a5c7c2d...` | Green |
| 20 | Live Cloudflare account changes remain explicit operator action | `docs/cloudflare-deployment.md`; `tests/ops/test_cloudflare_deployment_docs.py`; source/script scan finds no Cloudflare API mutation path | Green |

### 26.2 Carried Phase 5 security invariants

| ID | Carried invariant | Regression/source evidence | State |
|---|---|---|---|
| P5-1 | MCP caller cannot select trusted principal/profile | `tests/integration/test_phase5_authority_separation.py::test_mcp_registry_has_only_phase5_public_authority`; static profile remains runtime env in `tests/api/test_runtime.py`; Phase 6 auth docs prohibit claim/header profile selection | Green |
| P5-2 | MCP cannot grant or deny approvals | `test_mcp_registry_has_only_phase5_public_authority`; execution/admin dispatcher separation test; only `approval_status` remains public | Green |
| P5-3 | DENY cannot be overridden by approval | `tests/approvals/test_execution_authorizer.py::test_deny_never_consumes_supplied_approval`; Phase 5 current-policy matrix | Green |
| P5-4 | Approval-required operation cannot reach SSH before atomic consume | `tests/approvals/test_execution_authorizer.py::test_granted_exact_approval_is_consumed_before_authorization`; Phase 5 single-use integration matrix | Green |
| P5-5 | Consumed approval cannot replay concurrently or after restart | `tests/integration/test_phase5_security.py::test_concurrent_single_use_matrix_reaches_operation_once`; restart matrix; `tests/approvals/test_ledger_concurrency.py::test_concurrent_consume_has_exactly_one_success` | Green |
| P5-6 | Material input changes approval binding | `tests/integration/test_phase5_security.py::test_binding_mismatch_matrix_stays_pre_consume`; execution-authorizer binding-change regression | Green |
| P5-7 | Current policy/version change invalidates stale required grant | `tests/integration/test_phase5_security.py::test_current_policy_change_matrix`; execution-authorizer policy-change regressions | Green |
| P5-8 | Ledger time owns expiry semantics | Phase 5 restart/expiry matrix; `tests/approvals/test_service.py::test_service_restart_preserves_approval_states_and_applies_expiry` | Green |
| P5-9 | Execution client cannot acquire admin authority | `tests/integration/test_phase5_authority_separation.py::test_execution_and_admin_dispatchers_enforce_disjoint_authority`; Phase 6B separate socket mounts/UIDs | Green |
| P5-10 | MCP process does not open SQLite ledger storage | `test_mcp_runtime_has_socket_identity_only_not_ledger_storage_authority`; Phase 6B MCP has no data-volume mount | Green |
| P5-11 | HMAC key is unavailable to MCP | Same authority-separation test plus Compose mount-visibility/static/live tests | Green |
| P5-12 | Ledger/audit outage fails closed | `tests/integration/test_phase5_security.py::test_approval_persistence_outages_block_transport`; audit-outage matrix; Phase 6B outage live probe | Green |
| P5-13 | Approval does not bypass host-agent/OS policy | Phase 6 adds no approval authority to host-agent; full host-agent/SSH suite remains green; whole-phase source review shows only strict-default peer helper reuse for Ledger namespace visibility | Green |
| P5-14 | No raw shell fallback is exposed | `test_mcp_registry_has_only_phase5_public_authority` explicitly excludes `ssh_shell`; MCP server schema/registry tests remain green | Green |
| P5-15 | No destructive filesystem tool is exposed | `test_mcp_registry_has_only_phase5_public_authority` explicitly excludes `fs_delete`; filesystem registry remains typed/create-only | Green |
| P5-16 | Audit rows exclude credentials/raw argv/env/stdin/file bodies/unbounded output | `tests/integration/test_phase5_secret_retention.py`; `tests/api/test_audit_lifecycle.py` bounded/secret-safe regressions | Green |
| P5-17 | `fs_write` status 74 stays committed/durability-uncertain, distinct from generic uncertainty | `tests/api/test_filesystem_approval_http.py` status-74 assertions; `tests/api/test_write.py::test_fs_write_committed_uncertain_outcome_is_preserved`; Phase 5 security audit-outage case | Green |
| P5-18 | Consume is one execution attempt, not one successful execution | `tests/integration/test_phase5_security.py::test_consumed_mkdir_approval_is_not_restored_after_transport_abort`; `test_consumed_approval_survives_execution_start_audit_failure`; replay transport remains zero | Green |

### 26.3 Phase 6D final closure evidence

Before this status was written, the Phase 6D adversarial targeted set covering
Phase 5 security/authority/secret retention and Phase 6A-6D static contracts
passed. The Mac x86 live gate also passed the reproducible-image probe, the
Phase 6A image probe (3/3), the Phase 6B Compose probe (6/6), and the Phase 6C
connector probe (5/5).

The whole-Phase-6 review found no remaining Critical or Important issue. It
confirmed zero published MCP ports, static application profile authority,
separate Ledger/admin/storage authority, a file-only cloudflared Tunnel token,
no application handling of Cloudflare client/API credentials, and no automated
live Cloudflare account mutation.

Ruling carried into final closure: the shared Mac host test virtual environment
has a stale editable `/work` path, so Mac live probes set `PYTHONPATH` to the
exact Phase 6D worktree `src`. The cost if this ruling is wrong is host-side
Python dependency shadowing; this is mitigated by the complete Linux/amd64 test
suite and by the actual workload assertions running inside built Linux
containers.

Final closure gates are satisfied: PR-head CI run `37059153723` and merge-main push CI run `37059622970` both passed on the configured self-hosted Ubuntu 26.04 x86 runner, and post-merge Phase 6 branch/worktree cleanup completed. Live Cloudflare account provisioning remains an operator action. Phase 7 retains OS sandbox/egress examples, SSH CA, secret-manager integration, fuzz/property testing, and the broader hardening checklist.
