# Phase 6C Cloudflare Connector Reference Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a hardened `cloudflared` connector reference plus exact private-hostname/Portal/Gateway operator instructions, without mutating a real Cloudflare account.

**Architecture:** Extend the Phase 6B Compose reference with one profile-gated `cloudflared` service that joins only the private origin network and a dedicated Cloudflare egress network. The connector reads a remotely-managed Tunnel token from a read-only file via `--token-file`; it receives no SSH, application, origin-bearer, or Ledger secret mounts. Operator docs then bind one private hostname route to that connector and register the same private URL in MCP Portal with the existing origin bearer and Gateway routing enabled.

**Tech Stack:** Docker Compose, Cloudflare Tunnel/cloudflared 2026.9.3, Cloudflare MCP Portal/Gateway, pytest, PyYAML, self-hosted Ubuntu 26.04 x86 CI, authorized Mac x86 Docker host.

**Spec:** `docs/superpowers/specs/2026-10-02-phase-6-cloudflare-reference-deployment-design.md`

## Global Constraints

- Exact merged base is `34e99a86a2f39694f00e20bffb6da42f77292eee`.
- Do not mutate any live Cloudflare account in Phase 6C.
- Do not add a public MCP host port, public-origin fallback, or Quick Tunnel path.
- Keep the Phase 6B MCP/Ledger/admin UID/GID, socket, volume, and network authority boundaries unchanged.
- Add exactly one new runtime service: `cloudflared`, profile-gated behind `cloudflare`.
- Pin `cloudflare/cloudflared:2026.9.3@sha256:072c067d25ccbe61d46e18f0d0723255f2bb5304f7317caa95b27031520ff92c`.
- Explicitly run `cloudflared` as `65532:65532`, read-only root, `cap_drop: [ALL]`, and `no-new-privileges:true`.
- The pinned image entrypoint is `cloudflared --no-autoupdate`; Compose adds only `tunnel run --token-file /run/secrets/cloudflare-tunnel-token`, yielding process argv `cloudflared --no-autoupdate tunnel run --token-file ...`. Never put the Tunnel token value in argv or environment.
- The Tunnel token mount is the only secret mount visible to `cloudflared`.
- `cloudflared` joins exactly `origin_internal` and new non-internal `cloudflare_egress`; `cloudflare_egress` has service-level `gw_priority: 1` so it is the connector's default gateway.
- MCP must not join `cloudflare_egress`; Ledger/init/approvalctl remain networkless as in 6B.
- The private hostname is operator-owned and passed as `SSH_OVER_MCP_PRIVATE_HOSTNAME`; the MCP service receives that hostname as an additional `origin_internal` Docker network alias.
- The Portal upstream URL is exactly `http://<private-hostname>:8000/mcp`.
- Portal upstream auth remains `auth_type=bearer` using the Phase 6A origin bearer; that bearer is not mounted into `cloudflared`.
- Gateway routing must be enabled before private server registration/capability sync.
- Reference Compose requires Docker Compose 2.33.1+ because `gw_priority` selects the connector default gateway.
- CI remains self-hosted only; no Docker socket is added to the runner.
- Carry forward the unresolved Phase 6 application-image bit-reproducibility minor; 6C may improve connector pinning but must not claim the full criterion closed.

## Review Focus

- Tunnel token must never appear in resolved Compose environment, command argv, logs, inspect output beyond a file path, or repository examples. Task 1 owns static/secret tests; Task 2 owns live inspect/process checks.
- The private hostname must remain deployment-only routing data: it may appear only as the MCP network alias and docs/operator inputs, never as MCP environment, profile, principal, or tool input. Task 1 owns the static contract; Task 2 owns resolved-config/DNS proof.
- `cloudflared` must have no path to SSH keys, origin bearer, Ledger DB/HMAC, or Ledger sockets. Tasks 1–2 own mount inspection.
- Connector failure must leave MCP private and unpublished rather than creating any alternate host listener. Task 2 owns the live negative proof.
- Portal/Gateway instructions must not imply Gateway is the application authorization/audit boundary or that background sync traffic receives the same Gateway inspection as real-time tool calls. Task 3 owns the documentation assertions.

---

## File map

- Modify `deploy/compose/compose.yaml`: add profile-gated `cloudflared`, private-hostname alias, and `cloudflare_egress`.
- Modify `deploy/compose/reference.env.example`: add non-secret private-hostname and Tunnel-token-file path variables.
- Modify `tests/ops/test_compose_contract.py`: extend the existing raw-YAML service/network/env-key contract for the profile-gated connector while preserving all 6B authority assertions.
- Create `tests/ops/test_cloudflare_connector_contract.py`: daemon-free connector image/network/mount/secret contract.
- Create `tests/live/test_cloudflare_connector_reference.py`: resolved-config, image identity, container inspect, DNS/private-origin reachability, and connector-failure isolation tests without contacting a real account.
- Modify `tests/live/README.md`: exact 6C local connector-reference probe.
- Modify `docs/cloudflare-deployment.md`: private hostname route, connector startup, Portal bearer registration, Gateway validation, no-account-mutation boundary.
### Task 1: Add the static cloudflared Compose contract

**Files:**
- Modify: `deploy/compose/compose.yaml`
- Modify: `deploy/compose/reference.env.example`
- Modify: `tests/ops/test_compose_contract.py`
- Create: `tests/ops/test_cloudflare_connector_contract.py`

**Interfaces:**
- Consumes existing `origin_internal` network and MCP service aliasing.
- Produces service `cloudflared` and network `cloudflare_egress`.
- Produces env inputs `SSH_OVER_MCP_PRIVATE_HOSTNAME` and `SSH_OVER_MCP_CLOUDFLARED_TOKEN_FILE`.

- [ ] **Step 1: Write RED static service/network tests**

Pin the final contract: service profile exactly `["cloudflare"]`; exact pinned image/digest; `user == "65532:65532"`; read-only root, drop ALL, no-new-privileges, never privileged; command exactly uses `tunnel run --token-file /run/secrets/cloudflare-tunnel-token` because `--no-autoupdate` is already in the pinned image entrypoint; no `TUNNEL_TOKEN` environment; only mount target is the token file read-only; networks exactly `origin_internal` + `cloudflare_egress`; `cloudflare_egress.gw_priority == 1`; no ports, host namespaces, Docker socket, Ledger volume, SSH secret, app config, or origin bearer mount.

Also update the existing 6B raw-YAML expectations only after watching RED: its exact service set becomes the five services including profile-gated `cloudflared`, top-level networks gain `cloudflare_egress`, and the env example key set gains the two 6C inputs. Preserve every existing 6B mount/identity/zero-port assertion. Run targeted pytest and verify RED because the connector does not exist yet.

- [ ] **Step 2: Pin private-hostname interpolation contract**

Require MCP `origin_internal.aliases` to contain both `ssh-over-mcp-origin` and the operator interpolation for `SSH_OVER_MCP_PRIVATE_HOSTNAME`. Require `reference.env.example` to contain exactly one placeholder private hostname and one absolute Tunnel-token-file path, but no token bytes/value, Access service-token fields, or origin-bearer value.

Document accepted hostname shape in the example comment: lowercase DNS hostname, 1–253 chars, labels 1–63 chars using `a-z0-9-`, no leading/trailing hyphen, no IP literal, no URL scheme, no port/path.

- [ ] **Step 3: Implement the minimal Compose extension**

Add `cloudflare_egress: {}` and the profile-gated service. Attach `origin_internal` with default gateway priority 0 and `cloudflare_egress` with `gw_priority: 1`. Use `/run/secrets/cloudflare-tunnel-token` as its only mount. Do not add a healthcheck that requires live Cloudflare connectivity; 6C must remain locally testable before account mutation.
- [ ] **Step 4: Add hostname preflight helper to the static test only**

Because Compose cannot enforce full DNS syntax, the ops test parses the example/private-hostname fixture with a small helper and rejects schemes, ports, underscores, uppercase, empty labels, IP literals, and values longer than 253 chars. Do not add hostname parsing authority to the MCP application; this is deployment routing config, not caller identity.

- [ ] **Step 5: Run static verification and commit**

Run:
```bash
python -m pytest -q tests/ops/test_compose_contract.py tests/ops/test_cloudflare_connector_contract.py
python -m ruff check tests/ops/test_cloudflare_connector_contract.py
git diff --check
```

Review specifically for secret interpolation and accidental new mounts/networks.

Commit: `git commit -m "Ops: add Cloudflare connector reference"`

### Task 2: Prove connector isolation locally without a Cloudflare account

**Files:**
- Create: `tests/live/test_cloudflare_connector_reference.py`
- Modify: `tests/live/README.md`
- Modify Task 1 files only when a live RED exposes a concrete defect.

**Interfaces:**
- Opt-in env: `SSH_OVER_MCP_RUN_LIVE_CLOUDFLARE_REFERENCE=1`.
- Uses existing `SSH_OVER_MCP_COMPOSE_IMAGE` application image.
- Uses a fixture-only fake Tunnel token file; the connector is created/inspected but is not expected to establish a Cloudflare session.
- [ ] **Step 1: Write resolved-config RED/verification**

Render Compose with profiles `cloudflare` and `admin`. Assert exact five-service set; connector exact image/user/command/security options; connector only sees token-file bind mount; connector networks exactly the two approved networks with `cloudflare_egress.gw_priority == 1`; MCP has the private-hostname alias but no connector egress network; no service publishes MCP ports; no resolved environment contains token contents, `TUNNEL_TOKEN`, `CF-Access-Client-Secret`, or Cloudflare API token fields.

- [ ] **Step 2: Prove pinned cloudflared image identity**

Pull the pinned image/digest and assert via Docker inspect: repository digest resolves to the exact manifest-list digest; `.Config.User == "65532:65532"`; entrypoint begins with `cloudflared --no-autoupdate`; `cloudflared version` reports `2026.9.3`.

This test is live-Docker opt-in only.

- [ ] **Step 3: Create but do not start connector; inspect its authority**

Start the Phase 6B MCP stack normally, then create the connector with the `cloudflare` profile without starting it. Inspect: read-only root, CapDrop ALL, no added caps, no-new-privileges, user 65532:65532, exactly the token-file mount, exactly origin_internal + cloudflare_egress, `cloudflare_egress` selected as the default gateway, no PortBindings, and command containing only the token-file path rather than token contents.

Require the fixture Tunnel token host file to be mode `0600` and the container mount to be read-only. Document that native Linux bind mounts preserve numeric ownership, so production token files must be owned/readable by UID/GID `65532:65532` with mode `0400` or `0600`; Docker Desktop behavior is not treated as proof of native-Linux ownership remapping.

- [ ] **Step 4: Prove private hostname resolves to MCP without exposing a host port**

Run a one-shot Python probe container on `origin_internal` using the application image. DNS resolution of the configured private hostname must return the MCP container address; `GET http://<private-hostname>:8000/healthz` must succeed; an unauthenticated request to `/mcp` must receive 401; Docker inspect must still show empty MCP PortBindings.

The probe must not mount the origin bearer; this proves private routing and origin authentication remain separate layers.

- [ ] **Step 5: Prove connector failure cannot expose origin**

Capture the host-listener baseline first, then start `cloudflared` with the deliberately fake token file for a bounded interval of at most 10 seconds and allow it to fail/retry. Regardless of connector state, MCP must remain healthy locally, MCP PortBindings must stay empty, the host-listener state for port 8000 must be unchanged from baseline, and Ledger/MCP mount/network boundaries must remain unchanged. Inspect connector logs and require the distinctive fake token value to be absent. Stop/remove the connector and verify MCP remains healthy.

Do not assert on Cloudflare network error wording; only local security state is authoritative.

- [ ] **Step 6: Run complete live reference probe and commit**

Run on the authorized Mac x86 Docker host:
```bash
docker build --platform linux/amd64 -t ssh-over-mcp:phase6c .
SSH_OVER_MCP_RUN_LIVE_CLOUDFLARE_REFERENCE=1 \
SSH_OVER_MCP_COMPOSE_IMAGE=ssh-over-mcp:phase6c \
python -m pytest -q tests/live/test_cloudflare_connector_reference.py
```

Normal CI skips this probe. Any live failure enters systematic-debugging + RED→GREEN.

Commit: `git commit -m "Test: prove Cloudflare connector isolation"`

### Task 3: Document private route, Portal registration, and Gateway validation

**Files:**
- Modify: `docs/cloudflare-deployment.md`
- Create: `tests/ops/test_cloudflare_deployment_docs.py`
- Create or modify no executable Cloudflare-account automation.

**Interfaces:**
- Consumes `SSH_OVER_MCP_PRIVATE_HOSTNAME`, Tunnel token file, and the existing Phase 6A origin bearer.
- Produces an operator checklist only.

- [ ] **Step 1: Write RED documentation-contract tests**

Create `tests/ops/test_cloudflare_deployment_docs.py` and assert the guide does not yet satisfy the 6C contract: it must eventually contain the exact private URL form `http://<private-hostname>:8000/mcp`, `auth_type: bearer`, the phrase `Route traffic through Cloudflare Gateway`, an explicit statement that no 6C command mutates the account automatically, and distinct explanations of Tunnel token versus origin bearer. Run the focused test and verify RED against the current 6B document.

- [ ] **Step 2: Document Tunnel connector setup and token ownership**

Document: create/select a remotely managed Tunnel manually; copy only the Tunnel run token into an operator-owned file outside the repo; point `SSH_OVER_MCP_CLOUDFLARED_TOKEN_FILE` at it; set `SSH_OVER_MCP_PRIVATE_HOSTNAME`; require Docker Compose 2.33.1+; start the connector profile only after the 6B local stack is healthy.

State explicitly that anyone with the Tunnel token can run that tunnel. On native Linux, require the token file to be owned/readable by numeric connector identity `65532:65532` with mode `0400` or `0600`; never weaken this by running cloudflared as root.

- [ ] **Step 3: Document the private-hostname route**

In the Cloudflare dashboard/operator flow: connect the network with the Tunnel; create a private hostname route for exactly `SSH_OVER_MCP_PRIVATE_HOSTNAME` to that connector; do not create a public-origin DNS record for the MCP origin; verify route/connector health before Portal registration.

Explain that the same hostname resolves inside the connector's `origin_internal` Docker network through the MCP alias and is deployment routing data only, not application identity/profile input.

- [ ] **Step 4: Document Portal upstream registration**

Register exactly:
```text
HTTP URL: http://<private-hostname>:8000/mcp
auth_type: bearer
auth_credentials: <existing origin bearer>
```

The origin bearer is entered/stored in Portal upstream credentials, never cloudflared configuration. Turn on **Route traffic through Cloudflare Gateway** before Save/connect; wait for Ready/capability synchronization. Include no API command which mutates the live account.

- [ ] **Step 5: Add Gateway validation and scope guidance**

Require the operator to verify a real-time tool call appears in Gateway HTTP logs and that optional DLP can inspect/block real-time Portal tool traffic. State that application policy/approval/audit remains authoritative and that background credential/capability synchronization is not equivalent to the real-time Gateway-inspected path.

- [ ] **Step 6: Run docs/static tests and commit**

Run:
```bash
python -m pytest -q tests/ops/test_cloudflare_deployment_docs.py tests/ops/test_cloudflare_connector_contract.py
python -m ruff check tests/ops/test_cloudflare_deployment_docs.py
git diff --check
```
Expected: PASS.

Commit: `git commit -m "Docs: document Phase 6C private Cloudflare route"`

### Task 4: Whole-slice review, PR, exact-head CI, merge, and cleanup

**Files:**
- Modify production/tests/docs only for concrete review defects.

**Interfaces:**
- Consumes Tasks 1–3.
- Produces a merged, verified 6C slice without live account mutation.

- [ ] **Step 1: Run whole-slice security review**

Review exact diff from `34e99a8` for: no Tunnel token value in repository/argv/environment; cloudflared receives no app/SSH/origin-bearer/Ledger secrets; connector has only intended networks; MCP still has zero host ports and no cloudflare_egress; private hostname cannot select application profile/principal; docs distinguish Tunnel token, origin bearer, Access service token, and Cloudflare API token; no Cloudflare API/dashboard mutation is automated; Phase 5/6A/6B security boundaries remain unchanged.

Any Critical/Important finding returns to focused RED→GREEN.

- [ ] **Step 2: Run fresh verification**

Linux/amd64:
```bash
python -m ruff check src tests
python -m compileall -q src tests
python -m pytest -q
git diff --check
```

Mac x86: rebuild application image as `ssh-over-mcp:phase6c`; rerun Phase 6A live image probe; rerun Phase 6B live Compose probe; run Phase 6C connector-reference live probe.

- [ ] **Step 3: Push PR and require self-hosted exact-head CI**

Require existing `[self-hosted, linux, x64, ssh-over-mcp-mac-x86]` CI only. No Docker socket on runner and no GitHub-hosted fallback. Record exact PR-head SHA/run success, then perform a fresh final whole-branch review.
- [ ] **Step 4: Merge and require merge-main exact-head CI**

After merge, require a successful push CI whose `headSha` exactly equals the merge-main SHA. PR-head CI alone is insufficient.

- [ ] **Step 5: Clean verified 6C branch/worktree**

Delete only merged 6C worktrees/branches, prune refs, and verify root repo is clean.

Carry forward the unresolved application-image bit-reproducibility minor into 6D/final Phase 6 closure unless it is separately fixed with explicit RED/GREEN evidence.

## Phase 6C completion gate

6C is complete only when static connector contract, live local connector-isolation probe, updated operator route/Portal/Gateway guidance, full Linux regression, Phase 6A/6B/6C Mac x86 live probes, PR-head CI, merge-main exact-head CI, and final security review are all green with no remaining Critical/Important finding.

Only then begin the fresh Phase 6D planning cycle for Managed OAuth, Access service tokens, Gateway/DLP operational guidance, multi-profile deployment guidance, and final Phase 6 closure.

## Provider capability snapshot used by this plan

Checked on 2026-10-02:
- private MCP Portal upstreams require a private hostname/CIDR route through Tunnel or another Cloudflare One connector and Gateway routing for registration/capability sync;
- Portal upstream authentication supports static bearer credentials;
- Gateway routing applies to real-time Portal tool calls and is not equivalent coverage for every background synchronization operation;
- remotely-managed `cloudflared tunnel run --token-file <PATH>` is supported by cloudflared 2025.4.0+;
- private hostname routing through `cloudflared` requires cloudflared 2025.7.0 or newer; the pinned 2026.9.3 satisfies that minimum;
- current pinned cloudflared release used here is 2026.9.3.

Provider behavior is deployment input, not an application authorization invariant. Re-check these facts before any future live-account execution.