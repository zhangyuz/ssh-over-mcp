# Phase 6B Private Compose Reference Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a locally testable Docker Compose reference that preserves the Phase 5 Security Ledger authority boundary with zero published MCP host ports.

**Architecture:** Reuse the Phase 6A application image for four roles: root-only one-shot `ledger-init`, non-root `ledger`, non-root `mcp`, and ephemeral non-root `approvalctl`. Three distinct named volumes isolate ledger data, execution socket, and admin socket; numeric UID/GID plus Linux `SO_PEERCRED` remain the authorization mechanism. MCP gets only private-origin plus SSH-egress networking; ledger/admin/bootstrap have no network.

**Tech Stack:** Python 3.13/3.14, Docker Engine/Compose v5-compatible syntax, Linux AF_UNIX + SO_PEERCRED, SQLite, pytest, PyYAML, self-hosted Ubuntu 26.04 x86 CI plus opt-in live Docker verification on the authorized Mac x86 host.

**Spec:** `docs/superpowers/specs/2026-10-02-phase-6-cloudflare-reference-deployment-design.md`

## Global Constraints

- Phase 6A exact merged base is `6c16d780058cd9cc6beed0f36d5c30426c7ce86d`.
- No 6B service may publish an MCP host port; `mcp` may only `expose: ["8000"]`.
- `ledger`, `ledger-init`, and `approvalctl` use `network_mode: none`.
- MCP static profile remains operator-owned; Compose never derives profile from request headers or external identity.
- MCP receives the execution socket only, never ledger data/HMAC/admin socket.
- `approvalctl` receives the admin socket only, never execution socket or ledger data.
- Ledger receives data + execution + admin volumes and no TCP network.- Long-running services use `read_only: true`, `cap_drop: [ALL]`, and `security_opt: ["no-new-privileges:true"]`.
- `ledger-init` runs `0:0`, drops all capabilities, adds only `CHOWN` and `DAC_OVERRIDE`, uses no network, and never repairs unsafe existing state.
- Reference numeric identities are fixed: MCP UID `10001`, ledger UID/GID `10002:10002`, execution socket GID `10003`, approvalctl UID/admin socket GID `10004:10005`.
- MCP runs as `10001:10003`; approvalctl runs as `10004:10005`; ledger runs as `10002:10002` with supplementary groups `10003` and `10005`.
- Trusted child directories are: data `/var/lib/ssh-over-mcp/ledger`, execution `/run/ssh-over-mcp-exec/ledger`, admin `/run/ssh-over-mcp-admin/ledger`.
- HMAC key is exactly 32 random bytes, service-owned mode `0600`, create-only; bootstrap never creates or rewrites the database.
- Cloudflare connector/account configuration remains out of scope until 6C.
- GitHub CI remains self-hosted only; live Compose runs on the authorized Mac x86 Docker host, not the runner Docker socket.
- The 6A deferred bit-reproducibility minor remains open; 6B must not claim full Phase 6 reproducibility closed.

## Review Focus

- Pristine named-volume roots are root-owned; bootstrap must create trusted children but never normalize a pre-existing wrong-owner/wrong-mode child. Task 1 owns this regression.
- Socket filesystem permission is not authorization: wrong UID with the correct socket GID must still fail `SO_PEERCRED` on execution and admin endpoints. Task 3 owns the live negatives.
- Read-only socket-volume mounts must permit legitimate AF_UNIX connect while preventing MCP/approvalctl path mutation. Task 3 owns the live proof.
- Compose profiles/anchors/interpolation must not hide a host port, secret mount, extra capability, or unintended approvalctl startup. Tasks 2–3 own source and resolved-config checks.
- Graceful ledger restart must preserve state; a deliberately stale endpoint path must fail closed rather than being silently deleted. Task 3 owns both live cases.

---## File map

- Create `src/ssh_over_mcp/approvals/bootstrap.py`: secure one-shot ledger volume bootstrap and generic CLI error surface.
- Modify `pyproject.toml`: add `ssh-over-mcp-ledger-init` console entry point.
- Create `tests/approvals/test_bootstrap.py`: bootstrap TDD, secret-retention, and never-repair tests.
- Modify `tests/live/test_container_image.py`: require the fifth console entry point.
- Create `deploy/compose/compose.yaml`: 6B four-service private Compose reference.
- Create `deploy/compose/reference.env.example`: non-secret operator path/profile/image inputs.
- Create `tests/ops/test_compose_contract.py`: daemon-free structural Compose contract for ordinary CI.
- Create `tests/live/test_compose_deployment.py`: resolved Compose plus live identity/mount/restart/outage tests.
- Modify `tests/live/README.md`: exact 6B live probe commands.
- Modify `docs/cloudflare-deployment.md`: local private Compose operation only; no live Cloudflare mutations.

### Task 1: Add secure Security Ledger bootstrap

**Files:**
- Create: `src/ssh_over_mcp/approvals/bootstrap.py`
- Modify: `pyproject.toml`
- Create: `tests/approvals/test_bootstrap.py`
- Modify: `tests/live/test_container_image.py`

**Interfaces:**
- Consumes `SecurityLedgerRuntimeSettings.from_env()` and `load_ledger_hmac_key(settings.storage_settings())`.
- Produces `LedgerBootstrapError(RuntimeError)`.
- Produces `prepare_ledger_runtime(settings: SecurityLedgerRuntimeSettings) -> None`.
- Produces `run(env: Mapping[str, str] | None = None, *, stderr: TextIO | None = None) -> int`.- Produces console script `ssh-over-mcp-ledger-init = "ssh_over_mcp.approvals.bootstrap:main"`.

- [ ] **Step 1: Write RED first-initialization tests**

Use three pre-existing mount-root fixture directories and these child paths:
`<data>/ledger/ledger.db`, `<data>/ledger/ledger.key`, `<exec>/ledger/ledger.sock`, `<admin>/ledger/ledger.sock`.

With service UID/GID equal to the current test identity, assert bootstrap creates three child directories mode `0700`, creates one regular 32-byte HMAC key mode `0600`, and creates neither DB nor socket.

Run: `python -m pytest -q tests/approvals/test_bootstrap.py -k first_initialization`
Expected: FAIL because the module does not exist.

- [ ] **Step 2: Add RED idempotence and never-repair tests**

Cover: second run preserves exact key bytes; an existing DB sentinel is byte-for-byte unchanged; wrong key length/mode fails; wrong existing child mode/type/symlink fails; HMAC symlink/FIFO fails; failure leaves bad object mode/ownership/content unchanged.

- [ ] **Step 3: Implement minimal bootstrap filesystem logic**

Require DB/HMAC same parent and data/exec/admin child parents pairwise distinct. Missing child may be created then owned/mode-verified; existing child is validate-only. Missing key uses `O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC|O_NOFOLLOW`, `secrets.token_bytes(32)`, `fchown`, `fchmod(0600)`, `fsync`, then final validation via `load_ledger_hmac_key`. Never call `LedgerDatabase.open`.

- [ ] **Step 4: Add RED CLI secret-safe failure test, then implement `run/main`**

`run()` writes exactly `Security Ledger bootstrap failed\n` and returns `1` on configuration/bootstrap/storage error; success returns `0`. Distinctive invalid key content must not appear in public stderr/traceback.

- [ ] **Step 5: Add entry point and image-entrypoint regression**

Extend `pyproject.toml` and the Phase 6A live image expected console-entrypoint set.

Run:
```bash
python -m pytest -q tests/approvals/test_bootstrap.py tests/ops/test_container_build_contract.py
python -m ruff check src/ssh_over_mcp/approvals/bootstrap.py tests/approvals/test_bootstrap.py
```
Expected: PASS.

- [ ] **Step 6: Build image and run existing live image probe**

```bash
docker build --platform linux/amd64 -t ssh-over-mcp:phase6b .
SSH_OVER_MCP_RUN_LIVE_CONTAINER=1 SSH_OVER_MCP_CONTAINER_IMAGE=ssh-over-mcp:phase6b \
  python -m pytest -q tests/live/test_container_image.py
```

- [ ] **Step 7: Review Task 1 and commit**

Review create-only key semantics, race/type checks, secret retention, and absence of DB creation.

Commit: `git commit -m "Feat: add secure ledger volume bootstrap"`

### Task 2: Add the static private Compose contract

**Files:**
- Create: `deploy/compose/compose.yaml`
- Create: `deploy/compose/reference.env.example`
- Create: `tests/ops/test_compose_contract.py`

**Interfaces:**
- Consumes the Phase 6A/Task 1 image and existing runtime env names.
- Produces services `ledger-init`, `ledger`, `mcp`, `approvalctl`.
- Produces named volumes `ledger-data`, `ledger-exec`, `ledger-admin`.
- Produces networks `origin_internal` and `ssh_egress`; 6C later adds `cloudflare_egress` and `cloudflared`.

- [ ] **Step 1: Write RED structural Compose tests**

Parse YAML structurally and assert exact service set; no `ports`, `privileged`, host network/PID/IPC, Docker socket, or static IP; MCP only exposes `8000`; ledger/init/approvalctl use network none; MCP networks are exactly origin_internal + ssh_egress; origin_internal is internal; top-level ledger volumes are exactly the approved three.

- [ ] **Step 2: Pin exact identity and capability contract**

Assert `mcp.user=10001:10003`; `ledger.user=10002:10002` with `group_add=[10003,10005]`; `approvalctl.user=10004:10005`; `ledger-init.user=0:0`; all services read-only/drop ALL/no-new-privileges; only init adds exactly CHOWN + DAC_OVERRIDE; approvalctl profile is `admin`.

- [ ] **Step 3: Pin mount visibility and runtime environment**

Assert mount targets: init and ledger get all three ledger volumes writable; MCP gets `/etc/ssh-over-mcp/config.yaml`, `/etc/ssh-over-mcp/credentials.yaml`, `/run/secrets/ssh`, `/run/secrets/origin-bearer` read-only plus execution volume mounted at `/run/ssh-over-mcp-exec` read-only; approvalctl gets only admin volume at `/run/ssh-over-mcp-admin` read-only. Named data volume mounts at `/var/lib/ssh-over-mcp`.

Pin exact paths/IDs:
```text
DB=/var/lib/ssh-over-mcp/ledger/ledger.db
HMAC=/var/lib/ssh-over-mcp/ledger/ledger.key
EXEC=/run/ssh-over-mcp-exec/ledger/ledger.sock
ADMIN=/run/ssh-over-mcp-admin/ledger/ledger.sock
service=10002:10002
exec socket gid=10003, peer=10001:10003
admin socket gid=10005, peer=10004:10005
```

MCP must set bind `0.0.0.0`, origin token file `/run/secrets/origin-bearer`, ledger server `10002:10002`, and profile only from the operator environment variable.

- [ ] **Step 4: Implement minimal Compose reference**

Use `${SSH_OVER_MCP_IMAGE:-ssh-over-mcp:phase6b}`. The only host/operator interpolation names are `SSH_OVER_MCP_CONFIG_FILE`, `SSH_OVER_MCP_CREDENTIAL_MAP_FILE`, `SSH_OVER_MCP_SSH_SECRETS_DIR`, `SSH_OVER_MCP_ORIGIN_BEARER_FILE`, and `SSH_OVER_MCP_PROFILE`. Give MCP stable `origin_internal` alias `ssh-over-mcp-origin`.

Pin service entrypoints to `ssh-over-mcp-ledger-init`, `ssh-over-mcp-ledger`, `ssh-over-mcp-server`, and `ssh-over-mcp-approvalctl`. `ledger` depends on init with `condition: service_completed_successfully`; `mcp` depends on ledger with `condition: service_started`. MCP healthcheck uses Python stdlib against `http://127.0.0.1:8000/readyz` with interval `5s`, timeout `3s`, retries `12`, start-period `2s`. Add a bounded `/tmp` tmpfs only if live validation proves a read-only root requires it.

- [ ] **Step 5: Add non-secret `reference.env.example`**

Include exactly `SSH_OVER_MCP_IMAGE`, `SSH_OVER_MCP_PROFILE`, `SSH_OVER_MCP_CONFIG_FILE`, `SSH_OVER_MCP_CREDENTIAL_MAP_FILE`, `SSH_OVER_MCP_SSH_SECRETS_DIR`, and `SSH_OVER_MCP_ORIGIN_BEARER_FILE`, using placeholder absolute host paths and never secret values.

- [ ] **Step 6: Run static contract tests and commit**

```bash
python -m pytest -q tests/ops/test_compose_contract.py tests/ops/test_container_build_contract.py
python -m ruff check tests/ops/test_compose_contract.py
git diff --check
```

Commit: `git commit -m "Ops: add private Compose reference"`

### Task 3: Prove the live Compose authority boundaries

**Files:**
- Create: `tests/live/test_compose_deployment.py`
- Modify: `tests/live/README.md`
- Modify Task 1/2 owners only when a live RED exposes a concrete defect.

**Interfaces:**
- Live opt-in: `SSH_OVER_MCP_RUN_LIVE_COMPOSE=1`.
- Image: `SSH_OVER_MCP_COMPOSE_IMAGE`, required when opt-in is set.
- A module-scoped fixture owns a unique Compose project, temporary host config/credential-map/SSH-key/origin-bearer files, env file, startup, and `down -v --remove-orphans` teardown.

- [ ] **Step 1: Write live resolved-config RED test**

Run `docker compose ... config --format json`; parse the resolved JSON and re-assert zero published ports, exact users/groups/caps/security options, exact mounts/networks, and absence of Cloudflare/service-token secret environment. This is the authoritative anchors/interpolation check.

- [ ] **Step 2: Start real stack and verify bootstrap/runtime security**

Build `ssh-over-mcp:phase6b`, then `up -d --wait mcp`. Assert init exit 0, MCP healthy, exact numeric identities, ledger supplementary groups only 10003/10005, PID1 CapEff zero + NoNewPrivs 1 for MCP/ledger, init HostConfig has network none/read-only root/CapDrop ALL/CapAdd exactly CHOWN+DAC_OVERRIDE, key metadata is 32 bytes owner 10002:10002 mode 0600, and DB becomes 10002:10002 mode 0600.

- [ ] **Step 3: Prove mount and network isolation**

Assert MCP has no data/admin mount; approvalctl has no data/execution mount; MCP execution and approvalctl admin mounts are read-only; legitimate ping/list succeeds across them; path create/unlink attempts fail; ledger network mode is none; MCP only joins project origin_internal + ssh_egress; `docker compose port mcp 8000` has no binding and inspect PortBindings is empty.

- [ ] **Step 4: Prove exact peer identity**

One-shot execution client uses GID 10003 but wrong UID 10004 and must fail ledger ping. One-shot admin client uses GID 10005 but wrong UID 10001 and must fail `approvalctl list`. Normal MCP execution-client ping and normal approvalctl list must succeed.

- [ ] **Step 5: Prove restart persistence**

From the MCP identity use `SecurityLedgerClient.ensure_approval` with one fixed safe binding: `principal_id=static:developer`, `profile=developer`, `host=dev01`, `tool=fs_mkdir`, `privilege=user`, `policy_version=sha256:compose-live`, `normalized_path=/srv/app/new`, `argv_count=0`, `argv_fingerprint=fingerprint_argv(())`, timeout `60.0`, max-output `4096`; use request ID `req_` + 32 `1` characters and risk `HIGH`. Append one bounded `REQUEST_RECEIVED` audit event under a distinct request ID. Gracefully restart ledger and wait for MCP readiness. Assert key SHA-256 fingerprint unchanged without printing key, same approval remains visible, audit rows persist, and restart creates no duplicate approval.

- [ ] **Step 6: Prove outage and stale-endpoint fail-closed behavior**

Stop ledger: readiness becomes 503, execution-client ping fails, no host port appears. Recover and readiness returns healthy. Then stop ledger, inject a stale non-socket path using an isolated root test container mounting only the execution volume, and assert ledger startup fails rather than deleting/replacing it; clean only the test-created fixture and prove clean restart.

- [ ] **Step 7: Run complete live probe**

```bash
docker build --platform linux/amd64 -t ssh-over-mcp:phase6b .
SSH_OVER_MCP_RUN_LIVE_COMPOSE=1 SSH_OVER_MCP_COMPOSE_IMAGE=ssh-over-mcp:phase6b \
  python -m pytest -q tests/live/test_compose_deployment.py
```

Ordinary CI skips live cases without the opt-in.

- [ ] **Step 8: Review Task 3 and commit**

Every live failure uses systematic-debugging and a RED→GREEN regression before commit.

Commit: `git commit -m "Test: prove private Compose authority boundaries"`

### Task 4: Document 6B and run whole-slice review

**Files:**
- Modify: `docs/cloudflare-deployment.md`
- Modify production/Compose/tests only for concrete review defects.

**Interfaces:**
- Produces local operator instructions for build/start/readiness/approvalctl/teardown without touching a real Cloudflare account.

- [ ] **Step 1: Document local private Compose workflow**

Document image build, copy/edit of `reference.env.example`, absolute host path requirements, `docker compose up -d --wait mcp`, `docker compose --profile admin run --rm approvalctl list/show/grant/deny`, readiness from inside the private network, graceful restart, and `down -v` data-destruction warning. State clearly that 6C begins Cloudflare connector/private-route work.

- [ ] **Step 2: Document identity/mount trust model**

Explain numeric IDs 10001/10002/10003/10004/10005, why MCP/admin primary GIDs must match peer policy, why supplementary socket groups belong only to ledger, and why rootless/userns-remap remains unsupported until a live peer-ID proof passes.

- [ ] **Step 3: Whole-slice security review**

Review exact diff from `6c16d78` for bootstrap never-repair/create-only semantics, no secret output, no DB creation by bootstrap, exact mount visibility, zero ports, exact peer IDs, no new MCP authority, no Cloudflare secret/account mutation, and unchanged Phase 5 approval/audit semantics.

- [ ] **Step 4: Defect loop**

Every Critical/Important finding gets systematic root-cause analysis, focused RED, smallest fix, targeted GREEN, full regression, and repeat review until clean.

- [ ] **Step 5: Run fresh full verification**

```bash
python -m ruff check src tests
python -m compileall -q src tests
python -m pytest -q
git diff --check
```

Rebuild `ssh-over-mcp:phase6b` and rerun both live image and live Compose probes on Mac x86.

- [ ] **Step 6: Commit docs/review fixes**

Commit: `git commit -m "Docs: document Phase 6B private Compose"`

### Task 5: PR, exact-head CI, merge, and cleanup

**Files:**
- No planned product changes after the review gate.

**Interfaces:**
- Produces exact PR-head and merge-main self-hosted CI evidence plus a clean repository.

- [ ] **Step 1: Verify exact branch head and cleanliness**

Record status, head SHA, commit list from `6c16d78`, and fresh local/live verification evidence.

- [ ] **Step 2: Push PR and require existing self-hosted CI**

CI must still use `[self-hosted, linux, x64, ssh-over-mcp-mac-x86]`. Require exact PR-head Python 3.13/3.14 success. Do not add a Docker socket to the runner and do not use GitHub-hosted runners.

- [ ] **Step 3: Final whole-branch review**

Use an independent reviewer if available; otherwise explicitly record fresh author self-review. No Critical/Important finding may remain. Carry forward the 6A deferred image reproducibility minor unless this slice explicitly fixes it with its own RED/GREEN proof.

- [ ] **Step 4: Merge and require merge-main exact-head CI**

Record PR number, merge-main SHA, push CI run ID, exact matching `headSha`, and `success` conclusion. PR-head CI alone is insufficient.

- [ ] **Step 5: Clean only verified 6B branch/worktree**

Delete merged local/remote 6B branch/worktree, prune refs, and verify root repository is clean with only intended branches/worktrees.

## Phase 6B completion gate

6B is complete only when bootstrap unit tests, static Compose contract, live Mac x86 Compose authority/restart/outage tests, full Python regression, PR-head CI, merge-main exact-head CI, and final security review are all green with no remaining Critical/Important finding.

Only then begin a fresh Phase 6C planning cycle for the Cloudflare connector/private route.