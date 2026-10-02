# Phase 6A Hardened Origin Image Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the smallest deployable Phase 6 increment: an explicitly authenticated non-loopback MCP origin plus a hardened production OCI image, while preserving today's safe loopback behavior.

**Architecture:** Extend the existing runtime settings with one exact bind-host choice and an optional mounted origin-bearer secret file. A focused ASGI middleware authenticates only the MCP HTTP path before MCP parsing; health/readiness remain bounded unauthenticated probes. Package the unchanged Python authority model in one non-root multi-stage image, then prove image/runtime properties with unit tests plus an opt-in live Docker probe.

**Tech Stack:** Python 3.13 runtime image, MCP Python SDK v2, Starlette ASGI, Uvicorn, Pydantic v2, pytest, Docker/OCI, Ruff, self-hosted Ubuntu 26.04 x86 CI on Python 3.13/3.14.

**Spec:** `docs/superpowers/specs/2026-10-02-phase-6-cloudflare-reference-deployment-design.md`

## Global Constraints

- Bare-server bind default remains exactly `127.0.0.1`.
- `SSH_OVER_MCP_BIND_HOST` accepts exactly `127.0.0.1` or `0.0.0.0`; all other values fail closed.
- `0.0.0.0` requires `SSH_OVER_MCP_ORIGIN_BEARER_TOKEN_FILE`; missing/blank/invalid origin auth fails before serving.
- Loopback without an origin token preserves the current local-only behavior.
- Origin auth never selects or alters `principal_id` or `SSH_OVER_MCP_PROFILE`.
- `/healthz` and `/readyz` remain unauthenticated and reveal only existing bounded status.
- No Cloudflare account mutation, Compose stack, Tunnel configuration, claim-to-profile mapping, raw shell, destructive filesystem tool, or approval-semantic change belongs in 6A.
- The production image contains no environment-specific config or secrets and defaults to a non-root user.
- Phase 5 authority, audit, approval, mutation-uncertainty, and secret-retention invariants remain unchanged.
- CI remains only on `[self-hosted, linux, x64, ssh-over-mcp-mac-x86]`; do not add GitHub-hosted runners.
- Docker live tests are run on the authorized Mac x86 Docker host; the hardened CI runner intentionally has no Docker socket.

## Review Focus

- Duplicate or malformed `Authorization` headers must return the same generic 401 as a wrong token, without echoing any supplied credential; Task 2 owns the regression.
- Empty, oversized, symlinked, control-character, or non-regular token files must fail startup without exposing token bytes or sensitive file contents; Task 2 owns the regression.
- A missing/blank origin-token path with `0.0.0.0` must fail in runtime settings before Uvicorn starts; Task 1 owns the regression.
- Authentication must run before MCP request-body parsing: an unauthenticated oversized `/mcp` request gets 401, while an authenticated oversized request still gets the existing 413; Task 2 owns the regression.
- Health/readiness must remain credential-free and secret-free even when origin auth is enabled; Task 2 owns the regression.

---

## File map

- Modify `src/ssh_over_mcp/api/runtime.py`: bind-host and origin-token-file configuration contract.
- Modify `src/ssh_over_mcp/api/main.py`: pass validated bind host to Uvicorn.
- Create `src/ssh_over_mcp/api/origin_auth.py`: bounded secret-file loader plus MCP-path ASGI bearer middleware.
- Modify `src/ssh_over_mcp/api/app.py`: pass bind host to MCP SDK and wrap the final ASGI app with origin auth.
- Modify `tests/api/test_runtime.py`: settings RED/GREEN coverage.
- Create `tests/api/test_main.py`: prove Uvicorn receives the validated host.
- Create `tests/api/test_origin_auth.py`: secret loading, middleware ordering, duplicate-header, secret-retention, and health/readiness tests.
- Create `Dockerfile`: multi-stage Python 3.13 production image with non-root default.
- Create `.dockerignore`: exclude development state, VCS/worktrees, caches, local env/secrets, and private-key material from build context.
- Create `tests/ops/test_container_build_contract.py`: Dockerfile/`.dockerignore` contract that runs without a Docker daemon.
- Create `tests/live/test_container_image.py`: opt-in image inspection/runtime probe.
- Modify `tests/live/README.md`: exact live-image build/probe commands and expected platform.
- Modify `docs/mcp-api.md`: new runtime settings and origin-auth behavior.
- Modify `docs/cloudflare-deployment.md`: 6A origin-auth/image boundary only; defer Tunnel/Portal procedure to 6C.

---

### Task 1: Add the explicit bind-host runtime contract

**Files:**
- Modify: `src/ssh_over_mcp/api/runtime.py`
- Modify: `src/ssh_over_mcp/api/main.py`
- Modify: `tests/api/test_runtime.py`
- Create: `tests/api/test_main.py`

**Interfaces:**
- Consumes existing `load_runtime_settings(env: Mapping[str, str]) -> MCPRuntimeSettings`.
- Produces `MCPRuntimeSettings.bind_host: Literal["127.0.0.1", "0.0.0.0"]`.
- Produces `MCPRuntimeSettings.origin_bearer_token_file: Path | None`.
- `main() -> None` passes `settings.bind_host` unchanged to `uvicorn.run(..., host=...)`.

- [ ] **Step 1: Write RED settings tests for loopback defaults and explicit private bind**

Add tests asserting:
- no `SSH_OVER_MCP_BIND_HOST` gives `bind_host == "127.0.0.1"` and `origin_bearer_token_file is None`;
- explicit `127.0.0.1` behaves identically;
- `0.0.0.0` plus absolute canonical `SSH_OVER_MCP_ORIGIN_BEARER_TOKEN_FILE=/run/secrets/origin-bearer` is accepted;
- token-file configuration on loopback is also accepted.

Run:
```bash
python -m pytest -q tests/api/test_runtime.py
```
Expected: FAIL because the two settings fields do not exist.

- [ ] **Step 2: Add RED fail-closed parameterized settings tests**

Cover:
- bind values `""`, `localhost`, `::`, `::1`, `*`, `0.0.0.0 `, and arbitrary IPs;
- `0.0.0.0` with missing or blank token-file env;
- relative, double-slash, NUL-containing, or lexically noncanonical token paths.

Every failure must raise only `RuntimeConfigurationError("runtime configuration is invalid")`.

Run the targeted tests and verify RED.

- [ ] **Step 3: Implement the minimal settings model**

In `runtime.py`:
- add exact `Literal` bind-host typing;
- default env value to `127.0.0.1`;
- parse the optional token path;
- reuse one focused absolute/canonical path validator rather than duplicating ledger-path rules;
- enforce the non-loopback/token dependency inside `load_runtime_settings`.

Do not open/read the secret file in the settings parser.
- [ ] **Step 4: Add RED main-entrypoint test**

In `tests/api/test_main.py`, monkeypatch `load_runtime_settings`, `build_application`, and `uvicorn.run`; assert the exact validated `bind_host` and `port` reach Uvicorn without a second default.

Run:
```bash
python -m pytest -q tests/api/test_main.py
```
Expected: FAIL because `main.py` still hard-codes `127.0.0.1`.

- [ ] **Step 5: Replace the hard-coded Uvicorn host and verify GREEN**

Change only:
```python
host=settings.bind_host
```

Run:
```bash
python -m pytest -q tests/api/test_runtime.py tests/api/test_main.py
python -m ruff check src/ssh_over_mcp/api/runtime.py src/ssh_over_mcp/api/main.py tests/api/test_runtime.py tests/api/test_main.py
```
Expected: all pass.

- [ ] **Step 6: Review Task 1 diff and commit**

Review for any hidden hostname/IPv6 acceptance, secret-value parsing, or profile authority change.

Commit:
```bash
git add src/ssh_over_mcp/api/runtime.py src/ssh_over_mcp/api/main.py tests/api/test_runtime.py tests/api/test_main.py
git commit -m "Feat: add explicit MCP bind contract"
```
### Task 2: Add secret-safe origin bearer authentication

**Files:**
- Create: `src/ssh_over_mcp/api/origin_auth.py`
- Modify: `src/ssh_over_mcp/api/app.py`
- Create: `tests/api/test_origin_auth.py`
- Modify: `tests/api/test_http_app.py` only if an existing assertion is more naturally extended there.

**Interfaces:**
- Consumes `MCPRuntimeSettings.bind_host` and `origin_bearer_token_file` from Task 1.
- Produces `load_origin_bearer_token(path: Path) -> bytes`.
- Produces `OriginBearerAuthMiddleware(app: ASGIApp, token: bytes)`.
- Middleware protects `/mcp` and paths below `/mcp/`; it does not protect `/healthz` or `/readyz`.
- Authentication schemes are matched case-insensitively as HTTP auth schemes, but the header must contain exactly one scheme, one ASCII space, and one token.
- Every auth failure returns exactly HTTP 401 with JSON `{"error":"origin authentication failed"}` plus `WWW-Authenticate: Bearer`.

- [ ] **Step 1: Write RED secret-file loader tests**

Pin the loader contract:
- regular file containing 1–4096 visible ASCII bytes is accepted exactly;
- empty file, 4097-byte file, embedded CR/LF/NUL/control byte, directory, FIFO/non-regular file, and symlink are rejected;
- rejection raises the same stable `RuntimeConfigurationError("runtime configuration is invalid")`;
- exception text and traceback do not include a distinctive secret marker.

Use a token such as `SUPERSECRET_ORIGIN_MARKER_6A` only in test fixtures.

Run:
```bash
python -m pytest -q tests/api/test_origin_auth.py -k token_file
```
Expected: FAIL because the module does not exist.
- [ ] **Step 2: Implement the bounded no-follow loader**

Use `lstat` plus `os.open` with `O_RDONLY | O_CLOEXEC | O_NOFOLLOW` where available, verify the opened inode remains the inspected regular file, read at most 4097 bytes, and accept only bytes `0x21..0x7e`.

Do not strip whitespace or newlines; operators must provide the exact bearer token.

Run the loader tests and verify GREEN.

- [ ] **Step 3: Write RED ASGI auth matrix**

Using `build_application(settings)` and Starlette/TestClient or a minimal ASGI harness, cover:
- configured correct bearer reaches `/mcp`;
- missing, wrong, wrong scheme, empty bearer, duplicate Authorization headers, and malformed bytes all return the same 401 shape;
- 401 includes `WWW-Authenticate: Bearer`;
- neither supplied wrong token nor configured token appears in response text, logs captured by the test, exception text, or traceback;
- `/mcpfoo` is not accidentally treated as the MCP endpoint;
- `/mcp/` remains protected if routed.

Use `hmac.compare_digest` for the final byte comparison.

- [ ] **Step 4: Pin auth-before-parser ordering**

Add two oversized-body tests:
- wrong/missing bearer + body >128 KiB -> 401;
- correct bearer + body >128 KiB -> existing 413.

This proves the auth wrapper sits outside the MCP SDK request-body parser.
- [ ] **Step 5: Pin health/readiness behavior with auth enabled**

With a distinctive configured bearer:
- `GET /healthz` remains 200 without Authorization;
- `GET /readyz` remains its existing 200/503 ledger-dependent result without Authorization;
- neither body contains the bearer marker;
- no health/readiness call performs an MCP domain operation.

- [ ] **Step 6: Implement middleware and application composition**

In `app.py`:
- pass `settings.bind_host` to `mcp.streamable_http_app(..., host=...)`;
- load the bearer once during application construction when a token file is configured;
- when a token is configured, call `app.add_middleware(OriginBearerAuthMiddleware, token=token)` so the Starlette route/lifespan object is preserved while auth executes outside route parsing.

Do not add caller identity/profile parsing and do not place token bytes in `MCPRuntimeSettings`.

- [ ] **Step 7: Run Task 2 targeted and regression tests**

```bash
python -m pytest -q tests/api/test_origin_auth.py tests/api/test_http_app.py tests/api/test_runtime.py tests/api/test_main.py
python -m ruff check src/ssh_over_mcp/api tests/api
```
Expected: all pass.

Then run the Phase 5 HTTP/security regressions:
```bash
python -m pytest -q tests/api/test_approval_http.py tests/api/test_filesystem_approval_http.py tests/integration/test_phase5_security.py tests/integration/test_phase5_secret_retention.py tests/integration/test_phase5_authority_separation.py
```
Expected: pass with only pre-existing platform skips.

- [ ] **Step 8: Review Task 2 diff and commit**
Review specifically for path-prefix bypass, duplicate-header ambiguity, token leakage, auth-after-parser ordering, and accidental health authentication.

Commit:
```bash
git add src/ssh_over_mcp/api/app.py src/ssh_over_mcp/api/origin_auth.py tests/api/test_origin_auth.py tests/api/test_http_app.py
git commit -m "Feat: authenticate non-loopback MCP origin"
```

### Task 3: Build and prove the hardened production image

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`
- Create: `tests/ops/test_container_build_contract.py`
- Create: `tests/live/test_container_image.py`
- Modify: `tests/live/README.md`

**Interfaces:**
- Consumes the package console scripts already defined by `pyproject.toml`.
- Produces one application image whose default command is `ssh-over-mcp-server`.
- Live probe is enabled only when `SSH_OVER_MCP_RUN_LIVE_CONTAINER=1`; image name comes from `SSH_OVER_MCP_CONTAINER_IMAGE`.

- [ ] **Step 1: Write the opt-in live image contract test first**

When enabled, the test must:
- inspect `.Config.User` and reject empty/root/UID 0 defaults;
- run the image with `--read-only --cap-drop=ALL --security-opt=no-new-privileges:true`;
- assert runtime UID is non-zero;
- assert `CapEff == 0000000000000000`;
- assert `NoNewPrivs == 1`;
- assert `/var/run/docker.sock` is absent;
- import `ssh_over_mcp` and resolve all four console entry points without starting services;
- assert no repository `.env`, `.git`, `.worktrees`, `*.key`, or `secrets/` path is copied into the application source tree.
With the env flag absent, this test module skips cleanly in normal CI.

- [ ] **Step 2: Create the build-context exclusion contract**

`.dockerignore` must exclude at least:
```text
.git
.worktrees
.venv
.pytest_cache
.ruff_cache
__pycache__
.env
.env.*
secrets
*.pem
*.key
*.crt
known_hosts.local
dist
build
*.egg-info
```

In `tests/ops/test_container_build_contract.py`, assert the required ignore entries and statically pin the Dockerfile final-stage `USER 10001:10001`, `EXPOSE 8000`, and `CMD ["ssh-over-mcp-server"]`. This test must run in ordinary CI without a Docker daemon.

- [ ] **Step 3: Create the multi-stage Dockerfile**

Use `python:3.13-slim-bookworm` for both builder and runtime stages.

Builder:
- copy only package metadata/source/docs needed to build the wheel;
- build the project and dependency wheels into `/wheels`.

Runtime:
- install exclusively from `/wheels` with no compiler toolchain;
- create fixed non-root default identity `10001:10001`;
- set `USER 10001:10001`;
- set a non-writable application working directory;
- expose/document container port 8000 without publishing it;
- use `ssh-over-mcp-server` as default command;
- embed no runtime config or secret.

Do not add sudo, ssh client config, Docker CLI/socket, shell wrapper privilege logic, or Cloudflare binaries.
- [ ] **Step 4: Build on the authorized Mac x86 Docker host and verify the live test is RED/GREEN**

Run:
```bash
docker build --platform linux/amd64 -t ssh-over-mcp:phase6a .
SSH_OVER_MCP_RUN_LIVE_CONTAINER=1 \
SSH_OVER_MCP_CONTAINER_IMAGE=ssh-over-mcp:phase6a \
python -m pytest -q tests/live/test_container_image.py
```

Expected final result: all live image assertions pass.

If Docker build/runtime exposes a defect, use `superpowers:systematic-debugging`, add/strengthen the failing assertion first, and make the smallest Dockerfile fix.

- [ ] **Step 5: Document the exact live probe**

Update `tests/live/README.md` with:
- prerequisite: authorized Linux/amd64-capable Docker host;
- the two commands above;
- explicit note that normal CI skips this probe because the hardened self-hosted runner intentionally has no Docker socket;
- expected security properties.

- [ ] **Step 6: Run normal regression checks**

```bash
python -m pytest -q tests/ops/test_container_build_contract.py tests/live/test_container_image.py
python -m ruff check tests/ops/test_container_build_contract.py tests/live/test_container_image.py
git diff --check
```

Expected: normal invocation skips only the opt-in live cases and remains green.

- [ ] **Step 7: Review Task 3 diff and commit**

Commit:
```bash
git add Dockerfile .dockerignore tests/ops/test_container_build_contract.py tests/live/test_container_image.py tests/live/README.md
git commit -m "Build: add hardened application image"
```
### Task 4: Document 6A and run whole-slice security review

**Files:**
- Modify: `docs/mcp-api.md`
- Modify: `docs/cloudflare-deployment.md`
- Modify production/tests only if review finds a concrete defect.

**Interfaces:**
- Consumes Tasks 1–3.
- Produces operator documentation for the new local origin boundary; no Cloudflare account procedure is added yet.

- [ ] **Step 1: Update MCP runtime documentation**

Document exactly:
- `SSH_OVER_MCP_BIND_HOST` default/allowed values;
- `SSH_OVER_MCP_ORIGIN_BEARER_TOKEN_FILE`;
- loopback compatibility;
- non-loopback startup dependency on origin bearer;
- `/mcp` bearer requirement when configured;
- unauthenticated bounded health/readiness;
- token never chooses profile.

- [ ] **Step 2: Update Cloudflare deployment document only to the 6A boundary**

Add:
- build/run image concept;
- origin bearer as Portal-to-origin credential;
- distinction from Access service token;
- statement that Compose/Tunnel/private-route commands arrive in 6B/6C.

Do not invent live-account steps before those slices.

- [ ] **Step 3: Whole-slice review against Phase 5 and 6A invariants**

Review exact diff from `89ab5db` through current head. Verify:
- no request-controlled profile/principal path;
- no ledger/admin/storage authority added to MCP;
- auth occurs before MCP parser;
- health/readiness remain bounded;
- server default remains loopback;
- non-loopback cannot start without token;
- no raw shell/destructive tool/public-port behavior introduced;
- image embeds no secret/config.
- [ ] **Step 4: Defect loop**

For every concrete Critical/Important finding:
1. invoke `superpowers:systematic-debugging`;
2. write a focused RED regression;
3. apply the smallest fix;
4. rerun targeted tests;
5. rerun full tests;
6. repeat review until no Critical/Important finding remains.

- [ ] **Step 5: Run fresh full local verification**

On the repository Python 3.13 environment:
```bash
python -m ruff check src tests
python -m compileall -q src tests
python -m pytest -q
git diff --check
```

Also rebuild and rerun the live image probe from Task 3 on the Mac x86 Docker host.

Expected: full suite green with only intentional live/platform skips; live container probe green.

- [ ] **Step 6: Commit documentation/review regressions**

```bash
git add docs/mcp-api.md docs/cloudflare-deployment.md
git add <only any focused review regression/fix files>
git commit -m "Docs: document Phase 6A origin image"
```

### Task 5: PR, exact-head CI, merge, and cleanup

**Files:**
- No planned product changes.
- Record closure evidence in the existing Phase 6 spec/progress convention only after exact implementation evidence exists.
**Interfaces:**
- Consumes the reviewed 6A branch.
- Produces an exact-head self-hosted CI record and clean merged main.

- [ ] **Step 1: Verify branch cleanliness and exact head**

Record:
```bash
git status --short
git rev-parse HEAD
git log --oneline --decorate 408f8ad..HEAD
```

No uncommitted product changes are allowed.

- [ ] **Step 2: Push a Phase 6A PR and require the existing self-hosted CI**

The authoritative workflow must still resolve to:
```text
runs-on: [self-hosted, linux, x64, ssh-over-mcp-mac-x86]
```

Do not add or use a GitHub-hosted runner.

Require exact PR-head Python 3.13/3.14 success.

- [ ] **Step 3: Perform final code/security review before merge**

Use `superpowers:requesting-code-review`. If no independent reviewer tool is available, perform a fresh whole-branch author review and explicitly record that limitation.

Any new Critical/Important finding returns to RED/GREEN before merge.

- [ ] **Step 4: Merge only when clean and verify merge-main exact-head CI**

After merge, record:
- merge-main SHA;
- authoritative CI run ID;
- CI `headSha` exactly equals merge-main SHA;
- conclusion is `success`.

Do not call 6A complete from PR-head CI alone.

- [ ] **Step 5: Clean Phase 6A branch/worktree safely**

Remove only merged/verified Phase 6A worktrees and branches; prune remote refs. Preserve the approved Phase 6 design/plan history on `main`.

Verify final root state:
```bash
git status --short --branch
git worktree list
git branch -vv
git branch -r
```

## Phase 6A completion gate

Phase 6A is complete only when Tasks 1–5 are checked, local live image evidence is green, full Python tests are green, exact merge-main self-hosted Python 3.13/3.14 CI is green, and no Critical/Important review finding remains.

Only then begin a fresh Superpowers planning cycle for Phase 6B private Compose.
