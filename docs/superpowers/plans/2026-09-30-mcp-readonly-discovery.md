# Phase 4 MCP Read-only Discovery Surface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the first Phase 4 MCP surface: server-owned principal injection, safe host discovery, sanitized policy explanation, Streamable HTTP at `/mcp`, and local health/readiness endpoints, with no SSH side effects.

**Architecture:** Add a pure repository-owned application layer under `ssh_over_mcp.api`, then adapt it to the official MCP Python SDK v2. The first slice is deliberately read-only and non-networking: MCP handlers obtain a server-owned principal, call `MCPService`, and never receive an SSH executor or connection manager. The HTTP app is built only after local config, policy, and principal validation succeed.

**Tech Stack:** Python 3.13+, Pydantic 2, official MCP Python SDK v2 (`mcp>=2,<3`), Starlette, Uvicorn, Pytest/Pytest-asyncio, Ruff.

**Spec:** `docs/superpowers/specs/2026-09-30-mcp-surface-design.md`

## Global Constraints

- MCP clients refer to hosts only by logical inventory alias.
- MCP tool schemas MUST NOT contain a trusted `profile` field, raw SSH address/port/user, credential reference, host key, or config path.
- The first slice MUST NOT create SSH connections or perform remote filesystem access.
- Static principal profile is operator/server configuration only and MUST exist in the loaded central policy before an app can be ready.
- Visible host = host exists and `allowed_roles` is empty or contains the exact principal profile.
- Unknown and role-hidden host aliases use one public `host is not visible` error class/message.
- `hosts_list` capabilities are empty in this slice; do not infer them from policy rules.
- `policy_explain` accepts only `ssh_exec`, `fs_stat`, `fs_read`, `fs_mkdir`, and `fs_write`; arbitrary tool strings fail before policy evaluation.
- `policy_explain` output MUST NOT include matched rule IDs, effective role inheritance, configured roots, credential references, host keys, or environment values.
- `/healthz` and `/readyz` are plain HTTP custom routes, never MCP tools.
- Use MCP SDK v2 public imports: `from mcp.server import MCPServer`; do not use `mcp.server.fastmcp`.
- Run Streamable HTTP with `stateless_http=True` and `json_response=True`.
- Until OAuth is implemented, the packaged server binds only to `127.0.0.1`; do not expose the static-principal server on a configurable public bind address.
- Destructive filesystem mutation and raw-shell MCP tools remain absent.
- Authoritative CI remains the hardened Ubuntu 26.04 x86 self-hosted runner; do not add GitHub-hosted runner jobs.

## Review Focus

1. Hidden-host oracle: an unknown alias and a role-hidden alias must produce the same public error from both `host_info` and `policy_explain`.
2. Principal override: MCP tool schemas and calls containing a synthetic `profile` argument must be rejected before service execution; the static provider remains authoritative.
3. Secret serialization: discovery and explanation structured outputs must contain none of `address`, `port`, `ssh_user`, `credential_ref`, `host_key`, `allowed_roles`, matched rule IDs, or environment values.
4. Lifecycle side effects: app construction, `/healthz`, and `/readyz` must not invoke any SSH/domain operation or depend on remote host reachability.
5. Malformed MCP calls: SDK argument validation must reject malformed/missing tool input before the corresponding `MCPService` method is invoked.

---

### Task 1: Add MCP v2 dependency and repository-owned principal/result models

**Files:**
- Modify: `pyproject.toml`
- Create: `src/ssh_over_mcp/api/errors.py`
- Create: `src/ssh_over_mcp/api/models.py`
- Create: `src/ssh_over_mcp/api/principal.py`
- Create: `tests/api/test_principal.py`

**Interfaces:**
- Consumes: `PolicyDocument.roles`.
- Produces:
  - `PrincipalContext(profile: str)`
  - `PrincipalProvider.get_principal() -> PrincipalContext`
  - `StaticPrincipalProvider(*, profile: str, policy: PolicyDocument)`
  - `ExplainableTool = Literal["ssh_exec", "fs_stat", "fs_read", "fs_mkdir", "fs_write"]`
  - `HostSummary(alias: str, labels: tuple[str, ...] = (), capabilities: tuple[str, ...] = ())`
  - `HostsListResult(hosts: tuple[HostSummary, ...])`
  - `PolicyExplainRequest(host: str, tool: ExplainableTool, executable: str | None = None, args: tuple[str, ...] = (), cwd: str | None = None, path: str | None = None, env: dict[str, str] = Field(default_factory=dict), privilege: str = "user")`
  - `PolicyExplainResult(decision: Decision, reason: str, risk: RiskLevel, normalized_executable: str | None, normalized_cwd: str | None, normalized_path: str | None, approval_required: bool, policy_version: str)`
  - `ApiError`, `PrincipalConfigurationError`, `HostNotVisibleError`, `InvalidExplainToolError`.

- [ ] **Step 1: Write failing principal/model tests**

In `tests/api/test_principal.py`, add tests asserting:

```python
def test_static_principal_provider_returns_server_owned_profile(policy):
    provider = StaticPrincipalProvider(profile="developer", policy=policy)
    assert provider.get_principal() == PrincipalContext(profile="developer")


def test_static_principal_provider_rejects_unknown_profile(policy):
    with pytest.raises(PrincipalConfigurationError):
        StaticPrincipalProvider(profile="missing", policy=policy)


def test_host_summary_contains_only_safe_fields():
    assert set(HostSummary.model_fields) == {"alias", "labels", "capabilities"}
```

Also assert extra fields are rejected by `PrincipalContext`, `HostSummary`, and policy-explain models.

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```bash
python -m pytest -q tests/api/test_principal.py
```

Expected: FAIL because `ssh_over_mcp.api.principal` / models do not exist.

- [ ] **Step 3: Add dependencies and implement the minimal models/provider**

In `pyproject.toml`, raise the existing Pydantic floor and add runtime dependencies:

```toml
"pydantic>=2.12,<3",
"mcp>=2,<3",
"starlette>=0.49.1,<1",
"uvicorn>=0.31.1,<1",
```

Add dev dependency:

```toml
"httpx>=0.28,<1",
```

Implement the interfaces listed above. All Pydantic models use `ConfigDict(extra="forbid", frozen=True)`; collection defaults use `Field(default_factory=...)`, not mutable literals.

`StaticPrincipalProvider.__init__` raises `PrincipalConfigurationError("configured principal profile is invalid")` unless `profile in policy.roles`.

- [ ] **Step 4: Run focused tests and Ruff**

Run:

```bash
python -m pytest -q tests/api/test_principal.py
python -m ruff check src/ssh_over_mcp/api tests/api/test_principal.py
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/ssh_over_mcp/api/errors.py src/ssh_over_mcp/api/models.py src/ssh_over_mcp/api/principal.py tests/api/test_principal.py
git commit -m "feat: add MCP principal and result models"
```

---

### Task 2: Implement pure MCPService discovery and policy explanation

**Files:**
- Create: `src/ssh_over_mcp/api/service.py`
- Create: `tests/api/test_service.py`

**Interfaces:**
- Consumes:
  - `PrincipalContext`, `HostSummary`, `HostsListResult`, `PolicyExplainRequest`, `PolicyExplainResult` from Task 1.
  - `Inventory`, `PolicyEngine.evaluate(EvaluationRequest) -> PolicyDecision`.
- Produces:
  - `MCPService(*, inventory: Inventory, policy: PolicyEngine)`
  - `MCPService.list_hosts(principal: PrincipalContext) -> HostsListResult`
  - `MCPService.get_host(principal: PrincipalContext, alias: str) -> HostSummary`
  - `MCPService.explain_policy(principal: PrincipalContext, request: PolicyExplainRequest) -> PolicyExplainResult`.

- [ ] **Step 1: Write failing visibility tests**

Create fixtures with:
- one host with empty `allowed_roles`;
- one host allowing `developer`;
- one host allowing only `ops`;
- distinct secret `address`, `ssh_user`, `credential_ref`, and `host_key` values.

Add:

```python
def test_list_hosts_returns_only_visible_safe_metadata(service, developer):
    result = service.list_hosts(developer)
    assert [host.alias for host in result.hosts] == ["open-host", "developer-host"]
    assert all(host.labels == () for host in result.hosts)
    assert all(host.capabilities == () for host in result.hosts)
    serialized = result.model_dump(mode="json")
    assert "credential_ref" not in repr(serialized)
    assert "host_key" not in repr(serialized)


@pytest.mark.parametrize("alias", ["missing-host", "ops-only-host"])
def test_get_host_hides_unknown_and_role_hidden_aliases(service, developer, alias):
    with pytest.raises(HostNotVisibleError, match="host is not visible"):
        service.get_host(developer, alias)
```

Sort aliases and labels deterministically.

- [ ] **Step 2: Write failing policy-explain tests**

Add tests proving:
- the `EvaluationRequest.profile` seen by `PolicyEngine` equals the injected principal;
- unknown/hidden host fails before `PolicyEngine.evaluate` is called;
- unrecognized tool input fails as `InvalidExplainToolError` (defense-in-depth even though the Pydantic/Literal model normally rejects it);
- allow, deny, and approval-required decisions map to `PolicyExplainResult`;
- `reason` is one of the stable public strings:
  - `"allowed by central policy"`
  - `"denied by central policy"`
  - `"approval required by central policy"`;
- the result model has no matched-rule/effective-role/capability/env fields.

- [ ] **Step 3: Run service tests and verify RED**

Run:

```bash
python -m pytest -q tests/api/test_service.py
```

Expected: FAIL because `MCPService` does not exist.

- [ ] **Step 4: Implement MCPService**

Visibility helper:

```python
def _is_visible(host: Host, profile: str) -> bool:
    return not host.allowed_roles or profile in host.allowed_roles
```

`list_hosts` returns visible hosts sorted by alias; both labels and capabilities
are always `()` in this slice because existing inventory labels are not yet
classified as public metadata.

`get_host` checks existence and visibility in one branch and raises exactly:

```python
HostNotVisibleError("host is not visible")
```

`explain_policy`:
1. calls the same visibility check before evaluation;
2. builds `EvaluationRequest` with `profile=principal.profile`;
3. calls `PolicyEngine.evaluate`;
4. maps the decision to the stable public reason above;
5. copies only risk, normalized caller-originated fields, approval flag, and policy version.

Do not call `policy.explain_decision()` because it intentionally contains matched rule IDs/effective roles/capabilities that the MCP surface must not expose.

- [ ] **Step 5: Run focused tests and full policy regression**

Run:

```bash
python -m pytest -q tests/api/test_service.py tests/policy
python -m ruff check src/ssh_over_mcp/api tests/api
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ssh_over_mcp/api/service.py tests/api/test_service.py
git commit -m "feat: add read-only MCP application service"
```

---

### Task 3: Register the three read-only MCP v2 tools

**Files:**
- Create: `src/ssh_over_mcp/api/server.py`
- Create: `tests/api/test_mcp_server.py`

**Interfaces:**
- Consumes:
  - `MCPService`
  - `PrincipalProvider.get_principal()`
  - Task 1 result models.
- Produces:
  - `build_mcp_server(*, service: MCPService, principal_provider: PrincipalProvider) -> MCPServer`.

- [ ] **Step 1: Write failing tool-registry/schema tests**

Use the official v2 in-process client:

```python
from mcp import Client
```

Build the server and assert `client.list_tools()` exposes exactly:

```python
{"hosts_list", "host_info", "policy_explain"}
```

For every tool, assert:
- annotations have `read_only_hint is True`;
- annotations have `open_world_hint is False`.

Assert `"profile"` is absent from every tool input schema.

Assert `policy_explain`'s tool schema restricts `tool` to the five `ExplainableTool` values.

- [ ] **Step 2: Write failing tool-call tests**

Using `async with Client(mcp) as client`:

- `hosts_list` returns structured output with only safe fields.
- `host_info` returns a visible host.
- hidden and unknown `host_info` calls both return tool errors with public text `"host is not visible"` and no secret alias metadata.
- `policy_explain` returns sanitized structured output.
- passing an extra `profile` argument is rejected by SDK argument validation before the service method runs.
- missing/malformed required arguments are rejected before service execution.

Use a recording fake service in the last two tests and assert its call count stays zero.

- [ ] **Step 3: Run tool tests and verify RED**

Run:

```bash
python -m pytest -q tests/api/test_mcp_server.py
```

Expected: FAIL because `build_mcp_server` does not exist.

- [ ] **Step 4: Implement MCPServer registration**

Use only v2 public APIs:

```python
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
```

Construct:

```python
mcp = MCPServer("ssh-over-mcp")
```

Register `hosts_list`, `host_info`, and `policy_explain` with:

```python
annotations=ToolAnnotations(
    read_only_hint=True,
    open_world_hint=False,
)
```

Each handler:
1. calls `principal_provider.get_principal()`;
2. calls one service method;
3. catches repository-owned `ApiError` subclasses and raises `ToolError` with only the stable public message.

Do not catch arbitrary `Exception`; unexpected failures should use the SDK's generic unexpected-tool error path rather than leaking exception text.

- [ ] **Step 5: Run focused MCP tests**

Run:

```bash
python -m pytest -q tests/api/test_mcp_server.py
python -m ruff check src/ssh_over_mcp/api tests/api
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ssh_over_mcp/api/server.py tests/api/test_mcp_server.py
git commit -m "feat: register read-only MCP discovery tools"
```

---

### Task 4: Add local Streamable HTTP lifecycle, health/readiness, and server entrypoint

**Files:**
- Create: `src/ssh_over_mcp/api/runtime.py`
- Create: `src/ssh_over_mcp/api/app.py`
- Create: `src/ssh_over_mcp/api/main.py`
- Modify: `pyproject.toml`
- Create: `tests/api/test_runtime.py`
- Create: `tests/api/test_http_app.py`

**Interfaces:**
- Consumes:
  - `load_config(path) -> ConfigBundle`
  - `PolicyEngine`
  - `StaticPrincipalProvider`
  - `MCPService`
  - `build_mcp_server`.
- Produces:
  - `MCPRuntimeSettings(config_path: Path, profile: str, port: int = 8000)`
  - `load_runtime_settings(env: Mapping[str, str]) -> MCPRuntimeSettings`
  - `build_application(settings: MCPRuntimeSettings) -> Starlette`
  - `main() -> None`.

- [ ] **Step 1: Write failing runtime-settings tests**

Environment contract:

- required: `SSH_OVER_MCP_CONFIG`
- required: `SSH_OVER_MCP_PROFILE`
- optional: `SSH_OVER_MCP_PORT`, default `8000`, valid range 1–65535
- bind host is not configurable in this phase; runtime constant is `127.0.0.1`.

Tests assert missing/blank required values and invalid port fail with one repository-owned runtime configuration error that does not echo unrelated environment variables.

- [ ] **Step 2: Write failing HTTP lifecycle tests**

Build an app from a valid temporary config and assert:

```python
client.get("/healthz").json() == {"status": "ok"}
client.get("/readyz").json() == {"status": "ready"}
```

Both return 200.

Assert app routes contain `/mcp`, `/healthz`, `/readyz`.

Assert MCP `tools/list` remains exactly the three Task 3 tools; health/readiness are not tools.

Build with an unknown static profile and assert construction raises `PrincipalConfigurationError`; there is no ready app.

Use a fake `MCPService` whose methods raise if called and verify `/healthz` and `/readyz` still return 200, proving lifecycle endpoints perform no domain/SSH operation.

- [ ] **Step 3: Run runtime/HTTP tests and verify RED**

Run:

```bash
python -m pytest -q tests/api/test_runtime.py tests/api/test_http_app.py
```

Expected: FAIL because runtime/app modules do not exist.

- [ ] **Step 4: Implement runtime settings and application composition**

`load_runtime_settings` reads only the three named variables above.

`build_application`:
1. loads `ConfigBundle`;
2. constructs `PolicyEngine`;
3. constructs `StaticPrincipalProvider` and fails if profile is invalid;
4. constructs `MCPService`;
5. constructs `MCPServer`;
6. registers unauthenticated custom routes:
   - `GET /healthz -> {"status": "ok"}`
   - `GET /readyz -> {"status": "ready"}`;
7. returns:
   ```python
   mcp.streamable_http_app(
       stateless_http=True,
       json_response=True,
       host="127.0.0.1",
   )
   ```.

Do not probe inventory hosts during construction or readiness.

- [ ] **Step 5: Implement the executable entrypoint**

In `src/ssh_over_mcp/api/main.py`:

```python
def main() -> None:
    settings = load_runtime_settings(os.environ)
    app = build_application(settings)
    uvicorn.run(app, host="127.0.0.1", port=settings.port)
```

Add:

```toml
ssh-over-mcp-server = "ssh_over_mcp.api.main:main"
```

under `[project.scripts]`.

- [ ] **Step 6: Run focused transport tests**

Run:

```bash
python -m pytest -q tests/api
python -m ruff check src/ssh_over_mcp/api tests/api
python -m compileall -q src tests
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml src/ssh_over_mcp/api tests/api
git commit -m "feat: add local Streamable HTTP MCP server"
```

---

### Task 5: Synchronize source-of-truth docs and run exact-head verification

**Files:**
- Modify: `docs/mcp-api.md`
- Modify: `docs/development-plan.md`
- Modify: `README.md` only if it currently has a server-start section that would otherwise become false.

**Interfaces:**
- Consumes: the completed Tasks 1–4.
- Produces: documented first Phase 4 slice and exact-head CI evidence.

- [ ] **Step 1: Update MCP API documentation**

Document that the implemented Phase 4 slice now provides:

- Streamable HTTP MCP at `/mcp`;
- `/healthz` and `/readyz`;
- static server-owned principal profile;
- `hosts_list`;
- `host_info`;
- `policy_explain`.

Explicitly state:
- no SSH connection occurs in these three tools;
- label and capability lists are empty in this slice;
- tool arguments cannot set profile or raw SSH connection fields;
- the packaged static-principal server binds to localhost only;
- OAuth remains deferred.

- [ ] **Step 2: Update development-plan status**

Mark only the discovery/explanation slice implemented. Keep `ssh_exec`, filesystem MCP adapters, OAuth, audit, approval persistence, and destructive filesystem mutation as future work.

- [ ] **Step 3: Run focused and full local gates**

Run:

```bash
python -m ruff check src tests
python -m compileall -q src tests
python -m pytest -q
```

Expected: PASS on a prepared development environment.

- [ ] **Step 4: Run authoritative self-hosted exact-head gate**

Use the existing trusted `self-hosted-security.yml` workflow with the exact feature branch head on the hardened Ubuntu 26.04 x86 ephemeral runner.

Required evidence:

- runner hardening preflight PASS;
- Ruff PASS;
- cgroup read-only probe PASS;
- Python 3.13 compileall + full pytest PASS;
- Python 3.14 compileall + full pytest PASS;
- no GitHub-hosted runner.

- [ ] **Step 5: Whole-branch security review**

Review the net diff against `main` and explicitly verify:

- no tool input contains trusted profile or SSH credential/coordinate fields;
- no first-slice code imports/constructs `SSHExecutor` or opens AsyncSSH;
- hidden hosts remain indistinguishable from missing hosts;
- no matched policy rule IDs/effective roles/secrets are serialized;
- `/healthz` and `/readyz` are not MCP tools;
- only `hosts_list`, `host_info`, and `policy_explain` are registered;
- no `fs_move`, `fs_delete`, `ssh_shell`, privileged helper, or destructive filesystem implementation is introduced;
- server bind host remains fixed to `127.0.0.1` while using `StaticPrincipalProvider`.

- [ ] **Step 6: Commit docs, open PR, merge only after clean review**

```bash
git add docs/mcp-api.md docs/development-plan.md README.md
git commit -m "docs: record Phase 4 discovery MCP surface"
```

Open the PR with exact-head self-hosted evidence. Merge only if the server-side net diff review finds no blocker. Delete the completed feature branch after merge.
