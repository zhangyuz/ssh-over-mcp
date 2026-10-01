# MCP Surface Design

Date: 2026-09-30

Status: implemented; final surface review verified 2026-10-01

## 1. Purpose

Phase 3 established the trusted remote-host boundary:

- server-side inventory and central policy evaluation;
- pinned SSH host identity and pooled SSH transport;
- structured `ssh_exec`;
- ForceCommand enforcement through SMCP v1;
- workload identity transition and cgroup containment;
- descriptor-pinned read-only filesystem operations;
- create-only `fs_mkdir` and `fs_write` with real Linux adversarial proof.

Phase 4 adds the MCP-facing application surface.

The MCP layer is an adapter over those existing boundaries. It MUST NOT become a
second policy engine, a generic shell gateway, a credential carrier, or a bypass
around host-agent enforcement.

The first implementation slice establishes transport, server-owned identity,
health/readiness, discovery, and policy explanation before any MCP tool can
cause an SSH side effect.

## 2. Design goals

Phase 4 must provide:

1. Streamable HTTP MCP at `/mcp` using the official MCP Python SDK rather than
   hand-written MCP/JSON-RPC framing;
2. health and readiness endpoints outside the MCP tool surface;
3. a server-owned principal/profile boundary which client tool arguments cannot
   override;
4. a small application/service layer between MCP SDK handlers and existing
   inventory, policy, and SSH components;
5. bounded typed tool inputs and outputs;
6. no client-supplied SSH address, username, credential reference, host key, or
   policy profile;
7. exact preservation of the Phase 3 host-agent enforcement boundary;
8. a tool-by-tool rollout in independently reviewable slices.

## 3. Non-goals

Phase 4 does not implement:

- Cloudflare Access Managed OAuth;
- MCP Portal or Cloudflare Tunnel deployment;
- audit persistence or approval storage;
- raw-shell enablement for normal profiles;
- destructive filesystem namespace mutation;
- a generic privileged helper;
- client-selected credentials or arbitrary SSH targets;
- policy hot-reload;
- host runtime probing merely to make discovery richer;
- a second execution or filesystem implementation inside the MCP process.

OAuth/Portal integration belongs to the later Cloudflare phase. Audit and
approval persistence belong to Phase 5.

## 4. Architectural layers

The dependency direction is one-way:

```text
MCP SDK / HTTP transport
        |
        v
MCP tool adapters
        |
        v
MCPService + PrincipalContext
        |
        +--> Inventory
        +--> PolicyEngine
        +--> SSHExecutor / future filesystem SSH adapters
                         |
                         v
                    SMCP v1
                         |
                         v
                   host-agent
```

No inventory, policy, SSH, or host-agent module imports MCP SDK types.

### 4.1 Transport layer

The transport layer owns:

- MCP protocol negotiation;
- Streamable HTTP exposure at `/mcp`;
- request-context integration with the principal provider;
- process lifecycle;
- `/healthz` and `/readyz`.

It does not evaluate policy and does not construct SSH destinations from request
data.

### 4.2 MCP tool adapter layer

Each tool adapter:

1. obtains a trusted `PrincipalContext` from the server;
2. validates its typed MCP arguments;
3. calls exactly one `MCPService` operation;
4. maps the typed application result or application error to the MCP SDK.

Adapters contain no policy rules and no SSH protocol logic.

### 4.3 MCPService layer

`MCPService` is the application boundary for MCP-facing operations.

It receives existing domain components through dependency injection. It returns
repository-owned Pydantic/result models, never MCP SDK objects.

The service is responsible for:

- host visibility filtering;
- building central `EvaluationRequest` values using the trusted principal;
- calling `PolicyEngine`;
- later delegating allowed execution/filesystem operations to existing SSH/SMCP
  components;
- sanitizing discovery and explanation results.

It does not reimplement host-agent policy.

## 5. Principal and authentication boundary

MCP tool arguments MUST NOT contain a trusted `profile` field.

A principal is represented by a repository-owned value such as:

```text
PrincipalContext(profile: str)
```

The profile comes only from a `PrincipalProvider`.

### 5.1 Phase 4 static provider

Before OAuth integration, Phase 4 uses an operator-configured
`StaticPrincipalProvider`.

Requirements:

- the profile value is supplied by deployment/server startup configuration;
- it is not read from an MCP tool argument, query parameter, arbitrary client
  header, or request body field;
- startup fails closed if the configured profile does not exist in the loaded
  central policy;
- one static provider instance may be used for local development and dedicated
  integration tests.

This is a temporary authentication adapter, not a statement that a shared
production endpoint may trust all callers as one role.

### 5.2 Future OAuth provider

The later Cloudflare phase may replace the static provider with a provider which
maps verified identity claims to a profile through server-owned configuration.

That replacement must not change tool schemas or service authorization
semantics.

## 6. Server lifecycle and endpoints

The server exposes:

- `/mcp` — Streamable HTTP MCP;
- `/healthz` — process liveness;
- `/readyz` — local readiness.

`/healthz` returns success when the server process and HTTP stack are alive.

`/readyz` returns success only after:

- configuration is loaded and validated;
- `PolicyEngine` is constructed;
- the principal provider is valid;
- MCP service/tool registration is complete.

Readiness MUST NOT establish SSH sessions, enumerate remote filesystem state,
or require every inventory host to be online. Remote host availability is an
operation-level concern, not a process-readiness requirement.

Health/readiness endpoints are ordinary HTTP endpoints and MUST NOT appear in
the MCP tool registry.

The server MUST use the SDK's stateless Streamable HTTP mode when that mode is
available in the selected stable SDK version. If the SDK requires protocol
session state, that state is transport-only and MUST NOT become an
authorization source.

## 7. Configuration and secrets

The existing `ConfigBundle` remains the authority for inventory and central
policy.

Phase 4 runtime configuration additionally supplies transport/runtime settings
and the static principal profile. These values are operator-owned.

MCP clients may refer to a host only by logical inventory alias.

The following MUST NOT be accepted from MCP tool arguments:

- SSH address;
- SSH port override;
- SSH username;
- credential reference;
- host key;
- central-policy profile;
- local config path.

Credential material remains behind the existing server-side connection
boundary.

## 8. Host visibility

A host is discoverable to a principal only when all of the following hold:

1. the principal profile exists in central policy;
2. the host exists in server-side inventory;
3. the host's `allowed_roles` is empty or contains the principal profile.

This visibility rule is intentionally narrower than “present in inventory” and
simpler than attempting to prove a general operation-specific allow decision.

Visibility is not authorization to perform any specific operation. Every
operation which can act on a host still receives its own central policy
evaluation.

Unknown and non-visible aliases MUST produce the same public not-visible error
class so callers cannot distinguish “does not exist” from “exists but is hidden.”

## 9. Discovery result safety

### 9.1 `hosts_list`

The first implementation returns only the logical host alias. Existing
inventory labels are operator metadata but are not classified as public, so the
first slice returns an empty label list rather than assuming they are safe. It
also returns an empty capability list.

Discovery MUST NOT expose:

- address;
- SSH username;
- credential reference;
- host key;
- role allowlists;
- policy rule identifiers.

Label and capability advertisement are informational only and are never
authorization decisions. A later slice may populate either only from separately
reviewed server-owned public metadata; it MUST NOT expose raw inventory labels
or guess capability from partial policy-rule inspection.

### 9.2 `host_info`

The initial `host_info` implementation is static and non-networking.

It returns the same alias-only public identity for one visible host. Labels or
other metadata may be added only after they have an explicit public-data
contract.

It does not open SSH merely to provide “runtime information.” A future runtime
probe requires its own bounded design and policy decision.

## 10. `policy_explain`

`policy_explain` evaluates a hypothetical central-policy request without
executing it.

Inputs may describe the proposed operation:

- host alias;
- tool name;
- executable/argv/cwd when relevant;
- path when relevant;
- environment variable names/values only to the extent required by the existing
  policy model;
- requested privilege where supported.

The profile is always injected from `PrincipalContext`.

Before policy evaluation, the service applies the same host-visibility check as
`host_info`. Unknown and role-hidden hosts return the same not-visible error,
so `policy_explain` cannot be used as a hidden-inventory oracle.

The requested tool name is validated against the server's recognized MCP/domain
tool identifiers. Arbitrary tool strings are rejected as invalid input rather
than passed through to policy matching.

The tool returns a sanitized explanation containing only values safe for the
caller, such as:

- allow / deny / approval-required;
- generic reason;
- risk;
- normalized executable/cwd/path when those values originated from the caller;
- whether approval would be required;
- policy version.

It MUST NOT expose:

- matched rule identifiers;
- hidden role inheritance;
- configured policy roots;
- credential/host-key data;
- secrets from environment values.

A denied hypothetical request is a normal explanation result, not an execution
error.

`policy_explain` never opens an SSH connection.

## 11. First implementation slice

The first Phase 4 implementation slice contains only:

- MCP server/application skeleton;
- official SDK Streamable HTTP mount at `/mcp`;
- `/healthz`;
- `/readyz`;
- `PrincipalContext` and `StaticPrincipalProvider`;
- `MCPService`;
- `hosts_list`;
- `host_info`;
- `policy_explain`.

No tool in this slice creates an SSH connection.

This slice establishes the external schema and identity boundary before
side-effecting tools are introduced.

## 12. Later tool rollout

After the first slice is reviewed and merged, add tools in separate slices:

1. `ssh_exec`;
2. read-only `fs_stat` / `fs_read`;
3. create-only `fs_mkdir`;
4. create-only `fs_write`;
5. other documented process/service/log/metric tools only after their host-side
   enforcement boundaries exist.

`fs_move` and `fs_delete` remain unavailable because Phase 3e explicitly
deferred destructive namespace mutation.

`ssh_shell` remains disabled by default and is not part of the first normal
MCP execution surface.

## 13. Execution adapter rules

When `ssh_exec` is added:

- the MCP request uses host alias, executable, args, cwd, bounded environment,
  stdin, and timeout fields;
- the service injects the trusted profile;
- central `PolicyEngine` evaluates the request before any network access;
- the existing `SSHExecutor` performs the SSH/SMCP operation;
- no shell fallback is allowed;
- MCP timeout/output fields may only tighten server-owned defaults, never
  disable bounds.

The MCP layer does not translate structured execution into a shell command.

## 14. Filesystem adapter rules

When filesystem tools are added:

- the service injects the trusted profile;
- central policy evaluates the logical MCP operation;
- the SSH adapter sends the already-defined typed SMCP filesystem envelope;
- host-agent policy and descriptor-pinned/create-only enforcement remain
  independently authoritative.

The MCP layer never implements local pathname resolution for remote paths.

For `fs_write`, the Phase 3 committed/durability-uncertain outcome remains
distinct. The MCP mapping MUST preserve that “committed; do not blindly retry”
semantics rather than convert it into a generic retryable transport error.

## 15. Error model

Repository-owned application errors are mapped to stable public categories:

- invalid request;
- principal unavailable/invalid;
- host not visible;
- policy denied;
- approval required;
- SSH transport failure;
- host-key failure;
- remote policy denied;
- timeout;
- output truncated;
- execution failure;
- committed/durability-uncertain write outcome.

Public errors MUST NOT include:

- credential references;
- host keys;
- secret values;
- configured hidden hosts;
- policy rule identifiers;
- raw remote exception representations.

Transport/library exceptions are normalized at the adapter boundary.

## 16. MCP annotations

Where supported by the SDK/client ecosystem:

- `hosts_list`, `host_info`, and `policy_explain` are marked read-only and
  non-destructive;
- `fs_stat` / `fs_read` are read-only;
- `fs_mkdir` / `fs_write` are not read-only and are described accurately as
  create-only.

Annotations are client hints only. They are never authorization controls.

## 17. Security invariants

Phase 4 must preserve all of the following:

1. client input never selects the trusted profile;
2. client input never selects raw SSH connection coordinates or credentials;
3. no MCP handler can bypass central `PolicyEngine` for an operation requiring
   central policy;
4. no side-effecting operation reaches SSH before central policy allows it;
5. remote host-agent enforcement remains independently authoritative;
6. no structured denial falls back to raw shell;
7. discovery does not leak hidden inventory or credential/host-key fields;
8. health/readiness does not probe remote hosts;
9. MCP session state is not trusted as an authorization database;
10. destructive filesystem mutation remains absent.

## 18. Required tests

Before the first slice may merge, tests must prove:

### Principal boundary

- tool schemas do not contain a profile override;
- static principal is injected server-side;
- unknown static profile makes server construction fail closed and can never
  produce a ready server;
- changing request metadata cannot change the principal.

### Discovery

- visible hosts are listed;
- role-hidden hosts are omitted;
- unknown and hidden aliases have indistinguishable public failure class;
- address, SSH user, credential reference, host key, and role allowlists are not
  serialized;
- discovery performs no SSH/network call.

### Policy explanation

- uses the injected profile;
- allow, deny, and approval-required are represented as data;
- matched rule IDs and secret inventory fields are absent;
- explanation performs no SSH/network call.

### Transport/lifecycle

- MCP is mounted only at `/mcp`;
- health/readiness are not MCP tools;
- readiness fails when local configuration/principal initialization fails;
- readiness does not depend on remote host availability;
- malformed tool inputs fail before domain execution.

### Regression

- existing policy, SSH, host-agent, containment, and filesystem suites remain
  green on Python 3.13 and 3.14;
- hardened self-hosted Ubuntu 26.04 x86 runner remains the authoritative CI
  evidence;
- GitHub-hosted runners are not required.

## 19. Implementation order

Implement Phase 4 in reviewable slices:

1. application result/error models, `PrincipalContext`,
   `StaticPrincipalProvider`, and pure `MCPService` discovery/explain methods;
2. MCP SDK transport/application lifecycle, `/mcp`, `/healthz`, `/readyz`,
   and registration of the three read-only tools;
3. `ssh_exec` MCP adapter;
4. `fs_stat` / `fs_read` MCP adapters;
5. `fs_mkdir` MCP adapter;
6. `fs_write` MCP adapter with committed-outcome preservation;
7. final Phase 4 surface review.

Each slice follows RED -> GREEN -> self-hosted verification -> code review ->
merge. Completed feature branches are deleted after merge.

## 20. Evidence required to close Phase 4

Phase 4 may be marked implemented only after one exact main commit proves:

- Streamable HTTP MCP works at `/mcp`;
- health/readiness remain outside the tool surface;
- trusted profile cannot be client-overridden;
- discovery does not expose hidden hosts or secret connection metadata;
- central policy runs before every side-effecting SSH operation;
- host-agent policy remains independently enforced;
- create-only filesystem semantics survive MCP mapping;
- no destructive filesystem or raw-shell bypass is introduced;
- Python 3.13/3.14 full suites pass on the hardened Ubuntu 26.04 x86
  self-hosted runner.

Final Phase 4 review evidence:

- exact implementation commit:
  `79a3ebd6ed5e06b32ac1f152e3dc5b21e3ee9f5e`;
- authoritative self-hosted workflow run `36864606963`: success;
- registered MCP surface is exactly `hosts_list`, `host_info`,
  `policy_explain`, `ssh_exec`, `fs_stat`, `fs_read`, `fs_mkdir`, and
  `fs_write`;
- health/readiness remain outside the tool registry;
- no `ssh_shell`, `fs_move`, or `fs_delete` MCP handler is registered;
- central-policy-before-network and host-agent independent enforcement are
  covered by the merged side-effecting tool tests;
- create-only mkdir/write semantics and the distinct fs_write committed/
  durability-uncertain outcome survive the MCP mapping.

No Critical or Important finding remained in the final whole-surface review.

## 21. Deferred work

Explicitly deferred:

- OAuth/claim-to-profile mapping;
- approval persistence and single-use approvals;
- audit storage/query implementation;
- Cloudflare Portal/Tunnel/Gateway deployment;
- destructive namespace mutation;
- generic privileged helper;
- dynamic runtime host telemetry.

Those items require their own later-phase design/review and must not be smuggled
into Phase 4 as transport conveniences.
