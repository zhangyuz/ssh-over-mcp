# Cloudflare deployment

## Preferred topology

```text
MCP clients
    |
    | interactive: Managed OAuth
    | machine: Access service token
    v
Cloudflare MCP Portal
    |
Cloudflare Access
    |
Cloudflare Gateway
    |
private route
    |
Cloudflare Tunnel
    |
private ssh-over-mcp origin
```

## Portal

Use one MCP Portal endpoint for supported clients. The portal can curate which upstream tools are visible and provides a central access/logging layer.

## Interactive authentication

Managed OAuth is the preferred portal authentication mechanism for interactive MCP clients. The client completes an OAuth authorization-code flow through the user's browser rather than relying on a browser cookie redirect.

## Headless authentication

Autonomous agents and CI-style callers may use Cloudflare Access service tokens where portal/server policy permits. Service-token credentials are machine secrets and MUST NOT be exposed to the model.

## Phase 6A application image

Phase 6A provides the hardened application image and origin-authentication
boundary only. Build the Linux/amd64 reference image with:

```bash
docker build --platform linux/amd64 -t ssh-over-mcp:phase6a .
```

The image defaults to numeric non-root identity `10001:10001` and contains no
environment-specific policy, SSH credential, ledger HMAC key, or Cloudflare
credential. A direct container run still requires operator-mounted application
config, SSH key files, and the Security Ledger execution socket. The private
Compose topology arrives in Phase 6B; Tunnel/private-route and Portal operator
commands arrive in Phase 6C.

## Private origin

The MCP origin SHOULD remain private:

- no router port forwarding;
- no public origin hostname required;
- no Docker `ports:` publication unless an explicit local-only binding is needed;
- route the private hostname/IP through Cloudflare Tunnel;
- enable portal routing through Cloudflare Gateway for private MCP registration and use.

## Origin authentication

Phase 6A implements a static Portal-to-origin bearer boundary. Configure an
absolute mounted secret path in `SSH_OVER_MCP_ORIGIN_BEARER_TOKEN_FILE`; when
configured, `/mcp` accepts only `Authorization: Bearer <token>`. Binding the
server to `0.0.0.0` through `SSH_OVER_MCP_BIND_HOST` is rejected unless that
token-file setting is present. Health/readiness remain credential-free and
bounded.

This origin bearer is **not** a Cloudflare Access service token. The origin
bearer authenticates Portal-to-origin traffic. An Access service token
authenticates an approved headless client to Cloudflare Access/Portal. Neither
credential changes the server-owned `SSH_OVER_MCP_PROFILE`.

Private reachability alone is therefore never treated as caller
authentication. Portal/Tunnel configuration instructions are intentionally
deferred to Phases 6B/6C.

## Gateway

Gateway can be used for HTTP logging and DLP policies. These controls supplement, not replace, application policy.

## Protocol compatibility

The portal currently supports modern stateless MCP and earlier Streamable HTTP clients/upstreams. `ssh-over-mcp` should implement Streamable HTTP and track the current stable MCP SDK.

## Cloudflare is not the final authorization boundary

A portal allow policy answers who may reach the MCP service. The SSH control plane still decides which hosts/tools/commands/paths that caller profile can use.

## Deployment profiles

Phase 6A keeps one static server-owned profile per MCP process. Operators who
need materially different profiles deploy separate origin instances with
separate `SSH_OVER_MCP_PROFILE` values and origin credentials; the current
server does not multiplex caller-selected profiles behind paths such as
`/mcp/read` or `/mcp/admin`.

If true per-user authorization is required inside the origin, a later
user-aware authorization design must verify upstream identity rather than
trusting unverified identity headers.
