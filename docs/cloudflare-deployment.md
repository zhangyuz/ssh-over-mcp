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

## Private origin

The MCP origin SHOULD remain private:

- no router port forwarding;
- no public origin hostname required;
- no Docker `ports:` publication unless an explicit local-only binding is needed;
- route the private hostname/IP through Cloudflare Tunnel;
- enable portal routing through Cloudflare Gateway for private MCP registration and use.

## Origin authentication

Cloudflare access to the MCP origin SHOULD use an origin credential or upstream auth mode supported by the Portal. The origin should not assume that private network reachability alone authenticates callers.

## Gateway

Gateway can be used for HTTP logging and DLP policies. These controls supplement, not replace, application policy.

## Protocol compatibility

The portal currently supports modern stateless MCP and earlier Streamable HTTP clients/upstreams. `ssh-over-mcp` should implement Streamable HTTP and track the current stable MCP SDK.

## Cloudflare is not the final authorization boundary

A portal allow policy answers who may reach the MCP service. The SSH control plane still decides which hosts/tools/commands/paths that caller profile can use.

## Deployment profiles

For a simple deployment where end-user identity is not propagated to the origin, separate upstream profiles MAY be exposed, for example:

```text
/mcp/read
/mcp/dev
/mcp/ops
/mcp/admin
```

Each endpoint maps to a server-side policy profile and a distinct origin credential. Portal Access policy determines which upstream profile a user or service token may reach.

If true per-user authorization is required inside the origin, the upstream MCP service should implement an appropriate user-aware authorization design rather than trusting unverified identity headers.
