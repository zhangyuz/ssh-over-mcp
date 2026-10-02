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
Compose topology is documented below; Tunnel/private-route and Portal operator
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
deferred to Phase 6C.

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

## Phase 6B local private Compose reference

Phase 6B provides the local private deployment boundary before any live
Cloudflare account changes. Build the reference image first:

```bash
docker build --platform linux/amd64 -t ssh-over-mcp:phase6b .
```

Copy `deploy/compose/reference.env.example` to an operator-owned location
outside the repository and replace its placeholder values with absolute host
paths. The env file names paths only; secret bytes remain in mounted files.

Start the private origin with:

```bash
docker compose --env-file /absolute/path/reference.env \
  -f deploy/compose/compose.yaml up -d --wait mcp
```

The reference publishes **no host MCP port**. Readiness is checked by the
container healthcheck against `127.0.0.1:8000/readyz`; operators must not add
a temporary public port merely for health inspection.

Use the profile-gated ephemeral `approvalctl` service for approval
administration. Supported operator commands remain exactly `list`, `show`,
`grant`, and `deny`:

```bash
docker compose --env-file /absolute/path/reference.env \
  -f deploy/compose/compose.yaml --profile admin run --rm approvalctl <command>
```

A normal Ledger restart preserves the named data volume and therefore preserves
the HMAC key, approvals, and audit rows. `docker compose down -v` is
intentionally destructive: it deletes the named ledger volumes and must not be
used when state must be retained.

The numeric trust boundary is explicit:

- MCP runs as `10001:10003`;
- Ledger runs as `10002:10002`, with only supplementary socket groups
  `10003` and `10005`;
- `approvalctl` runs as `10004:10005`;
- MCP mounts only the read-only execution-socket volume;
- `approvalctl` mounts only the read-only admin-socket volume;
- only Ledger/bootstrap mount the DB/HMAC data volume.

Linux `SO_PEERCRED` still requires the exact configured UID/GID after the
filesystem socket permission check. Rootless Docker or user-namespace remapping
is not claimed equivalent until a live peer-identity proof validates the
kernel-visible IDs.

Cloudflare Tunnel, private-hostname routing, MCP Portal registration, and live
Access/Gateway changes remain Phase 6C work.
