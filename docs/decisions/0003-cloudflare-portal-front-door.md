# ADR 0003: Cloudflare MCP Portal as preferred front door

- Status: Accepted
- Date: 2026-09-26

## Context

The MCP service must be usable by interactive clients and autonomous agents from arbitrary locations while keeping the origin private.

## Decision

Use Cloudflare MCP Portal as the preferred client endpoint, Access Managed OAuth for interactive clients, Access service tokens for approved machine clients, Gateway for routing/logging/DLP where appropriate, and Cloudflare Tunnel/private routing to the MCP origin.

The origin retains its own policy enforcement and should authenticate upstream requests; Cloudflare reachability alone is not sufficient authorization.

## Consequences

- Clients receive one managed endpoint.
- The origin need not expose a public listening port.
- Cloudflare configuration becomes part of deployment but not the sole authorization boundary.

## Security impact

Positive: reduces origin exposure and centralizes identity/routing/observability while preserving application-layer policy.
