# ADR 0001: Policy-first SSH control plane

- Status: Accepted
- Date: 2026-09-26

## Context

The project must provide general host control to AI agents. A simple MCP wrapper around SSH would make the model effectively equivalent to a remote shell user and would not provide auditable, centrally managed authorization.

## Decision

All operations pass through a server-side policy engine. Policy is default-deny and deny-overrides-allow. Host identity and SSH credentials are server-owned. Managed hosts also enforce a second boundary through dedicated SSH accounts and a ForceCommand host agent.

## Consequences

- More implementation complexity than a direct shell wrapper.
- Policies become versioned security-critical configuration.
- The design supports multiple agents and trust levels without changing tool semantics.

## Security impact

Positive: reduces reliance on model behavior and limits blast radius of credential or control-plane compromise.
