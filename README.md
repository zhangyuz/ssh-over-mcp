# ssh-over-mcp

**Policy-enforced SSH remote control for MCP-compatible AI agents.**

`ssh-over-mcp` is a remote host control plane that exposes SSH-backed host administration capabilities through the Model Context Protocol (MCP). It is designed for ChatGPT, Claude, Cursor, autonomous agents, and other MCP clients while preserving server-side control over what each agent may do.

The project is intentionally **not** a thin wrapper around `/bin/bash`. Every operation is expected to pass through authentication, host inventory, role/policy evaluation, risk classification, optional approval, remote host enforcement, and audit logging.

## Current status

**Phase 3d2b2b2c1 — narrow containment-manager protocol.**

The bounded native execution path remains internally implemented, but remote
ForceCommand execution is still disabled.

ADR 0004 requires writable cgroup management to live outside the untrusted
workload privilege domain. This phase adds a versioned, bounded manager protocol
which exposes only:

- create scope;
- attach PID;
- kill all descendants;
- read accounting;
- close empty scope.

A create response returns an opaque 256-bit scope capability. Every subsequent
scope operation requires both the manager-owned scope identifier and that
capability. Message correlation is explicit, protocol types are strict, unknown
fields fail closed, and manager/backend exception details are not returned over
the protocol.

The current transport is **in-memory and test-only**. It validates the protocol
and adapter state machine but does not itself provide privilege separation.
A real local IPC/helper transport is the next increment.

**Remote command execution remains disabled in the ForceCommand CLI.**


## Documentation is the source of truth

The canonical specification lives in [`docs/`](docs/README.md). If code and documentation disagree, the documentation defines intended behavior until an explicit architecture decision changes it.

Start here:

- [Architecture](docs/architecture.md)
- [Security model](docs/security-model.md)
- [Threat model](docs/threat-model.md)
- [Policy specification](docs/policy-spec.md)
- [MCP API](docs/mcp-api.md)
- [Remote host agent](docs/ssh-host-agent.md)
- [Cloudflare deployment](docs/cloudflare-deployment.md)
- [Audit and approvals](docs/audit-and-approvals.md)
- [Development roadmap](docs/development-plan.md)
- [Self-hosted Docker runner](docs/self-hosted-runner.md)
- [Architecture decisions](docs/decisions/README.md)

Agents and contributors should also read [`AGENTS.md`](AGENTS.md).

## Security model in one paragraph

Policy is **default deny**. Allow rules define intended capability; deny rules override allows. The control plane never accepts arbitrary target addresses, usernames, SSH keys, or host keys from the model. Hosts come from server-side inventory. Structured command execution is preferred over shell strings. Raw shell is a separate privileged capability. Sensitive or high-risk actions can require short-lived, scope-bound approval. The remote host independently enforces restrictions using a dedicated SSH account, `ForceCommand`, OS permissions, and optional privileged helpers. The model is not a security boundary.

## Target architecture

```text
ChatGPT / Claude / Cursor / autonomous agents
                    |
             MCP Streamable HTTP
                    v
          Cloudflare MCP Portal
                    |
          Access Managed OAuth
        or Access Service Token
                    |
                    v
          Cloudflare Gateway
                    |
                    v
          Cloudflare Tunnel
                    |
                    v
      ssh-over-mcp control plane
                    |
         pinned-key SSH transport
                    v
          managed Linux hosts
```

## Python support

The package requires **Python 3.13 or newer**. CI explicitly validates the currently released stable series 3.13 and 3.14; newer Python feature releases are added to the validation matrix as they become stable.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

A loadable reference policy is in [`config/policy.example.yaml`](config/policy.example.yaml).

## Non-goals

The initial project does not aim to:

- replace SSH as a transport;
- expose unrestricted root access by default;
- accept arbitrary network targets from an LLM;
- treat command blacklists as the primary security boundary;
- rely on prompts or client-side confirmation as authorization;
- store long-lived host credentials in model-visible configuration.
