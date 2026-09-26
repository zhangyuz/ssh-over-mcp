# ssh-over-mcp

**Policy-enforced SSH remote control for MCP-compatible AI agents.**

`ssh-over-mcp` is a remote host control plane that exposes SSH-backed host administration capabilities through the Model Context Protocol (MCP). It is designed for ChatGPT, Claude, Cursor, autonomous agents, and other MCP clients while preserving server-side control over what each agent may do.

The project is intentionally **not** a thin wrapper around `/bin/bash`. Every operation is expected to pass through authentication, host inventory, role/policy evaluation, risk classification, optional approval, remote host enforcement, and audit logging.

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
         logging / DLP / policy
                    |
                    v
          Cloudflare Tunnel
                    |
                    v
      ssh-over-mcp control plane
   +--------------------------------+
   | MCP API                        |
   | identity/profile resolution    |
   | host inventory                 |
   | RBAC + policy engine           |
   | allow/deny evaluation          |
   | risk + approval engine         |
   | SSH connection manager         |
   | audit logger                   |
   +---------------+----------------+
                   | SSH
                   v
          managed Linux hosts
   +--------------------------------+
   | dedicated SSH account          |
   | ForceCommand host agent        |
   | host-local policy              |
   | OS ACL / sudo / sandbox        |
   +--------------------------------+
```

## Security model in one paragraph

Policy is **default deny**. Allow rules define the intended capability; deny rules override allows. The control plane never accepts arbitrary target addresses, usernames, SSH keys, or host keys from the model. Hosts come from server-side inventory. Structured command execution is preferred over shell strings. Raw shell is a separate privileged capability. Sensitive or high-risk actions can require short-lived, scope-bound approval. The remote host independently enforces restrictions using a dedicated SSH account, `ForceCommand`, OS permissions, and optional privileged helpers. The model is not a security boundary.

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
- [Architecture decisions](docs/decisions/README.md)

Agents and contributors should also read [`AGENTS.md`](AGENTS.md).

## Planned repository layout

```text
ssh-over-mcp/
├── README.md
├── AGENTS.md
├── pyproject.toml
├── docs/
│   ├── README.md
│   ├── architecture.md
│   ├── security-model.md
│   ├── threat-model.md
│   ├── policy-spec.md
│   ├── mcp-api.md
│   ├── ssh-host-agent.md
│   ├── cloudflare-deployment.md
│   ├── audit-and-approvals.md
│   ├── development-plan.md
│   ├── references.md
│   └── decisions/
├── src/ssh_over_mcp/
│   ├── api/
│   ├── policy/
│   ├── ssh/
│   ├── audit/
│   └── approvals/
├── remote/host_agent/
├── config/
├── tests/
└── .github/
```

## Protocol direction

The remote MCP endpoint should use **Streamable HTTP**. The preferred implementation target is the current stateless MCP protocol revision supported by the selected SDK and Cloudflare MCP Portal, while preserving compatibility with earlier Streamable HTTP clients where practical.

## Non-goals

The initial project does not aim to:

- replace SSH as a transport;
- expose unrestricted root access by default;
- accept arbitrary network targets from an LLM;
- treat command blacklists as the primary security boundary;
- rely on prompts or client-side confirmation as authorization;
- store long-lived host credentials in model-visible configuration.

## Status

**Architecture/specification phase.** The repository structure and source-of-truth documents are established first; implementation follows the roadmap in [`docs/development-plan.md`](docs/development-plan.md).
