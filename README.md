# ssh-over-mcp

**Policy-enforced SSH remote control for MCP-compatible AI agents.**

`ssh-over-mcp` is a remote host control plane that exposes SSH-backed host administration capabilities through the Model Context Protocol (MCP). It is designed for ChatGPT, Claude, Cursor, autonomous agents, and other MCP clients while preserving server-side control over what each agent may do.

The project is intentionally **not** a thin wrapper around `/bin/bash`. Every operation is expected to pass through authentication, host inventory, role/policy evaluation, risk classification, optional approval, remote host enforcement, and audit logging.

## Current status

**Phase 3d2b2b2c0 — containment privilege separation.**

The bounded native runner now uses request-scoped cgroup-v2 containment, but
remote ForceCommand execution remains disabled.

The current security review identified a post-attach escape condition: Linux
cgroup-v2 delegation prevents a delegatee from escaping the outer delegated
subtree, but a workload sharing the manager's migration authority can still
move between cgroups inside that subtree. Moving from a request scope back to
the delegated root would bypass request-specific limits and request-scoped
`cgroup.kill`.

ADR 0004 therefore requires writable cgroup management to move into a separate,
narrow containment-manager privilege domain. The existing start barrier and
bounded execution logic remain, but the child will not be released until the
manager confirms attachment and the workload must not inherit manager authority.

**Remote command execution is still disabled in the ForceCommand CLI.**


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
