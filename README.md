# ssh-over-mcp

**Policy-enforced SSH remote control for MCP-compatible AI agents.**

`ssh-over-mcp` is a remote host control plane that exposes SSH-backed host administration capabilities through the Model Context Protocol (MCP). It is designed for ChatGPT, Claude, Cursor, autonomous agents, and other MCP clients while preserving server-side control over what each agent may do.

The project is intentionally **not** a thin wrapper around `/bin/bash`. Every operation is expected to pass through authentication, host inventory, role/policy evaluation, risk classification, optional approval, remote host enforcement, and audit logging.

## Current status

**Phase 3d2b1 — forked child supervisor skeleton.**

Implemented through the current development branch:

- central default-deny policy and server-owned host inventory;
- pinned-key SSH transport and host-local canonical authorization;
- fd-pinned native ELF execution primitive with explicit argv/environment;
- parent-side native spec validation before fork;
- three close-on-exec stdio pipes;
- child `setsid()` session/process-group isolation;
- blocked-signal mask cleared and catchable signals reset to defaults;
- child `umask 077`;
- core dumps disabled with `RLIMIT_CORE=0`;
- stdin/stdout/stderr installed with `dup2()`;
- unrelated descriptors closed before exec while preserving only stdio + pinned executable/cwd fds;
- fixed generic child-failure message and exit code 125;
- parent receives PID plus stdin/stdout/stderr pipe handles;
- real native `cat` integration coverage for stdin/stdout and exit handling.

**Remote command execution is still disabled in the ForceCommand CLI.** Timeout, output ceilings, kill escalation, and execution-result framing are not implemented yet.


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
