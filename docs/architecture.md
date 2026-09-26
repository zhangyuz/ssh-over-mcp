# Architecture

## Goal

Provide general-purpose remote Linux host control to MCP-compatible agents while keeping authorization and enforcement outside the model.

## System context

```text
Interactive MCP clients                 Headless agents
(ChatGPT, Claude, Cursor)               (CI, local Docker agents)
          |                                      |
   Managed OAuth                         Access service token
          +------------------+-------------------+
                             |
                             v
                   Cloudflare MCP Portal
                             |
                      Cloudflare Access
                             |
                     Cloudflare Gateway
                  logging / DLP / HTTP policy
                             |
                     private network route
                             |
                      Cloudflare Tunnel
                             |
                             v
                  ssh-over-mcp control plane
          +------------------+------------------+
          | MCP transport / tool layer          |
          | identity/profile resolver           |
          | host inventory                      |
          | policy engine                       |
          | risk + approval engine              |
          | SSH connection manager              |
          | audit pipeline                      |
          +------------------+------------------+
                             |
                   pinned-key SSH
                             |
            +----------------+----------------+
            |                                 |
         host A                            host B
      ForceCommand                      ForceCommand
       host agent                        host agent
            |                                 |
       OS controls                        OS controls
```

## Trust boundaries

### 1. MCP client boundary

The client and model are untrusted with respect to authorization. Tool descriptions help correct use but MUST NOT be the enforcement mechanism.

### 2. Cloudflare boundary

Cloudflare authenticates the portal client and can provide policy, logging, routing, and DLP. The origin MUST still enforce its own authorization profile and MUST authenticate portal-to-origin traffic when possible.

### 3. Control-plane boundary

The control plane owns:

- host aliases and addresses;
- SSH usernames;
- credentials/certificate issuance;
- pinned host keys;
- role and policy assignment;
- command and path policy;
- approvals;
- audit decisions.

Model arguments MUST NOT override this inventory.

### 4. SSH host boundary

The managed host independently restricts the SSH account. A compromise or policy bug in the MCP layer must not automatically imply unrestricted root access.

## Component responsibilities

### MCP API

Provides typed tools and validates schemas. It does not decide authorization alone.

### Identity/profile resolver

Maps the authenticated portal path, origin credential, explicit deployment profile, or upstream user identity to one or more server-side roles. No role is accepted from model input.

### Host inventory

Resolves a stable host alias such as `prod-web-01` into address, port, SSH principal, credential reference, pinned host key, labels, and capability profile.

Host aliases are restricted to a non-pattern-safe identifier character set so they can also be used as host-key lookup aliases.

### Policy engine

Evaluates tool, host, role, filesystem path, executable, arguments, environment, privilege level, and request context. Decision order is deny-first and default-deny.

### Risk and approval engine

Classifies allowed operations. High-risk actions may require a scope-bound approval artifact before execution.

### SSH connection manager

Maintains host-key-verified connections keyed by inventory alias.

It MUST:

- validate the pinned inventory host key;
- avoid implicit trust-on-first-use;
- avoid ambient SSH configuration and ssh-agent credentials;
- disable password, keyboard-interactive, host-based, and GSS authentication for the service connection;
- pool connections only within the same inventory host identity;
- expire pooled connections after a configured maximum age;
- bound concurrent sessions per host.

### Structured SSH executor

Obtains an allow decision before opening the transport, creates the versioned request frame, invokes only the fixed `mcp-v1` remote command, and applies client-side timeout/input/output limits.

### Remote host agent

Runs under `ForceCommand` and validates an authenticated structured request. It independently enforces host-local rules and uses `execve`-style execution for structured commands.

### Privileged helper

Optional minimal root component for narrowly defined operations such as restarting approved services. It MUST NOT expose a generic `sudo <command>` interface to normal roles.

## Data flow: structured command

```text
tools/call ssh_exec
      |
      v
schema validation
      |
identity/profile + host inventory
      |
policy evaluation
      |
risk/approval evaluation
      |
audit decision event
      |
fixed SSH command: mcp-v1
      |
binary framed request on stdin
      |
remote ForceCommand agent
      |
remote policy / OS authorization
      |
execve(executable, argv, env)
      |
stdout/stderr/exit status
      |
audit completion event
      |
MCP response
```

## Data flow: raw shell

Raw shell is a distinct privileged capability. It MUST NOT be silently selected as a fallback when structured execution is denied. Policy should normally require an administrative or break-glass role plus short-lived approval.
