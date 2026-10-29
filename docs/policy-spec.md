# Policy specification

## Goals

The policy language must support general remote administration without turning every MCP caller into an unrestricted SSH user.

## Evaluation order

For a request `R`:

1. resolve server-side identity/profile;
2. resolve host alias from inventory;
3. verify role is allowed on host;
4. verify MCP tool/capability;
5. canonicalize request fields relevant to policy;
6. evaluate explicit deny rules;
7. evaluate explicit allow rules;
8. classify risk;
9. verify required approval;
10. produce an immutable decision record;
11. execute.

If no allow rule matches, the result is deny.

## Policy dimensions

Policies may match:

- profile/role;
- host alias and host labels;
- MCP tool;
- operation type;
- filesystem path;
- executable canonical path;
- executable class/capability;
- subcommand;
- argv patterns;
- working directory;
- allowed environment names and values;
- requested PTY;
- privilege level;
- network class;
- risk level;
- time/TTL constraints;
- approval state.

## Example

```yaml
version: 1

default: deny

roles:
  observer:
    hosts:
      include_labels: [linux]
    tools:
      allow:
        - hosts_list
        - host_info
        - fs_list
        - fs_stat
        - fs_read
        - process_list
        - service_status
        - logs_read
        - ssh_exec
    filesystem:
      read:
        allow:
          - /srv/projects/**
          - /var/log/**
        deny:
          - /srv/projects/**/.env
          - /srv/projects/**/.env.*
          - /srv/projects/**/secrets/**
          - /etc/shadow
          - /root/**
    exec:
      allow:
        - executable: /usr/bin/ls
        - executable: /usr/bin/stat
        - executable: /usr/bin/df
        - executable: /usr/bin/journalctl
          argv:
            allow:
              - ["--no-pager", "-u", "${SERVICE}"]
      deny:
        - capability: shell
        - capability: interpreter
    shell: false
    sudo: false

  developer:
    inherits: [observer]
    filesystem:
      write:
        allow:
          - /srv/projects/**
        deny:
          - /srv/projects/**/.git/**
          - /srv/projects/**/.ssh/**
    exec:
      allow:
        - executable: /usr/bin/git
          subcommands: [status, diff, log, fetch, pull, checkout]
        - executable: /usr/bin/npm
        - executable: /usr/bin/node
        - executable: /usr/bin/python3
    shell: false
    sudo: false

  operator:
    tools:
      allow:
        - service_status
        - service_action
        - logs_read
        - ssh_exec
    services:
      allow:
        - webapp.service
        - worker.service
      deny:
        - ssh.service
        - sshd.service
        - cloudflared.service
    shell: false
    sudo_profile: service_ops

  admin:
    tools:
      allow: ["*"]
    shell: true
    approvals:
      required_for:
        - raw_shell
        - root
        - destructive
```

## Phase 1 implemented schema

The Phase 1 implementation now defines the strict configuration schema in `src/ssh_over_mcp/policy/models.py` and `src/ssh_over_mcp/inventory/models.py`.

A versioned policy contains:

- `roles`: named `RoleSpec` objects with inheritance, environment allow/deny patterns, and explicit `shell` / `sudo` capability flags;
- `rules`: ordered-independent allow/deny rules with unique IDs;
- `risk.approval_required`: risk levels requiring approval before execution.

The policy digest (`policy_version`, `sha256:` over the canonical JSON dump of
the policy) MUST be identical in every process that loads the same policy.
Approval bindings, audit records and remotely pinned v5 host visibility trust
(`central_policy_sha256`) compare it across processes and hosts, so set-valued
fields such as `risk.approval_required` serialize in sorted order; they must
never depend on `PYTHONHASHSEED` or other per-process iteration order.

A rule may constrain roles, host aliases, required host labels, MCP tools, executable paths, executable capability classes, argv prefix, working-directory patterns, filesystem-path patterns, and privilege level.

The implementation evaluates **all matching rules**. Any matching deny wins. At least one allow must match or the request is denied.

Host membership is evaluated against the explicitly requested server-side profile. Role inheritance grants inherited policy rules; it does **not** implicitly grant a child role access to hosts which only list its parent role.

Requests cannot assert that approval has already been granted. For Phase 5D
`ssh_exec`, central policy still returns `approval_required`; the separate
`ExecutionAuthorizer` re-evaluates that policy decision and asks the trusted
Security Ledger to atomically consume an exact single-use grant before network
access. The only approval-related MCP execution input is an opaque
`approval_id`; it does not alter the policy decision itself.

The canonical loadable example is `config/policy.example.yaml`.

## Command classification

Commands should be classified by capabilities such as:

- read-only inspection;
- filesystem mutation;
- network client;
- process control;
- service control;
- package management;
- container runtime;
- interpreter;
- shell;
- privilege escalation;
- kernel/network administration.

This classification supplements path-specific allow rules and enables policy such as `deny capability: shell`.

## Argument rules

Rules MUST be applied to the argv array, not to a rejoined shell string, for structured execution. Matching SHOULD support exact values, bounded enum values, and typed placeholders. Free-form regex matching SHOULD be used sparingly because policy correctness becomes difficult to audit.

## Environment

Environment variables are deny-by-default. A policy may allow specific names. Security-sensitive loader/runtime variables such as `LD_PRELOAD`, `LD_LIBRARY_PATH`, interpreter startup hooks, and equivalent variables SHOULD remain denied unless a privileged profile explicitly requires them.

## Policy explanation

The control plane SHOULD expose a read-only `policy_explain` tool that returns the normalized request, matching rule IDs, final decision, risk class, and required approval type without exposing secrets.
