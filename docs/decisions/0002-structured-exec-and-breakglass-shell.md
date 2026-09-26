# ADR 0002: Structured execution plus privileged raw shell

- Status: Accepted
- Date: 2026-09-26

## Context

General host control requires flexible command execution. A command-string-only API makes policy analysis and injection resistance weak, while banning shell entirely prevents legitimate administrative recovery workflows.

## Decision

Provide `ssh_exec` using executable + argv + cwd + allowlisted environment as the normal path. Provide `ssh_shell` as a separate privileged capability, disabled for ordinary roles and suitable for approval-gated break-glass use.

Structured-command denial never falls back to raw shell automatically.

## Consequences

- Common operations remain policy-inspectable.
- Some advanced workflows require explicit shell elevation.
- Command-capability classification is still required because interpreters/build tools can execute arbitrary code without shell syntax.

## Security impact

Positive: eliminates shell parsing from the default execution path and makes unrestricted shell access explicit and auditable.
