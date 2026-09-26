# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3a behavior

The entrypoint is deliberately **parse-only**:

1. requires `SSH_ORIGINAL_COMMAND` to equal `mcp-v1` exactly;
2. rejects PTY-backed structured sessions;
3. reads and validates one bounded SMCP v1 request frame;
4. rejects malformed metadata or oversized stdin;
5. exits fail-closed with "execution unavailable".

It does **not** execute `executable`, `argv`, or application stdin yet.

This lets the ForceCommand boundary and wire parser be reviewed independently before host-local authorization and `execve` are introduced.
