# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3b behavior

The host agent is deliberately **non-executing**:

1. requires `SSH_ORIGINAL_COMMAND=mcp-v1` exactly;
2. rejects PTY-backed structured sessions;
3. loads the fixed host-local policy from `/etc/ssh-over-mcp/host-policy.yaml`;
4. requires a regular, root-owned, non-group/world-writable policy file without symlink following;
5. parses only the bounded SMCP metadata envelope;
6. applies exact profile/executable rules, environment rules, and host-side resource ceilings;
7. only after authorization reads bounded application stdin;
8. exits fail-closed with "execution unavailable".

It still does **not** execute `executable` or `argv`.

The reference policy is [`../../config/host-policy.example.yaml`](../../config/host-policy.example.yaml).

The next increment adds argv/cwd and executable filesystem canonicalization before any `execve` path is introduced.
