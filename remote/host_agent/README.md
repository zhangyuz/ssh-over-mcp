# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3d1 behavior

The host agent remains **non-executing**. It now performs:

1. exact ForceCommand/no-PTY validation;
2. trusted host-policy loading;
3. bounded metadata parsing and host authorization;
4. canonical executable/argv/cwd checks;
5. records executable/cwd device+inode+ctime identities;
6. immediately re-authorizes before preparation;
7. opens the canonical executable and cwd with no-follow/close-on-exec flags;
8. revalidates identity and executable security properties on the opened fd;
9. classifies the pinned executable as ELF, script, or other;
10. reads bounded application stdin while the fds remain pinned;
11. closes all prepared fds and exits with "execution unavailable".

No process is started.

fd pinning prevents pathname replacement from silently changing the object selected for future execution. It does not protect a deliberately mutable inode from in-place modification, so future execution keeps the trusted ownership/writeability requirements as part of its security boundary.

The next increment will execute only through the pinned descriptor path and will not reopen the executable pathname.
