# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3d2a behavior

The ForceCommand request path remains **non-executing**, but the package now contains a native execution primitive for the next supervised-child stage.

The primitive accepts only a previously fd-pinned `PreparedCommand` and:

1. requires native ELF format;
2. requires fd-based `os.execve()` support;
3. requires a pinned cwd;
4. revalidates the executable fd using device/inode/ctime;
5. revalidates the cwd fd using device/inode;
6. builds argv without shell parsing;
7. passes only the explicitly authorized request environment;
8. calls `fchdir(cwd_fd)`;
9. calls `os.execve(executable_fd, argv, env)`.

It does not reopen the executable pathname, perform PATH lookup, invoke a shell, or inherit the host-agent environment.

The primitive is deliberately child-only and is **not called by the CLI yet**. Remote requests still terminate with "execution unavailable".

Next: a supervisor which forks a disposable child, connects stdin/stdout/stderr, enforces timeout/output limits, and calls this primitive only inside the child.
