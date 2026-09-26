# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3c behavior

The host agent is deliberately **non-executing**. It now performs:

1. exact `SSH_ORIGINAL_COMMAND=mcp-v1` and no-PTY validation;
2. root-owned/no-symlink host-policy loading;
3. bounded metadata parsing and host resource-ceiling checks;
4. exact requested-command lookup;
5. token-based argv exact/prefix authorization;
6. requested executable → configured canonical realpath verification;
7. regular-file/execute-bit and ownership/writeability checks;
8. canonical cwd-root confinement with symlink-escape rejection;
9. bounded application-stdin read only after authorization;
10. fail-closed exit with "execution unavailable".

The reference schema is version 2 in [`../../config/host-policy.example.yaml`](../../config/host-policy.example.yaml).

No process is started yet. The next increment must use a race-resistant execution mechanism so an authorized executable/cwd cannot be swapped between authorization and execution.
