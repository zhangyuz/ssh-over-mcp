# Host agent

The remote ForceCommand host agent is implemented by the installable console entrypoint:

```text
ssh-over-mcp-host-agent
```

Normative behavior is defined in [`../../docs/ssh-host-agent.md`](../../docs/ssh-host-agent.md).

## Current Phase 3d2b2b1 behavior

The ForceCommand request path remains **non-executing**. The child supervisor now applies host-owned rlimits from host-policy schema v3 before native fd exec.

Required `child_limits`:

- CPU seconds;
- address-space bytes;
- maximum processes;
- maximum regular-file size;
- maximum open files.

The limits are carried inside the prepared command, applied only in the disposable child, and clamped down to any stricter inherited hard limit. The child never expands a parent/container hard limit. Core dumps remain disabled.

Rlimits are not treated as a sandbox. In particular, process limits are real-UID scoped and process-group escape remains possible. High-risk arbitrary-code execution still requires dedicated cgroup/systemd-scope or equivalent containment.

Still missing before remote execution is enabled:

- stronger descendant containment;
- final ForceCommand execution/result integration.

Next: Phase 3d2b2b2 defines the cgroup/systemd-scope containment boundary separately from the rlimit layer.
