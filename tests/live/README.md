# Live workload identity transition probe

This directory contains the dedicated Linux proof for the irreversible
host-agent-to-workload credential transition. It is intentionally separate from
ordinary pytest validation because the fixture requires real `CAP_SETUID` and
`CAP_SETGID`.

Run the complete disposable probe from the repository root:

```bash
./scripts/run-live-workload-identity-probe.py
```

The operator script builds a disposable Linux image and runs it with all runtime
capabilities dropped except `SETUID` and `SETGID`. Runtime networking is
disabled and the container is removed even if the probe fails or times out.

The root container process is used only to construct the fixture. Before probe
assertions begin, it drops to the non-root host-agent UID/GID, retains only the
two required effective/permitted capabilities, and keeps the manager-client
supplementary group.

The test then proves the real transition, irreversibility, parent/child
separation, expected cross-UID `kill(pid, 0) -> EPERM`, and state persistence
through the repository's pinned native fd-based ELF exec path.

Ordinary `pytest` runs do not set
`SSH_OVER_MCP_RUN_LIVE_WORKLOAD_IDENTITY=1`, so this probe is skipped and
generic validation does not require identity-changing capabilities.
