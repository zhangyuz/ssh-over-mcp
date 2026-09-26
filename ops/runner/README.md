# GitHub Actions runner image

This directory contains the Ubuntu 24.04 image used by the repository's
self-hosted validation runner.

Build and deploy through:

```bash
bash scripts/deploy-runner.sh up
```

The image supports Linux x64 and ARM64 runner packages. The deployment script
selects the architecture from the Linux or macOS Docker host and passes the
matching official SHA-256 to the build.

The container intentionally:

- runs jobs as non-root UID/GID 1001;
- has no Docker socket;
- is launched with all Linux capabilities dropped;
- uses `no-new-privileges`;
- has no writable host-cgroup mount.

See [`../../docs/self-hosted-runner.md`](../../docs/self-hosted-runner.md)
for the complete threat model and deployment procedure.
