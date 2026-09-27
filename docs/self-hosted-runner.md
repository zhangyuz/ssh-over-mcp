# Self-hosted Ubuntu 24.04 Docker runner

The project uses a dedicated self-hosted GitHub Actions runner container for
Linux execution semantics which are difficult to validate when GitHub-hosted
capacity is unavailable.

The runner image is always **Ubuntu 24.04**, even when the Docker host is macOS.

## What this runner validates

The Docker runner is intended to validate:

- Python 3.13 and 3.14;
- process creation with `fork()`;
- fd-based `execve()`;
- stdin/stdout/stderr supervision;
- POSIX signals and process groups;
- rlimits;
- the read-only cgroup-v2 capability probe;
- the normal project test suite.

It does **not** claim to validate writable cgroup containment.

The concrete cgroup backend will need a separate Linux-only integration runner
with a deliberately delegated writable cgroup subtree. We do not grant the
general Docker runner `--privileged`, `CAP_SYS_ADMIN`, host cgroup write
access, or the Docker daemon socket merely to make those tests pass.

## Host requirements

Supported deployment hosts:

- Linux with Docker Engine;
- macOS with Docker Desktop.

Recommended capacity:

- 2 CPU or more;
- 4 GiB RAM or more;
- outbound HTTPS access to GitHub;
- no inbound network service required.

On macOS, the runner still executes inside Docker Desktop's Linux VM. Apple
Silicon uses the Linux ARM64 runner package; Intel Macs use Linux x64.

## Runner image

The image is defined in:

```text
ops/runner/Dockerfile
```

Properties:

- base image: `ubuntu:24.04`;
- GitHub Actions Runner version pinned at build time;
- official runner archive SHA-256 verified before extraction;
- x64 and ARM64 supported;
- job process runs as fixed non-root UID/GID 1001;
- normal GitHub runner self-update remains enabled by default.

The current pinned bootstrap runner is `2.337.0`. When changing the pinned
version, update the matching official SHA-256 values in
`scripts/deploy-runner.sh`.

## Security properties of the container

The deployment script starts the container with:

```text
--cap-drop ALL
--security-opt no-new-privileges:true
--pids-limit 1024
--cpus 2
--memory 4g
--tmpfs /tmp:rw,exec,nosuid,nodev,size=512m
```

The explicit `exec` on `/tmp` is required because the Linux integration tests
create temporary executable fixtures under pytest's default temporary directory.
Docker Desktop may otherwise mount container tmpfs with `noexec`, which makes
valid `0755` test executables fail `X_OK` checks and `execve()` with
permission denied.

and does not mount:

- `/var/run/docker.sock`;
- host credentials;
- a writable host cgroup tree;
- the repository working tree.

The runner's job workspace lives only in the container filesystem. In
ephemeral mode the container is removed after its one assigned job.

The self-hosted workflow itself:

- is manual-only via `workflow_dispatch`;
- must be launched from trusted `main`;
- uses `permissions: contents: read`;
- receives no repository secrets;
- checks out the explicitly selected target ref only after runner hardening
  preflight;
- pins third-party GitHub Actions to full commit SHAs.

A selected target ref still contains executable code. Choosing the ref is an
explicit trust decision.

## Deploy on Linux or macOS

The same script is used on both operating systems:

```bash
bash scripts/deploy-runner.sh up
```

The script:

1. verifies Docker is installed and running;
2. detects Linux vs macOS;
3. detects x86-64 vs ARM64;
4. builds the matching Ubuntu 24.04 runner image;
5. obtains or accepts a short-lived GitHub runner registration token;
6. starts the hardened runner container.

### Registration token

Preferred options, in order:

1. export a one-time registration token:

   ```bash
   RUNNER_TOKEN='<token>' bash scripts/deploy-runner.sh up
   ```

2. if GitHub CLI is installed and authenticated with repository admin
   permission, omit `RUNNER_TOKEN`; the script requests a repository runner
   registration token through `gh api`.

A registration token is not a long-lived runner credential and must not be
committed.

To copy a token manually, use:

```text
Repository
→ Settings
→ Actions
→ Runners
→ New self-hosted runner
```

The script only needs the registration token; the host does not need to
install the GitHub runner binary directly.

## Common commands

Start the default ephemeral runner:

```bash
RUNNER_TOKEN='...' bash scripts/deploy-runner.sh up
```

Use an explicit name:

```bash
RUNNER_TOKEN='...' bash scripts/deploy-runner.sh up \
  --name ssh-over-mcp-dev-01
```

Show status:

```bash
bash scripts/deploy-runner.sh status
```

Follow logs:

```bash
bash scripts/deploy-runner.sh logs
```

Remove the runner container:

```bash
bash scripts/deploy-runner.sh down
```

Build only:

```bash
bash scripts/deploy-runner.sh build
```

## Ephemeral vs persistent

Ephemeral is the default:

```text
RUNNER_EPHEMERAL=true
Docker --rm
one GitHub Actions job
container exits
container is removed
runner is automatically deregistered by GitHub
```

This is the preferred validation mode.

For local bring-up only, a persistent runner is available:

```bash
RUNNER_TOKEN='...' bash scripts/deploy-runner.sh up --persistent
```

Persistent mode uses Docker's `unless-stopped` restart policy and retains the
runner configuration in the container writable layer.

Do not treat a persistent container as clean between jobs.

## Linux host behavior

On Linux, the Ubuntu container shares the Linux host kernel. This provides
useful validation of fork, fd execution, rlimits, signals, and read-only
cgroup-v2 discovery.

The container intentionally has no privilege to mutate the host's cgroup tree.

When the concrete cgroup backend is implemented, live writable-cgroup tests
will use a different Linux-only runner configuration with a narrowly delegated
subtree.

## macOS host behavior

On macOS, Docker Desktop executes the Ubuntu container inside its Linux VM.

This validates the Linux userspace/kernel behaviors exposed by that VM, which
is sufficient for the current test suite.

It does not prove how a production Linux host delegates writable cgroups and
therefore is not accepted as evidence for the future live cgroup backend.

No `--privileged` workaround should be added merely to make that future test
run on macOS.

## Run validation

After the runner reports online in GitHub:

1. open **Actions**;
2. choose **Self-hosted Docker validation**;
3. choose **Run workflow** from `main`;
4. enter the branch, tag, or commit SHA to validate;
5. run the workflow.

The job requires:

```yaml
runs-on: [self-hosted, linux, ssh-over-mcp-docker]
```

The preflight verifies:

- job UID is non-root;
- OS is Ubuntu 24.04;
- effective Linux capabilities are zero;
- `NoNewPrivs=1`;
- Docker socket is not mounted;
- cgroup v2 is visible;
- `cpu`, `memory`, and `pids` controllers are visible.

Only then is the selected ref checked out.

The full test suite runs sequentially on Python 3.13 and 3.14 in the same job,
which is compatible with one-job ephemeral runners.

## Updating the runner bootstrap version

The Docker build verifies the official Actions Runner archive checksum.

For the repository-pinned version, the deploy script already contains the
official x64 and ARM64 hashes.

To test another version without first changing the repository:

```bash
RUNNER_VERSION='<version>' \
RUNNER_SHA256='<official-sha256-for-this-architecture>' \
bash scripts/deploy-runner.sh build
```

A non-default version without an explicit checksum is rejected.

The image leaves GitHub runner automatic updates enabled so a bootstrap image
does not silently become unusable as GitHub advances the minimum accepted
runner version. Rebuild the image regularly and update the pinned version and
hashes in source control.

## Future cgroup-live runner

The future concrete `CgroupV2Backend` needs tests which can create a request
cgroup, write `memory.max`, `pids.max`, and `cpu.max`, attach a stopped
child to `cgroup.procs`, invoke `cgroup.kill`, and remove the empty scope.

Those tests MUST NOT be enabled by making this generic runner privileged.

They will use a separate Linux-only runner with a dedicated delegated cgroup
subtree and a separate custom label.
