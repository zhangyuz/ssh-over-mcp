# Mode A networked pilot — dedicated Yuz.local Engine handoff (2026-10-27)

**State: INFRASTRUCTURE PREPARED, APP NOT DEPLOYED, PR #342 DRAFT/HOLD.**

This replaces the obsolete *offline Docker media / no-NIC OCI guest* deployment dependency per [ADR 0024](../decisions/0024-networked-docker-mvp-vs-isolated-e2e.md). The **no-NIC native security regression** remains necessary for untrusted test isolation, but it is not a production topology requirement.

## Actual host state, independently checked

- Dedicated Lima 2.2.0 Virtualization.framework guest: `som-mode-a-netpilot-oct27`, Ubuntu **26.04.1 LTS** / amd64, 2 CPUs, 3 GiB RAM, 12 GiB guest disk; `plain: true`, no host mount, no inherited host containerd. Exact official Ubuntu cloud image `sha256:5645d0318ad21f643ebb1ac4567514620e9893380b07b0201fda163baa5b7eb5` verified against Lima template. Guest networking is enabled so a future authenticated remote MCP→SSH deployment can operate.
- Fresh dedicated Docker Engine **29.9.2** and Docker Compose plugin **5.6.1**, installed with signed APT package lists from `https://download.docker.com/linux/ubuntu` for `resolute`; Docker upstream key fingerprint `9DC858229FC7DD38854AE2D88D81803C0EBFCD88` verified before installation.
- Guest `/etc/docker/daemon.json` contains `{"userns-remap":"default","ip":"127.0.0.1"}`. Docker reports `name=userns`, AppArmor, seccomp and cgroup namespaces. Host subordinate mapping is `dockremap:100000:65536` for UID/GID; Docker image data resides at `/var/lib/docker/100000.100000`.
- A locally built `FROM scratch` + Ubuntu-signed `busybox-static` **no-NIC** disposable test container actually reported UID/GID maps `0 100000 65536`; `CapInh/CapPrm/CapEff/CapBnd/CapAmb` all **0**, `NoNewPrivs=1`. The test image was removed afterward. **This verifies Engine mapping, NOT privileged sshd/FS release acceptance.**
- Both pre-existing Lima VMs and both persistent Docker Desktop GitHub-runner containers remain untouched. No published MCP/SSH ports, app containers, Cloudflare tunnel, production runtime image, host firewall or Docker Desktop configuration has been changed.
- Staged **guest-local, non-exported** pilot identity and server config at `/var/lib/ssh-over-mcp/mode-a-fs-pilot`: distinct Ed25519 host keys and client keys for node01/node02; root-owned parent mode `0700`; each SSH container hostkey mode `0600`, owner remapped container-root UID/GID `100000:100000`; client private keys mode `0400`, owner mapped control user `110001:110003`; same mode/ownership for `control/config.yaml`, `credentials.yaml`, `origin-bearer`. Unique Bearer Token generated without printing, transmitting, or committing private bytes. Each authorized_keys file contains only its corresponding client public key. Policies default deny and enable only the two hosts and `fs_stat`, `fs_read`, `fs_mkdir`, `fs_write` on the two test resource roots, with required once-only approvals.

## Read-only reinspection

```sh
limactl list
limactl shell som-mode-a-netpilot-oct27 -- sudo docker info --format '{{json .SecurityOptions}}'
limactl shell som-mode-a-netpilot-oct27 -- sudo docker compose version
limactl shell som-mode-a-netpilot-oct27 -- sudo docker ps --format '{{.Names}} {{.Status}}'
```

To free memory **without deleting staged secrets**, `limactl stop som-mode-a-netpilot-oct27`; later resume with `limactl start --tty=false som-mode-a-netpilot-oct27`. Never run `docker system prune` or delete this VM automatically.

## Still required before production LIVE

1. Independent [#346](https://github.com/zhangyuz/ssh-over-mcp/issues/346) decision for FS-only four startup capabilities with post-ForceCommand `NNP=1` and nonzero `CapBnd`; do not silently weaken the five-zero production launcher. Explicit independent whole-PR release review/authorization.
2. Independently reviewed, **production-release-authorized and digest-pinned runnable** Ubuntu/OpenSSH SSH image and control image. GitHub OIDC CI-only artifact attestations are **not** production runtime approvals. No STOP78 bypass or CI-only overlay promotion by implication.
3. Operator-verified SSH host pin continuity, private key custody and rotation/recovery, and verified actual named-volume owner mapping under this Engine.
4. Approved ingress route from intended MCP client to a **private origin with Bearer authentication**, no public SSH/host ports, direct control→both SSH networks, **negative node→control new TCP/8000 and node↔node probes**, approved FS write/read/replay-deny, persistence/rollback, and no unrelated host side effects. Origin must be reachable to the intended client; VM SSH readiness alone is not user-facing availability.
5. Produce a successful authenticated MCP client request using the **deployed final Compose images**, not only disposable CI; then report concrete endpoint/access method and declared Mode A FS-only pilot scope. Mode B and all eight typed FS operations remain separate full-product deliverables.

**Never report LIVE until the above user-visible connectivity and release approvals are objectively observed.**
