# Yuz.local — Mode A FS-only pilot is LIVE on host loopback (2026-10-27)

**Exact status:** `LIVE, LOCAL-ONLY`. This is the operator-approved two-SSH-node **Mode A FS-only pilot**, **not** the distributed Mode B or complete eight typed FS-tool product. No public internet or LAN listener is enabled.

## Access

- Host: Mac `yuz.local`; dedicated VM `som-mode-a-netpilot-oct27` (Ubuntu 26.04.1, Docker Engine 29.9.2, userns-remap default, Compose 5.6.1).
- MCP: `http://127.0.0.1:18801/mcp` **from the Mac itself**. SSH encrypted port forwarding is owned by user LaunchAgent `com.som.modea.loopback`. Bearer authentication is mandatory; an anonymous MCP HTTP POST returns **401**.
- The generated random Bearer Token resides only in guest private file `/var/lib/ssh-over-mcp/mode-a-fs-pilot/control/origin-bearer` (mapped read-only control user); **never print, commit or put it in a URL/log**. Connecting remote services requires a separately approved TLS/private route and separate credential provision. No Cloudflare tunnel was configured in this release.
- Hostkeys are individually pinned in the private guest `control/config.yaml`. Node01 and node02 have distinct Ed25519 host and client keys; only their public portions are in the respective authorized_keys files.

## Immutable release identifiers / proof

- Git source HEAD: `e6357316d0c26c31921905a42199b7e121e944da`.
- Control image built on dedicated guest from the exact pinned Dockerfile base: `sha256:ee89cc1dc8f596f59160daff517dacf3f53e5c6c551bfd20bdd4acb4ded21925`.
- SSH images node01/node02: `sha256:053444836dd806b1adffac47e5887b8c57184f02c5d5f7d3d0b38988149b9529`; image-default sshd `-D -e`. CI artifact SHA256, GitHub workflow signer and exact merge-source identity were verified **before** importing. This matches the independent remapped CI image receipt; test-only GitHub attestations are **source provenance, not independent production signer**.
- Private image-ID env: `/var/lib/ssh-over-mcp/mode-a-fs-pilot/compose.env`; private operator-approved fourth overlay: `operator-approved-sshd-default.yaml`. Both root-owned, 0600, **not** committed. Tracked third overlay still STOP78. The private fourth overlay allows only the operator-accepted four-cap FS-only pilot and adds `restart: unless-stopped` to ledger, mcp, node01, node02.
- See [scoped operator decision ADR0025](../decisions/0025-mode-a-fs-only-operator-pilot-release.md) and [initial VM/key handoff](mvp-mode-a-yuz-local-networked-engine.md).

## Verified end-to-end on the actual machine

1. Five-service real Compose: `ledger-init` exited zero; `ledger`, `mcp` healthy, both default-start sshd nodes running; no published host ports.
2. Persistent Ledger admin socket: independent `approvalctl grant` for both nodes' mkdir/write; one-time consume, replay refused, binary readback exact.
3. Isolation: node→MCP new TCP 8000 refused, node01→node02 SSH 2222 refused, node→outside internet refused. The MCP origin is on the isolated bridge `172.30.253.10:8000`.
4. Mac through SSH tunnel: MCP JSON-RPC `initialize`, `hosts_list`, then both `fs_read` verified with Bearer; anonymous POST 401.
5. Controlled restart of Ledger/MCP/both SSH nodes, followed by the same Mac authenticated readback PASS; subsequent Compose recreation with `unless-stopped` continued to preserve FS data and authentication.
6. macOS user LaunchAgent managed loopback process was force-restarted (`launchctl kickstart -k`), its PID changed, and authenticated MCP two-node readback PASS.
7. **2026-10-28 actual cold boot recovery:** stop the dedicated VM with the LaunchAgent temporarily disabled, re-enable the approved LaunchAgent, then verify Lima/guest Docker restart policies recover the four services and the SSH tunnel resumes listening on `127.0.0.1:18801`. Anonymous MCP request returned 401; authenticated init, hosts_list, and byte-exact readback on **both** nodes PASS. No reset of named data volumes or Ledger; no other VM/Engine was touched. This is an operator-observed single cold-start recovery, not a guarantee of all future reboot paths.

## Repeatable Mac-local MCP acceptance

From the repository checkout on `yuz.local`:

```sh
/usr/bin/python3 ops/mvp/mode_a_host_loopback_acceptance.py
```

The fixed-target script uses Lima's approved non-interactive guest read to load the existing protected bearer **in memory only**, then talks exclusively to `http://127.0.0.1:18801/mcp`. It verifies anonymous 401, authenticated MCP initialization, hosts_list, and exact readback of the pre-existing two approval-test fixtures on node01 and node02. The script only calls read operations and prints bounded PASS/refusal markers without printing the bearer, private SSH keys or remote response bodies. It does **not** rotate credentials, grant approvals, change data, restart containers, or prove Mode B. If an operator intentionally changes the fixture bytes or paths, the check intentionally refuses rather than claiming health.

Synthetic regression: `PYTHONPATH="$PWD/src:$PWD" python3 -m pytest -q tests/ops/test_mvp_mode_a_host_loopback_acceptance.py` using the project's Python environment with pytest installed. Do not put the bearer into test fixtures or CLI arguments.

## Read-only health commands

```sh
launchctl print gui/$(id -u)/com.som.modea.loopback | grep -E 'state =|pid ='
curl --noproxy '*' --max-time 5 -s -o /dev/null -w '%{http_code}\n' -X POST -H 'Content-Type: application/json' --data '{}' http://127.0.0.1:18801/mcp
limactl list
limactl shell som-mode-a-netpilot-oct27 -- sudo docker ps --filter label=com.docker.compose.project=som342-mode-a --format '{{.Names}} {{.Status}} {{.Ports}}'
```

The unauthenticated MCP check should return `401` (not 200). A failure to connect indicates the tunnel or service is unavailable. **Do not expose the bearer in command arguments or shell history.**

## Safe stop, rollback and recovery

**Stop the local listener first** (no impact on other Lima VMs or shared Docker):

```sh
launchctl bootout gui/$(id -u)/com.som.modea.loopback
```

To stop this pilot's app without deleting data, on the guest:

```sh
limactl shell som-mode-a-netpilot-oct27 -- sudo docker stop som342-mode-a-mcp-1 som342-mode-a-node01-1 som342-mode-a-node02-1 som342-mode-a-ledger-1
```

Because the four containers have `restart: unless-stopped`, an explicitly stopped container remains stopped until intentionally started. To restore those same containers, use guest-scoped `sudo docker start som342-mode-a-ledger-1 som342-mode-a-node01-1 som342-mode-a-node02-1 som342-mode-a-mcp-1`, then restore the listener via:

```sh
launchctl bootstrap gui/$(id -u) /Users/yuz/Library/LaunchAgents/com.som.modea.loopback.plist
```

Do not use `docker system prune`, `docker compose down --volumes`, erase the VM, modify shared Docker Desktop, or delete the root-owned pilot key directory as a casual rollback. Preserve the ledger's exact grant history, distinct SSH hostkeys and named FS data volumes for recovery.

To halt **the entire dedicated VM** for maintenance, first stop the LaunchAgent as above (otherwise its KeepAlive restart path may relaunch the guest), then run `limactl stop som-mode-a-netpilot-oct27`. To resume, start the VM and bootstrap the loopback LaunchAgent; verify actual MCP and data readback again.

## Not claimed by this release

- No external LAN/Internet/Cloudflare MCP endpoint, no public SSH listeners, no independent security reviewer conclusion, no separate third-party production signing identity, no broad `exec` or cgroup management, no Mode B multi-host deployment and no complete eight-tool FS contract.
- The operator accepted the limited CapBnd residual risk for this **local FS-only pilot** on October 27, 2026; independent wider-production review and key rotation remain future work.
