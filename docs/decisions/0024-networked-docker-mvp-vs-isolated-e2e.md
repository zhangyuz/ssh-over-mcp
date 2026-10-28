# ADR 0024: Networked Docker MVP; no-NIC is an E2E isolation method, not production topology

- **Status:** operator-selected deployment direction on 2026-10-27; implementation/release remains DRAFT/HOLD in PR #342
- **Scope:** Mode A single-Engine FS-only pilot first; Mode B multi-host and full eight-tool product MVP remain separate mandatory deliverables under ADR 0021
- **Supersedes for product deployment:** proposed offline Engine package-closure and no-NIC OCI guest as mandatory prerequisites for the networked Mode A pilot. Does **not** amend the existing trusted-main isolated native Level-3 test authority.

## First-principles decision

The product exists so an authenticated MCP client can manage selected SSH endpoints over a real network. That requires an ingress path to the control plane and a narrowly scoped outbound SSH path from that plane to the targets. Neither a fully disconnected guest nor a bespoke offline Docker Engine media supply chain is an intrinsic requirement for production service availability.

A no-NIC VM remains useful for executing untrusted test code without exposing the persistent host/LAN; its internal guest-only loopback/container links can still run SSH. This is a **test trust boundary**, not a practical remote-service network topology. Do not conflate its security value with production connectivity, or claim that it was meaningless for isolated testing.

### Selected minimum delivery path

1. **Mode A:** an authorized, **networked Linux/amd64 Docker Engine** with normal Docker Compose. Prefer an isolated, collision-free Compose project on an existing compatible Engine **if the operator authorizes using that shared daemon**, otherwise a dedicated Linux Engine. The existing Yuz.local Docker Desktop backend is a possible candidate, not an automatically approved runtime. Ubuntu 26.04 is the **container image/package origin**, not a requirement that the Docker host itself run Ubuntu. Use standard signed Ubuntu APT within reviewed builds; no custom offline package closure, untrusted mirrors or disabled signature checks.
2. **Mode A services:** MCP + Ledger/control and at least two independent OpenSSH containers. Permit only authenticated MCP ingress (prefer existing Cloudflare/private origin) and MCP→each SSH target TCP/2222 inside Compose, plus explicitly approved operations/update traffic. SSH endpoints and MCP origin must not publish public host ports; require server-owned inventory, pinned SSH host keys, origin bearer token, least privilege, per-node volumes, fail-closed approvals and audit.
3. **Before network exposure:** demonstrate on actual target that SSH-node→MCP new TCP/8000 is refused, node01↔node02 refused, MCP ingress authenticated, MCP→both pinned SSH identities works, replay/unauthorized writes fail, data is separate, and teardown/rollback effective. The origin-only bind already tested on disposable Docker is a candidate, not target proof.
4. **Release image:** require independently verified source/image identity and an explicit replacement for the test-only STOP78 entrypoint. Do not convert a signed CI test archive to a production image by deleting a guard; require a separately reviewed final image and key lifecycle.
5. **Mode B:** production multi-host deployment still requires a privately routed network and three separate Engines: control plus two SSH hosts, with real host-to-host firewall/recovery verification. Mode A pilot does not satisfy Mode B; four create-only/stat/read operations do not constitute the full eight-tool contract.

### Preserved security gates

- Existing trusted-main *no-NIC native Level-3* regression retains its security purpose and exact-head evidence; it is **not** a production topology check.
- Risk-bearing SSH capabilities (NNP, userns, cap sets), host-key custody, authorization, approvals/audit, network ACLs, provenance, independent review and operator release permission are **not** waived.
- The offline Engine workflow remains disabled after execution safety blocked its activation. **Do not re-enable or reroute it**; the online option is a changed product architecture with separate operational safeguards, not a workaround to run the refused workflow.
- The stopped Lima som-mode-a-ubuntu2604 definition was created for a different gate and has unverified network security. Do not boot or mutate it automatically based on this ADR. On Yuz.local, read-only inventory found a Linux/amd64 Docker Desktop backend with Compose 5.5.1 and unrelated work; use of that shared daemon still requires deliberate non-interference scope/permission. Do not provision a redundant Ubuntu VM merely because earlier test plans called for one.

## Acceptance and next action

Use previous [Mode A OCI real dual-node CI](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/40569048733) as functional preflight only. Confirm an authorized networked Linux Engine (existing isolated Compose project or dedicated environment according to actual shared-workload risk), independently approved final image/keys, private ingress/egress and targeted live positive/negative checks. Then independent cross-boundary review and deployment authority. Until verified, report NOT LIVE, keep STOP78 and PR #342 Draft.

**Deferred TODO:** no-NIC OCI Engine guest, custom offline package media chain, manager/cgroup/exec enhancements and other nonpilot improvements. Keep the native no-NIC test regimen; its isolated execution purpose is not deferred.
