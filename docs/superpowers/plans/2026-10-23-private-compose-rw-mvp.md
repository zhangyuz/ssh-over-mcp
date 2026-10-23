# Private multi-SSH Compose read/write MVP — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Group multiple closely related checks into one meaningful, reviewable user capability/PR; avoid one PR per assertion.

**Goal:** Deliver a private MCP product where **both** (A) one Linux Engine running a control-plane Compose stack plus at least two SSH containers for development/E2E, and (B) **three distinct Linux hosts** (one control-plane Compose host and at least two independently deployed SSH-target Compose hosts) for actual use, support the same eight typed filesystem read/write operations, exact approval, audit, recovery and refusal semantics. Neither mode is optional.

**Architecture:** Extend Phase 6 control-plane Compose with a local disposable **Mode A** overlay, and build a reusable standalone SSH-target Compose project deployed **once per remote Linux Engine** in **Mode B**, connected to the distinct control-plane host by operator-approved private routed networking (not a cross-Engine Compose network). Both share source-verified images, static-profile inventory, central/host policy, SMCP, one-shot approvals and Ledger. Implement missing typed filesystem operations with FD-anchored safety. Production acceptance is blocked until both deployment modes pass separate genuine cgroup/manager, network and eight-tool E2E gates.

**Tech Stack:** Python 3.13/3.14, existing MCP SDK/AsyncSSH/Pydantic, Docker Engine + Compose on dedicated Linux x86_64 with cgroup v2, supported OpenSSH, existing signed/approved image paths, private Portal/Tunnel.

**Spec:** [2026-10-23-private-compose-rw-mvp-design.md](../specs/2026-10-23-private-compose-rw-mvp-design.md)
**ADR:** [0021-private-compose-rw-mvp-release-track.md](../../decisions/0021-private-compose-rw-mvp-release-track.md)

**状态：DRAFT — Mode A/Mode B 两种部署形态已由用户确认，其他 ADR/spec/plan 安全细节尚待完整评审。** 本次不授权 Docker 主机操作、新 trust/runtime/source、Compose 部署、merge 或 release。旧只读 observer 计划不再是实施目标；旧 main `0123346040eedae0fa4a92f50e556ba925fffd36` 的 11/11 CI 不认证任一新部署模式或全读写功能。

## Global constraints

- 启动前必读 `AGENTS.md`、`docs/development-methodology.md`、`docs/README.md`、`docs/security-model.md`、`docs/policy-spec.md`、`docs/mcp-api.md`、ADR0021、本 spec 和 worktree-local `progress.md`。
- 范围：一个组织、一个同权限组、一个 origin、server-selected 静态 `rw-operator`、至少两个 host aliases `node01` 和 `node02`、**八种 typed FS 能力**；无裸 Shell、无 root/sudo、无模型可控 IP/SSH 用户/密钥/profile。
- **用户已确认两个部署模式均是 MVP 的必交付项：** Mode A 单机一个 Linux Engine 上的控制面 Compose + 至少两个 SSH container 用于开发/E2E；Mode B control01 控制面独立 Linux Engine + ssh-host01、ssh-host02 两个**各自运行 SSH Compose project 的不同 Linux 宿主机**用于实际部署。模式 A 的成功不能作为 Mode B 完成证据。每个 sshd 均有独立 host key、数据卷、策略、host-agent/manager 身份和可验证权限边界；不能与 MCP/ledger/approvalctl 共用管理 socket 或秘密卷。
- 两种模式均禁止 `privileged: true`、Docker socket、host PID/network namespace、宽松 cap、宿主 `/` 或无审查 `/sys/fs/cgroup` rw 来绕过隔离；每个 SSH Engine 必须独立证明安全 cgroup 委托、manager/host-agent 身份、ForceCommand 与无横向访问。必须把 **ADR0007 精确无参数 sudo ForceCommand launcher 到有限 CAP_SETUID/GID 身份桥**视为待在容器中证明的部署事实：不能宣称所有 sshd/launcher 进程自启动即 non-root/no-new-privileges 而又期望 sudo 能提权；需独立审核最小初始权能、运行中身份降权、不可代理泛 sudo 与 host/manager 内核边界。Mode B 只能使用操作者批准的**私有可路由连接**，MCP 源 IP/identity→远端 SSH TCP/22 allow，公网和 SSH 节点横向访问 deny，不依赖 Compose 内置跨主机网络。任一关键链不可证明则 **M1b HOLD**，不许用 mock PASS 冒充真实部署。
- 旧四个 typed FS 能力的现有契约不可随便更改；新增 `fs_list/search/move/delete` 和 write append/replace 必须有两层策略、SMCP typed schema、no-follow inode/parent 边界、超限及并发拒绝。删除首发只支持明确路径的文件/空目录；递归删除不在已核定默认范围。
- 每个远端高影响读写默认 exact one-shot approval；Ledger required audit fail-closed；路径/host/内容/mode/策略版本变更不得重用 grant。未能判断操作是否发生时禁止自动重试或回报正常成功。
- 任何外部镜像/source、runtime/host key/凭据、Linux root/容器 daemon/Cloudflare 账号权限都由 operator-owned，缺授权可做不涉及外部真实动作的代码/合成测试，不能填 Axx PASS。
- T5B 来源/信任/真实 Mac UID502/APFS、受保护 staging Issue #259 和 Linux provenance C/D Issue #256 继续 HOLD。旧 trusted-main no-network L3 仍必要，但并不认证新的 Compose SSH 读写路径。
- 本次变更仅限待确认文档；没有批准代码实现、直推 main、PR merge、发布或具体 Docker 运行。

- **Protocol-first hard gate:** 在新 list/search 或 mutation 模式编码/暴露前先冻结 [设计 §2a](../specs/2026-10-23-private-compose-rw-mvp-design.md) 的 **SMCP v2 策略快照+epoch、Host Policy v5 deny 子树、远端持久 Operation ID/receipt/UNKNOWN、typed API/schema** 四套契约，配合独立 Review 和跨版本/失败测试。当前 v1/Host v3/v4/一次性 approval 不具备这些保证；M2a/M2b/M2c/M2d 仍 NOT_STARTED。

## Review focus（高风险负向输入）

1. Mode A 共享 Engine 的网络/卷或 Mode B 不同 Engine 的防火墙/路由配置导致 SSH 节点互访、公网 SSH ingress、共享管理 socket/密钥，或可写 cgroup/Docker socket 使低权限执行逃逸：M1a/M1b 分别必须真实证明隔离和故障拒绝。
2. `fs_move/delete/replace` 对 symlink/hardlink、mount 边界、被并发替换的父目录或现存目标意外覆盖：M2c/M2b 用稳定 FD 和 hostile-race 验证无越权副作用。
3. `fs_search/list` 的海量目录、环/深递归、磁盘慢读、FIFO/设备文件导致资源耗尽：M2a 有资源限制与真实拒绝/截断证据。
4. 一次批准被用于另一 SSH node、另一写入内容、append→replace 或重试/故障双重执行：M2d 覆盖所有绑定字段、持久化失败与不确定结果。
5. 多卷恢复只回退业务文件不回退 Ledger、SSH host keys 轮换不一致或旧 granted 审批仍有效：M4 检查一致性 checkpoint、全部审批 expiry 和每节点撤销。

## A01–A18 完整验收追踪（全部 NOT_RUN）

M1a **Mode A** `A01` 单 Engine 的 Compose 启动/连通；`A02` 两 SSH 容器权能与相互隔离拒绝；`A03` 重启、manager outage 与失败关闭。
M1b **Mode B** `A15` control01 + 两台独立远端 Linux Engine 的 Compose 启动/私网/host-key；`A16` 独立 per-host 身份/cgroup/卷和私网 ACL 拒绝；`A17` 跨主机网络分区、远端故障、密钥改变、审批重放的 fail-closed；`A18` 每个独立 Engine 的安装/更新/回滚和完整可追溯证据。
M2a/M2b/M2c/M2d `A04` 八个 typed FS 工具跨两节点正向；`A05` 路径/host-key/文件类型/资源限额负向；`A06` create/append/replace/move/delete 并发与失败原子性；`A07` exact one-shot approval 与跨 host/content/mode 重放拒绝；`A08` Ledger/审计/未知执行结果 fail-closed。
M3 `A09` 真实客户端在 **Mode A 和 Mode B** 均完成八工具，**Mode B 必须连通两台实际远端 Compose SSH 主机**；`A10` 生产模式的 Portal/origin 授权、来源限制、无公网 SSH/控制面端口及秘密隔离。
M4 `A11` **跨 control01/ssh-host01/ssh-host02 三个 Engine** 的协调停机、逐宿主机一致性快照/审计 checkpoint、全部旧审批失效；`A12` 独立节点及控制面凭据撤销。Mode A 冷恢复演练是前置测试，不替代真实分布式恢复。
M5 `A13` 精确 RC 全量回归及 **Mode A + Mode B 两套独立真实 Compose E2E**、代码安全独立复核；`A14` 合并后 main 11/11 且三台实际宿主机的 image/config/key/网络策略证据匹配，另获正式部署/发布批准。
所有编号的 PASS 均需见 spec §6 的实际环境、正反证据与 source SHA；旧 main CI 不得挪用。

## 0. 交付里程碑和独立批准

| Milestone | 可交付用户能力 | 证据编号 | 状态 |
|---|---|---|---|
| M0 | 双模式范围已确认；其余威胁/Compose 环境/权限与 ADR 完整接受待批准 | ADR0021 | PARTIAL_CONFIRMED（其余 WAITING_FOR_CONFIRMATION） |
| M1a 开发/E2E | 单台可销毁 Linux Engine 的控制面 Compose + 2 个独立 SSH Compose 容器 | A01–A03 | NOT_STARTED |
| M1b 实际部署 | control01、ssh-host01、ssh-host02 **三台不同 Linux Engine** 的独立 Compose 项目、私有 SSH 连接与故障拒绝 | A15–A18 | NOT_STARTED |
| M2a | 两个 host 的完整 bounded 只读：list/stat/read/search | A04–A05 部分 | NOT_STARTED |
| M2b | 安全写入：mkdir/create/explicit append/replace | A04/A06/A07 部分 | NOT_STARTED |
| M2c | 安全 move/delete 与独立 host/path 拒绝 | A04/A05/A06 部分 | NOT_STARTED |
| M2d | 全部 typed 工具的双层策略、批准、审计多主机矩阵 | A04–A08 | NOT_STARTED |
| M3 | 私有 Portal 的真实 MCP 客户端完成完整读写流程 | A09–A10 | NOT_STARTED |
| M4 | Compose+多卷当前一致性冷恢复与凭据撤销 | A11–A12 | NOT_STARTED |
| M5 | 冻结 RC、全量 CI+real E2E、安全复核、批准后发布 | A13–A14 | NOT_STARTED |

建议按 **M1a（单机开发/E2E 容器）→ M1b（独立宿主机部署/私网）**，再推进 M2a/M2b/M2c/M2d、M3、M4、M5 各自独立可验收的功能 PR；M2 各项可与 M1b 安全框架并行开展**纯代码开发与合成测试**，但不能在 M1b 未通过时宣称多宿主机写入安全。每个 PR 包含正向/拒绝路径、文档、review、精确 HEAD CI 和单独 merge 批准。首次在每台 Engine 上完成 host-agent/cgroup 授权与隔离验收后重新评估工期，不能沿用旧单机只读版 8–14 天估计。

## 1. M0 — 设计确认与环境/权限清单

**输入（未授权时仅记录需求，不探测/改变目标）：**

- [ ] 用户确认 ADR0021/spec/plan 对“所有读写”的定义：八种 typed FS、显式 append/replace、限定根、delete 默认仅文件/空目录。若包括递归删除、原生宿主文件或通用 shell，必须先改写设计并独立审查更高风险边界。
- [x] **部署形态已由用户确定：两种同时属于 MVP。** Mode A 单 Linux Engine、控制面和两个 SSH Compose 服务用于开发/E2E；Mode B 独立 control01 Linux Engine + 两台真实远端 SSH Linux Engine（ssh-host01/ssh-host02），**每台独立 Compose 项目**用于实际部署。选择已确认不等于 SSH 主机/私网/真实凭据的操作授权。
- [ ] 确认实际 **三台不同** Linux Docker Engine 的 operator/资产归属、受控连接方式（已有 VPN、private routed network 或获准 overlay）、私网 IP/DNS/ACL、对外和节点间防火墙、可信 SSH host-key 来源与更新批准流程；不得把同一 Engine 多容器视为完成 Mode B。
- [ ] 确认 Linux Engine/cgroup v2/SELinux/AppArmor 等实际限制、可信镜像/依赖 digest 和其批准来源；逐个 SSH 容器独立 cgroup 委托/manager/root bootstrap 的权能边界需特别设计和审核。
- [ ] 记录 Portal/client 能力及 owner、Docker/host-root 权限、批准的 SSH 凭据/host keys、业务数据卷可写范围、备份/撤销 owner 和可处置目标环境。
- [ ] 记录 M0 **PARTIAL_CONFIRMED**（只涵盖已确认的双部署模式）；ADR 状态仍 `Proposed`、整体设计/计划仍 `DRAFT`、其余安全/环境/发布授权仍 `WAITING_FOR_CONFIRMATION`。不要因范围已确认就标记可执行或发布。

### M0a — 无 Docker 权限时的可交付离线拓扑形态预检

- [ ] 提供安全、可重复的 **operator CLI**：仅读取 16 KiB 以内的正规 JSON 文件，判断声明的 Mode A 是同 Engine 双 SSH target、Mode B 是三个独立 Engine 标签（不证明其真实身份），校验固定 `node01/node02`、语法固定的 image SHA256 digest 和不同 SSH host-key fingerprint，未知字段/秘密/特殊文件/超限与错误模式必须拒绝且不回显输入。
- [ ] 同一用户命令可以得到有界单行 machine JSON 正向结果，**始终**声明 `deployment_ready=false`、网络/运行时/真实信任/真实 E2E 未验证；反向必须退出非零、不输出任何机器成功结果。纯离线运行，不启动 Docker/SSH、不授权新 trust 或 host root。独立测试双 Python + 手册，并在 feature PR 内独立 review。
- [ ] 完成后仍然不能把 M1a/M1b 或 A01–A18 标记 PASS；它只是缩短实际部署前的可发现配置错误，而不是完成 SSH Compose 产品。见 [操作员预检手册](../../runbooks/mvp-topology-preflight.md)。

## 2. M1a — 单机开发/E2E Compose 控制面与两个 SSH containers

**Files:**

- Modify: `deploy/compose/compose.yaml` 的接口契约；Create: `deploy/compose/compose.dev-ssh.yaml` 作为**单 Linux Engine 的可销毁多 SSH 容器 overlay**；更新 `deploy/compose/reference.env.example`；必要时 `.github/workflows/ci.yml` 中适用的 Compose 静态校验（不增 workflow 权限）。
- Create: `deploy/ssh-target/Dockerfile`、`deploy/ssh-target/sshd_config`、`deploy/ssh-target/host-agent-*.service` 或经审核的准确进程 supervisor contract、`deploy/ssh-target/install-manifest.json`（精确资产/权限），`docs/runbooks/compose-multi-ssh.md`、`tests/ops/test_compose_ssh_targets_contract.py`、`tests/live/test_compose_ssh_targets.py`。
- Reuse: `src/ssh_over_mcp/host_agent` 的 manager/cgroup/identity/ForceCommand 现有实现，以及 `ops/live-e2e` 的**安全测试思路**，但不能把 E2E 信任根或测试 root launcher 原样视为生产启动资产。

**Interfaces:** `docker compose -f deploy/compose/compose.yaml -f deploy/compose/compose.dev-ssh.yaml config` 为单机开发/E2E 提供无真实 secrets 的可验证构型。`node01`、`node02` 采用不同本地 volumes/host-key pins。**此 overlay 不得作为 Mode B 生产入口**。

- [ ] **RED：** 静态负向测试证明不存在目前可部署的两个 SSH targets；检测公网/未受限 `ports: 22`、`privileged`、docker.sock、host PID/NET、宿主 `/`、宽写 cgroup、共同 RW 卷、未 pin host key，缺少每目标隔离配置不得通过。再对**现有 MCP `ssh_egress: {}` 没有目的地 allowlist**与**默认可变镜像 `ssh-over-mcp:phase6b`**建立 RED 安全测试，避免将现有配置误判为仅可 SSH egress / digest 固定；生产新入口必须对现有 Compose 行为提供明确回归和迁移边界。
- [ ] **RED：** `tests/live/test_compose_ssh_targets.py` 定义真实连接正向：控制面可连接两台 `sshd` 的固定 SMCP/ForceCommand；负向：错误 host key、SSH PTY/port forwarding、manager outage、容器重启后隔离失效、横向卷访问失败；未获主机权限时标记 NOT_RUN/SKIPPED，不伪装通过。
- [ ] **设计/权限门禁：** 对 Compose 中 Linux Engine 的 cgroup v2 可委托范围、manager UID、launcher bootstrap 和仅 CAP_SETUID/CAP_SETGID 使用做单独威胁分析与独立审核；在每个 target 内验证不共享能写入祖先 `cgroup.procs` 的 workload 权能。若可行性不成立，**不要用 privileged/cgroup host root mount 解决**，保持 M1 HOLD 并提交可审阅的替代隔离架构 ADR。
- [ ] **GREEN：** 在获准的受限环境实现 Compose overlay/镜像/固定端点/手册，让 `node01` 和 `node02` 可以按指定身份配置启动并分别持久化卷与 host keys；复用原控制面 Ledger、admin socket 分隔、可选 private Tunnel，禁止 `sshd` 公网 host port。
- [ ] **验证 Mode A：** `docker compose config` 负向扫描 + 新测试；随后**仅经明确许可**在干净、可销毁 Linux Engine 上运行两个真实 sshd/manager, 验证 A01–A03 全项正反、重启清理、host-key 不变、审计前置；所有验收绑定镜像 digest/配置/源码 SHA。**明确记录 `MODE_A_PASS` 不能作为 `MODE_B_PASS`。**
- [ ] **PR 门禁：** 目标资产的 root/bootstrap 新信任来源如超出现有 ADR0007，则先完成对应 ADR/安全设计批准，再把功能实现和负向证据纳入本阶段；PR Ready 前有可复验真实正向与拒绝证据，或明确 BLOCKED，不能用只读 `config` 通过伪装完成。

## 2b. M1b — 三台独立宿主机 Compose 实际部署（独立交付门禁）

**Files:** Create `deploy/ssh-target/compose.yaml`（每台独立 Linux Engine 分别部署相同审查过的镜像/契约）、`deploy/ssh-target/reference.env.example`（每宿主机独立 secret/host-key/data 路径）、`deploy/compose/reference.multihost.env.example`（控制面每目标私网/hostname/host-key pin mapping）、`docs/runbooks/compose-multi-host.md`、`tests/ops/test_compose_multi_host_contract.py` 和 `tests/live/test_compose_multi_host.py`；必要时扩展 `docs/cloudflare-deployment.md` 和 `config/pilot/rw` 下两节点示例，禁止写入真实认证材料。

**Interfaces:** 受信的三个独立 operator-owned Linux Docker Engine：`control01` 独立 Compose 控制面项目、`ssh-host01`/`ssh-host02` 每台各自执行 `docker compose -f deploy/ssh-target/compose.yaml`（项目自身不控制其他 Engine）。MCP host inventory 由服务端绑定每个节点固定私网 endpoint + pinned host key + server-side credential ref，且跨主机网络先由 operator-owned VPN/private routing/firewall 提供。Docker Compose 的单机内部 `bridge`/DNS **不能被错误地当作跨宿主机网络**。默认模板使用不可能生产直连的占位值，所有占位符和缺少 host key/secret 来源 fail-closed。

- [ ] **RED：** 严格静态/集成测试确认不存在可用的真实多宿主机项目和网络证据；三个 Compose 配置分别验证非 privileged、无 Docker socket/host net/PID/cgroup root rw、无 SSH 公网 ports、**MCP 只能向两台获准 SSH private endpoints 出站**、节点间私网 lateral ACL 拒绝与远端节点不得调用 Ledger/admin、每节点独立数据/host-key/凭据与 manager 隔离；任何未按 digest pin 的生产镜像拒绝部署。错误 private address、缺少主机密钥、意外开放到互联网均阻止 deployment；不能把 Mode A 测试标记 Mode B PASS。
- [ ] **RED：** 在 `tests/live/test_compose_multi_host.py` 定义 A15–A18 实际接收条件：三**不同** Docker Engine 的 identity/hostname/digest，并验证断连与主机重启不会抹除 per-host operation journal/UNKNOWN 阻断状态；`control01` 分别访问 ssh-host01/02；强制验证 control→SSH allowed、SSH01↔SSH02 forbidden、公网 SSH forbidden、SSH→ledger/admin forbidden；错误/更换 host key、网络分区、远端节点失联、重启、非法审批重试均 fail-closed；无法获授权时保留 NOT_RUN。
- [ ] **安全设计与 operator 门禁：** 选择并书面批准跨宿主机私网/ACL、镜像/证书/key 来源、三个 Engine 的独立管理权限与部署边界；对远端 container 的 TCP/22 选择**仅私网接口显式发布 host-port**或批准的私有容器路由，并验证 Docker NAT/iptables/nftables、IPv4+IPv6、forwarding/direct routing、不同 gateway modes 和其他公网接口路由都不会绕开 default-deny ingress、禁止 `0.0.0.0` 公网监听；绑定私网 IP 本身不代表公网拒绝，须真实黑盒测试。若采用 Docker multi-host overlay，其 Swarm 集群管理权限应另获批准，不可由普通 Compose bridge 代替。逐个 Linux Engine 实证 delegated cgroup v2/manager/host-agent 的 CAP_SETUID/GID、ForceCommand、非 root 工作负载、运行时 namespace 和可写数据根隔离；不能靠 `privileged`, Docker socket, rootfs/cgroup rw 规避。
- [ ] **GREEN：** 提供可重复的每宿主机 Compose 安装/启动/更新/回滚 runbook（不能宣称单 Compose 自动横跨其他物理主机），附每主机固定镜像 digest、可恢复 host key、数据卷/SSH 用户配置、MCP 的固定逻辑别名私网地址/SSH pins、operator firewall/inbound allow list 与 out-of-band 密钥管理。要求重启之后 SSH 公网 ingress 仍关闭；停机、版本漂移、秘密缺失阻止 ready。
- [ ] **验收/PR:** **只有经分别批准的三台实际 Engine** 上的 A15–A18 全量正反/**互联网未授权目标出站拒绝**/网络分区/更新和审计数据均与精确源码/Compose config/image digest 对齐才将 `MODE_B` 标 PASS；现有本地回归、Mode A PASS 或 PR CI skipped 均不可替代。单独安全 review、host authorizations 和 operator merge approval；若 cgroup 或私网权限被阻断则保持 Draft/BLOCKED。

## 2c. Typed filesystem execution identity / resource contract (M1a, M1b, M2 prerequisite)

- [ ] **现有实现差距：** `src/ssh_over_mcp/host_agent/cli.py` 的 `FsStat/FsRead/FsMkdir/FsWrite` 在主机端**先于** `connect_authenticated_containment_manager` 和 `run_prepared_native` 被 `_run_filesystem_request` 执行，不继承 `ssh_exec` 的 per-request cgroup/child UID/privilege-drop 证明。M1a/M1b/M2 均必须针对**每个文件 typed 操作**明确最低有效 UID/GID/caps、manager 状态/服务依赖、descriptor-pinned OS access、进程隔离、CPU/IO/内存/打开 FD/深度/时间限制以及取消、写入中断与 UNKNOWN 结局。
- [ ] **RED：** 真容器中使用文件操作协议而非 `ssh_exec` 的 runner，证明在当前高权限 host-agent 上不能未经额外 host policy/OS 边界执行超限或越权 `fs_write/delete`；覆盖 manager unavailable、cgroup 不可委托、延迟/慢设备、FIFO、卡住的目录遍历、超时取消以及服务重启后资源残留。关键隔离路径未实证时保持 M1/M2 HOLD。
- [ ] **设计/安全审核：** 如需访问 manager，必须遵守现有独立管理者信任、身份降权和授权 IPC，不给普通 host-agent/SSH payload 通用 cgroup 迁移权；如选择独立受限 FS helper，需定义其预期开启文件身份、cap 归零、timeout/limit/error 后关闭以及与 ADR0007 精确 launcher 的兼容，独立 review 和对应隔离 E2E 后才启用 mutation。绝不能以 `ssh_exec` 的隔离通过代替所有 FS 操作的正反测试。

## 2d. 实现前的跨层协议冻结门禁（M2a/M2b/M2c/M2d BLOCKED，均 NOT_RUN）

**必读及单一权威：** [设计 §2a — 四份版本化契约](../specs/2026-10-23-private-compose-rw-mvp-design.md)：SMCP v2 中央策略快照/epoch/Host 逐节点授权、Host Policy v5 deny 子树、per-host durable Operation ID journal/commit receipt/UNKNOWN 协调、八种 FS typed schema。旧 SMCP v1 只支持单次 metadata envelope（`FsStat/Read/Mkdir/Write`）；Host Policy v3/v4 只有 allow roots；Ledger 只持久化审批/审计而没有远端文件提交状态。**四份契约需要先冻结并通过独立设计 Review，不能因为代码能够完成基本正向就向正式 MCP 暴露新操作。**

- [ ] **P1 快照/逐节点授权 RED：** 用当前 `ssh/protocol.py` 和 `policy/matcher.py` 证明**没有**受信 epoch 绑定的中央完整子树 ACL 快照、host 中央策略验证/撤销协议、policy version 同步或每节点 host 授权。构造根 allow + 子树 deny、policy 更新中断、部分 host ACK、网络隔离、过期/重放快照、签名 MAC 修改及 cursor 续页攻击；任何未确认 live policy epoch 的目录遍历/结果都拒绝且不泄漏路径和数量。
- [ ] **P1 协议冻结 GREEN：** 设计/独立审核 SMCP v2 新 envelope（显式版本/不可降级），含中央签发并可在 host 验证的 bounded 完整 effective subtree decision snapshot、签名/MAC、`policy_epoch`/digest、host identity/profile/root/tool、expiry/request ID、预算；Host 每次扫描节点前同时应用快照和本地 Host Policy deny、中央返回结果前同 epoch 再复核。策略变更要**冻结新操作、取消旧 epoch 查询和 cursor、等待所有相关 host 的撤销/新 epoch ACK**；ACK 不齐、epoch 丢失/回滚、网络分区或 snapshot 不受信一律 fail-closed。仅最终结果过滤不足以过关。签名密钥和策略 epoch 恢复的权威/信任根不可由 PR 自证。
- [ ] **P2 Host Policy schema 冻结：** 在 M2a 编码新 list/search 之前确定独立 **HostExecutionPolicy v5** 拟议 schema/配置样例/签名与 operator 升级路径：每 capability `allow_roots`, `deny_subtrees`（匹配子树根和所有后代）、metadata/content 可见性、资源预算、epoch/digest；中央及 host 的 deny 优先级、路径规范/挂载安全一致，v3/v4 对新增能力拒绝；定义错误 schema/unknown fields、祖先 deny + 子孙 allow 冲突、仅 `deny /srv/data/secrets/**` 的入口拒绝、`/secrets2` 不误匹配、Host rollback 与配置重启失效的两版本兼容矩阵。`HostFilesystemProfilePolicy` 当前 `extra=forbid` 及 v3/v4 不允许 silently accept 新规则。
- [ ] **P1 持久 operation 协议冻结：** 新增服务端全局 `operation_id` 与 host-bound immutable fingerprint、Ledger 先存 operation/approval audit，远端 per-host journal 的 `PREPARED→APPLYING→COMMITTED/ABORTED/UNKNOWN`、durable commit receipt/witness、SMCP v2 status-only 查询及重放拒绝；必须定义文件数据与 host journal 的真实崩溃一致性顺序，以及如何对齐 control ledger 和远端状态。当前 `request_id`/一次性 approval 消费**不等于幂等**。冻结恢复/冲突目标隔离策略：UNKNOWN 不自动执行、**新的人工审批也不得盲目重放 append/move/delete**；恢复需审计 Ledger、Host journal 与 inode/generation/digest 多证据，不能消歧则保持冻结。任何无法证明不可重复副作用的模式 release HOLD。
- [ ] **P2 typed API 冻结：** 先冻结可实现且严格向后兼容的 MCP/SMCP v2 Pydantic JSON Schema、source/target paths、审批绑定、`fs_search` 的 `name_glob` basename `*`/`?` 匹配与 `content_literal` 严格 UTF-8 字节级内容模式（无 regex）、固定 UTF-8 relative-path 字节排序、1–64 只对授权结果分页/opaque snapshot cursor、0–8 搜索深度；`fs_write` create `target_absent`、replace/append 必带旧目标 inode/generation+size+SHA256 的 `if_match`、操作 ID 与内容 digest、原子/持久提交和 UNKNOWN 分类。明确 `INVALID_REQUEST/DENIED/POLICY_STALE/CONFLICT/PRECONDITION_FAILED/LIMIT_EXCEEDED/UNSUPPORTED_ENCODING/IO_FAILED/UNKNOWN` 等稳定安全错误，不反射拒绝路径。冻结 deterministic 合成/竞争/故障的 RED vectors：UTF-8 invalid、空/超长查询、大小写、glob 特殊字符、跨页变更、cursor 重放、并发写改变、磁盘满/fsync 前后 crash、重复 `operation_id`、新 approval 与未知旧 operation。
- [ ] **先决条件复核：** 双 Python 源码/协议回归、独立安全设计评审、明确的 schema 版本兼容/迁移/rollback 和跨主机故障矩阵都记录到精确 HEAD；不能借此开放真实工具。只有冻结后才能实施 M2a/M2b/M2c/M2d，对照版本化契约审查每次功能迭代。Stage 1 仍须独立测试权限，Stage 2 的既有正式开放门禁及 premerge Native Level-3 不变。

## 3. M2a — `fs_list`/`fs_stat`/`fs_read`/`fs_search` 全部只读能力

**Files:** `src/ssh_over_mcp/api/{models,service,server}.py`, `src/ssh_over_mcp/ssh/{protocol,filesystem}.py`, `src/ssh_over_mcp/host_agent/{protocol,filesystem,policy}.py`, `src/ssh_over_mcp/policy/{models,matcher,engine}.py`, 新 v5 Host Policy schema/config + v1/v2 compatibility/migration tests, `tests/api/test_filesystem.py`（或实际现有最贴近模块）、`tests/ssh/test_filesystem.py`、`tests/host_agent/test_filesystem.py`、`docs/mcp-api.md`, `docs/policy-spec.md`。**M2a 之前必须完成 2d 的 Host Policy deny-subtrees/schema/epoch 和 SMCP v2 快照协议冻结**；测试路径若不匹配现有结构，先用真实目录确认后在 Draft PR 锁定精确文件名。

- [ ] **RED（P1 子路径泄漏/策略变更）：** 当前 `policy/matcher.py` 只判定请求路径，SMCP v1 无中央逐节点协议；必须证明 **parent allow 不蕴含 descendant allow**，并覆盖 epoch 不一致、MAC 篡改、Host Policy v3/v4 对新工具拒绝、目录扫描中策略撤销和旧游标重放。在 Mode A/B 每个 host 建造合成对抗树：允许 `/srv/data`、显式拒绝 `/srv/data/secrets` 与 `/srv/data/secrets/**`，其余目录允许；分别覆盖 `deny /srv/data/secrets` + `deny /srv/data/secrets/**` 与**仅有 `deny /srv/data/secrets/**` 的子树规则**，都不得泄漏 `secrets` 入口名称；调用 list/search 根及分页、多页/排序/大小限制、按文件名及内容搜索。拒绝子树的**入口名称、后代内容/metadata、命中总数/页数、游标、错误**均不得出现或反推出存在；再测试 deny 紧邻允许子项、跨页过滤、policy 版本变化后重放 cursor、节点 rename/symlink 替换、分页截断、FIFO/深度/慢搜索和 host-key 错误，所有未授权结果必须 fail-closed。
- [ ] **GREEN（取决于 2d SMCP v2/v5 冻结）：** 按**中央签发的完整快照 + policy_epoch/digest/过期/签名 + Host local deny**实现**远端逐遍历目录/文件节点授权**与 deny 子树先剪枝（不仅在结果过滤中隐藏），并在 MCP 发送客户端结果前以**同一 active epoch**进行中央再授权；策略更新须先取消旧快照/游标并等待所涉及 host 的 revoke/activate ACK，否则拒绝整个请求，绝不下发 root allow 后走旧 v1 远端遍历。返回条目/读取搜索内容之前逐项鉴权；授权路径需考虑 canonical 父子关系、所有祖先 deny、文件类型和目录 FD/inode 防 TOCTOU。只有通过授权过滤后的可见结果才能排序/计数/分页；opaque cursor 绑定 host/profile/root、policy version、filter/sort/page limit、有限时效且不能编码敏感名字或真实未授权偏移；规则不确定/变更/竞态直接拒绝、不返回局部结果。实现有界 list/search 请求/结果、独立 host roots/central allow+deny，无 shell/find 后门。
- [ ] **验证：** Mode A 和 Mode B 的真实 MCP list/search 正反路径，覆盖**父目录 allow + 子目录 deny**、中央授权快照/Host v5 policy-epoch 与签名错误、Host 收到旧版本、撤销 ACK 不齐、策略更新时游标续传拒绝、匿名 host/profile/游标重放及 `name_glob/content_literal` UTF-8 搜索；不可泄漏受保护名称/metadata/内容/数量；时间/深度/匹配/输出边界、独立 security review、精确 HEAD Native Level-3；完成 A04/A05 对应部分，不能只靠新增工具注册或 stub 判 PASS。

## 4. M2b — `fs_mkdir` 与 `fs_write` 的创建、追加、替换

**Files:** `src/ssh_over_mcp/api/{models,service,server}.py`, `src/ssh_over_mcp/host_agent/filesystem_mutation.py`, `src/ssh_over_mcp/host_agent/policy.py`, `src/ssh_over_mcp/ssh/{protocol,filesystem}.py`, `tests/api/test_filesystem_mutations.py`、`tests/host_agent/test_filesystem_mutations.py` 或同等现有测试、`docs/mcp-api.md`、`docs/policy-spec.md`。

- [ ] **RED：** 证明 create-only 现有实现不会覆盖/append；冻结 `create/append/replace` typed schema 与旧 target inode/generation/size/SHA256 的 `if_match` 及安全错误；测试 stale target、已存在目标、原子替换、操作 journal 未落盘/文件已提交而 receipt 未持久、网络中断、**人工新 grant 重放同一 append**、中断/磁盘满/fsync、并发写/父目录 symlink 及内容 hash/长度变更拒绝。
- [ ] **GREEN（取决于 2d typed/operation 协议冻结）：** 严格定义 `fs_write` v2 的 `mode=create/append/replace`、`target_absent` 或强制 `if_match`（旧 inode/generation/size/SHA256）、新数据 digest/size、host-bound global `operation_id` 和 per-host durable journal/收据；实现同卷 staging+atomic commit 或同等有实证的 crash-safe 顺序，旧 create-only v1 调用绝不变成 overwrite。**不能用 Ledger 消费 grant 替代远端去重，也不能以禁止自动重试代替 UNKNOWN 人工重试条件。**
- [ ] **不可用功能门禁：** M2b 可先完成严格 RED/GREEN；append/replace 在**生产配置中始终未暴露/默认拒绝**，仅可参照 M2c Stage 1 在操作者批准的 Mode A/隔离 Mode B、同候选 SHA、非生产凭据与数据根上受控做完整正反验收。M2d 的 source/destination/mode typed central policy、approval binding、Ledger/audit 严格迁移、一次性拒绝测试、独立审查及**合并前该 PR 精确 HEAD 真实 Native Level-3** 均通过前不得对正式环境开放；测试成功不授予生产权限。
- [ ] **安全门禁：** 追加/替换跨失败重试不默认重复写；一次性精确审批绑定 mode、host、目标路径、数据 digest/size 和 policy version；写成功与 post-attempt audit failure 有清晰不确定态。
- [ ] **验证：** 真实两目标容器读回数据、对比旧内容、拒绝跨根/跨目录卷/host、负向稳定无额外副作用；完成 A04/A06/A07 对应部分。

## 5. M2c — `fs_move`/`fs_delete` 的有界不可逆文件操作

**Files:** 同 M2b 适用 API/host-agent typed layers + `tests/host_agent/test_fs_move_delete.py`、`tests/api/test_fs_move_delete.py`、`docs/mcp-api.md`、`docs/security-model.md`（若新增实际不变量）。此外必须对 central `policy/models.py`、`policy/matcher.py`、`approvals/{models,binding,authorization,ledger,storage}.py` 的变更契约进行显式设计/测试，并锁定审批 Ledger 迁移与版本兼容。

- [ ] **RED：** 证明当前操作缺失；测试**同一 SSH host、同一获准根**内移动**普通文件**、删除普通文件与空目录；目录移动（包括空目录）**默认拒绝**，只有独立并发安全门禁证明后才能添加空目录移动正向验收。必须拒绝**非空目录移动（尤其其中有被 deny 的受保护子路径）**、已存在目标、目录非空删除、跨 SSH host、跨挂载、跨授权根、symlink/hardlink 绕过、并发 parent swap、检查空目录后并发创建子项以及递归删除。
- [ ] **GREEN：** 受限 destination/source typed schema 和 host policy 检查；目录 FD/inode pinning、空目录验证/竞争隔离、存在性/跨卷/失败原子性与删除审批，跨失败重试不执行第二次；拒绝**非空目录移动**以及任何未经批准的隐式 copy+delete。若未来放宽为非空目录移动，必须先对全部受影响子项的源/目的授权和抗竞争扫描另写 ADR，不能以父目录单点 allow 代表子项 allow。
- [ ] **Stage 1 — 仅授权隔离验收环境可调用（解决正向 E2E 循环）：** 在普通生产构型中，`fs_move` / `fs_delete` **始终未注册/不可用或双层 DENY**，包括 `ssh_exec` 等价绕行；内部 typed 实现可先 RED/GREEN。为了验证真实 MCP 正向调用，仅在操作者批准、可销毁的 Mode A **和**隔离 Mode B E2E 环境里，使用**与待审 PR 相同的候选源码 SHA / image digest**和独立非生产身份、host keys、Ledger、数据卷、审批、固定地址，启用显式 test-only capability，并限制目标端口/网络为获准测试主机。test-only flag/config 不能由 MCP 用户请求切换，不得挂接生产凭据/数据，不能被默认生产 Compose 继承；执行正向、边界/竞争、双路径拒绝、审批重放/失败和审计测试，结果标 `TEST_ONLY`，结束后关闭能力并销毁相关容器/卷，校验无残留。无真实验收授权、最小 host 隔离或资源上限，则保持 NOT_RUN，不能在生产上代试。
- [ ] **Stage 2 — 正式开放硬门禁（M2c → M2d + 2d durable Operation ID 协议）：** Stage 1 可用于收集证据，**不代表**工具获得生产能力；**必须先冻结并实测 per-host durable operation state/commit receipt 与跨网络 UNKNOWN 恢复，证明同 ID 不重做、人工新 approval 不造成重复不可逆副作用。**要正式开放 `fs_move` / `fs_delete`，以下条件必须**同时**通过：① M2d 对 source 和 destination 的**双路径、双 host-side/central allow + deny-overrides-allow 授权**（delete 检查目标、父目录、权限和 inode 前置条件，move 还检查目的父目录/已有目标）；② 一次性 Ledger 精确审批绑定 host、tool、source、destination、操作 mode、对象先决条件，跨 host/path/operation/mode 改参、重放、重试均拒绝；③ Ledger/audit/safe-summary/schema 版本化迁移、审计前置持久化与失败/UNKNOWN 处理通过；④ **同一候选构建**在 Mode A 和隔离 Mode B 的适用正反/资源限制验收及独立安全 review、精确 HEAD CI 全部 PASS；⑤ 根据 `docs/development-methodology.md` 在**可信已合并 main 编排器**的无网 guest 中对**同一精确 PR HEAD**取得真实 Native Level-3 PASS/清理证据，**合并前**完成；⑥ 合并/发布/生产启用分别取得操作员显式批准与适用的部署验收。任何 NOT_RUN、SKIPPED、证据 SHA 漂移或失败，正式环境都保持 **UNAVAILABLE / DENY（release HOLD）**；PR-native skipped 不等于 Native PASS，合并后 main11/11 不得代替合并前精确 HEAD 验证。
- [ ] **空目录移动的独立并发安全门禁：** **不能仅以先检查为空、随后调用 rename 来证明安全**。必须证明在源目录 FD/inode/父目录和目的父目录锚定的整个检查→提交窗口内，攻击者无法并发创建/迁入子项、替换父目录或通过 mount/symlink/hardlink 搬运被 deny 的内容；完成可重复的恶意线程/进程竞争、并发取消与失败原子性测试。**只要不能给出可复核的内核级同步/隔离或其他等价的无竞争保证，就独立禁用所有目录移动（包括空目录），即使普通文件 `fs_move` 已满足前述 M2d 门禁；不能把测试未撞到竞态当作证明。** 非空目录移动始终不在首发授权范围内。
- [ ] **验证：** 先在 Stage 1 的 Mode A/隔离 Mode B 非生产数据根对同一候选构建执行普通文件 move 与文件/空目录 delete 的 MCP 正向及全面拒绝验收；**正式环境只在 Stage 2 所有门禁、独立批准通过后**才验证启用。目录 move 仅在单独并发门禁通过后演示，否则 `DIRECTORY_MOVE_DISABLED` 且测试其拒绝；对抗跨 host/跨路径与审计/异常状态，完成 A04/A05/A06/A07/A08 的证据，不将 TEST_ONLY 误报为生产开放。

## 6. M2d — 完整多主机策略、审批与审计配套方案

**Files:** `config/pilot/rw/control-plane.example.yaml`、`config/pilot/rw/host-node01.example.yaml`、`config/pilot/rw/host-node02.example.yaml`、`config/pilot/rw/credential-map.example.yaml`、`docs/runbooks/compose-multi-ssh.md`、`tests/policy/test_compose_rw_profile.py`、`tests/api/test_compose_rw_approval_journey.py`、`tests/live/test_compose_rw_journey.py`，**并明确修改/回归** `src/ssh_over_mcp/policy/{models,matcher,engine}.py`、`src/ssh_over_mcp/approvals/{models,binding,authorization,ledger,storage}.py` 及对应 approval/ledger/schema tests（以实际路径为准）。

- [ ] **RED：** 当前 `EvaluationRequest` 只绑定一个 `path`，`build_approval_binding` 不含目标路径或写入 mode；新增 mutation 工具的 grant schema 不能只依赖现有 create-only binding。测试 append↔replace mode-only 变化、move destination-only 变化、目标身份变化、同一内容不同 host 的批准不能重用；新字段 missing/extra/unknown 一律严格拒绝。
- [ ] **GREEN：** 在暴露新写入能力前，把 source/destination、mode、源对象 inode/generation/size/hash 前置条件、bytes/content digest、额度及**server-minted `operation_id`** 作为 validated typed 字段贯穿中央 `EvaluationRequest`→policy matcher→`ApprovalBindingInput`/safe summary→Ledger 持久化/状态/审计，**并与各 host 不可复用的 durable operation journal/commit receipt 绑定**；明确版本化 schema、旧单路径调用兼容/不兼容旧 grant 的 fail-closed 迁移。实现对同 ID+fingerprint 的**状态查询而非再次执行**、不同 ID 但相同 UNKNOWN 目标的冲突冻结，不能用客户端提供的字符串绕过绑定。
- [ ] **RED：** 当前配置不等于全 RW profile；两个主机的不同读写根必须由 central/host policy 同时决定，deny 覆盖 allow。所有 mutation/high-impact read 必须 approval_required 且 SSH 连接前无副作用.
- [ ] **RED（P1 绕过检测）：** `rw-operator` 的 `ssh_exec` **默认拒绝**与 typed FS 相同的文件 mutation，包括 mkdir/create/append/replace/mv/rm/chmod/chown、解释器和 shell 包装、重定向、可控 argv/env/stdin/cwd 和同等副作用的命令组合；Mode A/B 的真实 E2E 应验证即使 typed FS 工具是 Stage 1 TEST_ONLY 或正式生产 DENY，也不能用 `ssh_exec` 完成等价写入，目标卷前后 digest/目录树、Ledger/审计和拒绝状态必须一致。非变更型诊断 `ssh_exec` 只允许固定可审计命令、不含路径/环境逃逸；将来任何等价写权限须新增独立 ADR/操作者批准并证明不弱于 typed FS 双层策略与精确审批/审计，否则禁止。
- [ ] **RED：** 跨 `node01`→`node02` 重放、create→replace、路径变更、内容变更、policy 变更、过期、重复重试和审计拒绝一律不能执行；写工具不可未经额外批准变成 root/ssh_shell/Docker 控制。
- [ ] **GREEN：** 单个 static `rw-operator` profile 的完整八工具配方、按 host 的固定独立根、独立 host key、最大读写限额和一致性测试；独立审批入口 `approvalctl` 沿现有 Ledger 语义运行。
- [ ] **M2c Stage 2 正式开放前置：** M2d 必须先交付**双路径中央/host 策略**、目的目录/目标对象/删除父目录授权、source/destination/mode/inode 前置条件参与的一次性精确绑定、Ledger/audit 严格版本化迁移与拒绝重放/修改/UNKNOWN 结果测试。Stage 1 仅支持**非生产隔离验收**的同 SHA test-only capability；任何 M2d/Native/Review/CI/真实验收依赖未实证，则正式 `fs_move`/`fs_delete` 保持 UNAVAILABLE / DENY。空目录移动另外证明不可并发插入/替换，否则目录移动禁用。
- [ ] **验证：** 先在**明确批准的隔离 Mode A/Mode B Stage 1 TEST_ONLY 环境**，用同候选构建完成真实两 SSH host 写入→读取→普通文件 move→文件/空目录 delete+跨 host 拒绝、审计/不确定结果负向验收；仅在单独证明空目录并发安全时才演示目录 move。全量策略/API/SSH/审批测试和该安全边界 PR **合并前精确 HEAD Native Level-3** 均通过后仍须独立 operator 生产启用/部署批准；A04–A08 绑定精确 SHA，不能依赖 stub 或 PR-native skipped job。

## 7. M3 — 私有 Portal 下的真实客户端全读写

**Files:** `docs/runbooks/compose-multi-ssh.md`、`docs/cloudflare-deployment.md`（必要时）、`docs/evidence/compose-rw-client-acceptance.md`、`tests/live/test_compose_deployment.py`（只延伸真实差异，不重复原有测试）。

- [ ] 确认操作员真实客户端 Streamable HTTP/Portal OAuth 能力与私有 hostname；仅在明确账户/网络许可下配置已批准 Portal/Cloudflare，不开放 origin/SSH 公网 port。
- [ ] 在 **Mode A 和 Mode B 分别**从真实客户端，对两个别名执行 hosts/policy、list/stat/read/search、mkdir、write create/append/replace、move/delete、读回/确认以及跨 host 错配/审批改参/重放/无权限 bearer 拒绝。**Mode B 必须观测 control01 经批准私网访问两台不同实际 SSH Engine**，证据有 operator 和 source/image/config digests；不能以本机 Docker network 的运行结果替代。
- [ ] Mode B 额外验证未授权 Portal 用户、坏 origin bearer、错误 host key、私网 ACL、公网扫描拒绝、网络分区、某节点掉线、Ledger 宕机和恢复重试，无跨 SSH 主机越权、未审计或第二次写副作用；只报告完成真实检查的 A09/A10。

## 8. M4 — Compose 多卷一致性、恢复与撤销

**Files:** `docs/runbooks/compose-rw-operations.md`、`docs/evidence/compose-rw-operations-acceptance.md`、`ops/pilot/check_cold_restore.py`（如确需有界检查）、`tests/ops/test_compose_rw_cold_restore.py`、`tests/live/test_compose_rw_recovery.py`。

- [ ] **RED：** 真实 **control01 Ledger + ssh-host01 data/key01 + ssh-host02 data/key02** 三套不共享存储在不同时间恢复时不一致，尤其 **Ledger grant 已消费但 Host 未记录操作、Host journal PREPARED/APPLYING、文件已更改但 durable commit receipt 未完成、控制面以新 grant 再次要求 append**；任意节点不可达/时钟不可信、旧审批 granted、第 101 条未过期审批、损坏 checkpoint 或旧审计尾段都不能恢复服务或实施第二次副作用。Mode A 同时做受限快照演练。
- [ ] **GREEN：** Mode B 由控制面关闭新审批/写入口，在**每台 SSH 宿主机分别**隔离写入口，按 **operation_id + host identity** 核对 Ledger 与远端持久 `PREPARED/APPLYING/COMMITTED/ABORTED/UNKNOWN`、commit receipt 和文件 inode/generation/hash；无法消歧保持 UNKNOWN/冻结目标并禁止**自动及盲目人工新审批重试**，不因失联认定未执行。待确认无在途危险写操作且所有节点停止后，分别做当前冷快照与可信统一 checkpoint、镜像/config/host key digests；scanner 不能自动开放网络/清 DB/换 key，pending/granted 必须完整扫描并等待可信 UTC 严格晚于 expiry。
- [ ] 实际验证多数据卷+审计 checkpoint 一致性、host key 独立恢复、错误密钥对拒绝、撤销 MCP bearer、每台 SSH 凭据与 Portal 访问后旧身份不可用；完成 A11/A12。

## 9. M5 — 精确 RC、完整验收与操作者批准发布

**Files:** `docs/evidence/compose-rw-mvp-release.md`、`docs/releases/compose-rw-mvp.md`、`docs/mvp-status.md`、`docs/development-plan.md`、`README.md`（实际功能落地后）。

- [ ] 收集 **A01–A18（含 A15–A18 多宿主机）** 的真实环境、operator、精确源码/image digest、**每个实际 Engine** 的 Compose config、私网/firewall route/ACL、各 sshd host key、测试/审计与权限拒绝证据；未实测的 ID 保持 NOT_RUN，不使用单测合成 PASS 填写。
- [ ] 运行双 Python 版本全回归，**分别**完成 Mode A 的单机可销毁 E2E 和 Mode B **control01 + ssh-host01 + ssh-host02 三 Engine** 的真实 Compose/SSH/manager/cgroup/私网 ACL/host key/读写/客户端/分区正反验收、独立源代码与安全审查及必需的 existing trusted-main no-network Level-3。未具备三台 Engine 或网络操作授权必须标记 `MODE_B_NOT_RUN` 并阻止发布。
- [ ] 精确 HEAD 经独立 review/CI 后请求 merge 批准，安全合并后对实际新 main SHA 使用 `python3 ops/live-e2e/merge_main_evidence.py --sha <actual40hex>`，必须 exit0、`MERGE_MAIN_VERIFIED 11/11`（包含真实 Level-3）。
- [ ] 冻结 RC 与 **Mode A 和 Mode B 各 Engine** 的全部 image/Compose/host-key/私网 ACL/config digests，提交具体跨宿主机部署、撤销、协调冷恢复与回滚方案，**额外获得每台 host、private network 和 operator release/deployment 的明确批准**后才实际发布；故障立即停止或回滚并保留证据。只有 A01–A18 中全部适用项真实 PASS 后才可标记 RELEASED。

## 10. 每个完整功能 PR 的统一执行循环

1. 核对真实 HEAD、Git status/PR/Review、已有 worktree 权属/`progress.md`、新旧批准记录；已有脏 worktree 不接管。
2. 独立 worktree 写 handoff `progress.md`、设计/威胁分析及验收 IDs；TDD RED→focused GREEN 后立即作者自审、开 Draft PR 并**及时请求早期独立 Review**，不等待完整 CI 或 Native Level-3。每个重大 GREEN/修复后的最新版本可重复请求审查；review findings 先修复并重测。
3. **并行开发与证据收集：** 早期独立 Review 可与双 Python 回归、负向竞争/越权测试、精确 HEAD 托管 CI、受许可的 Mode A/B test-only Compose probes 并行进行。PR 内容或 SHA 变化，旧 review/CI/Native 证据不自动继承；及时复查新 HEAD。这些并行活动不授予生产功能开放或 PR merge 权限。
4. **最终精确 HEAD Review / 合并前证据：** 收敛到候选不可变 SHA 后，取得该 HEAD 的独立最终 Review、所有适用 CI 与真实正反验收。**涉及 SSH transport、策略/审批/Ledger、host-agent、filesystem mutations、container/egress safety 的 PR**，必须经明确授权，在可信已合并 `main` 编排器的无网 guest 中对同一精确 PR HEAD 运行真实 Native Level-3，验证 guest/provider 清理；适用的真实 Compose probes 亦为合并前门禁。PR 自身 native SKIPPED、模拟测试或上一轮 main 11/11 不等于 PASS。关键 gate 未完成，PR 保持 Draft/BLOCKED；可继续独立审查，但**不能标记可合并 Ready 或请求 merge approval**。
5. **Merge Gate：** 只有最终同 SHA 的独立 Review CLEAN、完整 hosted CI 和需执行的真实 Native Level-3/Compose 验收达标，才进入 Ready 并另行请求 operator 精确 HEAD merge approval。使用受 SHA 保护的 squash merge；**合并后仍需实际新 main SHA 的 push/main 11/11（含真实 Native Level-3）**及额外多宿主机验收。只清理自己已归档、干净且完成的工作区/分支/远端 ref。
6. 不能从本 MVP 暗中扩展 T5B 信任根、Mac UID502/APFS 或 Linux provenance C/D 权限；遇到真正依赖阻塞写明 owner/影响的 Axx 和下一动作，不开展无关 C0 迭代。

## 11. 本次范围文档的审批与交接（仅文档）

- [ ] **用户已明确确认双模式范围**（单 Engine 供开发/E2E + 三个独立 Linux Engine 的 per-host Compose 实际部署）；等待用户审阅并**明确批准**新版 [ADR0021](../../decisions/0021-private-compose-rw-mvp-release-track.md)、本 spec 与本计划的其余安全、读写/容器权能细节。多宿主机具体 IP/私网 provider 和主机操作权仍未授权。
- [ ] 旧 docs-only 一次性直推 `main` 的请求是**条件式**，不能由本次范围修改自动启用。确认包含直推授权后只 stage 这批文档、检查 HEAD/remote 前进/全部相对链接、`git diff --check`，再尝试普通 fast-forward push；拒绝时走普通 docs PR，不绕分支保护。未经确认只保留 WIP。
- [ ] 推送后对**新的**文档 main SHA 做独立 canonical 11/11 验收；没验证前只记录已推送、不声称 MAIN_VERIFIED。
- [ ] 新产品实现仍必须走独立安全审查/feature PR/适用权限，不由 docs push 授予 host root、Docker、SSH host key、OAuth、merge 或 release 权限。
- [ ] 更新 `docs/mvp-status.md` 和本地 `progress.md` 精确记录每个 Axx 的 NOT_RUN/PASS/REFUSED、具体 owner 和缺失输入；本会话仅是文档范围调整。

## 12. 计划自检

- Spec §1/3 的**双模式 Compose** → M1a A01–A03 + **M1b A15–A18**；§2 八工具 → M2a/M2b/M2c/M2d A04–A08；§4 真客户端必须两模式 → M3 A09–A10；§5 **真实跨宿主机**恢复/撤销 → M4 A11–A12；§6/7 **双模式**发布/HOLD → M5 A13–A14。
- 原旧只读 observer/M1 单机原生安装计划不再能证明 MVP 完成；保留其历史安全不变量，不照搬其验收结论。
- 当前所有 checkbox 未勾选；设计 Proposed，验收 NOT_RUN，真正 Compose/SSH 读写和发布没有被宣称已实现。
