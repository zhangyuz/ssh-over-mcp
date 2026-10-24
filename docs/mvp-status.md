# MVP 当前交付入口：Compose 多 SSH 读写试点

> Candidate offline operator capability (unmerged, 2026-10-24): [`ops/mvp/subtree_visibility_preview.py`](../ops/mvp/subtree_visibility_preview.py) previews synthetic `fs_list`/`fs_search` path allow/deny subtree decisions only. It does not enable any MCP/host-agent tools, central snapshot or Host Policy v5, and does not change A01–A18 NOT_RUN or #342 Docker deployment HOLD. See [runbook](runbooks/mvp-subtree-visibility-preview.md).

**状态：双部署形态已由用户明确确认；ADR0021 其他安全设计/实施计划仍为 PROPOSED / DRAFT，待评审确认。**
**当前代码基线：** `6c3a2aee2a55baed86e7a871268c8eb9b0d194af`（PR #339 合并后的 main；[push-main CI #40007266579](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/40007266579) 为 11/11 PASS，含 Native Level-3）。本页仍是 MVP 工作计划状态，不是 Compose 实际部署/验收证据。

用户已确定的 MVP 目标：**MCP Server 和每一个 SSH Server 均使用 Docker Compose 部署**，至少两个独立 SSH 目标；支持 **全部八种 typed 文件读写操作**，在受控数据根内执行并保留现有审批/审计/SSH 隔离。**必须同时交付两种模式：Mode A 单 Linux Engine 多 Compose 容器供开发/E2E；Mode B 不同 Linux Engine 上分别启动独立 Compose 项目（control01 MCP/ledger/approval + ssh-host01 + ssh-host02）供实际部署。** 多宿主机模式需要 operator-approved 私有路由、SSH host-key pins、firewall/ACL 和真实网络故障验收，不得用单机测试代替。禁止以“支持所有读写”推出裸 shell、任意 host root 或 Docker 管理能力。

- [拟议架构范围 ADR0021](decisions/0021-private-compose-rw-mvp-release-track.md)
- [Compose 全读写 MVP 设计](superpowers/specs/2026-10-23-private-compose-rw-mvp-design.md)
- [实施计划](superpowers/plans/2026-10-23-private-compose-rw-mvp.md)
- [开发与安全验收方法](development-methodology.md)
- [完整 v1 历史路线图](development-plan.md)

## 当前 MVP 实现迭代（独立 feature PR，非部署验收）

- **离线 Compose 拓扑形态预检（已合入 main，PR #339）：** `python3 ops/mvp/topology_preflight.py --topology-json manifest.json`。支持声明式 Mode A 单 Engine + `node01`/`node02` 和 Mode B 三个不同 Engine 标签、OCI image digest 格式、SSH host-key fingerprint 格式、无秘密回显的拒绝与有界读入。参见 [离线部署拓扑预检手册](runbooks/mvp-topology-preflight.md)。**它只校验未认证的静态结构**，所有通过报告都明确 `deployment_ready=false`，runtime/network/trust/live E2E 均未验证；不能替代 M1a/M1b 真正的 Docker Compose 安装、host-agent/cgroup 隔离、host key 可信验证或主机部署许可。该检查仅为已合并的独立静态操作功能，绝非 M1a/M1b 的部署完成证明。
- **离线 Compose 配置结构预检（当前 feature 候选）：** `python3 ops/mvp/compose_config_preflight.py --mode dev-e2e|multi-host --control-json FILE ...` 可在不调用 Docker/SSH 的情况下，检查预先渲染的 Mode A 单 Compose 项目或 Mode B 三份独立 Compose 描述，并拒绝可识别的 mutable image、危险 host ports/caps/volume sharing/target lateral networks。详细输入/拒绝契约参见 [Compose 配置预检操作手册](runbooks/mvp-compose-config-preflight.md)。**所有通过报告均为静态形态、deployment_ready=false**；Mode A/B 真 Docker Engine、host keys、隔离及 network ACL 未测试，M1a/M1b A01–A03/A15–A18 继续 NOT_RUN。此候选在本 PR 合并前不得称为 main 已实现。

- **离线拓扑⇄Compose 交叉一致性预检（候选功能）：** `python3 ops/mvp/bundle_preflight.py --topology-json ... --control-json ... [--node01-json ... --node02-json ...]`。把 manifest 的 Mode A/B、控制面与两个 SSH 目标的 OCI **digest 声明字符串**与已渲染 Compose 配置进行有界一致性拒绝检查，避免两份独立有效的静态文件相互矛盾。它不会认证镜像来源、真实三台 Engine、SSH host-key、网络或运行时权限；通过时 `deployment_ready=false`。见 [离线跨文档一致性预检手册](runbooks/mvp-compose-bundle-preflight.md)。在独立 PR 审核合并之前不得称为 main 已交付或部署已验收。

## 当前工具实现差距

已存在 typed MCP `fs_stat`、`fs_read`、`fs_mkdir`（仅 create-only）、`fs_write`（仅 create-only）。**尚不能声称全功能：** `fs_list`、`fs_search`、`fs_move`、`fs_delete`，`fs_write` 覆盖/追加均需实现与真实验证；`fs_move` 首发只在同一 SSH host 获准根内生效，非跨主机文件转移。现有 host-agent 的 typed FS dispatch 在 manager/子进程降权前执行，现有中央 approval binding 缺少 move destination/write mode 两字段；**安全实现任务必须补齐，不得沿用旧 `ssh_exec` 隔离证据/旧 grant 假设。** **M2c 发布阻断：** `fs_move`/`fs_delete` 在 M2d 双路径中央/host 授权、一次性审批绑定、Ledger/audit 迁移、对抗验收和**合并前精确 HEAD Native Level-3** 全部 PASS 前必须保持 UNAVAILABLE/DENY。`fs_move` 首发仅可考虑普通文件；**空目录移动须单独证明检查→提交期间的并发安全，否则所有目录移动保持禁用**，非空目录始终拒绝。现有 Compose 已涵盖 MCP/ledger/admin/可选 Tunnel，但**尚无可验证的生产 Compose sshd 多目标栈**；其 `mcp` 的 `ssh_egress` 尚未限制出站目的地，默认 `ssh-over-mcp:phase6b` 也不是不可变生产 image digest，属于 M1a/M1b 安全阻断项。

| Milestone | 状态 | 核心完成标准 |
|---|---|---|
| M0 范围/安全决策 | PARTIAL_CONFIRMED | **两模式范围已确认**；ADR/spec/plan 其余内容、实际 host/cgroup/private network 权限仍待审批 |
| M1a 单机开发/E2E | NOT_STARTED | 同一可销毁 Linux Engine 的 Compose 控制面 + 两个独立 SSH 容器，真实隔离/ForceCommand（A01–A03） |
| M1b 多宿主机实际部署 | NOT_STARTED | control01/ssh-host01/ssh-host02 三台不同 Linux Engine，各自 Compose、私网 ACL、host-key、容器权限和故障演练（A15–A18） |
| M2 完整 typed 文件读写 | NOT_STARTED | 八种能力正反路径、覆盖/追加/移动/删除、安全审批/审计（A04–A08） |
| M3 真实 MCP 客户端 | NOT_STARTED | **Mode A 和 Mode B** 完整八工具；真实客户端在 Mode B 访问两台独立远端 SSH Engine，跨网络/认证拒绝（A09–A10） |
| M4 冷恢复与撤销 | NOT_STARTED | Mode A 演练与 Mode B 控制面+两远端节点**跨宿主机**多卷一致性、审批不可重放、凭据撤销（A11–A12） |
| M5 RC/发布验收 | NOT_STARTED | **两种模式分别真实 E2E**、A01–A18、独立 review、exact-main CI + 每宿主机部署/发布批准（A13–A14） |

## 全局代码/安全一致性复核（文档设计项，尚未落地）

- **P1 合并前 Native Level-3：** `docs/development-methodology.md` 要求 SSH、策略/审批、host-agent、filesystem mutation/egress 变更的 **PR 精确 HEAD** 在合并前经可信 `main` 编排器、无网 disposable guest 完整 Level-3；合并后对 **新 main** 的 11/11 是另一独立门禁。未经实际授权或 native skipped 不能声称可合并。
- **P2 文件操作身份隔离：** 现有 `host_agent/cli.py` 的 typed FS 请求在 manager 连接、`ssh_exec` 工作负载降权之前独立执行；需要为每种 FS 读写操作设计/实证有效 UID/GID/caps、OS root 边界、资源/时间/取消和 manager failure refusal，不能借用 `ssh_exec` containment PASS。
- **P2 新变更审批：** 现有 `EvaluationRequest`/`ApprovalBindingInput` 尚不包含 `fs_move` destination 和 `fs_write` append/replace mode；必须版本化扩展 policy、binding、Ledger/audit 与迁移测试，防止同一 grant 在不同 mode/目标之间被重用。M2b/M2c 新能力在生产未具备该依赖前不得开放；M2c 同候选 SHA 可仅在获许可、可销毁、与生产完全隔离的 Mode A/B 环境 `TEST_ONLY` 执行正反 E2E，获得 Stage 2 证明前继续生产 DENY。
- **P2 目录移动：** 首发 `fs_move` 默认只有普通文件的同一 SSH host/许可根内移动；**空目录移动单独 HOLD**，直到可证明检查→提交窗口中无并发创建/迁入子项与父目录替换。无法证明时禁止全部目录移动；非空目录移动始终拒绝。`fs_move`/`fs_delete` 必须先完成 M2d 和精确 PR HEAD 合并前 Native Level-3 才可开放。
- **Compose 原有实现差距：** 控制面 `ssh_egress` 目前未限制目标出站；默认 `ssh-over-mcp:phase6b` 是可变 tag。M1a/M1b 都必须完成 egress allowlist/deny、生产 image digest pin 与 Docker NAT/forwarding/iptables/nftables 实测；本机 Compose/E2E 成功不能代替多宿主机 M1b A15–A18。

- **P1 子路径授权/检索信息泄漏：** 目前 matcher 只检查请求目录；`fs_list`/`fs_search` 新实现必须逐遍历目录节点、逐文件及返回条目进行 central/host 授权，先剪枝 deny 子树，再只对可见结果分页/计数，隐藏拒绝子树的名称、内容、统计、游标/错误。以父目录 allow、子目录 deny 的 Mode A/B 对抗 E2E 为 A05 必需门禁。
- **P1 `ssh_exec` 绕过：** `rw-operator` 默认拒绝任何等价文件修改命令及 shell/解释器/重定向绕行；只读诊断必须独立严格 allow。任何例外另需 ADR/批准，并证明所有 typed FS 路径、mode、审批、审计约束不被绕过及真实负向 E2E。
- **P1 M2c 两阶段测试/开放：** 使用相同 SHA/digest 在获准可销毁 Mode A/隔离 Mode B 中以独立凭据、非生产数据和 `TEST_ONLY` capability 验证正向 MCP；生产始终 DENY。只有 M2d、双层双路径授权、一次性审批、Ledger/audit 迁移、独立最终 Review、精确 HEAD CI/合并前 Native Level-3 及真实两模式验收全部通过并获得 operator 启用许可，生产才开放。
- **P2 Review 并行纪律：** focused GREEN + 作者自审后及时开 Draft 并请求早期独立 Review，可与完整 CI/Native/Compose 测试并行；候选定稿后对精确 HEAD 重新完成最终独立 Review 和 merge gates，不能因早期 Review 已 CLEAN 就省略合并前验证。

**上述安全/交付阻断项当前均未完成真实验收；ADR 仍 Proposed，M1a/M1b/M2–M5 均 NOT_STARTED。**

## 新增协议级交付阻断项（均 NOT_IMPLEMENTED / NOT_RUN）

- **P1 中央→Host 遍历授权：** 现有 SMCP v1 仅请求级 `path`，没有可信中央 subtree decision snapshot、Host 端逐节点签名/epoch/expiry 校验、策略变更撤销 ACK/游标作废和中央结果复核。拟新增 SMCP v2 + Host Policy v5；**不可把事后过滤当安全边界**。Mode A/B 必测一台 host 在扫描时策略撤销、另一 host 不确认、快照篡改/旧版本及 deny 子树入口泄漏。
- **P1 分布式写入状态/幂等：** 现有 `request_id`/Ledger approval 消费没有与远端文件副作用一致的持久化 `operation_id`/Host journal/commit receipt。网络断连、commit-但未记收据、Host crash、人工重新审批都可能重复 append/move/delete；必须有 per-host durable journal、UNKNOWN 隔离与三方状态核对。无法证明安全不重做时，相关写入 mode 必须保持 DENY。
- **P2 Host Policy deny schema：** `HostFilesystemProfilePolicy` 当前只有 stat/read/mkdir/write_create allow roots，v3/v4 不支持 deny 子树及策略 epoch；新功能首先冻结 v5 明确的 allow/deny-subtree 优先级、子树根包含语义、版本迁移/回滚拒绝及 central/host 冲突向量。v3/v4 不能意外启用新 list/search 或 mutator。
- **P2 typed API 契约：** `fs_search` 的 restricted basename glob / UTF-8 literal、过滤后稳定排序/快照分页/一致性；`fs_write` 的 create absent、replace/append 精确 if-match generation+size+SHA256、durable Operation ID、UNKNOWN/CONFLICT/PRECONDITION_FAILED 等固定响应，在实现前必须完成 schema 与竞争故障测试向量冻结，不能将现有 create-only 行为静默改变。

以上与现有 **M2c Stage 1 隔离验收/Stage 2 生产开放**、合并前精确 HEAD Native Level-3 和合并后新 main 11/11 均是累计门禁，不互相替代；ADR0021 仍 Proposed，四项协议设计与真实部署没有获得正式执行或发布批准。

现有 `main` 的 [CI #39882670723](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/39882670723) 是旧基线 `MERGE_MAIN_VERIFIED 11/11`，**不能作为新 Compose 多 SSH 全读写的验收证据**。Issue [#259](https://github.com/zhangyuz/ssh-over-mcp/issues/259) 的 T5B/UID502/APFS/protected staging 与 Issue [#256](https://github.com/zhangyuz/ssh-over-mcp/issues/256) Linux C/D 仍 HOLD。

本次只更新待确认文档；**没有**创建 SSH 容器、部署 Compose、执行权限操作、启用新读写工具、推送 main 或发布 Release。
