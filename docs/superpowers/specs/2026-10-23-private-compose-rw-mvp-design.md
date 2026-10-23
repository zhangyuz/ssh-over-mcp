# 多 SSH 服务器读写型 Docker Compose MVP — 设计草案

**状态：DRAFT（部署双模式已确认，其他架构/安全设计待用户评审）。** 这份设计替换旧「单台原生主机、只读 observer」试点。范围更新不等于实现完成、可信镜像许可、主机提权、部署或发布批准。

**基线：** `0123346040eedae0fa4a92f50e556ba925fffd36`。
**决策：** [ADR0021](../../decisions/0021-private-compose-rw-mvp-release-track.md)。**实施计划：** [Compose RW MVP plan](../plans/2026-10-23-private-compose-rw-mvp.md)。

## 1. 用户目标与 MVP 边界

一个组织的同权限使用组，借助一个真实 MCP 客户端，经私有 Portal 进入固定 profile 的 MCP 控制面，操作多个**由 Docker Compose 部署的独立 SSH 服务器**。用户在受控路径内执行现有及新增**完整文件读取与写入操作**，每次读写经中央策略、主机端策略、SSH 主机密钥验证、需要时的审批及不可跳过的审计。用户只提供受信库存中的逻辑主机别名和限定工具参数；不直接选择 SSH 地址、密钥、凭据、主机身份、管理能力或操作 profile。

**MVP 必须同时交付、分别验收两种部署模式，用户已明确确认：**

- **Mode A — 单机开发/E2E：** 一台隔离、可销毁的 Linux Docker Engine，运行现有 MCP/ledger/approval Compose 控制面及至少两个 SSH Compose 服务/容器（`node01`、`node02`）。每个 SSH 服务独立 host key、策略、数据卷与 agent/manager 隔离。MCP 通过受限的内部容器网络访问目标，不发布 SSH 或控制面公网端口。适于高频、可重复的自动化正反回归，不作为多宿主机交付证据。
- **Mode B — 多宿主机实际部署：** **至少三台不同的、独立管理的 Linux Docker Engine 宿主机（独立物理机或 VM，不能是同一 Engine 上的多个容器）**：控制面主机 `control01` 用自己的 Compose 项目运行 `mcp`、`ledger`、`ledger-init`、`approvalctl` 和可选 `cloudflared`；独立 SSH 宿主机 `ssh-host01`、`ssh-host02` **各自执行本机 Compose 项目**，运行各自的 `sshd`、host-agent/manager 和独立持久化数据/host-key 资产。它们不是同一 Docker Engine 的两个容器，也不由一个 Compose 命令跨主机调度。控制面通过**经操作者批准的私有可路由网络**访问各 SSH 容器，固定 server-owned 地址/凭据/host-key 映射，主机网络防火墙只允许所需 MCP 来源访问指定 SSH 端点。MCP/ledger 管理 socket、密钥和节点数据卷绝不跨宿主机共享。

两种模式必须复用同一 SSH-target 镜像、host-agent/SMCP/安全策略语义与用户可见八工具接口；**各自的 Compose 项目结构、网络配置、能力约束和 E2E 验收证据独立**。Mode B 默认采用操作者管理的 VPN/私有路由与每宿主机独立 Compose；若选择 Docker multi-host `overlay`，其 [官方网络文档](https://docs.docker.com/engine/network/drivers/overlay/) 要求额外的 Docker Swarm 管理信任与节点加入操作，必须另行做权限/威胁分析及 operator 授权，不得把普通 Compose bridge 误认为跨主机网络。实际私有路由方案（如现有 VPN/overlay/私有路由）由部署操作员确认，不假设 Docker Compose 跨主机 networking 内置或直接接受任何公网 port。

## 2. MVP 功能清单与当前实现差距

“所有读写操作”指文件系统契约的全部八种**typed capability**，不限于已有 create-only 子集。首发不允许“任意路径的无限制读写”；读写在配置授权的共享/专用数据根内由操作系统权限独立约束。

| MCP 能力 | MVP 正向场景 | 当前 HEAD 的观察（不是实现承诺） |
|---|---|---|
| `fs_list` | 列出获准目录（有界条目/分页） | 尚无 MCP/host-agent 完整端到端适配 |
| `fs_stat` | 获取已许可文件、目录元数据 | 已有 typed 适配 |
| `fs_read` | 读取有界普通文件内容 | 已有 typed 适配 |
| `fs_search` | 在获准目录内有界检索文件/名称 | 尚无端到端适配 |
| `fs_mkdir` | 创建新目录，必要时逐层创建的语义必须单独审查 | 现有实现仅单层 create-only |
| `fs_write` | 创建、覆盖和追加普通文件，具备清楚的并发/原子性语义 | 现有仅 create-only，覆盖/追加不支持 |
| `fs_move` | 同一 SSH host/获准根内移动普通文件；**空目录移动仅在并发安全已证明后开放**，否则全部目录移动禁用；非空目录移动始终拒绝 | 尚无端到端适配 |
| `fs_delete` | 删除许可根内指定文件、空目录；递归删除需要单独设计及授权 | 尚无端到端适配 |

MVP 的“全读写”验收仅在上述**允许的操作语义及明确的数据根**内成立；`fs_move` 仅限**同一 SSH host 内**受授权的源/目标，不承诺跨 SSH host 的自动 move/copy/原子事务；任一 host 上的真实文件内容取决于该 host 经挂载的数据卷，不能跨 host 复用同一身份/路径授权。不能把 `fs_write` 当通用 shell，不能用任意 `/bin/sh`/解释器/包管理器/容器工具替代缺失的 typed API。**`rw-operator` profile 默认拒绝 `ssh_exec` 中所有能产生等价文件系统副作用的命令**（创建、覆盖、追加、移动、删除、chmod/chown、脚本/解释器和可写重定向等），无论是否位于固定 argv 白名单；不得绕过 typed FS 的路径/模式/精确审批/审计门禁。保留非变更型 `ssh_exec` 诊断命令仅在双层策略独立 allow、固定 executable+argv/cwd/env/stdin、可证明无 FS 副作用且有 E2E 拒绝证据时允许。将来确需通过 `ssh_exec` 开放任何等价写入，必须单独进行威胁分析与 ADR/操作者批准，证明与 typed FS **相同或更严格的路径授权、host、mode、destination、一次性批准、审计和故障拒绝**，并在合并前对绕行与替代 executable/argv 验证；不能仅添加白名单。`ssh_shell`、`service_action`、root/sudo、任意脚本执行与裸 Docker 管理**不是**该读写 MVP 的隐含能力，继续默认拒绝。现有 MCP registry 目前是九工具集合；新增 `fs_list/search/move/delete` 必须有正式行为、host-agent 协议、独立策略及双层验证，不能仅增加 tool name。

**读写安全要求：**

- 所有目录与文件必须有 canonical 绝对路径、服务端硬上限、profile/host-specific allow roots、deny 覆盖 allow，并在 host 端以 no-follow、`openat`/descriptor-pinning 或同等措施防止 symlink/TOCTOU 穿透、path traversal、mount 跨界、hardlink 越权、special-file/FIFO 阻塞。每项新操作独立验证边界。
- **`fs_list`/`fs_search` 子路径授权不继承父目录 allow：** 现有 `policy/matcher.py` 只按请求的一条 `path` 判定；允许列举 `/srv/data` **不等于**允许观察 `/srv/data/secrets` 或其后代。每次进入候选目录/打开文件**之前**，分别在中央策略与 host-side policy 上确认该节点的 canonical 绝对路径及所有必需的祖先路径；每个返回的路径、文件名、stat metadata 和内容片段也必须独立通过工具/host/路径 allow、所有层级 deny-overrides-allow（含 deny 子树）检查。**拒绝子树必须在遍历前剪枝；即使规则仅写作 `/srv/data/secrets/**`，其子树入口 `/srv/data/secrets` 的名称也须视为不可观察（需要明确的祖先/子树 deny 语义，不能仅按现有 `fnmatchcase` 字面结果匹配），否则拒绝整次请求；入口名称、后代名称/内容、匹配数、总数、分页游标及错误均不能让用户推知其存在。** 对允许父目录下被 deny 的直接子项，返回列表也不能包含其名称，即使搜索模式不会进入该子项。无法安全判定的节点、规则冲突、policy version 变化或遍历 race 一律 fail-closed，不返回局部敏感结果。实现不能简单复用只验证根路径的 matcher；须设计逐节点授权接口与 host-side 复核，并对 symlink/rename races 使用目录 FD/inode 锚定。
- **分页/搜索隐私约束：** 在**逐项授权并剪枝之后**才允许收集结果、计算可见计数及分页；游标须不透明、绑定 host/profile/root、policy version、filter/sort/page limit、受信快照或固定遍历状态与 expiry，不能直接含真实目录路径或被拒绝条目偏移。policy 改变、目录竞态或游标失效必须拒绝或从新的已授权快照重新启动，不能泄露旧页面结果。搜索内容时，在读取任意字节前先对该文件路径通过独立读授权；`fs_list` 不得仅凭父目录允许而返回子文件的机密属性。目录深度、匹配数、遍历时间、分页大小、最大输出和资源均有硬上限；超限 fail-closed 或仅返回明确授权后的截断结果，不能无界全盘枚举。
- `fs_write` 的 `create`、`replace`、`append` **必须明确区分**并有可审查的原子性/条件写契约；默认禁止覆盖，显式覆盖需匹配受限目标和审批。写中断、磁盘满、并发修改不得无意截断旧数据或出现静默重复写入。
- `fs_move` 首发默认只允许**普通文件**在同一个 SSH host、同一获准 filesystem/root 内安全重命名；**所有目录移动默认禁用**。仅当能够证明检查与提交窗口内不会被并发写入/迁入子项、父目录替换或以 mount/symlink/hardlink 绕开限制时，才可**单独启用空目录移动**。先 `readdir` 发现为空再 `rename` **不构成并发安全证明**；无法证明（或测试仅未复现竞争）则必须拒绝空目录移动。**非空目录始终拒绝**，以免搬走被 deny 的受保护子项（当前中央 matcher 只按被请求的单条 path 匹配）；必须拒绝跨权限区、跨 mount 和目标覆盖，不能隐式 copy+delete。未来若扩展非空目录移动，另需全部源/目的子项有界授权、抗竞争证明与独立 ADR。
- `fs_delete` 首发只允许指定文件/空目录，不支持递归清空数据卷；删除是不可逆操作，必须明确审批及审计。若希望递归删除，需单独威胁分析、设计和验收，不能悄然算入“所有读写”。
- **`fs_move`/`fs_delete` 两阶段开放门禁（M2c → M2d）：** **Stage 1 — 授权隔离验收环境**：默认生产 config、registry 与 host policy 均保持 `UNAVAILABLE / DENY`；为了避免循环依赖，可以只在经过独立批准、可销毁的 Mode A 和隔离的 Mode B 验收环境中，对**同一固定候选源码 SHA/镜像 digest**启用明确的 test-only capability allow 与非生产凭据/数据根，运行完整 MCP 正向、双路径对抗、故障、审批/审计负向测试；生产环境不能因测试开关、共享卷或同一镜像而继承授权，严禁连接真实生产数据，失败即关闭销毁，证据必须标为 `TEST_ONLY`、不得宣称发布 PASS。Stage 1 的启用以最小可验证的双层拒绝、测试身份隔离和 operator 测试许可为前提，不能把 test-only toggle 暴露给 MCP 用户或任意 SSH 负载。**Stage 2 — 正式环境开放**：仅在 M2d 的 **source/destination 双路径中央/host deny-overrides-allow 授权、一次性精确审批、Ledger/audit/safe-summary 严格版本化迁移**，Stage 1 两种模式的正反验收与独立安全 review、精确 HEAD CI、以及**合并之前同一精确 PR HEAD 真实 Native Level-3 PASS** 全部达标后，才允许经单独 operator 批准将对应工具在正式 profile/registry/host policy 中启用。任何条件 NOT_RUN/SKIPPED/失败则生产 `fs_move` 与 `fs_delete` 保持 `UNAVAILABLE / DENY`。空目录移动还需独立的并发安全证明，否则所有目录移动禁用。
- 写入操作（`fs_mkdir`、`fs_write` 各模式、`fs_move`、`fs_delete`）以及高影响读取，默认需完整 **一次性精确审批**，绑定静态 principal、host、tool、source/destination、内容 digest/size、模式、policy version、限额；修改参数、重试、同一批准跨主机复用均拒绝。**当前 `policy.models.EvaluationRequest` 仅有一个 `path`，`approvals.binding.build_approval_binding` 不含 destination 或 mutation mode**：必须先扩展严格 typed 中央策略请求/检查、Ledger `ApprovalBindingInput` 和 safe summary/audit 持久化协议、精确版本/向后兼容或迁移。未完成前不能开放 append/replace/move/delete；只改变 mode 或 destination 也必须无法消费此前 grant。不得在未得到必要审计持久化前执行。审批后执行结果不确定不得报告成功或透明重试。
- **读路径**不得读 `/run/secrets`、host key、程序/配置密钥、container runtime/proc 控制界面；**写路径**不得触碰 `/etc`、SSH 认证/密钥、rootfs、宿主机配置、管理 socket、cgroupfs、其他 SSH 容器卷。示例只开放 `/srv/mcp-data` 下经挂载明确允许的读写数据卷。

## 2a. 实现前必须冻结的协议契约（全部 PROPOSED / NOT_IMPLEMENTED）

以下四项是 **M2a/M2b/M2c/M2d 的共同前置设计门禁**，不能把当前 SMCP v1、Host Policy v3/v4、Ledger 审批消费或 create-only `fs_write` 描述为已经实现。接口/存储字段的最终 JSON Schema、兼容性、安全证明和测试向量必须在首个对应实现 PR 的设计 Review 中冻结，变更时重新复核。

### P1 — 跨层逐节点授权与可信策略快照（`fs_list`/`fs_search`）

**选择：短期有效、不可降级的中央策略授权快照 + Host 端逐节点本地判定 + 中央结果复核；不是“只验证初始目录，再远端全量遍历，最后过滤”。**

1. 新增版本化 **SMCP v2** 文件遍历 request/response；必须显式新版本/能力协商，不能向只理解 `version=1`、只携带单 `path` 的 host-agent 自动降级。中央控制面在发起遍历前使用当前生效的 host/profile/tool/allow+deny 构造**完整受限的 effective subtree decision snapshot**（含 deny 子树根本身和后代、所有相关祖先），并附带 `policy_epoch`、`policy_digest`、`snapshot_id`、主体/profile、唯一 host 身份/host key pin、操作/根路径、资源预算、请求 ID、过期时间及受信签名/MAC；编译策略包含全部相关允许与禁止表达式，不能仅签署根目录“允许”结论。由已固定的独立密钥域验证来源/完整性，限制长度、TTL 和重放；不得把可修改的模型输入或 unsigned JSON 当权威策略。
2. Host-agent 必须在**扫描每个候选目录入口之前**验证 snapshot 密钥、版本、有效期、target/profile/root/请求绑定及**本地主机 Host Policy** 对应版本/epoch，执行中央快照**和** Host Policy 的逐节点双层 deny-overrides-allow；进入目录、读取文件内容、返回条目名称或 metadata 之前分别判定；deny 子树（含入口）在 host-side 剪枝，根本不访问被拒绝后代。拒绝节点的存在不得影响公开的计数、游标、分页或时间/错误区分（需要限时、统一拒绝并做侧信道对抗检验）；所有最终结果的 path/metadata/片段在 MCP 控制面**返回客户端之前**再次以同一已生效 `policy_epoch` 判定，不得靠这次复核替代遍历前授权。
3. **策略更新的全局撤销屏障：** 受信任控制面管理每个 host/profile 的单调 `policy_epoch` 与 digest。激活新策略前冻结该 host 的新遍历/分页，将旧 epoch 的在途遍历取消并使游标失效，等待所有关联 host 通过受信版本化 **ACK** 明确确认旧 epoch 已撤销、新中央策略和 Host Policy epoch 已同步激活；任一 host 离线/拒绝确认、快照过期、epoch 不匹配、签名/密钥不受信或状态无法核实，则**不允许新的遍历，并拒绝旧请求/页，不返回部分结果**。Host 在每次节点访问/分页续传检查本地活跃 epoch 和撤销状态；中央响应发送前也再次检查全局 epoch。不得用单纯长 TTL、单次开始时校验或最终过滤替代实时撤销。需说明消息认证、持久化 epoch 单调性、重启/回滚恢复策略，并独立证实分区与更新竞态下的 fail-closed。
4. `fs_list`/`fs_search` 的 page token 仅指向**已授权**的有界快照（或受信稳定遍历状态），绑定 snapshot ID/epoch、host、profile、查询、排序、页大小与时效；任何目录 inode/generation 或 policy 变化均使其失效。无界遍历、返回未经授权名称、被拒绝子树的总数/命中数/分页偏移等一律不允许。M2a 的前置 E2E 必须测试 parent allow + child deny、`deny /srv/data/secrets/**` 时也隐藏 `secrets` 本身，以及遍历中权限撤销/远端离线/重连/旧游标重放。

### P2 — Host Policy deny 子树 schema 与版本门禁

当前 `HostFilesystemProfilePolicy` 仅有 `stat_roots/read_roots/mkdir_roots/write_create_roots`，`HostExecutionPolicy.version` 仅接收 `3|4` 且 `extra=forbid`；没有逐操作 `deny_subtrees`、遍历时授权与策略 epoch。**拟新增独立且显式的 Host Policy v5（实现前审查冻结）**：每个 FS capability 的 `allow_roots`、`deny_subtrees`（严格 canonical 绝对目录根，**包括根节点与任意后代**，不是 `fnmatch('root/**')` 的不完整匹配）、操作/metadata/content 可见性及预算；必须定义多个 allow/deny 冲突时 **deny 优先**，受信 `policy_epoch` + config digest + 启用状态。一个更深层 allow 不能覆盖任何祖先 deny。`deny_subtrees` 与挂载/符号链接目标实际 inode 边界同时检查，不得仅做字符串前缀匹配（`/data/secret` 不匹配 `/data/secrets2`）。

- 新工具与新增写模式仅在同时支持新 Host Policy、SMCP v2 及 central policy snapshot 的双方显式协商后才可启用；Host Policy v3/v4 或旧 SMCP v1 必须对新增能力**拒绝，不能静默忽略规则/降级为仅 allow roots**。已有 v3/v4 四个 create-only/read 接口保持原语义，新增 v5 时需做单独可逆迁移/回滚验证；新能力切回 v4 时即失效，已有旧 grant 不得带进新版本。
- v5 parser 的缺失/多余/未知字段、重复或重叠冲突、错误 schema/epoch、未签名或被回滚配置、规则中无效路径、规则大小超限均 fail-closed。central 与 host 的 deny/allow 编译算法、canonicalization、根及祖先判断必须共享正式测试向量，且独立有歧义路径/规则冲突/策略回退与重启负向测试。具体 schema 版本号是**拟议方案**，不意味着已完成设计批准。

### P1 — 分布式 mutation Operation ID、持久化执行结果与 UNKNOWN 协调

**现状：** SMCP v1 的 `request_id` 只标记一次请求，Ledger 的 Approval 是一次性执行前授权；远端不存在与文件副作用绑定的持久化操作记录/可验证 commit receipt。它们不构成分布式事务或 Exactly-once。在 Mode B 的网络分区、SSH 断连、远端重启或人工再次审批后，append/rename/delete 可能被重复实施。

- 拟引入服务端生成、全局唯一且不可由 MCP 用户决定的 `operation_id`（足够随机、不可复用）；其 **immutable fingerprint** 绑定 host/host key identity、profile/principal、tool、源/目标路径、模式、内容 SHA256/长度、policy epoch、文件代际/先决条件、approval ID/version 及资源限制。Ledger **先持久化** operation + exact approval 消费记录/审计事件，再允许投递；Host 在独立受保护的 per-host durable operation journal 中对 ID+fingerprint 唯一约束，拒绝同 ID 不同输入、过期/跨主机重放。SMCP v2 写入请求携带同一 ID+受信绑定，Host 持久化 `PREPARED` 才可执行，并在变更前证明文件先决条件与资源范围仍匹配。
- 每个 Host journal 必须能追踪 `PREPARED`、`APPLYING`、`COMMITTED`（带不可伪造/可验证的 `commit_receipt`：operation ID、host identity、result fingerprint、目标 inode/generation/size/hash、journal 序号、durability/witness 状态）、`ABORTED` 或 `UNKNOWN`，所有状态转换和实际文件提交按经过审查的 **fsync/WAL/atomic rename/目录持久化顺序**完成；**不能假设 SQLite+文件系统天然具备跨资源原子事务**。Host 重复收到同 ID 时只能查询持久状态/返回同一已证实收据，绝不能再次执行写入。Ledger 保存远端凭据摘要、状态、时间/证据与审计链，中央重连仅向**原 host 身份**查询状态，不能重新消费旧批准或生成新的写入副作用。
- 断连、Host 不可达、journal 损坏、write/fsync 失败、commit 发生但 receipt 尚未持久化等**崩溃窗口**一律 `UNKNOWN`，此时**不能证明是否实施过副作用**：冻结目标文件/路径的重试和新的冲突 operation；**禁止自动重试，也禁止操作者通过新审批盲目再次 append/replace/move/delete**。人工恢复须以受信 host journal + 文件 inode/generation/digest + Ledger/audit 三方核对确定已提交/未提交；若无法证明，保留 UNKNOWN/隔离、独立人工调查，绝不猜测「尚未执行」。新 operation ID 只在有可审计的**未发生副作用证据或明确完成后的新不同业务意图**且重新校验文件先决条件后才能提交。多主机间不支持隐式跨 host 事务或 copy+delete 回滚。
- **验收硬门禁：** 同候选 SHA 在 Mode A、隔离 Mode B 模拟每个故障窗口（Ledger 已消费但 host 未接单、Host PREPARED、数据已落盘而 receipt 未落盘、远端分区、客户端超时、主机/控制面 crash、journal 重放、重复/新 approval ID），必须证明无重复 append 和不可逆 move/delete、状态可恢复或可靠保持 UNKNOWN；任何无法证明**安全可重试性或不可重复副作用**的操作 mode **保持 UNAVAILABLE/DENY**。不得以「客户端不要重试」作为持久化幂等证明。

### P2 — 冻结 typed FS API 的输入、排序、条件写与结果状态

以下是待审查的 **v2 目标契约草案**（须在 M2a/M2b/M2c 实现之前完成 schema/测试向量冻结；旧 SMCP v1 及 MCP 既有 create-only 调用不得改写语义）：

| Tool / field | 目标契约与不可歧义规则 |
|---|---|
| `fs_list` | `host`, `root`, `page_size`（1–64）, `cursor?`; 仅目录，受允许根和快照约束；响应为获准 relative paths/可见 metadata、`next_cursor?`、`policy_epoch`、`snapshot_id`，按 canonical UTF-8 relative-path **字节序升序**且只对已授权结果排序；不提供被拒绝目录总量 |
| `fs_search` | `host`, `root`, `match_mode = name_glob \| content_literal`, `query`, `max_depth`（0–8）, `page_size`（1–64）, `cursor?`; `name_glob` 为**大小写敏感的 basename glob，仅 `*`/`?` 通配**，拒绝 `/`、`..`、`[]`、反斜杠、正则语法及无界模式；`content_literal` 为 **UTF-8 严格编码的字节级字面子串**（不使用 regex、大小写折叠、Unicode normalization），非 UTF-8 文件或不能确定编码时整个查询统一 `UNSUPPORTED_ENCODING`，不泄漏具体路径；结果按 canonical UTF-8 relative-path 字节序、同文件 offset 升序，固定 page snapshot；先逐路径读取授权，再读取内容，永不跨 deny subtree |
| `fs_write(create)` | 路径与 `mode=create`、`target_absent` 必需；已有目标 `CONFLICT`，绝不隐式 overwrite；内容为明确长度、SHA256、规范 base64（现有 v1 规则保持）；全部写入受上限限制 |
| `fs_write(replace)` | `mode=replace` + 严格 `if_match`（**host-bound target inode/generation token、旧文件 size + SHA256**）+ 新内容 digest/length；若目标变化、被替换、同名 race 或 token 过期，一律 `PRECONDITION_FAILED`，不得截断旧文件或执行旧请求 |
| `fs_write(append)` | `mode=append` + 严格旧文件 `if_match`（generation token、size、SHA256）及追加 bytes/digest；必须证明**单 operation ID 幂等**，优先使用同卷 staging 完整新内容 + 校验后 atomic rename/目录 fsync（或同等经审查机制），禁止无 journal 的原地 append；并发改变时拒绝而非重复追加 |
| `fs_move`/`fs_delete` | typed source/destination 或 delete target、文件类型、当前 inode/generation 与目标不存在前置条件；只允许同 host/根，默认不覆盖目标、不递归删除，目录移动另需并发隔离证明；均带 `operation_id` 并走上述 durable journal |
| 错误/状态 | 固定机器状态 `INVALID_REQUEST`, `DENIED`, `POLICY_STALE`, `CONFLICT`, `PRECONDITION_FAILED`, `LIMIT_EXCEEDED`, `UNSUPPORTED_ENCODING`, `IO_FAILED`, `UNKNOWN`；均不反射被拒绝文件名/内容。变更成功必须返回经验证的 `COMMITTED` 收据，未确定只返回 `UNKNOWN`（禁止当成功或自动重试）。MCP 层的稳定 public error、SMCP 版本兼容及安全摘要要独立 Review |

必须明确：同一查询的排序、分页和匹配需要**有界稳定快照**；遍历中数据变化则拒绝/使 cursor 失效，而非将不一致的页面拼接成“确定性搜索”。这些字段、限制值及状态名称是**供冻结的设计草案**，不代表任何现有工具已经支持；实现前必须对正常、空内容、UTF-8 错误、边界值、并发变化、恢复/重放以及老客户端兼容编写确定性正反测试。对无法获得正确 inode/generation/快照能力的文件系统，相关 mode 必须禁用，不能删除前置条件以求兼容。

## 3. Compose 拓扑与隔离边界

复用 `deploy/compose/compose.yaml` 的 MCP/ledger/admin/cloudflared 控制面契约，同时提供两种不同的**显式 Compose 入口**。新 SSH-target 镜像/ForceCommand/manager 配方由安全审核冻结，禁止把 E2E fixture 的 root launcher 改名作为生产入口。

**Mode A — 一个受控开发/E2E Engine：**

```text
Compose on disposable engine:
  [mcp / ledger / approvalctl / optional cloudflared]
                 | isolated internal ssh networks
       +---------+-----------+
       |                     |
  [sshd-node01]         [sshd-node02]
  [volume01,key01]      [volume02,key02]
```

**Mode B — 多宿主机实际部署（每台都是自己的 Compose project）：**

```text
MCP Client -> Private Portal -> control01 (Compose: mcp/ledger/approval)
                                      | approved private routed network
                          +-----------+-----------+
                          |                       |
                   ssh-host01                 ssh-host02
                  (Compose: sshd)            (Compose: sshd)
                    data/key01                 data/key02
```

建议分别定义 `deploy/compose/compose.yaml`（控制面复用）、`deploy/compose/compose.dev-ssh.yaml`（Mode A 可销毁环境 overlay）和 `deploy/ssh-target/compose.yaml`（Mode B **每台** SSH 宿主机重复安装的独立项目），配套不包含真实密钥的双模式 operator 配置、host-key pin inventory 与 runbook。具体文件名在设计评审通过后冻结，不预先宣称已实现。

- MCP origin、ledger、approvalctl 与 `sshd-nodeNN` 均由 Compose 部署；MCP 不使用 Docker socket，不使用 `network_mode: host`、`pid: host`、`privileged: true`、共享宿主根目录或无约束 capability。`sshd` 服务不得对公网 `ports:` 发布 22；从外网到 sshd 不设 ingress。每个 SSH container 用独立持久数据卷/host-key 卷/登录凭据/host-policy；重建容器保留经操作员批准的固定 host key，变化必须拒绝而非 TOFU。
- 管理与审批 socket 不加入 SSH target 网络或文件挂载。**既有控制面 Compose 的 `mcp` 已挂载 `ssh_egress: {}`，它本身并非出站目的地 allowlist**；Mode A 中应分隔各 SSH container 对象的网络、禁止未经批准的对外出站并验证 deny，不能靠 `internal: true` 仅阻止外部 ingress 就声称 ssh egress 受控。Mode A 中目标间默认不许互访；如同桥不能隔离需每目标独立网络和防火墙，必须验证。Mode B 不共享 Docker network：经审批的 private routed network/VPN/overlay 只连控制面 MCP 出站→两 SSH 主机指定 22/TCP 入口，目标主机 ingress ACL 限制控制面来源，禁止 SSH01→SSH02 横向访问、未授权公网路由和反向访问 Ledger/admin。网络中断/攻击者发来的错误 host key 必须 fail-closed，绝不禁用 pinned-host-key 或在断网时开启开放端口。
- 每个 sshd 使用固定服务身份、只允许专用 SSH key、ForceCommand、禁止 PTY/forwarding/非经批准 shell，并由 server 端固定信任、credential-ref/host-key 映射。Mode A 可以绑定受限 Compose DNS alias；Mode B 必须绑定经批准的远端私网地址/名称 + SSH host-key pin，且 host key 更换须通过独立操作员审核和安全轮换，绝不 TOFU 或在重建后默默重置。用户不能拼接新 host、主机 IP 或 SSH 登录信息。
- **现有 host-agent 文件系统请求和 `ssh_exec` 不走相同执行链：** `host_agent/cli.py` 对 `FsStat/FsRead/FsMkdir/FsWrite` 在 manager 连接和工作负载 UID 降权**之前**直接分派到 `_run_filesystem_request`；不能用已通过的 `ssh_exec` per-request cgroup 测试证明 typed FS 操作也具有相同身份、capability、CPU/IO/进程、取消或 manager-outage 拒绝保证。M1/M2 必须明确文件操作的最小有效 UID/GID/capability、容器和 OS 路径访问边界、per-request 资源/超时、调用后权限清理、manager 缺失时 fail-closed，以及对应真实正反验证；必要时设计一个独立受限文件操作 helper/管理入口，不能直接在特权 host-agent 进程执行可写操作。
- 现有 host-agent 原生 `ssh_exec` 设计依赖 CAP_SETUID/CAP_SETGID 和**独立管理者拥有的委托 cgroup v2 子树**。Compose 服务不能通过简单挂 `/sys/fs/cgroup` rw、`--privileged`、宿主 Docker socket 或 Docker Desktop 的伪 Linux cgroup 视为满足。**实施前必须先做 Linux Engine 上的权能/委托/降权/manager 身份威胁建模与可重复正反验收。** 若容器无法达到现有隔离不变量，则阻止这条 Compose SSH 产品链上线，另写 ADR 和获批的隔离架构；不可降低原有限制来达成“一条 compose up”。
- **当前 `deploy/compose/compose.yaml` 中控制面镜像默认是可变的 `ssh-over-mcp:phase6b`，不是固定 digest，M1 必须明确增加生产镜像 pin/验证机制，且不得直接改变旧部署默认行为而没有迁移与回归测试。** 发布镜像需固定 digest/批准来源，非 root 常态运行；只有经独立审核的精确 bootstrap 可在有限启动阶段拥有所需权能，完成约束、验证、降权后再导入应用。安装冲突、旧宿主卷、已有 UID/GID 与旧密钥状态一律 fail-closed，绝不自动 chown、删除或接管。
- **每个 Linux Engine 都独立验证**镜像 digest、`docker compose config`（仅处理不含真实秘密的配置或经过可信脱敏后的结果，防止 secret/env 进入日志）、网络/端口/卷/用户/cap/security-opt、运行中 sshd/ForceCommand、cgroup/UID、真实文件读写正反案例、重启/故障/日志和持久化。Mode B 容器对外可达的 22/TCP 必须经 operator 批准采用**仅绑定私网接口的精确 host-port 映射**或明确受控容器子网私有路由之一，配合主机 ingress allowlist/默认拒绝、防 Docker NAT/转发规则绕开防火墙；不允许 `0.0.0.0:22` 或任何公网网卡暴露。**绑定私网 IP 不是充分条件**：如果宿主机启用 IP forwarding，其他接口也可能经路由访问该已发布端口；需覆盖 IPv4/IPv6、Docker `nat`/`routed`/`nat-unprotected` gateway modes、direct routing 及 iptables/nftables 后端，在不同外部接口真实探测并拒绝非批准来源（参见 [Docker port publishing](https://docs.docker.com/engine/network/port-publishing/) 和 [Docker firewall](https://docs.docker.com/engine/network/packet-filtering-firewalls/)）。Mode A 不能代替 Mode B；Mode B 须另证真实多宿主机网络 ACL、错误 peer/host key、node 离线、网络分区/恢复、跨主机审批不可重放、源/目标数据卷不共享以及 SSH 容器的隔离能力。Compose 架构不天然提供宿主机级完整隔离。

## 4. 策略、用户与真实客户端

MVP 仍是一个组织、同一权限层的固定服务端 profile，可命名为 `rw-operator`；不提供 per-human claim/role 映射。这是完整 v1 RBAC/多权限方案的**显式受限产品子集**，不得把 Portal 身份本身记录成 SOM 内已鉴别的个人审计主体。一个 origin 的所有通过 Portal 用户在 SOM 内共享该静态 profile；不同权限组/不同信任级别应使用**不同 origin+profile+凭据**。两个或以上 SSH 别名经受信任 inventory 明确列举，每台 host 各自可赋予不同读写 roots/配额。

真实客户端仍优先验证 ChatGPT 远程 MCP（能力、连接配置待实际账号确认），其次可由操作者指定 Streamable HTTP/OAuth 支持的客户端。完整流程：登录 → `hosts_list`/`host_info` → `policy_explain` → 对两台主机分别读取与列表 → mkdir/new write → read-back → append/replace → move → delete → 检索 → 独立 `approvalctl` 逐请求批准 → 所有审计与拒绝路径核对。不存在的工具不可声称已经验收；需要实际 MCP client 走完整路径，不以单测或模拟 SDK 代替。

保持无 public origin port、Cloudflare Portal/Access 与 Origin bearer 双层认证、Tunnel token/SSH secret/ledger key/API token 分离、Ledger 不可用前置拒绝 SSH 副作用。**当前只读 observer 策略不适用**，要专门编写逐工具的明确 allow 与显式 deny，并覆盖多主机错配、profile 泄漏与审批复用攻击。

## 5. 数据持久化、恢复与撤销

Compose 数据卷包括控制面宿主机的 `ledger-data`、**每台独立 SSH 宿主机本地**的业务 rw 数据卷、经许可保存的 per-host host keys；凭据与 HMAC key 由各自受保护的外部来源提供，不跨主机共享业务卷、秘密卷、Unix sockets 或 runtime 管理权限。Mode A 使用隔离、可销毁的本地测试卷。Mode B 恢复必须协调**跨实际宿主机**的 Ledger、两台数据卷、host keys、批准配置、镜像 digest 和审计 checkpoint 在可验证的一致性点；**必须逐个 `operation_id` 对账每台 Host 的 durable operation journal/commit receipt/UNKNOWN 与控制面 Ledger**，任何 UNKNOWN 在无法人工可信消歧之前不得重启相关目标写入；控制面无法保证全节点已停止写入时不得开放恢复服务。

跨宿主机冷备份：在 control01 关闭 Portal 和所有 admin/批准/执行写入口 → 在 ssh-host01/02 的**每台**防止新的写入并对在途请求确定或标记 UNKNOWN → 在各宿主机停止相关 Compose 服务 → 保存带主机 ID、可信 UTC、SSH host-key identity 和镜像/config digest 的逐节点快照及外部可信统一 checkpoint → 离线恢复每台及控制面 → 全节点审计/读写状态核验后才可重新开放。Mode A 单机恢复只能充当快速前置测试，不替代上述协调停机。仅当可信当前 UTC 严格晚于**全量扫描**所有 pending/granted expiry、且无遗漏审计尾段时才可重新开放；现有 list100/deny(GRANTED) 不足以证明撤销。`fs_write/move/delete` 的崩溃窗口、同名卷混用、回滚到旧写入与审计错配必须 fail-closed；不承诺任意旧快照恢复或自动跨主机事务回滚。

认证 bearer、SSH credential、host key、Portal access 撤销及 Compose 故障后重启必须分别实际测试。所有真实 host/Compose 变更由指定操作者批准执行；普通 agent 不自行 Docker socket、特权 cgroup、账户/Cloudflare 管理或主机安装。

## 6. 验收矩阵（全部初始 NOT_RUN）

| ID | 必须通过的真实场景 | Owner |
|---|---|---|
| A01 | **Mode A：** 一个可销毁 Linux Engine 的 Compose 启动 MCP、Ledger、审批与至少两个 SSH 容器，真实可连接；无公网 SSH/origin 端口 | M1a |
| A02 | **Mode A：** 两个 SSH 容器独立卷/host key/身份与 cgroup/ForceCommand，host escape 和目标间横向访问拒绝 | M1a |
| A03 | **Mode A：** 重启/替换/manager 故障与单机容器断连 fail-closed，无绕过审批/审计 | M1a |
| A04 | 两主机所有 8 个 typed FS 工具正向读写；每台可配置不同读/写数据根 | M2 |
| A05 | `fs_list/search` 使用真实 SMCP v2 中央快照+Host v5 deny 子树逐节点授权，parent allow/child deny 预剪枝、中央复核；policy epoch 变更/partial ACK/过期 MAC/旧游标等全部 fail-closed，名称、metadata、内容、数量不泄漏；symlink/race、错误 host-key、资源超限拒绝 | M2 |
| A06 | create `target_absent`、replace/append `if_match`(inode/generation/size/SHA256) 与 journal `operation_id`，文件 move/delete 在并发、fsync、断连、crash-after-effect-before-receipt、人工再次批准时**不重复执行**；Mode A/B 同候选 TEST_ONLY，生产默认 DENY；空目录 move 未证竞争安全则禁用 | M2 |
| A07 | `fs_move` source/destination 与 `fs_delete` 目标/父目录双层授权；全局 Operation ID 与 source/destination/mode/旧文件 precondition 的一次性精确审批/远端 journal 绑定，跨 host/路径/内容/模式/新 grant/重放或过期不能重复执行；M2d/迁移未完成正式不可用 | M2 |
| A08 | Ledger 审批已消费但远端未开始、远端 APPLYING、数据提交但 durable receipt 未写、断连/恢复/host journal 丢失的 UNKNOWN 统一冻结目标/拒绝自动或盲目人工新批准重试；控制面/Host 证据不一致与审计失败均 fail-closed | M2 |
| A09 | **Mode B：** 真实客户端通过私有 Portal 连接 control01 和两台不同宿主机的 SSH 目标，完成全部读写及独立批准/审计；Mode A 的相同正反流程也须通过 | M3 |
| A10 | **Mode B：** Portal/origin bearer 双层拒绝、各远端主机只接受 MCP 来源的私网 SSH ingress、错误 peer/key 与公网尝试拒绝、秘密与审计输出无泄漏 | M3 |
| A11 | **Mode B：** 控制面 Ledger 与两台独立 SSH Host journal/数据卷跨节点一致性冷恢复，逐 Operation ID 对齐 COMMITTED receipt/UNKNOWN、审批 expiry/审计 checkpoint，未证明写入是否已提交或缺一台节点时保持关闭；Mode A 演练亦通过 | M4 |
| A12 | 每个 SSH host 凭据、控制面 bearer、客户端访问撤销及服务重新启动后旧身份拒绝 | M4 |
| A13 | 精确候选版本普通全量测试、**Mode A + Mode B 分别的真实 Compose/SSH 正反验收**、独立审查及 canonical native Level-3 通过 | M5 |
| A14 | 实际 main 11/11、**两模式及各独立宿主机**镜像/Compose config/SSH host key 与运行版本证据匹配，经明确多宿主机部署/发布批准后完成 | M5 |

| A15 | **Mode B：** control01、ssh-host01、ssh-host02 三台独立 Linux Engine 各自 `docker compose` 启动；control01 到两个远端 SSH 目标的真实专用私网链路与固定 host-key 验证 | M1b |
| A16 | **Mode B：** 各宿主机独立身份/cgroup/数据卷和网络 ACL；禁止 SSH01↔SSH02、SSH→Ledger/admin 与公网 SSH ingress，跨主机错误配置拒绝 | M1b |
| A17 | **Mode B：** SSH host 丢失/私网分区/host-key 或 policy epoch 变更/配置漂移/重启/旧快照与审批重放均拒绝；Host durable operation journal 保留 UNKNOWN/receipt、不因 reconnect 或新 grant 隐式重执行写入 | M1b |
| A18 | **Mode B：** 经批准的每宿主机 Compose 安装/升级/回滚，固定镜像 digest、源配置校验、秘密和 host key 保留、无共享 Docker daemon/卷权限，并形成操作员可复核的证据包 | M1b |

## 7. 未解除的安全/发布依赖

ADR0021 仍需书面用户接受，才可把此**Compose RW 产品试点**与新的 UID502/APFS/protected native staging readiness 里程碑分开排程。已有 canonical trusted-main **no-network Level-3** 仍是必须项；根据 `docs/development-methodology.md`，改动 SSH 传输、策略/审批、host-agent、文件变更、容器/出站安全的 PR **必须在合并之前**由已合并可信 `main` 上的编排器在无网络 disposable guest 中对**精确 PR HEAD**单独运行实际 Level-3，并取得结果和资源清理证据（需要事先授权）。PR 托管普通 CI PASS、PR-native Level-3 SKIPPED、或仅有上一个 main 的 11/11 不能替代。合并之后仍须对**新 main**独立验证 11/11。只测旧 E2E 路径也不能验证新的 Compose SSH 隔离/全读写；新增实测须另具真实环境、批准和可复验安全证据。Issue #259 T5B 来源/签名/信任/host 权限/真实 Mac Gate B 与 Issue #256 Linux C/D 依旧 HOLD，试点 release 不能把其中任一项标记 DONE。

当前只变更**拟议功能范围与文档**，不含任何已完成容器构建、SSH 部署、新工具实现、写入数据、账号/网络变更、root/特权执行、合并或发布。设计和实施计划均须审阅/确认后才能作为正式执行入口。
