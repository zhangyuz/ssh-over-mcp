# 双 SSH 节点真实 MCP 只读验收入口（Mode A / Mode B）

在**已另行批准、真正部署**的 MCP + 两个独立 SSH 节点上使用。该命令直接经 HTTP MCP 调用 `hosts_list` → 两个节点的 `fs_stat`/`fs_read`，不执行 SSH shell、Docker、部署或远端写操作。

准备条件：operator 预先在 **node01、node02 各自**的已授权数据根中创建相同绝对路径的普通文件，但内容分别不同，事先独立记录两个文件的 SHA-256；控制面服务端已固定两个节点的 SSH 身份、host-key pin、授权和审计。不能从 MCP 返回的数据反推所谓期望哈希。

```sh
python3 ops/mvp/dual_host_read_smoke.py \
  --endpoint https://mcp.internal.example/mcp \
  --token-file /secure/location/origin-bearer \
  --path /srv/data/probe.txt \
  --node01-sha256 <64-lowercase-hex-for-node01> \
  --node02-sha256 <64-lowercase-hex-for-node02>
```

成功只输出目标别名和哈希（不输出 token、文件路径或内容）；失败只输出稳定拒绝码并返回非零状态。每个探针内容必须不超过 **4096 字节**，两个期望哈希必须不同。仅接受 HTTPS，临时本机测试可显式使用 `--allow-loopback-http`，只能连接 loopback。

**范围：** 这是实际可运行的客户端验收工具，不是部署证明。现阶段已经通过本地合成 MCP 响应的定向测试，**尚未对真实双 SSH Compose 栈运行**。需要实际通过 Mode A 和 Mode B 后分别登记证据；这不等于写入验收、八工具完成或 Native Level-3。

**MVP TODO（按阻塞优先级）：**
- [ ] 提供可信的可执行 SSH OCI 镜像、最小 sshd/agent/manager 授权链和真正委派的 cgroup，单机双节点 Mode A 实测；原生 APT runner 来源格式问题记为依赖，不继续频繁微调。
- [ ] 用本 CLI 对 Mode A / Mode B 做真实双节点只读正反验收；随后完成现有 create-only `fs_mkdir`/`fs_write` 的审批和写后读验收。
- [ ] 实现剩余的 `fs_list`、`fs_search`、`fs_move`、`fs_delete`、append/replace，必须先补齐逐节点授权、双路径审批、幂等收据并通过安全门禁。Mode B 的跨 Linux Engine 私网、host-key、故障/撤销测试仍需操作授权。

所有 TODO 都是**待实现/待验收**，不是已通过的门禁。
