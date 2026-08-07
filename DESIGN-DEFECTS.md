# 设计缺陷排查报告

> 生成时间：2026-07-29 | 范围：内核模块 + Rust 守护进程 + Leptos 前端  
> 定级依据：`STANDARDS.md`（Critical / High / Medium / Low）

本报告记录本轮设计缺陷排查结果。标注 ✅ 的条目已在本 PR 修复；其余为已知债务，按优先级待后续迭代处理。

---

## 一、本 PR 已修复

| 定级 | 模块 | 缺陷 | 修复要点 |
|------|------|------|----------|
| Critical | kmod `ban-manager.c` | 拒绝封禁本机 IP 时未释放 `fw->lock` | 两处 return 前 `spin_unlock_bh` |
| Critical | kmod `state-persist.c` | 恢复永久封禁未 `timer_setup`，`kmalloc` 未清零 `reason` | 改为 `kzalloc` + 始终 `timer_setup` |
| Critical | kmod `netdev`/`firewall.h` | 本地 IP 缓存指针与 count 拆分发布，缩容时可读越界 | 合并为 `struct local_ip_cache` 一次 RCU 发布 |
| Critical | kmod `netdev.c` | 无活动地址时提前返回，旧自动白名单/缓存残留 | `current_count==0` 时清理自动白名单并清空缓存 |
| Critical | kmod `netlink.c` | 控制面无鉴权，任意本地进程可改策略 | 要求 `CAP_NET_ADMIN` |
| High | kmod `rate-detector.c` | `fw_max_rate_entries` 形同虚设，可被源地址伪造耗尽内存 | 创建条目时强制容量上限 |
| High | kmod `netfilter.c` | ICMPv6 Echo 未映射，IPv6 ICMP flood 检测盲区 | Echo Request 映射为 `IPPROTO_ICMP` |
| High | daemon `lifecycle.rs` | 非回环绑定且无认证时认证失败开放 | 拒绝启动无认证的非回环 HTTP |
| High | daemon `handlers.rs` | `BanHistory::record_unban` 从未调用 | 内核解封事件路径调用 |
| High | frontend SSE | `1_u64 << attempt` 在长断线后移位溢出 panic | 先 `min(5)` 再移位 |

---

## 二、仍待处理的重要设计缺陷

### Critical / High（内核）

1. ✅ **`active_bans_list` 无独立锁** — 已增加 `active_bans_lock`；写端经 `active_bans_add/del`；锁顺序为桶锁 → 活跃链表锁。
2. ✅ **定时器生命周期** — 过期回调在摘链前校验 `unban_time`（续期则重武装）；持桶锁内仍用非 sync `timer_delete`。
3. ✅ **模块退出 RCU** — `cleanup_all_entries` 末尾 `synchronize_rcu` + `rcu_barrier`；init 失败路径改为阶梯清理（procfs 失败会 `fw_netlink_exit`）。
4. ✅ **本机“保护”实为信任整段子网** — 自动发现/缓存改为精确 /32、/128；子网信任仅 manual 白名单。
5. ✅ **配置双脑** — `ban_ip` 读 `fw_info.ban_time`；速率检测读 `fw_info.static/dynamic_threshold_enabled`（netlink 热更新生效）。模块参数仅作启动默认。
6. ✅ **白名单与封禁非原子互斥** — 桶锁内插入前/后白名单 RCU 检查；后检失败同锁回滚；续期路径遇白名单则摘链。
7. ✅ **持久化格式脆弱** — 写 `.tmp` + `mv -f` 原子替换；`CRC32` 校验；reason 取行尾（可含空格）；截断打 warn。
8. ✅ **Netlink 列表 API 不可扩展** — LIST bans 分页（offset/limit，页大小 256）；响应带 total/offset；守护进程多页累计后再对账。

### High（守护进程 / 前端）

9. ✅ **Netlink 发送成功 ≠ 内核成功** — `CmdResult` 对 BanIp 失败回滚 `ACTIVE_BAN_CACHE`；完整请求-ACK 状态机（延迟 `record_ban`）仍待深化。
10. ✅ **守护进程接收未校验发送方** — `recvmsg` + 拒绝 `nl_pid != 0`。
11. ✅ **封禁缓存无周期性对账** — `reconcile_with_kernel` + LIST 响应全量对账；stats 线程每 60s 拉 LIST。
12. ✅ **配置热重载非事务** — 提交前失败保持旧配置；inotify/组件同步失败回退；回滚改为弹出最近快照；metrics 绑定/凭据变更告警需重启。
13. ✅ **SSE `/api/v1/events` 无认证** — 纳入与 API 相同的 Basic Auth 中间件；支持 `?access_token=`（Base64 user:pass）供 EventSource；连接上限仍为 10。
14. **日志 inotify 事件类型不当** — 监视文件却注册目录子事件，轮转后可能盯死旧 inode。
15. **SQLite 进热路径** — 失败日志同步写库；查询阻塞 2-worker Tokio。
16. **用户态 DDoS 检测器休眠但代码仍在** — 与内核检测概念重复，误启风险高。

### Medium

17. 端口扫描“唯一端口”实为端口跳变计数；`port_scan_detected` 从不递增。
18. IPv4 哈希用可预测 `hash_min`，与 IPv6 随机 `jhash` 不对称。
19. 白名单 IPv6 前缀未在核心 API 规范化（procfs/netlink 语义不一致）。
20. 全局服务定位器状态阻碍原子快照与可测性。
21. 健康检查恒返回 ok，与 Netlink/子系统就绪无关。

---

## 三、建议修复顺序

1. ~~`active_bans_list` 锁纪律 + 定时器/RCU 生命周期（防内核损坏）~~ ✅
2. ~~Netlink 请求-ACK + 守护进程发送方校验 + 周期对账（消除双脑）~~ ✅（ACK 为 CmdResult 回滚缓存的最小闭环；完整延迟写历史仍待）
3. ~~本机保护改为精确地址；子网信任改为显式策略~~ ✅
4. ~~配置单一 RCU/版本化快照；HTTP/SSE 认证与绑定策略统一~~ ✅（运行态读 `fw_info.*`；SSE 与 API 同鉴权；热重载已事务化，metrics 绑定/凭据仍需重启）
5. ~~持久化与列表分页 API 重做~~ ✅

剩余 High：#14 inotify 轮转、#15 SQLite 热路径、#16 休眠用户态 DDoS 检测器；#9 完整延迟 `record_ban` ACK 仍可深化。

---

## 四、说明

- 部分历史文档（如 `CODEBASE-ANALYSIS.md` 中“仅 pre_routing 有效、其余 hook 空转”）已过时：当前仅注册 IPv4/IPv6 `NF_INET_PRE_ROUTING`。
- `hash_ipv6()` 已在 `firewall.h` 声明，但仍与 `hash_ip()` 并行，属于 Medium 可维护性债务，未在本 PR 强制合并以免扩大 diff。
