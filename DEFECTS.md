# 功能缺陷清单

> 生成时间：2026-11-11
> 更新时间：2026-11-11（第八轮：短报文绕过、白名单设备归属、信誉分可见性、重试退避与持久化读路径）
> 状态标记：🔴 待修复 | 🟡 修复中 | 🟢 已修复 | ⚪ 设计取舍/复核为误报

---

## 统计

| 严重度 | 发现总数 | 已修复 | 待修复 |
|--------|----------|--------|--------|
| CRITICAL | 4 | 3 | 1 |
| HIGH | 26 | 25 | 0 |
| MEDIUM | 72 | 52 | 9 |
| LOW | 72 | 17 | 54 |
| **合计** | **174** | **97** | **64** |

另有 13 项经复核为误报或设计取舍（标 ⚪），不计入待修复：H-6、M-1、M-2、M-3、M-10、M-14、M-22、M-B7、M-D1、M-D4、M-D5、M-E2、L-E4。

---

## CRITICAL 级（4 项）

### C-1 🟢 netlink 传输层 socket flags 未恢复
- **文件**: `src/daemon/internal/kernel/transport.go:230-233`
- **状态**: ✅ 已修复 — 错误路径恢复原始 flags

### C-2 🔴 前端 SSE 认证 token 暴露在 URL query string
- **文件**: `frontend/src/api/endpoints.ts:499-513`
- **问题**: Basic auth token 放在 EventSource URL，出现在浏览器历史/access log
- **影响**: 凭据泄漏风险
- **修复**: 文档化风险 + 考虑短期 SSE 专用 token
- **难度**: 中 | **风险**: 中（需后端配合）

### C-3 🟢 前端 DataTable 默认 rowKey 使用数组 index
- **文件**: `frontend/src/components/DataTable.tsx:79`
- **状态**: ✅ 已修复 — 移除默认回退，添加开发环境警告，补充 3 处遗漏的 rowKey

### C-4 🟢 Makefile `ci` 目标并行构建不安全
- **文件**: `Makefile:328`
- **状态**: ✅ 已修复 — 7 个阶段改为线性依赖链（ci-format → ci-contract → ci-build → ci-test → ci-cleanup → ci-summary）

---

## HIGH 级（26 项）

### H-1 🟢 内核模块 ip_fast_csum 读取越界
- **文件**: `src/kernel-module/fw_hook.c:159-162,191`
- **状态**: ✅ 已修复 — 缓冲区从 20 字节增大到 60 字节

### H-2 🟢 intent.IP 与 info.IP 不一致
- **文件**: `src/daemon/internal/runtime/executor.go:1138-1141`
- **状态**: ✅ 已修复 — 统一使用 `.Unmap()` 后的 canonical 形式

### H-3 🟢 SseProvider context 每帧触发全树重渲染
- **文件**: `frontend/src/providers/SseProvider.tsx`
- **状态**: ✅ 已修复 — 改外部 store + `useSyncExternalStore`：连接态只在跃迁、各域只在自身更新时换引用，逐帧时间戳只重画徽标；Provider 下发的 context 恒定，子树不再被带动

### H-4 🟢 useLiveData 用 JSON.stringify 做深比较
- **文件**: `frontend/src/hooks/useLiveData.ts:50-61`
- **状态**: ✅ 已修复 — 改用 shallowEqual 函数

### H-5 🟢 RealtimeBadge 1 秒 interval 永不停止
- **文件**: `frontend/src/components/state/RealtimeBadge.tsx:80-84`
- **状态**: ✅ 已修复 — 添加 SSE 连接状态依赖

### H-6 ⚪ 认证锁定为进程级（契约约束的取舍）
- **文件**: `src/daemon/internal/http/auth_lockout.go:22-62`
- **复核**: 按来源 IP 计数需要契约先定义「信任哪一层代理的 X-Forwarded-For」；`contract/http.fwidl` 未给出该边界，按 IP 切分反而让攻击者用伪造头绕过锁定。现实现按进程单账本计数，是契约口径下的正确落点。若要改 per-IP，必须先在契约里写清可信代理。

### H-7 🟢 白名单删除内核失败不回滚
- **文件**: `src/daemon/internal/http/whitelist.go:100-130`
- **状态**: ✅ 已修复 — 先尝试内核删除，成功后再删内存

### H-8 🟢 内核 fw_ban_del/procfs 缺失 netlink 发送锁
- **文件**: `src/kernel-module/fw_ban.c:596`, `fw_procfs.c:438,444`
- **状态**: ✅ 已修复 — 发送路径统一加 `fw_nl_send_lock()/unlock()` 与 `fw_nl_sock_available()` 检查

### H-9 🟢 Transport.Close/Send 竞态
- **文件**: `src/daemon/internal/kernel/transport.go:502-533`
- **状态**: ✅ 已修复 — Close() 先取 sendMu 再取 closeMu，关闭 fd 前释放 sendMu

### H-10 🟢 TryInsert/MarkPendingAck 竞态窗口
- **文件**: `src/daemon/internal/bans/cache.go:60-71`
- **问题**: TryInsert 后、MarkPendingAck 前，reconcile 可能移除幽灵条目
- **状态**: ✅ 已修复 — 新增 `InsertPending` 在插入锁内同时置 pending（`insertLocked`）；
  executor、手工封禁与批量封禁三条路径统一切到该入口，败者不再触碰条目或延期

### H-11 🟢 Facts.writeBack 并发逐出问题
- **文件**: `src/daemon/internal/persist/facts.go:422-494`
- **问题**: `writeAll` 在锁外写库期间条目可被逐出；写失败后把待写量还回孤儿条目，
  而逐出路径的 `writeBack` 已经返回，这部分扣分再也不会落盘
- **状态**: ✅ 已修复 — `requeueLostLocked` 按索引现状处理：同一条目直接累加 pending；
  已被替换的条目并入新条目并重算显示分；已逐出条目重新挂回 lru + index；
  `facts_test.go` 覆盖替换与逐出两种路径

### H-12 🟢 前端 Logs 分页越界无自动修正
- **文件**: `frontend/src/views/Logs.tsx:140-173`
- **状态**: ✅ 已修复 — 按 totalPages 夹取当前页码

### H-13 🟢 前端认证令牌跨 tab 不同步
- **文件**: `frontend/src/api/auth.ts`, `frontend/src/providers/AuthProvider.tsx`
- **状态**: ✅ 已修复 — 迁移到 localStorage，AuthProvider 订阅 storage 事件

### H-14 🟢 executor.go panic 导致进程崩溃
- **文件**: `src/daemon/internal/runtime/executor.go:214`
- **状态**: ✅ 已修复 — 周期任务登记失败改为返回 error，组合根优雅失败

### H-15 🟢 facts.go 类型断言 panic
- **文件**: `src/daemon/internal/persist/facts.go:518-530`
- **状态**: ✅ 已修复 — Stats() 改用 comma-ok

### H-16 🟢 Makefile Go 版本门禁与 go.mod 不一致
- **文件**: `Makefile:42`, `src/daemon/go.mod:3`
- **状态**: ✅ 已修复 — `GOVER ?= 1.26`

### H-17 🟢 CI upload-artifact 版本混用
- **文件**: `.github/workflows/ci.yml:557`
- **状态**: ✅ 已修复 — 统一为 v6

### H-18 🟢 配置文档默认值与 config/default.yaml 不一致
- **文件**: `docs/zh/configuration/yaml-config.md:32,36-37`
- **状态**: ✅ 已修复 — ban_time 900、凭据 admin/changeme 并注明生产必须覆盖

### H-19 🟢 日志流不跟随日志轮转
- **文件**: `src/daemon/internal/http/logs.go:319-420`
- **问题**: 守护进程日志 sink 按大小自行轮转（rename 或原地截断）；流持有旧 fd，
  rename 后永远 EOF、截断后要等文件重新长过旧偏移才恢复，面板实时日志静默停住
- **状态**: ✅ 已修复 — 每拍核对 inode 与长度，失配即重开路径并丢弃旧半行；
  回归测试见 `logs_stream_test.go`

### H-20 🟢 配置对象并发读写无同步
- **文件**: `src/daemon/internal/config/guard.go`（包级 RWMutex）、
  `src/daemon/internal/runtime/file_reloader.go`（`applyConfig` 的 `*cfg = newCfg`）、
  `src/daemon/internal/http/config_api.go`（`persistWebui` / `syncDdosToggles` 写 `cfg.Webui` / `cfg.Ddos`）
- **问题**: 热重载在 executor goroutine 整份替换 `*cfg`，PUT `/api/v2/config` 在 HTTP
  goroutine 原地改字段；两者与 HTTP handler、executor 的字段读取之间没有任何同步。
  Go 内存模型下这是数据竞争：读侧可能看到新旧混合状态（如切片槽位已换、len 未换），
  且 `-race` 必然报告
- **影响**: 重载与配置写入并发时配置可能读到半更新状态，极端情况切片越界
- **状态**: ✅ 已修复 — `config` 包提供包级 RWMutex（`LockConfig`/`RLockConfig`），
  锁只包住字段读写，文件 I/O、netlink 下发与 `Reload`/`Rollback` 均在锁外；
  多字段判断在同一把读锁内一次取全；`config_guard_test.go` 用真实 reloader +
  两写三读并发，`go test -race ./...` 全绿

### H-21 🔴 Blocklist.de 条目 TTL 固定 2 小时，每轮刷新后 92% 时间不起作用
- **文件**: `src/daemon/internal/threatfeeds/sources/blocklist.go:25`
- **问题**: 该源 `Parse` 固定 `expiresAt = now+2h`，而其余源（ipsum/firehol/dshield/feodo）
  都是 25 小时；`refresh_interval` 默认 24 小时、允许 60s–86400s（`config/parser.go:764`），
  调度器再加 ±30 分钟抖动（`manager.go:79`）。`Lookup` 跳过过期条目（`cache.go:166,180`），
  `Cleanup` 随后删除，而 `/api/v2/threat-feeds` 只在拉取失败时报错——拉取成功即 `sync ok`，
  `entry_count` 仍是解析时的数量
- **影响**: 默认配置下每轮刷新后第 2 小时起 blocklist_de 对判定链路完全失效，面板无告警；
  文档 `docs/zh/configuration/threat-feeds.md:276` 写「默认 24 小时过期」，与实现不符
- **状态**: ✅ 已修复 — TTL 改为 25h，与其他源一致；`sources_test.go` 断言解析结果的
  `ExpiresAt-now` 在 25h±1min
- **难度**: 低 | **风险**: 中（判定命中率）

### H-22 🔴 集群聚合键不做 IPv4-mapped 归一，所有映射地址塌进 `::/48`
- **文件**: `src/daemon/internal/decision/cluster.go:29-31`、`src/daemon/internal/detect/cidr.go:38-48`、
  `src/daemon/internal/config/types.go:18-23`、`src/daemon/internal/logparse/ip.go:76-88`
- **问题**: `ExtractIP` 只对保留段检查做 Unmap，返回的仍是 `netip` 原值；`FamilyOf` 按
  `addr.Is4()` 判定，`::ffff:1.2.3.4` 得 10，于是 `SubnetKey` 用 PrefixV6（默认 48）掩码，
  不同 /24 的映射地址得到同一个 `::/48` 键
- **影响**: 双栈 nginx/apache 日志中的 IPv4-mapped 源被当成同一网段：≥5 个、每 IP ≤3 次
  失败即误报集群扫描；`executor.go:1178` 对 `::/48` 下发网段封禁，IPv6 前缀命不中 IPv4
  包（脏条目）；`pipeline.go:445-447` 随后清空这些 IP 的真实失败计数，单 IP 判定被饿死
- **状态**: ✅ 已修复 — `pipeline.collectLine` 统一 `Unmap()`，`config.FamilyOf` 与
  `detect.SubnetKey` 各自 Unmap 兜底；新增 mapped/dotted 同键、不同 /24 不同键与
  `DetectCluster` 分组测试
- **难度**: 低 | **风险**: 中（误封网段 + 漏封单 IP）

### H-23 🟢 IPv4 短报文（<60 字节）绕过封禁表与速率判定
- **文件**: `src/kernel-module/fw_hook.c:171,197-203`
- **问题**: 为修复校验和越界把 `skb_header_pointer` 的请求长度从 20 改成 60，但该函数在
  `offset+len > skb->len` 时返回 NULL，代码随即 `return NF_ACCEPT`。裸 SYN（40 字节）、
  小 UDP/ICMP 都不到 60 字节
- **影响**: 已封禁 IP 的 SYN/ACK/RST flood 全部放行，`fw_ban_lookup` 与 `fw_rate_observe`
  完全触不到，也无法自决封禁；`fw_stat_account` 不计，直方图与全局流量同时失真
- **状态**: ✅ 已修复 — 先取 `sizeof(struct iphdr)` 校验 version/ihl/tot_len，线性化后
  按 `ihl*4` 重取完整头到 60 字节栈缓冲；短报文进入统计、速率与封禁查找，畸形头仍放行
- **难度**: 低 | **风险**: 高（核心拦截失效）

### H-24 🟢 守护进程下发的白名单条目被 netdev 对账当作自动条目删除
- **文件**: `src/kernel-module/fw_netdev.c:183-186`、`fw_netlink.c:812-813`、`fw_wl.c:157-200`
- **问题**: daemon 的 `trusted_ips` 与面板白名单都以空设备名下发布；`fw_nl_handle_whitelist`
  把空串传成 NULL，条目 `device_name` 为空；`fw_netdev_dev_is_auto()` 只排除 `"manual"`
  与 `"restored"`，空串被判为自动条目
- **影响**: 任意 netdev 事件（docker/veth 创建删除即可）触发对账，本机不存在的条目被
  `fw_wl_remove_quiet` 删除并广播 REMOVE；daemon 同步删镜像，面板白名单消失，可信地址
  重新参与封禁判定，可能自锁。daemon 的 `reconcile()` 不对账白名单，只有重启才重下发
- **状态**: ✅ 已修复 — `fw_netdev_dev_is_auto()` 把空设备名判为非自动；daemon 下发的
  空名白名单不再被 netdev 对账清理，manual/restored 语义不变
- **难度**: 低 | **风险**: 高（白名单失效导致误封）

### H-25 🟢 内存信誉分加载一次后不再回读，每小时信誉恢复对判定层不可见
- **文件**: `src/daemon/internal/persist/facts.go:247-265,383-393`、`internal/persist/recovery.go:29`
- **问题**: `loadScoreLocked` 置 `scoreLoaded=true` 后永不重读；`RecoverReputation` 只 UPDATE
  库。IP 留在 LRU（容量 4096）期间，判定链一直用旧的低分（阈值 -1/-2 长期生效），而
  `/stats/reputation` 从库读显示已恢复满分
- **影响**: 两条读路径长期矛盾；同一 IP 在进程生命周期内被判为低信誉，只有被逐出 LRU
  才可能自愈
- **状态**: ✅ 已修复 — 每 5 分钟按 `dbScore - pending` 重载内存分，库侧恢复与封禁写库
  对判定层可见；重载与刷盘以 `dbMu` 串行，未落盘扣分不被抹掉
- **难度**: 中 | **风险**: 中高（阈值正确性）

### H-26 🟢 每次入队都唤醒重试协程，指数退避在持续失败时被击穿
- **文件**: `src/daemon/internal/persist/retry_queue.go:108-135,158-189`
- **问题**: `Enqueue` 每次都 `notify()`，`run` 的 `select` 里 wake 随时抢走定时分支；
  每次入队还同步 `persist()`（全队列 Marshal + 临时文件 + rename，持 `persistMu`）
- **影响**: DB 不可用期间，重试频率≈入队频率而非 `RetryInterval×2^n`，每批对整条队列
  逐条执行，单连接 busy_timeout 下可长时间钉住后台协程；封禁路径退化为 O(n) 同步磁盘
  I/O，n 接近上限时 O(n²)
- **状态**: ✅ 已修复 — 仅空队列→非空或退避归零后唤醒后台协程；入队改为脏标记 + 300ms
  合并落盘，`Stop` 强制落盘，退避在持续失败期间不再被入队打断
- **难度**: 中 | **风险**: 中高（故障期 DB 雪崩与封禁延迟）

---

## MEDIUM 级（72 项）

### 内核模块（4 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-1 | `fw_hook.c` | 32 位平台 total_len 比较溢出 | ⚪ 复核：`pkt_len` 已是 u32，比较无溢出 |
| M-2 | `fw_ban.h:2-18` | 哈希表扩容无上限 | ⚪ 复核：封禁表按 `prefix_len` 分层、桶数组初始化即定长，全模块无 rehash/扩容路径（「扩容」是旧实现的描述）；条目总量由 `fw_max_ban_entries` 在桶锁内封顶 |
| M-3 | `fw_procfs.c:83-92` | procfs 写回调 buffer 长度截断 | ⚪ 复核：`count > out_size-1` 直接返回 `-EINVAL`，不是静默截断 |
| M-4 | `fw_netlink.c:185-199` | 多播广播失败仅 rate-limited 日志 | 🟢 已修复：统一出口 `fw_nl_broadcast_event`，非 `-ESRCH` 失败累加 atomic64 并在每条告警带出累计值。**未在真实环境注入 `-ENOBUFS` 验证**，仅有编译与代码审查证据 |

### 内核深层（5 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-K1 | `fw_rate.c:753-763` | rate_window 读侧缺 READ_ONCE 配对 | 🟢 已修复 |
| M-K2 | `fw_rate.c:589-592` | window_start/last_activity 缺 WRITE_ONCE | 🟢 已修复 |
| M-K3 | `fw_netlink.c:1064-1078` | netlink 消息缺 NLMSG_ALIGN 对齐 | 🟢 已修复（并对末条报文按剩余长度截断） |
| M-K4 | `fw_state.c:589-602` | 恢复时 filp_open 的任何错误都当「首次启动无文件」吞掉，EACCES/EIO 被静默 | 🟢 已修复（仅 ENOENT 按首启处理，其余报具体 errno 并让 insmod 失败） |
| M-K5 | `fw_state.c:699-709` | 恢复标记先于路径校验与打开置位，修正模块参数后无法再恢复 | 🟢 已修复（失败路径 clear_bit，可重试；新增空文件/短读校验） |

### 守护进程（10 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-5 | `runtime/executor.go:431-447` | poll 把 POLLHUP/POLLERR 当数据 | 🟢 已修复（只认 POLLIN，错误走终止路径） |
| M-6 | `runtime/file_reloader.go:20` | logger 为 nil 时无防护 | 🟢 已修复 |
| M-7 | `cmd/firewall-daemon/main.go` | 默认凭据 admin/changeme 无启动告警 | 🟢 已修复（用户名与密码两个维度分别告警，绝不打印凭据值） |
| M-8 | `http/auth.go` | 认证锁定机制无集成测试 | 🟢 已修复（`tests/test_23_auth_lockout.py`：阈值/成功清零/匿名不计数/进程级锁定/重启清空；阈值与窗口从 `contract/http.fwidl` 读取。**需 root 的运行时执行未跑**） |
| M-9 | `http/bans.go` | 内核解封失败只记日志不回传前端 | 🟢 已修复（先下内核，失败回 40002 并保留镜像；补契约测试） |
| M-10 | `kernel/client.go:190-217` | Ban 返回 Delivered 非 Executed | ⚪ 设计取舍 |
| M-11 | `persist/facts.go:296-301` | 风险事件队列高负载下静默丢事件 | 🟢 已修复（丢弃累计到 `eventDrops`，首次与每 30 秒告警一次并带出累计值与队列容量；告警移到释放缓存锁之后。事件仍可能丢，这是「不阻塞主链路」的既有取舍，但现在可观测；内存风险向量不受影响） |
| M-12 | `logger/logger.go:225-238` | LogThrottler TOCTOU 竞态 | 🟢 已修复（CAS 循环） |
| M-13 | `geoip/egress.go:73-97` | egress probe 接受私有 IP | 🟢 已修复（只收公网单播，补单测） |
| M-14 | `persist/db.go:207` | SQL ALTER TABLE 字符串拼接 | ⚪ 复核：三个实参均为 db.go:162-167 的常量字面量，不接受外部输入；pragma 查询已用绑定参数 |

### 守护进程深层（11 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-D1 | `sse.go:228-278` | SSE Broker run() 过早退出 | ⚪ 复核：退出路径均由 Stop() 接管 |
| M-D2 | `db.go:284-331` | CleanupExpired 五条 DELETE 无事务 | 🟢 已修复（单事务，补回滚测试） |
| M-D3 | `manager.go`, `scheduler.go` | FeedManager.Stop() 不等待 in-flight | 🟢 已修复（doneCh + sync.Once；Stop 先 cancel 再等待调度器退出） |
| M-D4 | `executor.go:884-906` | 配置重载失败未显式回滚 | ⚪ 复核：`fileReloader.Reload` 只写临时 newCfg，校验全部通过后才 `*cfg = newCfg`；失败时 e.cfg 未动 |
| M-D5 | `retry_queue.go:299-325` | flush() DB 不可用时丢失任务 | ⚪ 复核：Stop() 随后 persist 快照，不丢 |
| M-D6 | `http/logs.go:319-341` | 日志流生产者退出后连接悬挂，只发心跳占名额 | 🟢 已修复（生产者退出即关闭发送通道） |
| M-D7 | `http/config_api.go:197-236` | 配置文件直接截断写，崩溃/磁盘满留下半份 YAML，下次启动或重载起不来 | 🟢 已修复（同目录临时文件 + Sync + rename，沿用旧文件权限） |
| M-D8 | `http/config_api.go:98-109` | 并发局部更新在锁外基于旧值合并，后写请求把先写字段覆盖回旧值 | 🟢 已修复（合并/校验移入 configFileMu，以锁内现值为底） |
| M-D9 | `ingest/reader.go:103-160` | inode 轮转时直接关旧 fd，最后一次读取后写入的行整段丢失 | 🟢 已修复（先按偏移读完旧 fd，旧尾巴 Rotated=false 分批交出，读干后才切换） |
| M-D10 | `http/stats.go:177-218` | SSE 每帧重查 7 天活动行；近 5 分钟计数查询失败把 0 当有效读数缓存 30 秒 | 🟢 已修复（活动行按 30 秒缓存；任一窗口查询失败不落缓存） |
| M-D11 | `runtime/file_reloader.go` | 热重载整份替换配置，把启动期出口探测写入的 `ServerLatitude/Longitude/ServerCoordsSource` 抹掉；文件未声明坐标时地理能力在第一次 SIGHUP 后退化 | 🟢 已修复（文件未设坐标且现行来源为 detected 时保留运行时坐标；文件坐标优先生效，补两条回归测试） |

### 前端（6 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-15 | `BaseChart.tsx` | Canvas 图表无文本替代 | 🟢 已修复（按 option 生成 aria-label + 隐藏摘要，覆盖折线/柱/饼/仪表/雷达/热力） |
| M-16 | `CommandPalette.tsx` | 键盘操作提示仅视觉可见 | 🟢 已修复（aria-describedby 关联含 Esc 的完整说明，视觉提示行 aria-hidden） |
| M-17 | `Dashboard.tsx:132-136` | kernel_version 回退逻辑死代码 | 🟢 已修复（Tag 无条件渲染） |
| M-18 | `endpoints.ts:456` | syncThreatFeeds 未传 signal | 🟢 已修复（按钮与深链均传 AbortSignal） |
| M-19 | `useAsync.ts:161-173` | 非 ApiError 异常静默包装 | 🟢 已修复（保留原 message，DEV 打原错误） |
| M-20 | `Logs.tsx:214-260` | 500 行缓冲区高频日志静默丢弃 | 🟢 已修复（溢出计数并提示） |

### 前端深层（7 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-F1 | `usePersistentState.ts:58-59` | 忽略跨 tab 的删除事件 | 🟢 已修复（回退初始值） |
| M-F2 | `DrawerForm.tsx:61-77` | 提交存在双次点击窗口 | 🟢 已修复（入口先置 submitting，取消确认时复位） |
| M-F3 | `NotificationProvider.tsx:92-103` | clear 依赖 items 导致 context 不稳定 | 🟢 已修复（itemsRef） |
| M-F4 | `useSse.ts` | SSE 重连后不立即触发数据校准 | 🟢 已修复（断线过才在重连成功时广播刷新，首次连接不重复拉取） |
| M-F5 | `ErrorBoundary.tsx:34-37` | 无错误持久化或上报 | 🔴 |
| M-F6 | `useSse.ts:107-122` | JSON.parse as T 类型断言未验证 | 🟢 已修复（按域校验容器形状，坏帧丢弃并 DEV 告警） |
| M-F7 | `api/client.ts:170-173` | API 响应 as T 断言未验证 | 🟢 已修复（统一校验非 null 对象/数组，形状错误抛 ApiError） |

### 跨模块（3 项）
| # | 问题 | 状态 |
|---|------|------|
| M-21 | 无并发 config reload + ban/unban 集成测试 | 🟢 已修复（`tests/test_24_concurrent_reload_bans.py`：四线程并发封禁/churn/写配置/重载，断言无 5xx、重载计数增长、终态与文件/API 对账。**需 root 的运行时执行未跑**） |
| M-22 | kmod-remote 不拷贝 contract 生成头文件 | ⚪ 复核：`Makefile:217-218` 的 rsync 同时上传 `src/kernel-module` 与整个 `contract` 目录，生成头文件随行 |
| M-23 | 内核异步拒绝封禁后，`ban_events` / `ban_history` / 信誉扣分不撤销 | 🔴 问题：自动路径在 `banSink.InsertPending` 先落库再下发（`cmd/firewall-daemon/main.go:832-867`），内核异步回 `CmdResult` 拒绝时 `handleCmdResult` 只撤内存镜像（`kernel/consumer.go:526-542`）。内核表满/泛洪闸门拒绝的封禁会在历史里留下一条不存在的封禁，并累计信誉扣分与复发次数（渐进式时长会据此升级）。修复需 DB 侧反向操作（删除对应事件、回退计数与信誉），或改为确认后落库 |

### 构建/文档（8 项）
| # | 问题 | 状态 |
|---|------|------|
| M-B1 | `clean` 未清理 `tmp/` 目录 | 🟢 已修复 |
| M-B2 | Node.js 版本 README/CI/package.json 不一致 | 🟢 已修复（README/CONTRIBUTING/build-system 统一 24） |
| M-B3 | 迁移文档引用本地绝对路径 | 🟢 已修复 |
| M-B4 | AGENTS.md 将未验证内核列为已验证 | 🟢 已修复（改称「内核兼容性状态」） |
| M-B5 | 构建文档 Go 版本过时 | 🟢 已修复（1.26） |
| M-B6 | `.gitignore` 未覆盖测试产物 | 🟢 已修复 |
| M-B7 | `debian/control:11` 显式依赖 build-essential | ⚪ 复核：`dkms` 自身依赖 gcc/make（apt 实测 `Depends: kmod, gcc, dpkg-dev, make \| build-essential, patch`），本包显式保留可不受上游依赖变更影响，冗余但无害 |
| M-B8 | `debian/control:11` 的 `linux-headers` 是多提供者虚包，非交互 apt 无法选定具体实现，安装直接失败 | 🟢 已修复：改为 `linux-headers-generic \| linux-headers-amd64`（本机 Ubuntu 实测 `linux-headers-amd64` 无候选、`linux-headers-generic` 有候选） |

### 契约/测试（5 项）
| # | 问题 | 状态 |
|---|------|------|
| M-T1 | 契约缺少显式版本号字段 | 🔴 |
| M-T2 | 测试稳定性：大量 time.sleep | 🔴 |
| M-T3 | 测试断言质量：仅检查状态码 | 🔴 |
| M-T4 | 缺少负面测试 | 🔴 |
| M-T5 | 配置日志缺少上限校验 | 🔴 |

### 错误处理（2 项）
| # | 问题 | 状态 |
|---|------|------|
| M-E1 | fmt.Errorf 缺少 %w 导致错误链断裂（多处） | 🔴 |
| M-E2 | CidrKey.Parse MustCidrKey panic | ⚪ 复核：`MustCidrKey` 仅在两处 `_test.go` 调用，生产路径一律走返回 error 的 `ParseCidrKey` |

### 情报源/热重载/判定链路（7 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-24 | `threatfeeds/cache.go:133-140`、`manager.go:191-203` | 同一 IP 跨源直接覆盖，置信度取决于 results 通道到达顺序。IPsum/FireHOL/DShield 大量重叠，同一地址在 0.85 与 0.7 间随机取值，直接决定「≥0.8 直接封禁」是否触发 | 🟢 已修复：键冲突保留 confidence 更高者、相等保留先到者；两种到达顺序结果一致 |
| M-25 | `threatfeeds/manager.go:87-94`、`cmd/firewall-daemon/main.go:391-399` | 一个源名写错 → `NewFeedManager` 返回错误 → `feedMgr = nil`，三个 threat-feeds 接口全部 503、判定层失去情报能力，只有一条 Warn。与「每个源独立、失败不影响其他源」的文档口径矛盾 | 🟢 已修复：未知源 Warn 后跳过，其余源正常装配；全部未知才报错 |
| M-26 | `threatfeeds/manager.go:216-242,272-279` | HTTP 200 但内容不可解析/为空时按成功处理：清零 `ConsecutiveFailures`、清熔断、刷新 `LastUpdate`。上游错误页/限流文本让条目数归零仍显示 ok，熔断永不触发，旧条目靠 TTL 苟活 | 🟢 已修复：0 条目按本轮失败处理，累计失败并触发熔断 |
| M-27 | `runtime/file_reloader.go:119`、`logger/logger.go:97-105`、`cmd/firewall-daemon/main.go:452-456` | 热重载改 `log_file` 后整份换入配置，但 sink 与级别只在 `logger.Init` 建一次；`LogFilePath` 闭包读新 `cfg.LogFile`，面板去新路径读而写入仍在旧文件，日志面板永久空白且无告警 | 🟢 已修复（声明需重启）：重载检测 log_file/log_level/log_format 变化逐项 Warn；日志接口只报启动时登记的实际写入路径，面板不再指向空文件 |
| M-28 | `runtime/pipeline.go:439-448`、`runtime/executor.go:1165-1174` | `ScanClusters` 无条件 `window.Forget`，而 `audit_only: true`（默认）时并不下发。审计观察期内单 IP 计数每检测周期被清，检出下降且无可察觉痕迹 | 🟢 已修复：`onHit` 返回是否处置，仅真正下发后清计数（下发失败也清，避免每周期重复告警） |
| M-29 | `decision/ddos.go:70-160`、`config/parser.go:628` | `NewDdosEngine`/`HandleEvent`/`CleanupStale` 生产侧零引用（仅本包测试），`ddos.auto_ban_threshold` 因此无消费者，改它无效；每 IP 违规累计与 `TrackedIPs` 永远为空，「第 N 次越线」语义缺失 | 🔴 待修复：需决定接线或删键，涉及产品语义 |
| M-30 | `ingest/reader.go:179`、`ingest/watcher.go:96`、`runtime/executor.go:495-526,561-591` | 读路径只有事件驱动、每次最多 256 KiB，无周期性补偿；inotify 溢出（`WD=-1`）在 `registry.Resolve` 落空被静默丢弃。执行体阻塞期间写入被合并或溢出后，写方转静默，尾部内容永久不判定（漏封）且无告警 | 🟢 已修复：识别 `IN_Q_OVERFLOW`，逐源连读补至偏移不再前进（单源上限 64 批）；新增 reader 与溢出补读测试 |

### 持久化/HTTP 读路径（4 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-31 | `persist/reputation.go:87-91`、`persist/facts.go:531-536` | `total_failures` 按「每次批量落盘 +1」而不是每次失败 +1：一个刷盘周期内的 n 次失败只记 1 次，契约的累计失败次数被系统性低估 | 🟢 已修复：`RecordFailure` 携带失败条数，`total_failures` 按条累加；3 次失败断言 |
| M-32 | `persist/risk_vectors.go:86-154` | `BatchDecayVectors` 全仓无调用者，库里的风险向量永不衰减；API 返回事件当日满值，与契约「半衰期 7 天」不符（行仍按 updated_at 清理，无无限增长） | 🟢 已修复：`risk_engine.enabled` 时每小时调度衰减，按 `updated_at` 起算间隔，避免每拍重复复利；补直接衰减与接线测试 |
| M-33 | `http/recommendations.go:58,95`、`persist/history.go:117` | 白名单推荐在 IP 级先按 `min_bans` 过滤，再按 /24 聚合；20 台各封 2 次的 /24（合计 40）在 `min_bans=5` 时返回空，子网级阈值成死代码，`total_bans/affected_ips` 也被低报 | 🟢 已修复：聚合下推到持久层，`min_bans` 在 /24、/48 聚合结果上判定；补段合计达标用例 |
| M-34 | `http/risk.go:115-136`、`persist/attack_events.go:41-47` | `/api/v2/risk/events/:ip` 以 `since=0` 取该 IP 全量事件再内存截断 100；`total` 也取截断后的长度。高频攻击源单次请求可把数十万行读进内存 | 🟢 已修复：SQL `LIMIT/OFFSET` 下推、`total` 改 COUNT 全集；契约同步 limit/offset 与 total 语义 |

---

## LOW 级（72 项）

### 内核模块（6 项）
| # | 文件 | 问题 |
|---|------|------|
| L-1 | `fw_hook.c` | 缺少 skb_linearize 检查 |
| L-2 | `fw_ban.c` | ban_count procfs sprintf 无溢出检查 |
| L-3 | `fw_netlink.c` | CmdResult errno 未翻译 |
| L-K4 | `fw_stats.c:141-160` | 直方图读侧无配对屏障（🟢 已修复：WRITE_ONCE/READ_ONCE 配对） |
| L-K5 | `fw_rate.c:413` | smp_mb__after_atomic 用于非原子操作（🟢 已修复：`clearing` 发布用 `WRITE_ONCE`+`smp_mb`，读侧 `READ_ONCE`；覆盖 exit/clear 与回收、插入三条路径） |
| L-K6 | `fw_ban.c:305-306` | 续期 mod_timer 交互（无实际影响） |
| L-K7 | `fw_state.c:188-240` | 保存分页按 offset 遍历，期间到期摘链会跳过或重复条目 |

### 守护进程（12 项）
| # | 文件 | 问题 |
|---|------|------|
| L-4 | `geoip/geoip.go` | MMDB 元数据无版本校验 |
| L-5 | `threatfeeds/http.go` | 重试退避无 jitter |
| L-6 | `threatfeeds/scheduler.go` | 全局 math/rand 无显式种子 |
| L-7 | `http/metrics.go` | Prometheus 格式不完整 |
| L-8 | `persist/facts.go` | 进程被杀时未落盘信誉分丢失 |
| L-9 | `threatfeeds/sources/dshield.go` | 忽略 attacks count 和 range 列 |
| L-10 | `http/body.go` | 允许无 Content-Type 的 JSON 请求 |
| L-11 | `risk/engine.go` | 缓存过期时 ShouldBan 返回 false |
| L-12 | `geoip/egress.go` | 每次调用创建新 HTTP client |
| L-D6 | `sse.go:318-323` | detach 阻塞发送可能泄漏 goroutine |
| L-D7 | `http/logs.go:60-84` | 每次查询两遍全文件扫描，大日志下 CPU 放大 |
| L-E3 | `daemonize.go:84,89` | PID 文件 Close 错误未检查 |
| L-E4 | `detect/cidr.go:133` | CidrKey.Parse panic（⚪ 复核：仅测试调用 `MustCidrKey`，生产走 `ParseCidrKey`） |

### 审计补充（14 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| L-27 | `logger/logger.go:97-102`、`http/logs.go:46-53` | 未配置 `log_file` 时写入默认 `/var/log/firewall.log`，但 `SetLogFile` 只在配置非空时登记，HTTP 侧读空值回 503「日志文件未配置」：进程在写日志，面板却说没有。修复：登记解析后的路径 | 🟢 已修复：登记解析后的实际写入路径；目的地不含文件时不登记，接口如实回未配置 |
| L-28 | `config/parser.go` 的 `validateThreatFeedURL`、`threatfeeds/http.go:107-119` | 配置期接受任意 http(s)，运行期只放行 4 个域名且强制 https；自定义镜像能通过启动校验，每轮失败后熔断。修复：配置期复用同一白名单 | 🟢 已修复：白名单与 https 校验抽到 `config.ValidateThreatFeedURL`，配置期与运行期共用 |
| L-29 | `geoip/egress.go:95-109`、`threatfeeds/http.go:123-125` | 非公网判定只排除 RFC1918/ULA/环回/链路本地/组播；`netip.IsPrivate()` 不含 100.64.0.0/10、192.0.0.0/24、198.18.0.0/15、240.0.0.0/4，探测端点返回 100.64.0.1 会被当地理出口，SSRF 检查也可被解析到该段绕过 | 🟢 已修复：显式排除 100.64/10、192.0.0/24、198.18/15、240/4，两处共用同一判据 |
| L-30 | `threatfeeds/sources/*.go`、`threatfeeds/parser.go` | 默认 `bufio.Scanner` 单行上限 64 KiB，任一行超长即 `scanner.Err()` 使整个源失败。修复：`scanner.Buffer` 调大并跳过超长行 | 🟢 已修复：`sources` 改为缓冲 1 MiB 的逐行读取，超长行丢弃后继续；100 KiB 与超上限行测试 |
| L-31 | `threatfeeds/parser.go:23` | `ParseIPList` 与 `sources.parseIPList` 重复，生产路径不调用（仅测试），属可删除死代码 | 🔴 待修复（死代码，无行为影响） |
| L-32 | `decision/policy.go:149-176` | 退化分支 `expiresAt=now+1` 但 `Duration=0`、`IsPermanent=false`，`executor.go:1222-1230` 会把 0 当永久下发，镜像 1 秒后过期；现被 `validateBantime`（`parser.go:539`）归一，暂不可达 | 🟢 已修复：退化分支改为 `Duration=1`、`IsPermanent=false`，字段自洽并有断言 |
| L-33 | `analysis/prediction.go:230-239` | 趋势用「24h ÷ 7 日均值」，契约 `contract/http.fwidl:1529` 写「与前一日的量比较」，口径不一致 | 🟢 已修复：改为近 24h 与前一日 24h 比较，与契约一致；补四组样本测试 |
| L-34 | `analysis/recommendations.go:194-201` | `current=1` 时 direction 为 decrease/increase，推荐值仍等于 1，读数自相矛盾 | 🟢 已修复：取整后与 current 相等时方向归 maintain；补 0/1/中间值测试 |
| L-35 | `decision/policy.go:9-12` | 包注释仍写乘法模型与信誉系数 1.0/0.8/0.5，与同文件加法实现及 AGENTS「加法模型」矛盾，易误导改判据的人 | 🟢 已修复：包注释改为加法模型，行为未动 |
| L-36 | `persist/retry_queue.go:388-391` | `LoadPersisted` 超出 `MaxSize` 时静默截断（只 Info），被截掉的任务永久丢失（历史/信誉/事件底账少记） | 🟢 已修复：截断记 Warn，带丢弃条数与上限 |
| L-37 | `kernel-module/fw_wl.c:220-225` | 本机地址的白名单条目只能添加、无法删除：`fw_wl_remove` 对 `fw_local_lookup` 命中的地址一律 `-EPERM`，而接口地址已不再自动写入白名单，残留条目还会挡住建封 | 🔴 待修复 |
| L-38 | `kernel-module/fw_state.c:493-505` | 恢复时 `banned_at` 被重置为模块加载时刻，`duration_secs` 退化为剩余时长；到期正确，但 daemon 的历史与时长直方图每次重启后偏小 | 🔴 待修复 |
| L-39 | `persist/retry_queue.go:118-127,230-271` | 满队丢弃与 batch 回填竞争：batch 执行期间被丢弃的任务若失败会作为 remaining 写回，丢弃语义被撤销，队列可超 `MaxSize`（未验证，时序依赖强） | 🟢 已修复：批次重建后同一锁周期再裁剪，容量上限重新成立；并发回归测试 |
| L-40 | `http/metrics.go:63-64` | `/metrics` 在读锁内写网络；慢抓取会阻塞新指标注册（`Counter/Gauge` 的写锁），进而钉住请求路径。写错误被忽略 | 🟢 已修复：锁内只做快照，排序与响应写出移到解锁后 |


### 前端（12 项）
| # | 文件 | 问题 |
|---|------|------|
| L-13 | `DataTable.tsx:47` | rowKey 默认 "_index" 文档未说明风险 |
| L-14 | `useHotkey.ts` | r 键刷新可能与浏览器冲突 |
| L-15 | `Analysis.tsx:86-87` | analysis/summary 和 analysis/ip 后端是桩 |
| L-16 | `Bans.tsx:142-147` | 每个临时封禁独立 setInterval |
| L-17 | `ThreatFeeds.tsx` | confidence 假设 0-1 范围 |
| L-18 | `ErrorBoundary.tsx` | 显示原始错误信息 |
| L-19 | `endpoints.ts` | getHealth 和 getHealthz 重复 |
| L-20 | `NotificationProvider.tsx` | clear 遍历销毁 toast |
| L-21 | `format.ts` | copyToClipboard 使用废弃 API |
| L-22 | `useAsync.ts` | 7 处 exhaustive-deps 抑制 |
| L-23 | `Analysis.tsx` | 松散字符串键查找表 |
| L-24 | `client.ts` | ApiError 未显式设置原型链 |

### 前端深层（4 项）
| # | 文件 | 问题 |
|---|------|------|
| L-F8 | `Logs.tsx:280-289` | live→history→live 切换不清理旧数据 |
| L-F9 | `ThreatFeeds.tsx:273-300` | 深链 sync 未传 AbortSignal（🟢 已修复） |
| L-F10 | `Bans.tsx:381-463` | columns 依赖 lastUpdatedAt 过宽 |
| L-F11 | `useAsync.ts:182-195` | enabled 翻转触发冗余请求 |

### 集成测试缺失（5 项）
| # | 问题 |
|---|------|
| L-25 | 无 auth lockout 机制测试（🟢 已修复：`tests/test_23_auth_lockout.py`） |
| L-26 | 无并发 config reload 测试（🟢 已修复：`tests/test_24_concurrent_reload_bans.py`） |
| L-27 | 无分页边界测试 | 🟢 已修复：登记解析后的实际写入路径；目的地不含文件时不登记，接口如实回未配置 |
| L-28 | 无 batch ban 限制测试 | 🟢 已修复：白名单与 https 校验抽到 `config.ValidateThreatFeedURL`，配置期与运行期共用 |
| L-29 | 无 daemon 崩溃重连测试 | 🟢 已修复：显式排除 100.64/10、192.0.0/24、198.18/15、240/4，两处共用同一判据 |

### 构建系统（8 项）
| # | 问题 |
|---|------|
| L-30 | frontend stamp file 导致不必要重构建 | 🟢 已修复：`sources` 改为缓冲 1 MiB 的逐行读取，超长行丢弃后继续；100 KiB 与超上限行测试 |
| L-31 | kmod-remote 依赖本地 contract 生成 | 🔴 待修复（死代码，无行为影响） |
| L-B8 | Makefile.dkms 使用 $(shell pwd) |
| L-B9 | bench Makefile sink 未用 LDFLAGS |
| L-B10 | CI 产物名不含版本信息 |
| L-B11 | Release workflow 无构建验证 |
| L-B12 | README 重复许可证章节 |
| L-B13 | 无 SELinux/AppArmor profile |

### 契约/测试（4 项）
| # | 问题 |
|---|------|
| L-T6 | 契约间 BanEntry/BanResponse 字段差异 |
| L-T7 | gen.py 空字符串边界 |
| L-T8 | 测试使用私有 IP 可能冲突 |
| L-T9 | 缓存缺穿透/雪崩防护 |

### 错误处理/边界（5 项）
| # | 问题 |
|---|------|
| L-E5 | stats.go defer Close 错误未检查 |
| L-E6 | contract/messages_out.go slice 越界风险 |
| L-E8 | 日志流 pending 缓冲临时增长 |
| L-E9 | `http/handlers.go` 包注释把 50003 写成「查询失败」，与 `envelope.go` 的「库未初始化/503」不符（🟢 已修复） |
| L-I1 | `ingest/registry.go:183-187` Iterate 浅拷贝 Owners，注释称「改动不影响注册表」不成立 |

---

## 设计取舍（不修复）

| # | 问题 | 原因 |
|---|------|------|
| ⚪-1 | Ban 返回 Delivered 非 Executed | 异步设计，内核执行后通过 CmdResult 报告失败 |
| ⚪-2 | 进程被杀时未落盘信誉分丢失 | 信誉分只是渐进调整量，非封禁事实 |
| ⚪-3 | 允许无 Content-Type 的 JSON 请求 | 命令行客户端兼容性 |
| ⚪-4 | analysis/summary 和 analysis/ip 是桩 | 功能规划中，前端已优雅降级 |
| ⚪-5 | SSE broadcast channel 满时丢弃 | 防止慢客户端拖住发布方 |
| ⚪-6 | Facts 缓存容量 4096 | 内存占用可控，超出时逐出 |
| ⚪-7 | RetryQueue 有界队列超出丢弃 | 防止内存无限增长 |

---

## 修复进度

### 批次 1（已提交）：CRITICAL + HIGH 7 项
C-1、C-3、H-1、H-2、H-4、H-5、H-7

### 批次 2（已提交）：并发与内核发送锁 12 项
C-4、H-8、H-9、H-12、H-13、H-14、H-15、H-16、H-17、H-18、M-F1、M-F2

### 批次 3（已提交）：四路并行 23 项
- 内核：M-K1、M-K2、M-K3、L-K4
- 守护进程：M-5、M-6、M-12、M-13、M-D2、H-19、M-D6
- 前端：M-17、M-18、M-19、M-20、M-F3、L-F9
- 构建/文档：M-B1、M-B2、M-B3、M-B4、M-B5、M-B6

### 批次 4（已提交）：内核状态恢复与守护进程写路径 9 项
- 内核：M-K4、M-K5
- 守护进程：M-7、M-9、M-D3、M-D7、M-D8、M-D9、M-D10

### 批次 5（已提交）：前端实时流与无障碍 6 项
- H-3、M-F4、M-F6、M-F7、M-15、M-16

### 批次 6（已提交）：封禁原子性、信誉欠账、配置锁与集成用例
- 守护进程：H-10、H-11、H-20、M-D11、M-11、L-E9
- 内核：M-4、L-K5
- 构建/测试：M-8、M-21、L-25、L-26、M-B8
- 复核为误报/取舍：M-2、M-3、M-22、M-B7、M-E2、L-E4

### 批次 7（已提交）：情报源、日志路径、集群键与读取补偿
- 情报源：H-21、M-24、M-25、M-26、L-28、L-29、L-30
- 判定链路：H-22、M-28、L-32、L-35
- 日志/读取：M-27、L-27、M-30
- 分析读数：L-33、L-34

### 待修复重点（按风险排序）
1. **CRITICAL**：C-2（SSE 凭据在 URL，需前后端配合）
2. **MEDIUM 数据正确性**：M-23（内核拒绝封禁后底账不回撤）、M-29（DDoS 引擎未接线、
   `auto_ban_threshold` 无消费者）、M-F5
3. **测试缺口**：M-T1~M-T5、M-E1
4. **LOW 批量**：其余 52 项，按模块分批处理
