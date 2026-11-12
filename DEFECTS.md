# 功能缺陷清单

> 生成时间：2026-11-11
> 更新时间：2026-11-12（第十四轮：深度扫描 50+ 项，已修复 30 项）
> 状态标记：🔴 待修复 | 🟡 修复中 | 🟢 已修复 | ⚪ 设计取舍/复核为误报

---

## 统计

| 严重度 | 发现总数 | 已修复 | 待修复 |
|--------|----------|--------|--------|
| CRITICAL | 5 | 4 | 1 |
| HIGH | 83 | 67 | 15 |
| MEDIUM | 192 | 100 | 81 |
| LOW | 177 | 34 | 142 |
| **合计** | **457** | **205** | **239** |

另有 13 项经复核为误报或设计取舍（标 ⚪），不计入待修复：H-6、M-1、M-2、M-3、M-10、M-14、M-22、M-B7、M-D1、M-D4、M-D5、M-E2、L-E4。

---

## CRITICAL 级（5 项）

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

### C-5 🟢 封禁节点摘链用 `hlist_del_rcu`，到期回调与删除路径竞态可二次摘链
- **文件**: `src/kernel-module/fw_ban.c:303-313`（到期回调）、`581-590`（`fw_ban_del`）、`625-640`（白名单联动）、`353-356`（退出清理）
- **问题**: `hlist_del_rcu()` 会把 `pprev` 写成 `LIST_POISON2`，而到期回调的守卫是
  `hlist_unhashed(&n->hash)`（判 `pprev == NULL`）。删除路径先 `timer_delete()` 再摘链，但
  `timer_delete()` 不同步：若定时器回调已在另一 CPU 上运行并卡在桶锁上，删除路径摘链、
  `call_rcu()` 之后，回调拿到锁时 `hlist_unhashed()` 为假，会按「仍在链上」继续执行
  `hlist_del_rcu()`；此时 `next` 已是 `LIST_POISON1`，`__hlist_del` 经毒化指针写
  `next->pprev`，触发内核 Oops。退出清理与白名单联动同理
- **影响**: 解封 / 到期 / 白名单删除与到期定时器重合时内核崩溃（可被正常运维操作触发）
- **状态**: ✅ 已修复 — 到期回调、退出清理、`fw_ban_del`、白名单联动四处摘链全部改用
  `hlist_del_init_rcu()`（恢复 `pprev == NULL`），`hlist_unhashed()` 守卫因此成立；
  `timer_delete()` 保持非同步语义
- **难度**: 低 | **风险**: 高（内核 Oops）

---

## HIGH 级（44 项）

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

### H-21 🟢 Blocklist.de 条目 TTL 固定 2 小时，每轮刷新后 92% 时间不起作用
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

### H-22 🟢 集群聚合键不做 IPv4-mapped 归一，所有映射地址塌进 `::/48`
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

### H-27 🟢 到期回调把「续期为永久」的封禁当作到期删除
- **文件**: `src/kernel-module/fw_ban.c:455-470`（续期）、`300-313`（到期回调）
- **问题**: 续期为永久时插入路径执行 `is_permanent = 1` 并 `timer_delete()`；`timer_delete()`
  不同步，已在运行的回调仍会继续。回调只在 `!is_permanent` 分支重武装，看到
  `is_permanent == 1` 就落入摘链删除分支，把刚续成永久的封禁解掉
- **影响**: 永久封禁偶发消失；调用方（API / 自动判定）拿到成功回执却不再拦截
- **状态**: ✅ 已修复 — 回调在续期判断前先读 `is_permanent`，为真则释放锁直接返回，
  不摘链、不推送解封
- **难度**: 低 | **风险**: 中高（封禁丢失）

### H-28 🟢 自决封禁路径在 softirq 中调用可休眠的 `down_read`
- **文件**: `src/kernel-module/fw_hook.c:146-152` → `fw_ban.c:525` → `fw_netlink.c:104`
- **问题**: netfilter 钩子运行在 softirq，自决封禁调用
  `fw_ban_try_add(..., notify=true)`，插入成功后 `fw_nl_send_lock()` 是
  `down_read(&fw_nl_send_sem)`。非 PREEMPT_RT 内核在 softirq 中休眠是非法操作；
  同一文件里到期回调与 DDoS 事件推送都已改用 `trylock`，只有这条路径漏掉
- **影响**: 触发 `BUG: sleeping function called from invalid context`，内核告警/崩溃
- **状态**: ✅ 已修复 — 自决路径传 `notify=false`，封禁成功后在同一 `trylock` 分支补发
  `BanStateChange`，DDoS 事件照常单独推送；softirq 内不再取休眠锁，镜像也无需等对账
- **难度**: 低 | **风险**: 高（内核上下文违规）

### H-29 🟢 模块卸载窗口内 netlink 仍处理封禁/白名单指令
- **文件**: `src/kernel-module/fw_netlink.c:861-1071`（`fw_nl_recv_msg`）、`fw_main.c:333-344`
- **问题**: `fw_exit()` 先清理 `fw_ban/fw_wl/fw_rate/fw_stats/...`，最后才
  `fw_netlink_exit()`；`fw_nl_recv_msg` 没有任何 `fw_is_shutting_down()` 检查。该窗口内
  daemon 仍可下发 BAN_IP/ADD_WHITELIST：查白名单时表已释放（UAF），新插入的封禁会
  重新武装定时器，模块卸载后定时器回调指向已卸载代码
- **影响**: rmmod/升级模块时若 daemon 正在下发，内核 UAF 或卸载后回调崩溃
- **状态**: ✅ 已修复 — `fw_nl_recv_msg` 入口检查 `fw_is_shutting_down()`，关闭中直接丢弃
  指令并记 rate-limited 日志，不再触碰已释放的表
- **难度**: 低 | **风险**: 高（卸载期内核崩溃）

### H-30 🟢 内核事件的空 jail 覆盖守护进程镜像，所有下发封禁归入空 jail
- **文件**: `src/daemon/internal/kernel/consumer.go:415-416,755-770,776-800`、`contract/netlink.fwidl:163,386-393`
- **问题**: `BanIp` 没有 jail 字段，内核为 daemon 下发的封禁广播
  `jail_name = ""`（契约约定「空串表示由 daemon 推断」）。`banInfoFromChange()` 直接用
  `ev.JailName` 覆盖 `Upsert`，把 `InsertPending` 里记录的真实 jail 冲成空串；对账构造的
  `banInfoFromEntry()` 同样直接取内核条目。`CountByJail()` 与按 jail 批量解封因此全部
  落在 `""`
- **影响**: 面板每个 jail 的活跃封禁数恒为 0/错误，按 jail 批量解封失效；正常自动封禁
  路径全部受影响
- **状态**: ✅ 已修复 — 事件与对账在 `JailName` 为空时保留镜像里已有的 jail 归属，
  仅本地也无归属时才用空串
- **难度**: 低 | **风险**: 中高（运维视图与批量操作失真）

### H-31 🟢 netlink 链路断开后接收回路退出，进程继续运行但永久失聪
- **文件**: `src/daemon/internal/kernel/reactor.go:70-86`、`src/daemon/internal/runtime/supervisor.go:57-69`
- **问题**: `Run()` 收到 `EventLinkDown` 只记一条 Warn 后 `return`；Supervisor 只等待
  goroutine 结束，不重启也不上报。此后封禁事件、指令回执、对账响应全部无人接收，
  守护进程仍正常提供 HTTP/前端
- **影响**: 模块重载或 socket 异常后，面板与判定链路静默失效，直到人工重启
- **状态**: ✅ 已修复 — reactor 支持 `WithLinkDownHandler`，组合根把链路断开转为致命错误并
  请求退出，由 systemd `Restart=on-failure` 拉起；回调只触发一次
- **难度**: 中 | **风险**: 中高（控制面静默失效）

### 第十轮补充（HIGH 7 项）

### H-32 🟢 速率表清空把节点重新挂进分页表，RCU 读者看到被投毒的 `next`
- **文件**: `src/kernel-module/fw_rate.c:329-430`、`src/kernel-module/fw_types.h`
- **问题**: `fw_rate_clear_all` 先 `hlist_del`（非 RCU 变体）摘链，再把节点按 `af/prefix`
  重新挂进 staging 哈希表以「按页释放」。`hlist_del` 会把 `next` 写成 `LIST_POISON1`，
  而被摘下的节点仍可能被 RCU 读侧遍历；同时 staging 表本身没有桶锁保护
- **影响**: 清空速率表（配置清零 / 卸载前）并发打流时读侧可能沿毒化指针访问，触发
  Oops；staging 链损坏还会让部分节点永不释放
- **状态**: ✅ 已修复 — 删除 staging 表，每桶在桶锁内只摘一批（≤32）到栈上，
  逐条 `hlist_del_rcu`，锁外 `on_each_cpu` 清槽 + `call_rcu`；`clear_all` 与 `exit`
  由 `fw_rate_clear_lock` 串行
- **难度**: 中 | **风险**: 中高（内核崩溃 / 内存泄漏）

### H-33 🟢 速率分页每页重置全局流量计数，守护进程把后续页读成 0
- **文件**: `src/daemon/internal/kernel/client.go:380`、`src/kernel-module/fw_netlink.c`
- **问题**: 内核在每页响应里取走并清零全局 `packets/bytes` 计数，分页时所有页都带
  「本页期间」的增量；守护进程原先逐页用返回值覆盖全局字段，续页间隔极短，最终读数
  被最后一页的趋零值取代
- **影响**: 负载下速率视图与告警阈值读数偏低甚至归零，DDoS 面板失真
- **状态**: ✅ 已修复 — `listRatesAll` 只在 `offset == 0` 时采纳全局计数，后续页
  只合并条目；补分页测试
- **难度**: 低 | **风险**: 中（运维视图失真）

### H-34 🟢 IPv6 首片被当作无传输层头，封禁/速率判定整段失效
- **文件**: `src/kernel-module/fw_hook.c:365-412`
- **问题**: 扩展头遍历遇到 `NEXTHDR_FRAGMENT` 直接 `break` 并把 `proto` 置 0，
  但分片偏移为 0 的首片**仍带传输层头**，SYN/UDP 端口/ICMPv6 Echo 全部读不到
- **影响**: 攻击者给报文加一个分片头即可绕过 TCP 标志异常、协议专项速率与端口门控
- **状态**: ✅ 已修复 — 解析 8 字节 `frag_hdr`，仅非首片（`ntohs(frag_off) & IP6_OFFSET`）
  置 `frag_nonfirst`，首片继续按 `frag.nexthdr` 解析传输层；AH 长度按
  `(hdrlen + 2) * 4` 前进
- **难度**: 中 | **风险**: 高（可绕过封禁与速率判定）

### H-35 🟢 批量解封先删镜像再逐条删内核，失败条目从面板消失但内核仍在封禁
- **文件**: `src/daemon/internal/http/bans.go:283`
- **问题**: `UnbanAllTemporary` 先清空本地封禁镜像，再逐条调内核删除；任一删除
  失败时只记日志，该 IP 已不在镜像里，后续对账/页面都看不到它
- **影响**: 内核实际仍丢包，面板显示「已全部解封」，且无法再次从面板解除
- **状态**: ✅ 已修复 — 先取 `TemporaryInfos()` 快照，逐条删内核，成功才
  `GlobalCache().Remove` 并记历史；失败条目保留在镜像
- **难度**: 低 | **风险**: 中高（封禁状态与界面不一致）

### H-36 🟢 `GetJailStats` 在 RLock 内返回内部结构指针，解锁后继续被改写
- **文件**: `src/daemon/internal/config/jails_api.go:61`
- **问题**: 返回 `*JailRuntimeStats` 指向 jail 配置里的运行态对象，`RLock` 只保护取指针；
  调用方随后读字段时 `UpdateJailStats` 可能正在写同一结构
- **影响**: `-race` 可复现数据竞争，统计接口读到撕裂字段（计数与速率不自洽）
- **状态**: ✅ 已修复 — 改为返回值拷贝 `(JailRuntimeStats, bool)`，两处调用点同步调整
- **难度**: 低 | **风险**: 中（数据竞争）

### H-37 🟢 禁用 jail 仍持有共享日志文件的 owner 身份，关闭后继续收行
- **文件**: `src/daemon/internal/ingest/registry.go:102`、`src/daemon/internal/runtime/executor.go:857`
- **问题**: `Register` 只追加 owner，没有「按 jail 移除」的入口；jail 被禁用或改名后
  旧 owner 残留，共享同一日志文件的判定仍把行分发给它
- **影响**: 已停用的 jail 继续产生封禁事件/审计记录，与面板显示矛盾
- **状态**: ✅ 已修复 — 新增 `SetLogOwners(path, jails)` 精确替换日志 owner，
  保留非日志 owner 与 `SourceID`/watch/偏移；对账按清理后路径聚合调用；
  配置回滚路径补 `reconcileWatches()`
- **难度**: 中 | **风险**: 中高（停用规则仍生效）

### H-38 🟢 威胁情报接受 `/0` 等超宽网段，单条记录可覆盖全部地址空间
- **文件**: `src/daemon/internal/threatfeeds/sources/ipsum.go:69-94`
- **问题**: 解析只校验 `net.ParseCIDR` 成功，不设前缀下界；`0.0.0.0/0`、`::/0`
  以及掩码后为全零的地址会被当作正常条目缓存，置信度 ≥ 0.8 时直接进入封禁判定
- **影响**: 上游一条坏记录即可让所有来源地址命中情报封禁（或反之整段被误判），
  且白名单只能靠人工兜底
- **状态**: ✅ 已修复 — 统一 `parseFeedEntry`：IPv4 前缀 < /8、IPv6 < /16、
  未指定地址与掩码后全零网络一律拒绝并计数告警；Ipsum/DShield/Feodo 共用
- **难度**: 低 | **风险**: 高（误封全部流量）

### 第十一轮补充（HIGH 5 项）

### H-39 🟢 长封禁时长经 32 位 jiffies 回绕，365 天封禁实际数分钟即到期
- **文件**: `src/kernel-module/fw_ban.c:87-110,173-180,320-335`
- **问题**: 到期时刻按 `jiffies + duration_secs * HZ` 计算并存进 `unsigned long`；
  32 位内核上 365 天（约 1.1e10 个 jiffy）远超 `MAX_JIFFY_OFFSET`，乘法与加法回绕，
  `mod_timer` 得到的是过去或极近的时刻
- **影响**: 面板与 API 承诺的长期封禁在数分钟后被内核自行摘除，攻击者自动恢复访问
- **状态**: ✅ 已修复 — `banned_at`/`unban_jiffies` 改存绝对 Unix 秒，定时器只武装
  `min(剩余秒 × HZ, MAX_JIFFY_OFFSET)` 的一段，到期回调按绝对时刻续武装
- **难度**: 中 | **风险**: 高（封禁静默失效）

### H-40 🟢 状态文件按行还原，reason/device 未消毒可注入伪造的封禁与白名单行
- **文件**: `src/kernel-module/fw_state.c:132-150,240-320`
- **问题**: 保存端只对 jail 名做换行清洗；`reason` 与白名单 `device_name` 直接
  `snprintf` 进行缓冲。含 `\n` 的字段能把一行拆成多行，重启恢复时被解析成额外的
  `BAN_`/`WL_` 条目
- **影响**: 通过封禁原因或设备名写入的换行可在重启后植入任意地址的封禁或放行规则
- **状态**: ✅ 已修复 — 三类字符串字段都在本地副本上经 `fw_state_sanitize_field`
  清洗后再写行，行数与字段数不可能被载荷扩张
- **难度**: 低 | **风险**: 高（持久化规则被篡改）

### H-41 🟢 netlink 发送用阻塞式 sendto 且无超时，缓冲满时钉住整条采集与关停
- **文件**: `src/daemon/internal/kernel/transport.go:266-355,581-615`
- **问题**: 发送路径是主链路唯一 goroutine 上的阻塞 `sendto`；对端接收队列满时
  无限等待，`Close` 又要先取 `sendMu`，SIGTERM 后进程同样退不出去
- **影响**: 内核侧一次拥塞即让日志采集、判定与进程关停同时停摆
- **状态**: ✅ 已修复 — `MSG_DONTWAIT` + `poll(POLLOUT)` 分段等待（上限 2 秒），
  每片检查关闭标志；`Close` 先置标志、信号链路断开，再取 `sendMu` 关 fd
- **难度**: 中 | **风险**: 高（守护进程整体卡死）

### H-42 🟢 风险向量后台衰减先读全表再逐行回写，覆盖并发写入的新快照
- **文件**: `src/daemon/internal/persist/risk_vectors.go:116-190`
- **问题**: `BatchDecayVectors` 读出全部行、在 Go 侧算衰减、再整列 upsert；
  读与写之间事件 worker 写入的新向量会被旧值的衰减结果覆盖，谁后写谁赢
- **影响**: 活跃攻击期间的风险分被静默回退，阈值判定与自动封禁读到过期读数
- **状态**: ✅ 已修复 — 衰减与「近零删除」合并进单个事务：一条 UPDATE 按各行
  `updated_at` 用 `pow(0.5, …)` 原子衰减并只处理 `updated_at <= now` 的行；
  权重由引擎经 `SetRiskVectorWeights` 注入，两处口径同源
- **难度**: 中 | **风险**: 中高（风险分失真）

### H-43 🟢 分析面先取最近 1 万条事件再按时间过滤，窗口外事件挤掉窗口内样本
- **文件**: `src/daemon/internal/analysis/detection.go:33-120`、`prediction.go:47-120`、
  `recommendations.go:31-90`、`network.go:30-60`、`persist/ban_events.go:154-528`
- **问题**: 周期性/协同/预测/建议/网段分布都从 `GetBanEvents(10000)` 拿数据；
  先按 `banned_at` 降序截断再在 Go 里筛窗口，攻击量一大，7 天/30 天窗口只剩最近几天
  的样本，统计与趋势在无任何提示的情况下失真
- **影响**: 复发率、复发间隔、趋势与预测基于残缺样本，误判与误建议直接进面板
- **状态**: ✅ 已修复 — 窗口条件与聚合下推 SQL：`BanJailStatsSince`、
  `BanDurationStatsSince`（LAG + 中位数）、`BanAggregatesByIPSince`、
  `GetIPBanIntervalStats`、`GetJailBanWindowCounts`、`StreamJailBans` 按
  `(jail, banned_at)` 流式扫描；原始时刻只对最终入选地址按名单取回
- **难度**: 高 | **风险**: 高（分析结论系统性偏差）

### 第十二轮补充（HIGH 1 项）

### H-44 🟢 封禁表分页遍历在 RCU 读侧直接 memcpy jail_name/reason，并发解封可能释放节点
- **文件**: `src/kernel-module/fw_ban.c:735-736`
- **问题**: `fw_ban_fill_entries` 在 rcu_read_lock() 内直接 `memcpy(rows[].jail_name, n->jail_name)`，
  但并发的 `fw_ban_del` 会摘链并 `call_rcu` 释放节点；RCU 读侧临界区不阻止释放，只延迟到
  grace period 结束，而 memcpy 期间可能正好在 grace period 内
- **影响**: LIST_BANS 分页期间并发解封可能触发 use-after-free，内核 Oops
- **状态**: ✅ 已修复 — 每个桶在桶锁内拷贝字段到栈上（同 `fw_ban_insert` 第 544-546 行的做法），
  解锁后再写入 rows
- **难度**: 中 | **风险**: 高（内核崩溃）

### 第十四轮补充（HIGH 8 项）

### H-45 🟢 netlink 消息批处理在 shutdown 期间未逐条检查 shutting_down 标志
- **文件**: `src/kernel-module/fw_netlink.c:900-1141`
- **问题**: `fw_nl_recv_msg()` 的外层 `while` 循环处理单 skb 中的多条 netlink 消息。`fw_is_shutting_down()` 检查只在循环顶部做一次，第一条消息通过后 `fw_exit()` 可能已销毁 ban/wl/rate 表，后续消息仍会调用已销毁的子系统
- **影响**: 模块卸载期间处理批量 netlink 消息可能访问已释放内存，内核 Oops
- **状态**: ✅ 已修复 — 在每个修改操作的 switch case（BAN_IP/UNBAN_IP、ADD_WHITELIST/REMOVE_WHITELIST、SET_CONFIG、SET_PROTECTED_PORTS）前再次检查 `fw_is_shutting_down()`，为 true 则 break

### H-46 🟢 状态持久化依赖 `/bin/mv` 和 `/bin/rm`，最小化环境可能不存在
- **文件**: `src/kernel-module/fw_state.c:164-180`
- **问题**: `fw_state_atomic_replace()` 调用 `call_usermodehelper("/bin/mv", ...)` 做原子替换，`fw_state_unlink()` 使用 `/bin/rm`。在 initramfs 或最小化嵌入式环境中这些工具可能不存在，导致状态无法持久化且 `.tmp` 文件残留
- **影响**: 状态持久化静默失败，重启后封禁表丢失
- **状态**: ✅ 已修复 — 新增 `fw_state_init()` 在模块加载时通过 `filp_open(O_PATH)` 探测 `/bin/mv` 和 `/bin/rm`，缺失则 `pr_warn` 告警但不阻止加载

### H-47 🟢 封禁表插入时发现过期条目未移除，导致计数膨胀
- **文件**: `src/kernel-module/fw_ban.c:480-505`
- **问题**: `fw_ban_insert_locked()` 找到已存在但已过期的节点时，直接走新插入路径而不删除旧节点。结果同一 (af, addr, prefix_len) 在哈希桶中有两个节点，`ban_count` 被多加 1，直到旧节点的定时器触发清理
- **影响**: 封禁表接近容量时可能因虚高的 `ban_count` 触发 `-ENOSPC` 拒绝新封禁
- **状态**: ✅ 已修复 — 发现过期节点时先完整删除（timer_delete + hlist_del_init_rcu + atomic_dec + call_rcu），再走新插入路径

### H-48 🟢 SSE Broker 的 register/unregister channel 在 Stop() 后未关闭
- **文件**: `src/daemon/internal/http/sse.go:228-278`
- **问题**: `SSEBroker.run()` 退出后 `register` 和 `unregister` channel 未被显式关闭。虽然 `attach()` 有 `<-b.stopCh` 保护不会永久阻塞，但 channel 依赖 GC 回收而非显式清理
- **影响**: 潜在的 goroutine/channel 泄漏，频繁启停场景下资源累积
- **状态**: ✅ 已修复 — 添加 `done` channel，`Stop()` 等待 `run()` 退出后再关闭 `register`/`unregister`
- **难度**: 低 | **风险**: 低（资源泄漏）

### H-49 🟢 FeedManager.RefreshAll 的等待 goroutine 在 context 取消时可能阻塞
- **文件**: `src/daemon/internal/threatfeeds/manager.go:170-197`
- **问题**: `RefreshAll` 创建的等待 goroutine（`wg.Wait()` 后关闭 results channel）在调用方提前退出时可能阻塞。虽然 `wg.Wait()` 最终会完成，但 worker 的 HTTP 请求超时可能导致长时间阻塞
- **影响**: context 取消场景下 goroutine 生命周期延长
- **状态**: ✅ 已修复 — 派生子上下文，`RefreshAll` 返回时取消所有 worker 的 HTTP 请求

### H-50 🟢 InboundExecutor.Close() 与 poll() 的 fd 竞态
- **文件**: `src/daemon/internal/runtime/executor.go:373-382,432-470`
- **问题**: `Close()` 调用 `e.watcher.Close()` 关闭 inotify fd 时，主循环可能正在 `unix.Poll(fds, ...)` 阻塞。关闭 fd 后 `Poll` 的行为未定义——可能返回 EBADF，也可能在 fd 复用后读到错误数据
- **影响**: 极端情况下可能读到错误的 inotify 事件或 EBADF 恐慌
- **状态**: ✅ 已修复 — 添加 `mainDone` channel，`Close()` 等待 `Run()` 退出后再关闭 watcher

### H-51 🟢 main.go 中 transport 可能被 double-close
- **文件**: `src/daemon/cmd/firewall-daemon/main.go:295,669-671`
- **问题**: `NewInboundExecutor` 失败时显式调用 `transport.Close()`，但 `defer transport.Close()` 已注册。虽然 `Transport.Close()` 内部有 `closed` 标志做幂等保护，但依赖实现细节
- **影响**: 代码意图不清晰，未来实现变化可能引入 bug
- **状态**: ✅ 已修复 — 移除显式 `transport.Close()` 调用，统一由 defer 管理

### H-52 🟢 Facts.eventWorker 在事件入队时未捕获向量快照
- **文件**: `src/daemon/internal/persist/facts.go:233-247`
- **问题**: `eventWorker` 处理事件时先 `InsertEvent`（可能慢），再 `riskEngine.GetVector` 获取向量快照。两次调用之间向量可能因衰减而变化，导致写入数据库的向量与事件发生时的实际向量不一致
- **影响**: 风险向量历史数据不准确，审计追溯时看到衰减后的值
- **状态**: ✅ 已修复 — `riskEvent` 结构体添加 `vector`/`hasVector` 字段，在事件入队时捕获向量快照

### 第二轮扫描补充（HIGH 16 项）

### H-53 🟢 测试 ip_is_banned() 子串匹配产生误判
- **文件**: `tests/conftest.py:230-236`
- **问题**: `ip_is_banned()` 使用 `ip in content` 做子串匹配，查询 `10.0.0.1` 时会匹配到 `10.0.0.10`、`10.0.0.100` 等
- **影响**: test_03_ban_unban.py 和 test_04_whitelist.py 中依赖此函数的断言可能假阳性
- **状态**: ✅ 已修复 — 改为逐行精确匹配，`line.strip() == ip`

### H-54 🟢 并发测试断言薄弱，未验证实际操作结果
- **文件**: `tests/test_07_concurrency.py:35-78`
- **问题**: `test_concurrent_ban` 只断言耗时不超过 5 秒，未验证 20 个 IP 是否真的被封禁；`test_read_during_write` 断言 `ban_count >= 0` 恒真
- **状态**: ✅ 已修复 — join 后添加断言验证所有 IP 确实被封禁

### H-55 🟢 并发封禁测试不捕获子线程异常
- **文件**: `tests/test_07_concurrency.py:40-47`
- **问题**: 20 个线程直接调用 `PROC_BANS.write_text(ip)` 不捕获异常，`OSError` 在子线程中静默丢失
- **状态**: ✅ 已修复 — 使用 `safe_ban()` 包装函数收集子线程异常到线程安全列表

### H-56 🟢 CI 降级运行缺少新测试关键字
- **文件**: `.github/workflows/ci.yml:537-553`
- **问题**: `-k` 过滤表达式缺少 `cluster_scan`（test_22）、`auth_lockout`（test_23）、`concurrent_reload_bans`（test_24）
- **状态**: ✅ 已修复 — `-k` 过滤补充 `cluster_scan`、`auth_lockout`、`concurrent_reload_bans`

### H-57 🟢 配置重载测试直接修改源配置文件
- **文件**: `tests/test_17_config_reload.py:124-166`
- **问题**: 直接修改 `CONFIG_DIR / "default.yaml"`，测试中途崩溃会永久损坏配置
- **状态**: ✅ 已修复 — 使用 `tmp_path` 保存备份副本，`try/finally` 保证崩溃恢复

### H-58 🟢 daemon_lifecycle fixture 可能杀掉生产进程
- **文件**: `tests/test_20_daemon_lifecycle.py:46-87`
- **问题**: 清理旧 PID 文件时直接读 PID 并 kill，未验证进程确实是测试实例
- **状态**: ✅ 已修复 — 清理旧 PID 前验证 `/proc/{pid}/cmdline` 含测试配置路径

### H-59 🟢 test-kernel-compat.sh 产物路径与编译脚本不一致
- **文件**: `scripts/test-kernel-compat.sh:39,92`
- **问题**: 使用 `kernel-module-$kernel_version` 路径，但 `build-kmod-multi-version.sh` 输出到 `kernel-module/$kernel_version`
- **状态**: ✅ 已修复 — 改为 `kernel-module/$kernel_version`

### H-60 🟢 firewall-daemon.service ExecStart 路径与 Makefile 不一致
- **文件**: `firewall-daemon.service:12`
- **问题**: 硬编码 `/usr/sbin/firewall-daemon`，但 Makefile 默认安装到 `/usr/local/sbin/`
- **状态**: ✅ 已修复 — 改为 `ExecStart=__SBINDIR__/firewall-daemon`，让 Makefile 的 sed 替换生效

### H-61 🟢 deploy.sh script 模式 SCP 缺少 SSH_OPTS
- **文件**: `scripts/deploy.sh:300`
- **问题**: script 模式的 SCP 命令未传入 `SSH_OPTS`，首次连接可能交互确认主机密钥而挂起
- **状态**: ✅ 已修复 — 改为 `scp "${SSH_OPTS[@]}" /tmp/firewall-deploy.tar.gz ...`

### H-62 🟢 内核状态持久化路径验证不禁止空格/换行
- **文件**: `src/kernel-module/fw_state.c:94-125`
- **问题**: `fw_state_validate_path()` 不禁止空格、换行符（`\n`、`\r`）及 ASCII 控制字符，模块参数含特殊字符可能导致非预期文件操作
- **状态**: ✅ 已修复 — 添加控制字符检查，`(unsigned char)*p < 0x20` 时返回 `-EINVAL`

### H-63 🟢 IPv6 扩展头 offset 整数回绕绕过 pskb_may_pull
- **文件**: `src/kernel-module/fw_hook.c:397-401`
- **问题**: `offset += ((unsigned int)opt.hdrlen + 2) * 4` 可能导致 offset 回绕，`pskb_may_pull(skb, offset + sizeof(...))` 因回绕成小值而意外通过
- **状态**: ✅ 已修复 — 在每次 offset 增加后添加 `if (offset > skb->len) return NF_DROP;`

### H-64 🔴 速率表清表遍历 65536 个桶（含空桶）
- **文件**: `src/kernel-module/fw_rate.c:329-357`
- **问题**: `fw_rate_drain_table()` 遍历全部 65536 个桶，每桶取锁/解锁，SET_CONFIG 修改 rate_window 时触发毫秒级延迟尖峰
- **修复**: 取锁前用 `hlist_empty()` 跳过空桶，或用位图记录非空桶索引

### H-65 🔴 fw_rate_cpu_slot 结构体跨 3 条 cache line
- **文件**: `src/kernel-module/fw_types.h:343-364`
- **问题**: 热路径字段（packets/bytes/协议计数器/last_activity）分布在不同 cache line，10Mpps+ 场景下成为瓶颈
- **修复**: 将热字段集中到结构体前部，使用 `__attribute__((aligned(64)))` 确保 cache line 对齐

### H-66 🔴 fw_stats_pcpu 热路径触发 4-6 条 cache line miss
- **文件**: `src/kernel-module/fw_types.h:401-414`
- **问题**: `fw_stat_account()` 写入的字段分散在 1.5KB 结构体中，每次调用可能触发多条 cache line miss
- **修复**: 将直方图字段与 UDP/ICMP 槽分离到不同 per-CPU 结构体

### H-67 🟢 procfs 可写条目未检查 CAP_SYS_ADMIN
- **文件**: `src/kernel-module/fw_procfs.c:1066-1085`
- **问题**: bans/whitelist/config 写入口只依赖文件权限 0600，未像 netlink 路径那样检查 `capable(CAP_SYS_ADMIN)`
- **状态**: ✅ 已修复 — 在 bans_write、whitelist_write、config_write 入口添加 `if (!capable(CAP_SYS_ADMIN)) return -EPERM;`

### H-68 🟢 测试直接修改源配置且无崩溃恢复
- **文件**: `tests/test_17_config_reload.py:124-166`
- **问题**: 修改仓库源码目录中的 `default.yaml`，pytest 被 SIGKILL 时配置永久损坏
- **状态**: ✅ 已修复 — 同 H-57，使用 `tmp_path` + `try/finally`

### 第三轮扫描补充（HIGH 5 项）

### H-69 🔴 SuccessEnvelope 忽略 json.Marshal 错误
- **文件**: `src/daemon/internal/http/envelope.go:33`
- **问题**: `json.Marshal(data)` 的错误被显式忽略，序列化失败时 `Data` 字段序列化为 `null`，客户端收到 `code:0, data:null` 的"成功"响应，数据已丢失但无报错
- **影响**: 分析面 handler 返回复杂嵌套结构时可能静默丢失数据
- **修复**: 至少记录 `slog.Error` 日志；或改为返回 `(ApiResponse, error)` 让调用方回 500

### H-70 🔴 writeJSON Encode 失败后客户端收到截断 JSON
- **文件**: `src/daemon/internal/http/server.go:155-157`
- **问题**: `json.NewEncoder(w).Encode(data)` 的写入错误仅记录日志，HTTP 状态码已写出，客户端收到截断的 JSON 响应体
- **影响**: 客户端无法解析响应但也收不到错误码
- **修复**: 使用 `json.Marshal` 预序列化来避免半写状态

### H-71 🔴 ensureColumn SQL 注入脆弱设计
- **文件**: `src/daemon/internal/persist/db.go:216`
- **问题**: `ALTER TABLE` 使用 `fmt.Sprintf` 拼接表名和列名，当前安全但未来维护者可能引入用户可控输入
- **影响**: 潜在的 SQL 注入风险
- **修复**: 添加启动期校验，确保 table/column 名仅包含字母数字和下划线

### H-72 🔴 threatfeeds Cache.Merge 忽略 entryKey 返回值
- **文件**: `src/daemon/internal/threatfeeds/cache.go:139`
- **问题**: `entryKey(e.IP)` 返回的 `isCIDR` 和 `bits` 被忽略，每次 Merge 都要全表重建 CIDR 索引
- **影响**: 接近 100 万条时性能开销显著
- **修复**: 增量更新 CIDR 索引而非全量重建

### H-73 🔴 EventPump Directives 为 nil 时静默丢弃内核指令
- **文件**: `src/daemon/internal/kernel/consumer.go:196-200`
- **问题**: `PumpDeps.Directives` channel 为 nil 时 CONFIG_CHANGE 和封禁下发被拒只记日志，组合根装配遗漏时所有内核反向指令被静默丢弃
- **影响**: 配置变更不生效但面板显示成功，生产环境难以诊断
- **修复**: 在 `NewEventPump` 构造时对关键依赖做 nil 检查并打 Warn 级别日志

### H-74 🔴 测试端口硬编码冲突（test_22 与 test_12）
- **文件**: `tests/test_22_cluster_scan.py:70`, `tests/test_12_permanent_ban.py:149`
- **问题**: 两个测试文件都将 `metrics_port` 硬编码为 `9123`，顺序运行时 TIME_WAIT 状态导致绑定失败
- **修复**: 统一使用 `free_tcp_port()` 动态分配端口

### H-75 🔴 并发 ban/unban 测试缺少最终状态一致性验证
- **文件**: `tests/test_07_concurrency.py:69-92`
- **问题**: `test_concurrent_ban_unban` 仅验证 `PROC_STATS` 非空，未验证封禁列表最终状态是否与操作序列一致
- **修复**: 增加最终状态断言：验证 `current_bans` 等于预期值

### H-76 🔴 test_14 使用固定 sleep 而非轮询等待内核状态
- **文件**: `tests/test_14_ban_netfilter.py:28-49`
- **问题**: 三个测试用例使用 `time.sleep(1)` 等待内核状态更新，高负载时不足、低负载时浪费
- **修复**: 改用 `wait_until` 轮询，设置合理超时

### H-77 🔴 性能测试缺少预热阶段和系统负载感知
- **文件**: `tests/test_08_stress_perf.py:23-41`
- **问题**: 直接测量 50 次封禁耗时，无预热步骤，未记录系统负载，不同 CI 环境结果不可复现
- **修复**: 增加 3-5 次预热写入，附带系统负载信息

### H-78 🔴 批量封禁测试写入后未等待 procfs 同步即断言
- **文件**: `tests/test_03_ban_unban.py:30-38`
- **问题**: `test_batch_ban` 调用 `ban_multiple` 后立即 `count_bans()` 断言，内核哈希表与 procfs 文件刷新存在竞态
- **修复**: 在 `count_bans()` 前增加 `wait_procfs()` 或使用 `wait_until` 轮询

### H-79 🔴 CommandPalette active 索引越界导致 Enter 执行空操作
- **文件**: `frontend/src/components/CommandPalette.tsx:201-203`
- **问题**: `filtered` 列表缩短后 `active` 可能越界，`runActive()` 读取 `ordered[active]` 得到 `undefined`，静默丢失按键
- **修复**: `const cmd = ordered[Math.min(active, ordered.length - 1)]`

### H-80 🔴 Dashboard emptyStats() 每次渲染返回新引用导致 useMemo 失效
- **文件**: `frontend/src/views/Dashboard.tsx:57`
- **问题**: `live.value` 为 null 时每次渲染调用 `emptyStats()` 返回新对象引用，所有图表 `useMemo` 全部失效重建
- **修复**: 将 `emptyStats()` 返回值缓存为模块级常量

### H-81 🔴 AuthProvider 初始加载时过期令牌导致受保护内容闪现
- **文件**: `frontend/src/providers/AuthProvider.tsx:57-59`, `frontend/src/app/router.tsx:31-38`
- **问题**: localStorage 中存在过期令牌时，`AuthProvider` 直接设为 `authenticated`，`RequireAuth` 放行渲染，直到首个 API 返回 401 才跳回登录页
- **修复**: 增加 `probeAuth` 探测步骤，引入 `authenticating` 初始状态

### H-82 🔴 Logs.tsx 日志流 getSseStatus 未传 AbortSignal
- **文件**: `frontend/src/views/Logs.tsx:276`
- **问题**: 日志流的 `onerror` 中 `getSseStatus()` 未传入 AbortSignal，组件卸载时请求不会被中断
- **修复**: 仿照 `useSse.ts` 创建 AbortController ref

### H-83 🔴 StatCard 可点击时缺少无障碍属性
- **文件**: `frontend/src/components/StatCard.tsx:67-78`
- **问题**: 传入 `onClick` 时 Card 变为可点击但缺少 `role="button"`、`tabIndex={0}` 和 `onKeyDown`，键盘用户无法操作
- **修复**: 添加 `role="button"`、`tabIndex={0}`、`onKeyDown` 处理 Enter/Space

---

## MEDIUM 级（172 项）

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

### 第九轮补充（8 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-36 | `kernel-module/fw_rate.c:648-674`、`daemon/internal/config/kernel_view.go:30-38` | 动态阈值以 `baseline_pps/bps` 为乘数，但全仓无 `BASELINE_UPDATE` 发送方（`ConfigFlagBaselineUpdate` 只在 `names.go` 出现），`analysis.EWMASmoother` 无生产调用者，`ddos.baseline_warmup_samples` 只解析不使用。基线恒为 0 时动态阈值算出 0；若同时关闭静态阈值，任意有流量的源都会被判「total rate」并自决封禁 | 🟢 已修复：动态阈值按维度生效——该维度基线为 0 或比例缺失时该维度不参与判定，静态仍生效；两维度都无动态阈值且静态关闭时不做总速率判定；乘法溢出时阈值取 `U64_MAX` 而非 0。基线接线与 M-29 一并决策 |
| M-37 | `kernel-module/fw_netlink.c:776-789,765`、`daemon/internal/http/bans.go:37-40,119-124` | BAN_IP 的 `duration_secs` 与 SET_CONFIG 的 `ddos_ban_duration` 都不做 365 天上限校验；状态恢复把 `remaining > 365 天` 的行判为损坏并丢弃（`fw_state.c:481-486`）。API 允许到 `MaxUint32` 秒 | 🟢 已修复：内核 BAN_IP 与 SET_CONFIG 按 `FW_BAN_TIME_MAX` 拒绝超限；daemon `CreateBan`/`BatchBan` 限制 365 天并返回可读 4xx |
| M-38 | `kernel-module/fw_state.c:73-78,605-610,186-205` | 保存端按「容量参数 × 160 字节」反推上限并截断，恢复端固定 32 MiB；`fw_max_ban_entries` 等参数无上限校验，配置 20 万条以上时保存文件超过恢复上限，整个状态文件被 `-EFBIG` 拒绝 | 🟢 已修复：保存端以 `fw_state_max_file_size()` 为字节预算逐行累计；超预算条目丢弃并累加 `truncated`，落盘文件不再可能超过恢复端上限 |
| M-39 | `kernel-module/fw_stats.c:210-270` | UDP 端口表（512 项）与 ICMP 类型表（128 项）只增不老化；表满后新键直接丢弃并计入 spill，旧条目 `last_seen` 永远不更新，长期运行后分析视图固化在最早的端口集合 | 🟢 已修复：表满插入时按 `last_seen` 淘汰最旧条目（`hash_del_rcu` + `call_rcu`），被淘汰键让位新键；既有 spill 计数保留 |
| M-40 | `daemon/internal/bans/ban.go:102-121`、`kernel/consumer.go:755-800`、`http/bans.go:244-246` | 守护进程封禁镜像没有 `PrefixLen`：事件/对账里前缀丢失，DELETE 解封一律用 `FullPrefixLen(addr)`。网段封禁（如 /24）解封时前缀不匹配，内核回 `-ENOENT`，封禁无法从面板解除 | 🟢 已修复：`BanInfo` 携带 `PrefixLen`，事件、对账、单条解封与 `UnbanAllTemporary` 统一使用镜像前缀，未知前缀才退回 `FullPrefixLen`。缓存键仍按地址归一，同地址不同前缀共用一条镜像，后写入者为准 |
| M-41 | `daemon/internal/logparse/rule.go:50-75` | `tryMatch` 从 `len(groups)/2-1` 倒序到 1，从不检查组 0。无捕获组的正则（如整行匹配 `(?:\d{1,3}\.){3}\d{1,3}`）能编译通过、配置校验通过，但永远匹配不到 IP，jail 静默失效 | 🟢 已修复：捕获组倒序扫描到组 0 作为回退，无捕获组的规则按整体匹配命中；组 0 含额外文本时仍由完整校验拒绝 |
| M-42 | `daemon/internal/runtime/executor.go:735-756,908-919` | 轮转事件先 flush 半行，随后 `dropSource` 对读取器 `Reset()` 关 fd；最后一批最多 256 KiB 的未读尾巴若没被前面的 MODIFY 事件单批读干（事件合并、路径已消失）就丢失，且不发生成行判定 | 🟢 已修复：轮转摘源前用 `DrainTail` 有界读干旧 fd，逐 jail 送入判定后再 `Reset`；补轮转尾部用例 |
| M-43 | `daemon/internal/logparse/splitter.go:55-75` | 尾部达到 `MaxLineBytes` 时直接清空缓冲；若物理行跨读批次（单批上限 256 KiB，短读也会切行），剩余半行会在下一批被当成新行输出，产生伪造 IP 行 | 🟢 已修复：超长行进入「丢弃至下一个换行」状态，`Clear`/`Flush` 复位；每条超长物理行只计一次，后续半行不再成行 |

### 第十轮补充（MEDIUM 7 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-44 | `kernel-module/fw_hook.c:370-404` | IPv6 AH 扩展头按 `ipv6_optlen()`（`(hdrlen+1)*8`）前进，但 AH 的长度字段单位是 4 字节且含 2 字节固定头，正确步进是 `(hdrlen+2)*4`；AH 之后的内层头被错位解析 | 🟢 已修复：仅 `NEXTHDR_AUTH` 走 4 字节公式，其余扩展头保持 8 字节公式 |
| M-45 | `daemon/internal/runtime/executor.go:804` | 轮转事件到达时读取器可能已自行切到新 inode；旧逻辑无条件从新文件头重读，导致同一段内容被判定两次（重复封禁/重复审计） | 🟢 已修复：先比较 `reader.Inode()` 与路径当前 inode，相同则只重挂 watch（`rebindWatch`）并返回；重挂失败先摘源并把路径记入 `pendingReadd`，不会留下无 watch 的源 |
| M-46 | `frontend/src/hooks/useSse.ts:305` | StrictMode 的 mount→unmount→mount 中，卸载 cleanup 把 `mountedRef` 置 false 后，第二次挂载的连接 effect 未复位，之后所有事件写入都被判为「已卸载」丢弃 | 🟢 已修复：连接 effect 起始处无条件 `mountedRef.current = true` |
| M-47 | `scripts/fetch-geoip.sh:132-133` | 临时文件建在 `$TMPDIR` 再用 `mv` 落到目标目录；跨文件系统时 `mv` 退化为复制+删除，不再原子，更新中被读取会拿到半份 MMDB | 🟢 已修复：临时文件直接建在 `$TARGET_DIR`，`mv -f` 保证同文件系统原子替换；替换前 `chmod 0644` |
| M-48 | `frontend/src/views/Logs.tsx:231` | 溢出丢弃计数在 state updater 外按 `liveCountRef` 计算，连续 `setState` 批处理时读到旧长度；StrictMode 双调用 updater 还会重复计数 | 🟢 已修复：溢出判断移入 `setLiveLines` 的 updater，用单调 `line.id` 与 `countedDropIdRef` 去重，另一 effect 把 `droppedRef` 同步到展示 state |
| M-49 | `daemon/internal/http/config_api.go:394-437` | `patchWebuiYAML` 把整份 YAML 解析成 `map[string]any` 再 `Marshal` 写回，PUT /config 成功后文件里所有注释丢失、键顺序被重排 | 🔴 待修复：改用 `yaml.Node` 只替换 `webui`/`ddos` 对应节点，保留注释与顺序 |
| M-50 | `daemon/internal/http/server.go:130-150` | 连接上限统计所有连接（含长驻 SSE），且满额时 `http.Error` 回裸文本 503，不走统一信封、无 `Retry-After`；前端按业务码判定的错误处理拿不到可读提示 | 🔴 待修复：SSE 连接不应占用普通请求名额，满额响应改用 `WriteServiceUnavailable` 并带重试提示 |

### 第十一轮补充（MEDIUM 21 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-51 | `kernel-module/fw_netlink.c:826-856` | 白名单只校验前缀长度与地址字段，不校验 `fw_addr_is_valid`；`1.2.3.4/0` 归一成 `0.0.0.0/0` 后可放行全部地址，删除侧按前缀匹配还能连带清掉封禁 | 🟢 已修复：归一前后各校验一次地址有效性，非法地址回 `-EINVAL` |
| M-52 | `kernel-module/fw_ban.c:465-535` | 洪泛闸门在去重/过期/容量判定之前扣预算：重复封禁、已被淘汰条目与表满时的失败尝试都消耗配额，真实新封禁被误拒 | 🟢 已修复：闸门移到三点判定之后、插入之前，仅真正新建节点时计费 |
| M-53 | `daemon/internal/runtime/executor.go:907-935` | 对账重挂前无条件 `delete(pendingReadd)`，Stat/inotify/权限失败时丢失 `fromStart`，下一轮以文件尾打开轮转后的新文件，整段写入被跳过 | 🟢 已修复：仅 `addSharedLogSource` 确认新增后删除待重挂项；挂失败的源保持原语义 |
| M-54 | `daemon/internal/runtime/executor.go:595-635` | 同一路径既是配置文件又是日志文件时，配置分支直接 `return`，日志 owner 虽保留却永远无人读取；对账只对齐 owner，不会补建读取器 | 🟢 已修复：先按日志 owner 收完本批字节再重载配置；对账遇到「已 watch 但无读取器」的路径补建并读一次 |
| M-55 | `daemon/internal/runtime/executor.go:1336-1375` | 集群网段封禁下发成功后不写任何底账：`ban_events`/`ban_history`/信誉表都看不到，复发统计与分级成效凭空缺一段 | 🟢 已修复：新增可选 `ClusterBanRecorder`，成功下发后经与自动单 IP 同一入口记账（不占活跃缓存、不动 facts） |
| M-56 | `daemon/internal/runtime/file_reloader.go:78-95` | 回滚从备份文件解析配置后原样换入，`ConfigFile` 指向 `config.yaml.rollback`，配置 watch 从此挂在备份文件上，真实配置变更不再触发重载 | 🟢 已修复：按重载器持有的来源还原单文件/目录语义后再应用 |
| M-57 | `daemon/internal/runtime/supervisor.go:69-95` | 关停链逐段各等一个 timeout，总时长随执行体数量线性叠加；前段超时后仍为后段耗预算，调用方资源释放被拖后 | 🟢 已修复：全部段共用一个截止时间，每段只等剩余时间；截止后其余段只置令牌并报 `TimedOut` |
| M-58 | `daemon/internal/http/analysis_payload.go:613-650` | 时长直方图按 `d < upper` 分桶，恰好 1800/86400 秒的封禁落进下一桶，与「≤5 分钟 / 5–30 分钟」的标签错开一格 | 🟢 已修复：改为右闭 `d <= upper`，边界值用例覆盖 300/1800/7200/86400 |
| M-59 | `daemon/internal/http/risk.go:66-90` | 风险向量列表的 `total` 取本次返回条数，记录超过 100 条时永远钉在 100，前端分页读数失真 | 🟢 已修复：`CountRiskVectors()` 单独统计全集；先 COUNT 再取列表，避免单连接嵌套查询 |
| M-60 | `daemon/internal/geoip/egress.go:91-115` | 出口探测只拒绝私网/回环/链路本地等，未覆盖 `0.0.0.0/8`、TEST-NET-1/2/3、`192.88.99.0/24`、`100::/64`、`2001:2::/48`、`2001:db8::/32`；伪造响应可把地理库定位到本机或文档网段 | 🟢 已修复：补齐特殊用途网段表，命中即拒绝该探测结果 |
| M-61 | `daemon/internal/http/stats.go:158-230` | 跨日后查询失败仍回读上一自然日的缓存，今日封禁数/近 5 分钟封禁数与趋势图显示昨天的读数 | 🟢 已修复：只有缓存 `dayStart` 与本次窗口相同才复用，否则回 0/空 |
| M-62 | `daemon/internal/config/parser.go:529-572` | `max_retries` 无上限校验：单 IP 只保留 100 个失败时间戳，有效阈值还要叠加高峰期 +2 与内网 +3；配置 96 以上时窗口计数永远达不到阈值，jail 配置成功但一条都不封 | 🟢 已修复：`defaults.max_retries` 与 jail 级统一拒绝 >95，错误写明上限由来 |
| M-63 | `daemon/internal/http/bans.go:191-215,421-441` | 手工单条与批量封禁只写历史/事件，不扣信誉分：这些地址在信誉表里没有 `last_ban`、`total_bans` 停在 0，后续自动判定的渐进时长与低信誉阈值全部算错 | 🟢 已修复：两条成功路径都补 `RecordBan(persist.DefaultBanPenalty)`；失败不下发的不扣分 |
| M-64 | `daemon/internal/persist/facts.go:506-540` | `NoteBan` 在条目被 LRU 逐出后重新加载库值再自增，把同一次已落库的封禁记两遍，次数与扣分翻倍 | 🟢 已修复：仅「本次封禁前已有内存读数」时自增/扣分；新条目读库值不再重复计数，补逐出后调用用例 |
| M-65 | `frontend/src/hooks/useLiveData.ts:66-116` | REST 序号在响应落地时才分配，慢响应会以更大序号反超在途期间到达的 SSE 帧，页面被旧数据覆盖直到下一轮轮询 | 🟢 已修复：序号在请求发起时预分配并随响应返回，数据未变化时不推进展示戳 |
| M-66 | `daemon/internal/http/bans.go:191-215`、`daemon/cmd/firewall-daemon/main.go:910-925` | 手工封禁写库后不通知 `Facts` 内存缓存，同一 IP 的自动判定在下次回读前仍按旧次数/旧信誉计算渐进时长 | 🔴 待修复：把 `noteBan` 注入 HTTP 层或在底账入口统一刷新事实缓存 |
| M-67 | `daemon/internal/risk/engine.go:130-140`、`src/daemon/internal/persist/risk_vectors.go` | 启动时从不调用 `Engine.SetVector` 载入库中向量；进程重启后内存风险分为空，后台衰减仍在改库，判定面看不到历史风险 | 🔴 待修复：启动装配时按库中向量预热引擎（或按需读取） |
| M-68 | `daemon/internal/http/handlers.go:340` | 攻击地理分布仍用 `GetBanEvents(attackGeoEventLimit)` 取最近 N 条，超出后地理统计与总量口径不一致 | 🔴 待修复：与网段分布同口径，按窗口在 SQL 内聚合 |
| M-69 | `daemon/internal/http/config_api.go:142-151` | 目录模式（多文件合并、`config_file` 为空）下 PUT /config 无法保存；当前只把 EISDIR 换成明确的 40004，面板仍然改不了配置 | 🔴 待修复（功能缺口）：确定目录模式的叠写策略与目标文件后再实现；当前至少不写坏文件 |
| M-70 | `daemon/internal/persist/risk_vectors.go:130-165`、`facts.go:71-180` | `risk_engine.half_life_days` 只传给内存引擎；库侧每小时衰减固定用 `risk.HalfLifeDays=7`，配置的自定义半衰期对持久化向量不生效 | 🔴 待修复：半衰期与权重一起经 `SetRiskVectorWeights` 同源注入 |
| M-71 | `kernel-module/fw_netdev.c:240-290` | 网卡白名单对账单轮最多 64 遍，扫到上限即返回；同一轮里摘掉的老条目不会触发下一轮工作，残留条目要等下一次外部事件才被处理，期间放行集合与网卡实际地址不一致 | 🟢 已修复：触及上限且本轮有摘除时重新排队延迟工作，直到收敛或被关停标志拦下 |

### 第十二轮补充（MEDIUM 2 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-72 | `daemon/internal/http/config_api.go:149-156` | 目录模式检查在 `configFileMu` 锁外，检查与加锁之间配置路径可能被热重载改变，导致误判或写入错误路径 | 🟢 已修复：目录检查移入锁内 |
| M-73 | `daemon/internal/persist/risk_vectors.go:163-171` | 风险向量衰减的 DELETE 用 `updated_at = ?` 匹配刚 UPDATE 的行，但衰减期间新写入的向量 `updated_at` 也是 now，会被误删 | 🟢 已修复：DELETE 只按衰减后的字段值判断近零，不依赖 `updated_at` 匹配 |

### 第十三轮补充（MEDIUM 1 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-74 | `daemon/internal/ingest/registry.go:215-219` | `Iterate` 方法传递浅拷贝，Owners 切片与内部共享；注释声称"fn 拿到的是状态副本"但实际不成立，Get/Remove/Entries 都做了深拷贝 | 🟢 已修复：Iterate 深拷贝 Owners 切片 |

### 第十四轮补充（MEDIUM 21 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-75 | `kernel-module/fw_hook.c:226,302,312` | IPv4 路径中 `fw_stat_account(pkt_len)` 用 IP 头声明的长度，`fw_stat_global_traffic(skb->len)` 用实际 skb 长度，两者不一致导致全局流量与每 IP 速率统计口径不同 | 🔴 |
| M-76 | `kernel-module/fw_netlink.c:845` | 白名单归一化时 `fw_addr_normalize(af, (void *)addr, ...)` 强转 `const` 修饰符，修改 netlink skb 中的数据，技术上是未定义行为 | 🔴 |
| M-77 | `kernel-module/fw_hook.c:398-401` | IPv6 扩展头解析中 AH 头的 `offset += ((unsigned int)opt.hdrlen + 2) * 4` 在 `hdrlen=255` 时可能溢出 32 位 unsigned int，导致传输头从错误偏移解析 | 🔴 |
| M-78 | `kernel-module/fw_netlink.c:697-701` | `rate_window_jiffies` 更新有 `smp_wmb()`，但 `fw_rate_observe` 的读侧与 `fw_procfs.c:633` 的 `rate_window_seconds` 读取未配对 `READ_ONCE`，KCSAN 会报数据竞争 | 🔴 |
| M-79 | `kernel-module/fw_procfs.c:694,735,797...` | 7 个 procfs `show` 函数分配 ~12KB 的 `fw_analysis_snapshot`，在 seq_file 上下文中可能接近内核栈限制 | 🔴 |
| M-80 | `kernel-module/fw_netlink.c:166,596` | `nlmsg_new(payload, GFP_ATOMIC)` 在进程上下文（netlink recv）中使用，应改用 `GFP_KERNEL` 避免不必要的分配失败 | 🔴 |
| M-81 | `daemon/internal/threatfeeds/scheduler.go:56-95` | `Run` 方法在首次执行 `fn()` 后才创建 timer，若 `fn` 启动子 goroutine，`Stop()` 不等待这些子任务 | 🔴 |
| M-82 | `daemon/internal/threatfeeds/cache.go:115-161` | `Merge` 在持写锁期间复制整个 entries map（最多 100 万条）并重建索引，大缓存下会阻塞所有 `Lookup` 数秒 | 🔴 |
| M-83 | `daemon/internal/http/server.go:130-150` | `connectionLimiter` 在 handler panic 时 `defer` 中的 `activeConns--` 不执行，连接计数永久泄漏，最终所有新连接被 503 拒绝 | 🔴 |
| M-84 | `daemon/internal/persist/retry_queue.go:452-494` | `LoadPersisted` 不校验加载任务的 `EnqueuedAt`，崩溃恢复时可能载入过期任务；遇到未知 `op` 的任务会永久错误但不触发 persist | 🔴 |
| M-85 | `daemon/internal/risk/engine.go:241-272` | `evictLocked` 在持写锁期间创建切片并排序（最多 10 万条），阻塞所有读写操作 | 🔴 |
| M-86 | `daemon/internal/threatfeeds/http.go:34-52` | `safeDialContext` 只返回 `candidates[0]`，第一个地址连接失败时不尝试其他候选，绕过了标准 happy eyeballs | 🔴 |
| M-87 | `daemon/internal/ingest/watcher.go:97-115` | `ReadEvents` 使用 `unsafe.Pointer` 解析 inotify 事件，若 `raw.Len` 异常大可能导致 offset 溢出读取 buffer 外内存 | 🔴 |
| M-88 | `frontend/src/views/Logs.tsx:189-193` | 切换到历史模式时 `useAsync` 的 `enabled` 翻转已触发取数，但 `useEffect` 因 `mode` 变化又调用 `refetch()`，产生双重请求 | 🟢 已修复：用 prevModeRef 检测 mode 刚变为 history 的渲染，跳过该次 refetch |
| M-89 | `frontend/src/views/Analysis.tsx:303-322` | `tabItems` 的 `useMemo` 依赖数组包含 `UseAsyncResult` 对象，每次渲染返回新引用，记忆化完全失效 | 🟢 已修复：依赖改为各 result 的具体字段（.data, .isLoading, .error, .refetch, .isUserFetching） |
| M-90 | `frontend/src/hooks/useSse.ts:283` | `onerror` 回调中的 `getSseStatus()` 未传递 `AbortSignal`，组件卸载后请求仍会在后台完成 | 🟢 已修复：在 useEventStream 中维护专用 AbortController，closeStream 和卸载清理中 abort |
| M-91 | `contract/gen.py:457` | `field_size` 对 `str`/`bytes` 类型 `count=0` 时返回 0 不报错，未来可能产生零宽字段 | 🟢 已修复：添加断言 `count <= 0` 时抛出 `ValueError` |
| M-92 | `contract/gen.py:2735-2738` | OpenAPI 生成中 `r.auth == "optional"` 分支引用 `OptionalAuth`，但 `ROUTE_AUTH` 只声明 `none/required`，是死代码 | 🟢 已修复：删除死代码分支 |
| M-93 | `Makefile:264-267` | 内核模块 staging 复制 `contract/generated/*.h` 在目录为空时会失败中断构建 | 🟢 已修复：`|| test -z` 允许空目录 |
| M-94 | `contract/gen.py:2597-2613` | OpenAPI 类型映射中 `i8` 错误映射为 `int32`，应为 `int8` 或注明不支持 | 🟢 已修复：修正为 `int8`/`uint8`/`int16`/`uint16` 并补充范围约束 |
| M-95 | `contract/verify_http.py:708` | `_const_value` 使用 `eval` 计算常量，`ZeroDivisionError` 被宽泛 `except` 捕获后返回 `None`，掩盖除零错误 | 🟢 已修复：单独捕获 `ZeroDivisionError` 并抛出 `ValueError` |

### 第二轮扫描补充（MEDIUM 20 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-96 | `kernel-module/fw_netlink.c:950-978` | DAEMON_REGISTER 释放锁后探活，重新加锁后探活结果已过期，第三个 daemon 可在窗口内完成注册 | 🔴 |
| M-97 | `kernel-module/fw_hook.c:227` | `pkt_len` 来自报文头部可被伪造，攻击者可膨胀字节速率统计误触发字节速率阈值封禁 | 🔴 |
| M-98 | `kernel-module/fw_ban.c:254` | `fw_ban_alloc()` 高频 `GFP_ATOMIC` 分配加剧内存碎片，DDoS 期间分配失败率上升 | 🔴 |
| M-99 | `kernel-module/fw_wl.c:136-143` | 子网链遍历 O(N) 线性扫描，每包热路径查找延迟随子网条目数线性增长 | 🔴 |
| M-100 | `kernel-module/fw_stats.c:399-404` | `fw_stats_flush_all()` 同步等待所有 CPU flush，128 CPU 系统单次 IPI + 锁竞争数十微秒 | 🔴 |
| M-101 | `kernel-module/fw_ban.c:707-748` | `fw_ban_fill_entries()` 持桶锁遍历整个 hlist，极端情况（所有条目落入同一桶）阻塞其他 CPU | 🔴 |
| M-102 | `kernel-module/fw_rate.c:261-315` | `fw_rate_reclaim_work()` 每 10 秒扫描全部 65536 个桶，非空桶数百时占用显著 CPU | 🔴 |
| M-103 | `docs/zh/configuration/procfs.md:18` | stats 计数器数量标注为 13，实际为 14（遗漏 `state_save_truncated`），扩散到 5 个文档 | 🟢 已修复：改为 14 个计数器 |
| M-104 | `docs/zh/migration-threat-feeds.md:234-236` | 置信度阈值 FAQ 写 0.9/0.7，与实现和其他文档的 0.8 矛盾 | 🟢 已修复：改为 >= 0.8 直接封禁 |
| M-105 | `scripts/deploy.sh:289` | script 模式的 sed 替换 `__SBINDIR__` 是空操作（服务文件已硬编码路径） | 🟢 已修复：配合 H-60 占位符修复自动生效 |
| M-106 | `scripts/build-kmod-multi-version.sh:151` | `cd "$PROJECT_ROOT"` 后未恢复工作目录，连续调用时可能不符预期 | 🟢 已修复：使用子 shell `(cd ... && make ...)` |
| M-107 | `docs/zh/configuration/examples.md:73-75` | 文档指出 redis.yaml 注释与实现不符但未修正，`service.go` 服务名表无 redis | 🟢 已修复：修正注释说明使用 defaults 段的值 |
| M-108 | `docs/zh/migration-api-v2.md:13,47-48` | 健康检查端点迁移描述与其他文档矛盾（根路径 vs /api/v2/ 前缀） | 🟢 已修复：明确根路径已删除，仅 /api/v2/ 有效 |
| M-109 | `tests/test_10_daemon_logparse.py:65-80` | `test_special_char_log` 只断言 procfs 可访问，未验证特殊字符是否被正确处理 | 🔴 |
| M-110 | `tests/test_14_ban_netfilter.py:26-53` | 使用固定 `time.sleep(1)` 等待内核状态更新，CI 高负载下可能不够 | 🔴 |
| M-111 | `tests/test_12_permanent_ban.py:135-198` | daemon stderr 重定向到 DEVNULL，启动失败时无法诊断 | 🔴 |
| M-112 | `tests/test_15_ddos_detection.py:39-45` | 只断言子串匹配 `"firewall_ddos" in metrics`，可能匹配到 HELP/TYPE 注释行 | 🔴 |
| M-113 | `tests/test_16_webui_api.py:105-111` | 响应时间阈值 1000ms 无预热、无多次采样，CI 负载波动时间歇性失败 | 🔴 |
| M-114 | `tests/test_22_cluster_scan.py:27` | `DETECT_WAIT_SECONDS = 25` 硬编码，CI 高负载可能不够，且整体耗时超 50 秒无 slow 标记 | 🔴 |
| M-115 | `tests/test_21_multi_jail.py:69` | 启动 daemon 后固定 `time.sleep(2)` 未验证是否真的启动成功 | 🔴 |

### 第三轮扫描补充（MEDIUM 20 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-116 | `daemon/internal/http/envelope.go:33` | `json.Marshal(data)` 错误被忽略，序列化失败时 `Data` 为 `null`，客户端收到假成功 | 🔴 |
| M-117 | `daemon/internal/http/server.go:155-157` | `writeJSON` Encode 失败后客户端收到截断 JSON，状态码已写出无法回退 | 🔴 |
| M-118 | `daemon/internal/persist/db.go:216` | `ensureColumn` 用 `fmt.Sprintf` 拼接 SQL，当前安全但设计脆弱 | 🔴 |
| M-119 | `daemon/internal/threatfeeds/cache.go:139` | `Merge` 忽略 `entryKey` 返回值，每次全表重建 CIDR 索引 | 🔴 |
| M-120 | `daemon/internal/http/logs.go:62-66` | `GetLogs` 两遍扫描间文件可能轮转，导致 `totalLines` 与 `items` 不一致 | 🔴 |
| M-121 | `daemon/internal/http/logs.go:289-300` | `tailLogs` 的 `file.Close()` 失败仅 Warn，文件句柄可能泄漏 | 🔴 |
| M-122 | `daemon/internal/bans/cache.go:195-207` | `IsPending` 在读路径中隐式清理过期条目，语义不一致 | 🔴 |
| M-123 | `daemon/internal/persist/retry_queue.go:193` | `Stop()` 的 `flush` 用 `context.Background()` 无超时，DB 不健康时阻塞关停 | 🔴 |
| M-124 | `daemon/internal/runtime/executor.go:66-70` | 溢出补读单源连续读满 16 MiB，其他源 inotify 事件堆积 | 🔴 |
| M-125 | `daemon/internal/http/sse.go:246-249` | `register` 分支 `stopped` 时 `return` 而非 `continue`，剩余消息不处理 | 🔴 |
| M-126 | `tests/test_12_permanent_ban.py:165-169` | daemon stdout/stderr 重定向 DEVNULL，启动失败无法诊断 | 🔴 |
| M-127 | `tests/test_20_daemon_lifecycle.py:76-81` | `daemon_process` fixture 用 DEVNULL 丢失错误输出 | 🔴 |
| M-128 | `tests/test_17_config_reload.py:135-137` | 配置修改依赖脆弱字符串替换，静默失败时测试虚假通过 | 🔴 |
| M-129 | `tests/test_04_whitelist.py:107-132` | 白名单容量测试所有写入失败时断言退化恒成立 | 🔴 |
| M-130 | `tests/test_04_whitelist.py:95-105` | 白名单格式验证依赖内核抛异常，静默忽略时测试失败 | 🔴 |
| M-131 | `tests/test_07_concurrency.py` 等 | 并发/压力测试仅覆盖 IPv4，IPv6 路径未验证 | 🔴 |
| M-132 | `tests/test_04_whitelist.py:51-76` | 白名单保护测试未验证 `whitelist_add` 是否真正生效 | 🔴 |
| M-133 | `tests/test_13_frp_jail.py:61` | FRP 测试硬编码端口 9119 且未检查外部 daemon | 🔴 |
| M-134 | `tests/test_17_config_reload.py:47-65` | `backup_config` fixture 与测试 finally 重复发送 SIGHUP | 🔴 |
| M-135 | `tests/test_12_permanent_ban.py:37-44` | 永久封禁测试观察窗口过短，未真正验证不过期 | 🔴 |


---

## LOW 级（152 项）

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

### 第九轮补充（4 项）
| # | 问题 |
|---|------|
| L-41 | `contract/procfs.fwidl:242-243` 与 `kernel-module/fw_types.h:91-107`：契约写速率表上限 65536（锚 `fw_max_rate_entries`），实际硬上限是 `FW_RATE_CPU_SLOTS=512`；该参数也没有模块文档声明的 1024–262144 范围校验，写 1 即让速率跟踪近乎失效。契约注记与 init 校验需按真实口径修正。🟢 已修复（口径）：契约注记与模块参数说明改为「有效上限 = min(`fw_max_rate_entries`, `FW_RATE_CPU_SLOTS=512`)」；参数仍只拒绝 0，低于 512 时按槽位封顶 |
| L-42 | `daemon/internal/ingest/reader.go:118`：同 inode 的截断检测只认 `size < offset`；copytruncate 后在下一次轮询前又写回超过旧偏移时，新内容被当作已读丢弃。🟢 已修复：维护 64 字节尾部指纹，同 inode 尺寸未缩但尾部内容变化时按重写处理并从头读 |
| L-43 | `daemon/internal/daemonize/daemonize.go:75-110`、`cmd/firewall-daemon/main.go:91`：PID 文件不加锁、不校验属主存活；第二个实例覆盖 PID 文件，先退出的实例会删掉后者文件，陈旧 PID 也可能指向无关进程。🟢 已修复：写前用 `kill(pid, 0)` 判存活并拒绝覆盖；退出只删除属主 PID 与自身一致的文件 |
| L-44 | `daemon/internal/kernel/consumer.go:517`：`CmdResult.ErrorCode` 是负 errno，`Value: uint64(int64(...))` 回绕成极大无符号数；`telemetry.Event.Value` 注释约定承载 errno。🟢 已修复：CmdResult 事件不再写 `Value`，错误码只经 `ErrorCode` 字段传递 |

### 第十轮补充（LOW 9 项）
| # | 问题 |
|---|------|
| L-45 | `kernel-module/fw_main.c:149`：容量参数只拒绝 0，超过 `INT_MAX` 时在容量比较处按 int 取值为负，检查恒成立（新增恒失败或速率表恒放行）。🟢 已修复：`fw_params_validate` 对四个容量参数统一拒绝 `> INT_MAX` |
| L-46 | `daemon/internal/http/threat_feeds.go`：空 id 分支引用了契约未声明的 `40006`，属于不可达的错误映射。🟢 已修复：删除该分支，按契约走参数校验路径 |
| L-47 | `daemon/internal/runtime/executor.go:1069`：配置回滚（SIGUSR1）只替换配置与 jail，不重算日志源与 owner；回滚到旧配置后日志路径/共享关系仍是回滚前的。🟢 已修复：`rollbackConfig` 末尾调用 `reconcileWatches()` |
| L-48 | `daemon/internal/runtime/executor.go:1427`：多个 jail 共享同一日志文件时，全局行/字节计数按 jail 各加一次，页面显示的量随共享 jail 数倍增。🟢 已修复：`drainSource` 只对第一个 jail 传 `global=true`，`mirrorGlobal` 独占累加 |
| L-49 | `frontend/src/views/Bans.tsx:317`：封禁成功提示按 `duration_seconds` 判永久，`duration_seconds=0`（契约语义为永久）会显示「0 秒」；表单也未说明留空/0 的含义。🟢 已修复：`permanent` 为真或 `duration_seconds` 为 0 均按永久展示，表单补「留空或填 0 = 永久封禁」 |
| L-50 | `frontend/src/components/DataTable.tsx:67`：使用 `process.env.NODE_ENV` 判开发环境，Vite 构建期不注入该变量，dev 告警在生产与开发下都失效。🟢 已修复：改 `import.meta.env.DEV` |
| L-51 | `Makefile:125,149`：版本探测用 `grep -oP`（PCRE），BSD/macOS grep 不支持，`make check-deps` 在非 GNU 环境直接失败。🟢 已修复：改用 `grep -oE` + `head`/`sed` |
| L-52 | `contract/verify_http.py:1381-1443`：`parse_ts_interfaces` 逐行匹配，单行写多个字段（`a: string; b: number`）只取第一个；`strip_ts_comments` 还按 `//` 剥注释，会误伤 `https://` 等字符串。契约校验存在漏检/误报面。 | 🔴 待修复 |
| L-53 | `kernel-module/fw_netlink.c:377-420,455-500`：LIST_BANS / LIST_WHITELIST / LIST_RATES 按 offset/limit 遍历活表，分页期间到期摘链或并发插入会让后续页跳过或重复条目，daemon 的全量对账因此可能漏项。 | 🔴 待修复 |

### 第十一轮补充（LOW 6 项）
| # | 问题 |
|---|------|
| L-54 | `scripts/build-kmod-multi-version.sh:284,348`、`scripts/test-kernel-compat.sh:127-135`：`set -e` 下 `((success++))` 首次自增前的值为 0，算术命令退出码为 1，脚本在该行直接终止，后续版本不再编译/测试。🟢 已修复：全部改成 `((x+=1))` |
| L-55 | `debian/linux-firewall-kmod.postinst:31-45`：只对 `uname -r` 编译 DKMS 模块；双内核/回退内核机器上升级后另一内核没有 `firewall.ko`，切回即加载失败。🟢 已修复：遍历 `/lib/modules/*/build` 逐个 build/install，单内核失败告警跳过，全部失败才以 1 退出 |
| L-56 | `frontend/src/views/Login.tsx:133-137`：登录页称会话令牌「仅保存在当前标签页，关闭即失效」，实际是 Basic token 存 `localStorage`、跨标签页共享、退出登录才清除。🟢 已修复：文案改为真实存储与失效语义 |
| L-57 | `frontend/src/views/Analysis.tsx:145-149`：阈值建议的 `DIRECTION_META` 缺 `maintain`，后端返回该方向时标签回落成原始英文。🟢 已修复：补 `maintain → 维持` |
| L-58 | `kernel-module/fw_types.h:240-241`：字段注释仍写 `banned_at /* jiffies */`、`unban_jiffies /* 到期 jiffies */`，与新时长模型（绝对 Unix 秒）相反。🟢 已修复：注释改为 Unix 秒/绝对到期秒 |
| L-59 | `contract/http.fwidl:761,1339,1461,1578,1769,1718`：契约注记仍写「最多取最近 10000 条」与「桶边界左闭右开」，实现已改为窗口下推 SQL 与右闭分桶；契约作为线格式真相源与实现分叉。 | 🔴 待修复 |

### 第十二轮补充（LOW 1 项）
| # | 问题 |
|---|------|
| L-60 | `daemon/internal/runtime/executor.go:1345`：集群网段封禁的 reason 拼接 jail 名，jail 名含非 ASCII 或超长时会被契约的 str[32] 截断成不完整 UTF-8 序列。🟢 已修复：jail 名截断到 20 字节，留空间给 ": cluster" 标签 |

### 第十四轮补充（LOW 20 项）
| # | 问题 |
|---|------|
| L-61 | `kernel-module/fw_types.h:241`：字段 `unban_jiffies` 命名暗示 jiffies，实际存储 Unix 秒，易误导维护者 |
| L-62 | `kernel-module/fw_ban.c:328`：`fw_ban_expire_cb` 中 `!READ_ONCE(n->is_permanent)` 检查冗余，函数已在 317-321 行提前返回 |
| L-63 | `kernel-module/fw_state.c:738-748`：状态恢复时单行解析失败被静默丢弃，管理员无法知道有多少条目丢失 |
| L-64 | `kernel-module/fw_netlink.c:510-525`：`fw_nl_rates_elapsed_secs` 对 `fw_nl_rates_last_jiffies` 的读写无任何同步原语，依赖隐式的 socket 串行化 |
| L-65 | `kernel-module/fw_ban.c:377`：`fw_ban_exit` 使用 `timer_delete()` 而非 `timer_delete_sync()`，依赖回调的 `hlist_unhashed` 检查，设计约束未显式文档化 |
| L-66 | `kernel-module/fw_hook.c:302-312`：TCP 异常包（SYN+FIN 等）被计入 per-protocol 直方图但不计入全局流量计数器，导致 DDoS 基线低估实际流量 |
| L-67 | `kernel-module/fw_netdev.c:226-285`：网卡白名单对账每次删除后从 offset 0 重新开始扫描，最坏情况 O(N²) |
| L-68 | `kernel-module/fw_main.c:352-358`：`fw_local_exit()` 和 `fw_ports_exit()` 缺少 `synchronize_rcu()` + `rcu_barrier()`，模块卸载时可能有未完成的 kfree_rcu 回调 |
| L-69 | `kernel-module/fw_procfs.c:192-196`：`bans_write` 中 "unban " 前缀解析跳过 5 字符但检查 6 字符，逻辑正确但脆弱 |
| L-70 | `daemon/internal/threatfeeds/cache.go:167-199`：`Lookup` 发现过期条目时跳过但不删除，过期条目积累降低查询效率 |
| L-71 | `daemon/internal/kernel/transport.go:338`：`sendLocked` 在 EAGAIN 时使用 `time.Sleep` 退避，高频发送场景下可能影响性能 |
| L-72 | `daemon/cmd/firewall-daemon/main.go:751-773`：`requestRollback` 依赖外部 `pgrep` 命令，最小化容器可能不存在 |
| L-73 | `daemon/internal/http/logs.go:182-204`：`GetLogs` 需要两次全量扫描日志文件（计数 + 取数据），大日志下耗时数十秒 |
| L-74 | `daemon/internal/risk/engine.go:161-185`：`ComputeEffectiveThreshold` 接收 `ip string` 参数但未使用，接口设计遗留 |
| L-75 | `frontend/src/views/Dashboard.tsx:219`：「丢弃数据包」指标卡使用 `DeleteOutlined` 图标（垃圾桶），语义上不够准确 |
| L-76 | `frontend/src/views/Whitelist.tsx:116-130`：新增白名单时未客户端校验 CIDR 是否已存在，重复添加要等后端报错 |
| L-77 | `frontend/src/lib/charts.ts:84-85`：面积图渐变色通过 `${color}55` 拼接 hex 透明度，依赖 color 始终是 6 位 hex 格式 |
| L-78 | `frontend/src/lib/defaults.ts:46`：`EMPTY_CHART` 常量与 `emptyChartData()` 函数并存，消费方可能混淆 |
| L-79 | `frontend/src/views/Login.tsx:33-38`：`useEffect` 依赖数组包含 `location.state`，每次导航可能产生新引用触发不必要的 effect |
| L-80 | `contract/verify_http.py:2086-2088`：`_GAP_RULES` 正则使用全角右括号 `[^）]*`，但问题文本中是半角 `)`，导致正则永远匹配不到 |


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

### 批次 8（已提交）：第八轮 11 项
H-23、H-24、H-25、H-26、M-31、M-32、M-33、M-34、L-36、L-39、L-40

### 批次 9（已提交）：第九轮 18 项
- 内核：C-5、H-27、H-28、H-29、M-36、M-37、M-38、M-39
- 守护进程：H-30、H-31、M-40、M-41、M-42、M-43、L-42、L-43、L-44
- 契约：L-41（提交范围 aebe60a5..44e1a118）

### 批次 10（已提交）：第十轮 19 项
- 内核：H-32、H-33、H-34、M-44、L-45
- 守护进程：H-35、H-36、H-37、M-45、L-46、L-47、L-48
- 情报源：H-38
- 前端/脚本：M-46、M-47、M-48、L-49、L-50、L-51

### 批次 11（已提交）：第十一轮 25 项
- 内核：H-39、H-40、M-51、M-52、M-71、L-58
- 分析/持久化：H-42、H-43、M-58、M-59、M-64
- 运行时/传输：H-41、M-53、M-54、M-55、M-56、M-57
- 配置/HTTP：M-60、M-61、M-62、M-63
- 前端/脚本：M-65、L-54、L-55、L-56、L-57

### 批次 12（已提交）：第十二轮 4 项
- 内核：H-44
- 配置/HTTP：M-72
- 持久化：M-73
- 运行时：L-60

### 批次 13（已提交）：第十三轮 1 项
- 日志采集：M-74

### 批次 14（已提交）：第十四轮 30 项
- 内核 HIGH：H-45、H-46、H-47
- 守护进程 HIGH：H-48、H-49、H-50、H-51、H-52
- 内核安全：H-62、H-63、H-67
- 测试 HIGH：H-53、H-54、H-55、H-56、H-57、H-58
- 脚本 HIGH：H-59、H-60、H-61
- 前端 MEDIUM：M-88、M-89、M-90
- 契约 MEDIUM：M-91、M-92、M-93、M-94、M-95
- 文档 MEDIUM：M-103、M-104、M-105、M-106、M-107、M-108

### 待修复重点（按风险排序）
1. **CRITICAL**：C-2（SSE 凭据在 URL，需前后端配合）
2. **MEDIUM 数据正确性**：M-23（内核拒绝封禁后底账不回撤）、M-29（DDoS 引擎未接线、
   `auto_ban_threshold` 无消费者）、M-49（PUT /config 抹掉 YAML 注释）、M-50（连接上限
   与 SSE 共用名额、503 不走信封）、M-66（手工封禁不刷新事实缓存）、M-67（启动不载入
   风险向量）、M-68（地理分布仍截断 1 万条）、M-69（目录模式无法保存配置）、M-70
   （自定义半衰期不作用于库侧衰减）、M-F5
3. **测试缺口**：M-T1~M-T5、M-E1、L-52（verify_http 解析盲区）、L-59（契约注记与
   实现分叉）、L-53（活表分页与对账漏项）
4. **LOW 批量**：其余 57 项，按模块分批处理
