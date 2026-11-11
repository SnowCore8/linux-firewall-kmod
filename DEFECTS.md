# 功能缺陷清单

> 生成时间：2026-11-11
> 更新时间：2026-11-11（第六轮：封禁镜像原子性、信誉欠账回填、热重载坐标保留、广播丢失计数与认证/并发集成用例）
> 状态标记：🔴 待修复 | 🟡 修复中 | 🟢 已修复 | ⚪ 设计取舍/复核为误报

---

## 统计

| 严重度 | 发现总数 | 已修复 | 待修复 |
|--------|----------|--------|--------|
| CRITICAL | 4 | 3 | 1 |
| HIGH | 20 | 19 | 0 |
| MEDIUM | 61 | 42 | 8 |
| LOW | 58 | 5 | 52 |
| **合计** | **143** | **69** | **61** |

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

## HIGH 级（19 项）

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

---

## MEDIUM 级（61 项）

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

---

## LOW 级（58 项）

### 内核模块（6 项）
| # | 文件 | 问题 |
|---|------|------|
| L-1 | `fw_hook.c` | 缺少 skb_linearize 检查 |
| L-2 | `fw_ban.c` | ban_count procfs sprintf 无溢出检查 |
| L-3 | `fw_netlink.c` | CmdResult errno 未翻译 |
| L-K4 | `fw_stats.c:141-160` | 直方图读侧无配对屏障（🟢 已修复：WRITE_ONCE/READ_ONCE 配对） |
| L-K5 | `fw_rate.c:413` | smp_mb__after_atomic 用于非原子操作 |
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
| L-27 | 无分页边界测试 |
| L-28 | 无 batch ban 限制测试 |
| L-29 | 无 daemon 崩溃重连测试 |

### 构建系统（8 项）
| # | 问题 |
|---|------|
| L-30 | frontend stamp file 导致不必要重构建 |
| L-31 | kmod-remote 依赖本地 contract 生成 |
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
- 内核：M-4
- 构建/测试：M-8、M-21、L-25、L-26、M-B8
- 复核为误报/取舍：M-2、M-3、M-22、M-B7、M-E2、L-E4

### 待修复重点（按风险排序）
1. **CRITICAL**：C-2（SSE 凭据在 URL，需前后端配合）
2. **MEDIUM 数据正确性**：M-23（内核拒绝封禁后底账不回撤）、M-F5
3. **测试缺口**：M-T1~M-T5、M-E1
4. **LOW 批量**：其余 52 项，按模块分批处理
