# 功能缺陷清单

> 生成时间：2026-11-11
> 更新时间：2026-11-11（第二轮挖掘完成）
> 状态标记：🔴 待修复 | 🟡 修复中 | 🟢 已修复 | ⚪ 设计取舍/不修复

---

## 统计

| 严重度 | 发现总数 | 已修复 | 待修复 |
|--------|----------|--------|--------|
| CRITICAL | 4 | 1 | 3 |
| HIGH | 18 | 6 | 12 |
| MEDIUM | 35+ | 0 | 35+ |
| LOW | 50+ | 0 | 50+ |
| **合计** | **107+** | **7** | **100+** |

---

## CRITICAL 级（4 项）

### C-1 🟢 netlink 传输层 socket flags 未恢复
- **文件**: `src/daemon/internal/kernel/transport.go:230-233`
- **状态**: ✅ 已修复 — 错误路径恢复原始 flags
- **修复代理**: general-purpose-c057cbb50b558499

### C-2 🔴 前端 SSE 认证 token 暴露在 URL query string
- **文件**: `frontend/src/api/endpoints.ts:499-513`
- **问题**: Basic auth token 放在 EventSource URL，出现在浏览器历史/access log
- **影响**: 凭据泄漏风险
- **修复**: 文档化风险 + 考虑短期 SSE 专用 token
- **难度**: 中 | **风险**: 中（需后端配合）

### C-3 🟢 前端 DataTable 默认 rowKey 使用数组 index
- **文件**: `frontend/src/components/DataTable.tsx:79`
- **状态**: ✅ 已修复 — 移除默认回退，添加开发环境警告，补充 3 处遗漏的 rowKey
- **修复代理**: general-purpose-94e169b935a16f3d

### C-4 🔴 Makefile `ci` 目标并行构建不安全
- **文件**: `Makefile:328`
- **问题**: `ci` 的 7 个前置目标无依赖链，`make ci -j` 会并发执行各阶段
- **影响**: 开发者使用 `make ci -j$(nproc)` 时构建失败
- **修复**: 为每个阶段添加线性依赖链
- **难度**: 低 | **风险**: 低

---

## HIGH 级（18 项）

### H-1 🟢 内核模块 ip_fast_csum 读取越界
- **文件**: `src/kernel-module/fw_hook.c:159-162,191`
- **状态**: ✅ 已修复 — 缓冲区从 20 字节增大到 60 字节
- **修复代理**: general-purpose-c057cbb50b558499

### H-2 🟢 intent.IP 与 info.IP 不一致
- **文件**: `src/daemon/internal/runtime/executor.go:1138-1141`
- **状态**: ✅ 已修复 — 统一使用 `.Unmap()` 后的 canonical 形式
- **修复代理**: general-purpose-3aa5af09fe600cdf

### H-3 🔴 SseProvider context 每帧触发全树重渲染
- **文件**: `frontend/src/providers/SseProvider.tsx:55-63`
- **问题**: 每秒最多 5 次全树重渲染
- **影响**: 高频攻击时面板卡顿
- **修复**: 拆分 context 或用 useSyncExternalStore
- **难度**: 中 | **风险**: 中

### H-4 🟢 useLiveData 用 JSON.stringify 做深比较
- **文件**: `frontend/src/hooks/useLiveData.ts:50-61`
- **状态**: ✅ 已修复 — 改用 shallowEqual 函数
- **修复代理**: general-purpose-94e169b935a16f3d

### H-5 🟢 RealtimeBadge 1 秒 interval 永不停止
- **文件**: `frontend/src/components/state/RealtimeBadge.tsx:80-84`
- **状态**: ✅ 已修复 — 添加 SSE 连接状态依赖
- **修复代理**: general-purpose-94e169b935a16f3d

### H-6 🔴 认证锁定 DoS
- **文件**: `src/daemon/internal/http/auth_lockout.go:22-62`
- **问题**: 进程级单一计数器，10 次失败锁定所有请求
- **影响**: 管理员被锁 60 秒
- **修复**: 改为 per-IP 锁定
- **难度**: 中 | **风险**: 中

### H-7 🟢 白名单删除内核失败不回滚
- **文件**: `src/daemon/internal/http/whitelist.go:100-130`
- **状态**: ✅ 已修复 — 先尝试内核删除，成功后再删内存
- **修复代理**: general-purpose-3aa5af09fe600cdf

### H-8 🔴 内核 fw_ban_del/procfs 缺失 netlink 发送锁
- **文件**: `src/kernel-module/fw_ban.c:596`, `fw_procfs.c:438,444`
- **问题**: 模块卸载期间可能与 netlink socket 释放并发，导致 use-after-free
- **影响**: 内核崩溃
- **修复**: 添加 `fw_nl_send_lock()/unlock()` 保护
- **难度**: 低 | **风险**: 低

### H-9 🔴 Transport.Close/Send 竞态
- **文件**: `src/daemon/internal/kernel/transport.go:502-533`
- **问题**: Close() 持 closeMu，Send() 持 sendMu，两锁不同
- **影响**: 关停期间 Send 使用已关闭的 fd，导致 panic
- **修复**: Close() 中也获取 sendMu
- **难度**: 低 | **风险**: 低

### H-10 🔴 TryInsert/MarkPendingAck 竞态窗口
- **文件**: `src/daemon/internal/runtime/executor.go:1114-1127`
- **问题**: TryInsert 后、MarkPendingAck 前，reconcile 可能移除幽灵条目
- **影响**: 刚下发的封禁被对账逻辑错误移除
- **修复**: 在 TryInsert 内部同时设置 pending 标记
- **难度**: 中 | **风险**: 中

### H-11 🔴 Facts.writeBack 并发逐出问题
- **文件**: `src/daemon/internal/persist/facts.go:449-478`
- **问题**: 锁外执行数据库写入期间，条目可能被逐出，pending 数据丢失
- **影响**: 信誉分计算不准确
- **修复**: 为条目增加 writing 标志阻止并发修改
- **难度**: 中 | **风险**: 中

### H-12 🔴 前端 Logs 分页越界无自动修正
- **文件**: `frontend/src/views/Logs.tsx:140-173`
- **问题**: 过滤后结果减少时，当前页码可能超出范围，显示空表格
- **影响**: 用户看到空白表格
- **修复**: 仿照 Bans 页添加 totalPages 夹取逻辑
- **难度**: 低 | **风险**: 低

### H-13 🔴 前端认证令牌跨 tab 不同步
- **文件**: `frontend/src/api/auth.ts:45-57`
- **问题**: sessionStorage per-tab，一个 tab 登出后其它 tab 仍持有失效凭据
- **影响**: 多 tab 使用体验差
- **修复**: 迁移到 localStorage + storage 事件同步
- **难度**: 中 | **风险**: 中

### H-14 🔴 executor.go panic 导致进程崩溃
- **文件**: `src/daemon/internal/runtime/executor.go:214`
- **问题**: TimerTable 登记失败时 panic，整个守护进程崩溃
- **影响**: 所有防护失效
- **修复**: 改为返回 error 并优雅降级
- **难度**: 低 | **风险**: 低

### H-15 🔴 facts.go 类型断言 panic
- **文件**: `src/daemon/internal/persist/facts.go:522`
- **问题**: `el.Value.(*factsEntry)` 未检查 ok
- **影响**: Stats() 方法 panic 导致调用方崩溃
- **修复**: 使用 comma-ok 模式
- **难度**: 低 | **风险**: 低

### H-16 🔴 Makefile Go 版本门禁与 go.mod 不一致
- **文件**: `Makefile:42`, `src/daemon/go.mod:3`
- **问题**: Makefile 检查 Go >= 1.23，go.mod 要求 1.26.0
- **影响**: 依赖检查假阳性
- **修复**: GOVER 改为 1.26
- **难度**: 低 | **风险**: 低

### H-17 🔴 CI upload-artifact 版本混用
- **文件**: `.github/workflows/ci.yml:557`
- **问题**: 前三处用 v6，测试报告用 v4，download 用 v7
- **影响**: 测试报告可能无法下载
- **修复**: 统一为 v6
- **难度**: 低 | **风险**: 低

### H-18 🔴 配置文档默认值与 config/default.yaml 不一致
- **文件**: `docs/zh/configuration/yaml-config.md:32,36-37`
- **问题**: ban_time 文档写 600 实际 900；凭据文档写"空"实际 admin/changeme
- **影响**: 文档误导用户
- **修复**: 更新文档默认值
- **难度**: 低 | **风险**: 低

---

## MEDIUM 级（35+ 项）

### 内核模块（4 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-1 | `fw_hook.c` | 32 位平台 total_len 比较溢出 | 🔴 |
| M-2 | `fw_ban.c` | 哈希表扩容无上限 | 🔴 |
| M-3 | `fw_proc.c` | procfs 写回调 buffer 长度截断 | 🔴 |
| M-4 | `fw_netlink.c` | 多播广播失败仅 rate-limited 日志 | 🔴 |

### 内核深层（3 项，第二轮挖掘）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-K1 | `fw_netlink.c:689-690` | rate_window_jiffies 缺 READ_ONCE 配对 | 🔴 |
| M-K2 | `fw_rate.c:589-590` | window_start/last_activity 缺 WRITE_ONCE | 🔴 |
| M-K3 | `fw_netlink.c:1065` | netlink 消息缺 NLMSG_ALIGN 对齐 | 🔴 |

### 守护进程（10 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-5 | `transport.go:409-412` | poll() 检查 Revents!=0 而非 POLLIN | 🔴 |
| M-6 | `file_reloader.go:25` | logger 为 nil 时无防护 | 🔴 |
| M-7 | `config/default.yaml` | 默认凭据 admin/changeme 无启动告警 | 🔴 |
| M-8 | `http/auth.go` | 认证锁定机制无集成测试 | 🔴 |
| M-9 | `http/bans.go:233-241` | 内核解封失败只记日志不回传前端 | 🔴 |
| M-10 | `kernel/client.go:190-217` | Ban 返回 Delivered 非 Executed | ⚪ 设计取舍 |
| M-11 | `persist/facts.go:296-301` | 风险事件队列高负载下静默丢事件 | 🔴 |
| M-12 | `logger/logger.go:225-232` | LogThrottler TOCTOU 竞态 | 🔴 |
| M-13 | `geoip/egress.go:73-83` | egress probe 接受私有 IP | 🔴 |
| M-14 | `persist/db.go:207` | SQL ALTER TABLE 字符串拼接 | 🔴 |

### 守护进程深层（5 项，第二轮挖掘）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-D1 | `sse.go:228-278` | SSE Broker run() 过早退出 | 🔴 |
| M-D2 | `db.go:284-331` | CleanupExpired 五条 DELETE 无事务 | 🔴 |
| M-D3 | `manager.go:299-302` | FeedManager.Stop() 不等待 in-flight | 🔴 |
| M-D4 | `executor.go:884-906` | 配置重载失败未显式回滚 | 🔴 |
| M-D5 | `retry_queue.go:299-325` | flush() DB 不可用时丢失任务 | 🔴 |

### 前端（6 项）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-15 | `BaseChart.tsx` | Canvas 图表无文本替代 | 🔴 |
| M-16 | `CommandPalette.tsx` | 键盘操作提示仅视觉可见 | 🔴 |
| M-17 | `Dashboard.tsx:132-135` | kernel_version 回退逻辑死代码 | 🔴 |
| M-18 | `endpoints.ts:456` | syncThreatFeeds 未传 signal | 🔴 |
| M-19 | `useAsync.ts:163-165` | 非 ApiError 异常静默包装 | 🔴 |
| M-20 | `Logs.tsx:54` | 500 行缓冲区高频日志静默丢弃 | 🔴 |

### 前端深层（7 项，第二轮挖掘）
| # | 文件 | 问题 | 状态 |
|---|------|------|------|
| M-F1 | `usePersistentState.ts:58-59` | 忽略跨 tab 的删除事件 | 🔴 |
| M-F2 | `DrawerForm.tsx:61-77` | 提交存在双次点击窗口 | 🔴 |
| M-F3 | `NotificationProvider.tsx:92-97` | clear 依赖 items 导致 context 不稳定 | 🔴 |
| M-F4 | `useSse.ts:147-149` | SSE 重连后不立即触发数据校准 | 🔴 |
| M-F5 | `ErrorBoundary.tsx:34-37` | 无错误持久化或上报 | 🔴 |
| M-F6 | `useSse.ts:92` | JSON.parse as T 类型断言未验证 | 🔴 |
| M-F7 | `api/client.ts:189,196,207` | API 响应 as T 断言未验证 | 🔴 |

### 跨模块（2 项）
| # | 问题 | 状态 |
|---|------|------|
| M-21 | 无并发 config reload + ban/unban 集成测试 | 🔴 |
| M-22 | kmod-remote 不拷贝 contract 生成头文件 | 🔴 |

### 构建/文档（7 项，第二轮挖掘）
| # | 问题 | 状态 |
|---|------|------|
| M-B1 | `clean` 未清理 `tmp/` 目录 | 🔴 |
| M-B2 | Node.js 版本 README/CI/package.json 不一致 | 🔴 |
| M-B3 | 迁移文档引用本地绝对路径 | 🔴 |
| M-B4 | AGENTS.md 将未验证内核列为已验证 | 🔴 |
| M-B5 | 构建文档 Go 版本过时 | 🔴 |
| M-B6 | `.gitignore` 未覆盖测试产物 | 🔴 |
| M-B7 | `debian/control` build-essential 依赖 | 🔴 |

### 契约/测试（5 项，第二轮挖掘）
| # | 问题 | 状态 |
|---|------|------|
| M-T1 | 契约缺少显式版本号字段 | 🔴 |
| M-T2 | 测试稳定性：大量 time.sleep | 🔴 |
| M-T3 | 测试断言质量：仅检查状态码 | 🔴 |
| M-T4 | 缺少负面测试 | 🔴 |
| M-T5 | 配置日志缺少上限校验 | 🔴 |

### 错误处理（2 项，第二轮挖掘）
| # | 问题 | 状态 |
|---|------|------|
| M-E1 | fmt.Errorf 缺少 %w 导致错误链断裂（多处） | 🔴 |
| M-E2 | CidrKey.Parse MustCidrKey panic | 🔴 |

---

## LOW 级（50+ 项）

### 内核模块（6 项）
| # | 文件 | 问题 |
|---|------|------|
| L-1 | `fw_hook.c` | 缺少 skb_linearize 检查 |
| L-2 | `fw_ban.c` | ban_count procfs sprintf 无溢出检查 |
| L-3 | `fw_netlink.c` | CmdResult errno 未翻译 |
| L-K4 | `fw_stats.c` | 直方图 per-CPU 数据竞争 |
| L-K5 | `fw_rate.c:413` | smp_mb__after_atomic 用于非原子操作 |
| L-K6 | `fw_ban.c:305-306` | 续期 mod_timer 交互（无实际影响） |

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
| L-E3 | `daemonize.go:84,89` | PID 文件 Close 错误未检查 |
| L-E4 | `detect/cidr.go:133` | CidrKey.Parse panic |

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

### 前端深层（4 项，第二轮挖掘）
| # | 文件 | 问题 |
|---|------|------|
| L-F8 | `Logs.tsx:280-289` | live→history→live 切换不清理旧数据 |
| L-F9 | `ThreatFeeds.tsx:267-281` | 深链 sync 未传 AbortSignal |
| L-F10 | `Bans.tsx:381-463` | columns 依赖 lastUpdatedAt 过宽 |
| L-F11 | `useAsync.ts:182-195` | enabled 翻转触发冗余请求 |

### 集成测试缺失（5 项）
| # | 问题 |
|---|------|
| L-25 | 无 auth lockout 机制测试 |
| L-26 | 无并发 config reload 测试 |
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

### 错误处理/边界（4 项）
| # | 问题 |
|---|------|
| L-E5 | stats.go defer Close 错误未检查 |
| L-E6 | contract/messages_out.go slice 越界风险 |
| L-E7 | fw_state.c filp_open 错误区分 |
| L-E8 | 日志流 pending 缓冲临时增长 |

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

### 批次 1：CRITICAL + HIGH（已完成 7/18）
- 🟢 C-1: transport.go socket flags 未恢复
- 🟢 C-3: DataTable rowKey 默认 index
- 🟢 H-1: ip_fast_csum 越界
- 🟢 H-2: intent.IP 与 info.IP 不一致
- 🟢 H-4: useLiveData JSON.stringify 深比较
- 🟢 H-5: RealtimeBadge interval 永不停止
- 🟢 H-7: 白名单删除内核失败不回滚
- 🔴 C-2, C-4, H-3, H-6, H-8~H-18（11 项待修复）

### 批次 2：MEDIUM 低风险（0/15）
- 全部待修复

### 批次 3：MEDIUM 中风险（0/7）
- 全部待修复

### 批次 4：LOW 优先级修复（0/50+）
- 全部待修复
