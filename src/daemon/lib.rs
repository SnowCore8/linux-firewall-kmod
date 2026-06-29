//! `firewall_daemon` 库根
//!
//! 本 crate 是 `linux-firewall-kmod` 项目的用户态守护进程,提供与 fail2ban 类似但更轻量、
//! 面向嵌入式 Linux 防火墙内核模块的"日志 → 失败计数 → 封禁决策 → netlink 下发 → "完整链路。
//! 守护进程与内核模块之间通过 netlink 双向实时通信,`/proc/firewall/*` 仅作为用户操作接口。
//!
//! # 架构概览
//!
//! - `main` (`main.rs`): 入口,负责 CLI 解析、信号注册、守护进程化与主循环调度
//! - `types`: 跨模块共享的数据结构 (`Jail` / `Config` / `FailedEntry` / `DaemonStats`)
//!   以及系统级常量
//! - `logger`: 基于 slog 的结构化日志系统 (异步终端输出)
//! - `ban`: 通过 netlink 与内核模块通信,支持 IPv4/IPv6 封禁、解封、
//!   永久黑名单同步
//! - `log_parser`: 从日志行提取 IP (正则 + 字符串回退)
//! - `failed_tracker`: 滑动窗口失败计数与封禁触发 (O(1) 平均复杂度)
//! - `jail`: 服务名智能匹配 + 智能默认参数推断 + `ReDoS` 防护正则编译 + 配置克隆
//! - `config`: YAML 解析 (严格模式 key 白名单 + 路径安全 3 重检查 + 失败回滚)
//! - `file_monitor`: inotify 文件监控 + 轮转检测 + 主事件循环 (poll + SIGHUP 重载)
//! - `http_exporter`: Prometheus `/metrics` 端点 + Basic Auth + 暴力破解防护
//! - `web_ui`: Web 监控大盘 + JSON API（静态资源嵌入）
//!
//! # 行为对齐
//!
//! 所有模块均与已删除的 C 版 (`src/daemon/*.c`) 严格行为等价,通过 111 项集成测试套件
//! (以 `RUST=1` 运行) 验证。CLI 标志、YAML 字段、procfs 命令格式、默认参数值均与 C 版
//! 完全一致,以保证既有 bash 测试套件和系统配置无需修改。
//!
//! # 关键设计决策
//!
//! - **单 crate binary**:无 workspace 拆分,简化交叉编译与 DKMS 集成
//! - **滑动窗口 `recent_head`**:`FailedEntry` 维护 O(1) 平均的前缀跳过 (R9-7 优化)
//! - **配置双缓冲**:SIGHUP 重载时先 clone 旧配置,失败时旧配置不受影响
//! - **path 安全 3 重检查**:`..` 遍历 / URL 编码绕过 / shell 元字符注入
//!
//! # 并发模型与锁顺序
//!
//! ## 全局 static 分布
//!
//! | 类别 | static | 说明 |
//! |------|--------|------|
//! | 信号控制 | `GLOBAL_RUNNING` / `GLOBAL_RELOAD` | 信号处理函数写，主循环读 |
//! | 文件监控 | `FILE_STATES` / `INOTIFY_STATE` | 主循环独占读写 |
//! | 封禁缓存 | `ACTIVE_BAN_CACHE` (OnceLock) | 启动时初始化，运行时 ban/unban 操作 |
//! | 统计计数 | `DAEMON_STATS` / `JAIL_STATS` / `DDOS_STATS` / `BAN_DURATION_BUCKETS` | 全 Atomic，Relaxed 序 |
//! | HTTP 导出 | `EXPORTER_RUNNING` / `EXPORTER_PORT` / `AUTH_STATE` | 导出器线程 + auth 逻辑 |
//! | 基础设施 | `GLOBAL_LOGGER` / `SYNC_DIRTY` | 日志 / 同步标志 |
//!
//! ## 锁获取顺序（防死锁）
//!
//! 当需要同时获取多把锁时，必须按以下顺序获取：
//!
//! ```text
//! 1. GLOBAL_RUNNING / GLOBAL_RELOAD       (AtomicBool, 无锁竞争)
//! 2. FILE_STATES.read() / .write()        (RwLock)
//! 3. INOTIFY_STATE.fd.write()             (RwLock)
//! 4. ACTIVE_BAN_CACHE.bans.write()        (RwLock, 内部)
//! 5. ACTIVE_BAN_CACHE.by_jail.write()     (RwLock, 内部)
//! 6. JAIL_STATS.write()                   (RwLock, OnceLock 内部)
//! ```
//!
//! **规则**：
//! - 禁止在持锁时执行 IO（网络、磁盘）
//! - Atomic 操作（Relaxed 序）不视为"持锁"
//! - `parking_lot` 锁无写线程饥饿，但仍须遵守顺序避免 ABBA 死锁

pub mod ban;
pub mod config;
pub mod config_reloader;
pub mod daemonizer;
pub mod ddos_detector;
pub mod failed_tracker;
pub mod file_monitor;
pub mod history_snapshot;
pub mod http_exporter;
pub mod ip_reputation;
pub mod ip_utils;
pub mod jail;
pub mod line_processor;
pub mod log_parser;
pub mod log_rotation;
pub mod logger;
pub mod netlink;
pub mod signals;
pub mod types;
pub mod web_ui;
