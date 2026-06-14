//! `firewall_daemon` 库根
//!
//! 本 crate 是 `linux-firewall-kmod` 项目的用户态守护进程,提供与 fail2ban 类似但更轻量、
//! 面向嵌入式 Linux 防火墙内核模块 (`/proc/firewall/bans` procfs 接口) 的"日志 → 失败
//! 计数 → 封禁决策 → 写 procfs → 写 `SQLite` 永久黑名单"完整链路。
//!
//! # 架构概览
//!
//! - `main` (`main.rs`): 入口,负责 CLI 解析、信号注册、守护进程化与主循环调度
//! - `types`: 跨模块共享的数据结构 (`Jail` / `Config` / `FailedEntry` / `DaemonStats`)
//!   以及系统级常量
//! - `logger`: 基于 slog 的结构化日志系统 (异步终端输出)
//! - `ban`: 与 `/proc/firewall/bans` procfs 的安全交互,支持 IPv4/IPv6 封禁、解封、
//!   永久黑名单同步
//! - `log_parser`: 从日志行提取 IP (正则 + 字符串回退)
//! - `failed_tracker`: 滑动窗口失败计数与封禁触发 (O(1) 平均复杂度)
//! - `jail`: 服务名智能匹配 + 智能默认参数推断 + `ReDoS` 防护正则编译 + 配置克隆
//! - `config`: YAML 解析 (严格模式 key 白名单 + 路径安全 3 重检查 + 失败回滚)
//! - `file_monitor`: inotify 文件监控 + 轮转检测 + 主事件循环 (poll + SIGHUP 重载)
//! - `http_exporter`: Prometheus `/metrics` 端点 + Basic Auth + 暴力破解防护
//! - `sqlite`: 永久黑名单持久化 (WAL 模式 + 软删除 + 启动去重迁移)
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
//! - **procfs fd 缓存**:`/proc/firewall/bans` 每次封禁避免 open/close (R9-9 优化)
//! - **滑动窗口 `recent_head`**:`FailedEntry` 维护 O(1) 平均的前缀跳过 (R9-7 优化)
//! - **配置双缓冲**:SIGHUP 重载时先 clone 旧配置,失败时旧配置不受影响
//! - **path 安全 3 重检查**:`..` 遍历 / URL 编码绕过 / shell 元字符注入

pub mod ban;
pub mod config;
pub mod config_reloader;
pub mod daemonizer;
pub mod ddos_detector;
pub mod failed_tracker;
pub mod file_monitor;
pub mod file_reader;
pub mod http_exporter;
pub mod jail;
pub mod line_processor;
pub mod log_parser;
pub mod log_rotation;
pub mod logger;
pub mod signals;
pub mod sqlite;
pub mod sqlite_writer;
pub mod types;
