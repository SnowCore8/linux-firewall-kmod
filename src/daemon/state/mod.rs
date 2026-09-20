//! 状态层：每个数据域**单所有者**，读侧拿不可变快照。
//!
//! # 分层
//!
//! - [`cidr`]：白名单 CIDR 的唯一规范化实现。键是 [`cidr::CidrKey`] 而不是
//!   `String`，使「插入了未规范化的键」不可表达。
//! - [`hub`]：版本化发布点。每个域一个单调版本号，SSE 据此只序列化变化的域；
//!   唤醒走 `watch`（只保留最新值，与快照语义吻合）。
//!
//! 后续步骤（2.E-2）在此加入 `bans` / `whitelist` / `rates` / `stats` 四个
//! 所有者：写侧独占自己的状态，读侧只经 `snapshot()` 取 `Arc<不可变快照>`。
//!
//! # 为什么不用服务定位器
//!
//! 旧实现把状态放在 `OnceLock` / `LazyLock` 全局里（`ACTIVE_BAN_CACHE`、
//! `WHITELIST_CACHE`、`RATE_CACHE`、`DAEMON_STATS`…），跨模块读写共享可变全局，
//! 并为此维护一套「6 步锁获取顺序」的文档约定。本节的新模块一律由组合根
//! 构造并注入句柄：跨模块传递的是**消息**或 `Arc<不可变快照>`，锁顺序协议不再
//! 需要，读路径也不再能顺手改统计（缺陷 E 的根因）。

pub mod cidr;
pub mod hub;

pub use cidr::{CidrError, CidrKey};
pub use hub::{Domain, Hub, SharedHub, Versions};
