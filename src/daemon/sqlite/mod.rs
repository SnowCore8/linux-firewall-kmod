//! `SQLite` 永久黑名单：WAL 模式 + 软删除 + 启动时迁移
//!
//! # 子模块划分
//!
//! - [`connection`][]: 连接管理 + 全局 DB 注册 + schema 初始化
//! - [`permanent_bans`][]: 永久封禁 CRUD 操作
//! - [`stats`][]: 统计查询 + 数据清理
//!
//! # 关键设计
//!
//! - **WAL 模式**：`PRAGMA journal_mode=WAL` + `synchronous=FULL`，读写并发不互斥
//! - **软删除**：`is_active=0` 而非真删除，审计可追溯
//! - **启动迁移**：旧版 C 时代的 `permanent_banlist` 表无 `UNIQUE(ip)` 约束，
//!   启动时检测到旧表则执行：去重 → 复制到带 UNIQUE 的 `_new` 表 →
//!   DROP 旧表 + RENAME 新表（原子事务）
//! - **敏感目录保护**：`ensure_db_dir` 拒绝 `/`、`/etc`、`/usr`、`/bin`、`/sbin` 等
//!   系统目录，防止误把数据库建到根分区
//!
//! 本文件内 `u64 → i64` / `u32 → i64` 显式 cast 是 Unix 时间戳的常规做法
//! （`u64` 范围远超 1970-2100 年 32-bit 上限，实际不可能 wrap），`usize → i32`
//! 仅出现在 SQL `INTEGER` 字段处，目标 SQL 内无 64-bit 支持

#![allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_lossless
)]

// 模块声明

mod connection;
mod permanent_bans;
mod stats;

// Re-export 所有公共类型和函数
pub use connection::{
    clear_global_db, get_conn, get_global_db, set_global_db, sqlite_close, sqlite_init,
    with_global_db, PermanentBanEntry, SqliteDb,
};
pub use permanent_bans::{
    sqlite_add_permanent_ban, sqlite_add_permanent_bans_batch, sqlite_is_permanent_banned,
    sqlite_is_permanent_banned_ipv6, sqlite_load_all_permanent_bans, sqlite_remove_permanent_ban,
};
pub use stats::{sqlite_get_stats, sqlite_purge_deleted, sqlite_update_hit_stats};
