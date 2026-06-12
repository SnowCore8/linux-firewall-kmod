//! `SQLite` 永久黑名单: WAL 模式 + 软删除 (`is_active=0`) + 启动时迁移去重表结构
//!
//! 本文件内 `u64 → i64` / `u32 → i64` 显式 cast 是 Unix 时间戳的常规做法
//! (`u64` 范围远超 1970-2100 年 32-bit 上限,实际不可能 wrap),`usize → i32`
//! 仅出现在 SQL `INTEGER` 字段处,目标 SQL 内无 64-bit 支持
// 文件级 cast 警告抑制(详见模块文档)
#![allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_lossless
)]
//!
//! # 关键设计
//!
//! - **WAL 模式**:`PRAGMA journal_mode=WAL` + `synchronous=FULL`,读写并发不互斥
//! - **软删除**:`is_active=0` 而非真删除,审计可追溯
//! - **启动迁移**:旧版 C 时代的 `permanent_banlist` 表无 `UNIQUE(ip)` 约束,
//!   启动时检测到旧表则执行:去重 → 复制到带 UNIQUE 的 `_new` 表 →
//!   DROP 旧表 + RENAME 新表 (原子事务)
//! - **敏感目录保护**:`ensure_db_dir` 拒绝 `/`、`/etc`、`/usr`、`/bin`、`/sbin` 等
//!   系统目录,防止误把数据库建到根分区
//!
//! # 启动时迁移流程
//!
//! 1. 探测 `permanent_banlist` 旧表是否存在
//! 2. 若 `_new` 表空且旧表存在 → 迁移 (去重 + 复制 + DROP + RENAME)
//! 3. 若 `_new` 表已有数据 → 二次启动,删 `_new`
//! 4. 若全新库 → 直接 RENAME `_new` → `permanent_banlist`
//!
//! # 批量插入语义
//!
//! - 遇 `UNIQUE` 约束冲突 → 跳过该条,继续
//! - 遇其他错误 → 立即回滚整个事务
//!
//! # 全局 DB 注册
//!
//! [`set_global_db`] / [`clear_global_db`] / [`with_global_db`] 让 `ban` 模块
//! 在 Permanent/UnbanPerm 时无需持有 `Arc<SqliteDb>` 句柄。

use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OpenFlags};


// ============================================================================
// 永久封禁条目
// ============================================================================

/// 永久封禁记录。对应 `SQLite` `permanent_banlist` 表的一行。
#[derive(Debug, Clone)]
pub struct PermanentBanEntry {
    /// `SQLite` 自增主键
    pub id: i32,
    /// IP 字符串 (v4 或 v6 原始文本)
    pub ip: String,
    /// IPv4 网络字节序数值;IPv6 为 0
    pub ip_num: u32,
    /// 封禁原因 (e.g. `"manual permanent ban"` / `"ssh brute force"`)
    pub reason: String,
    /// 创建时间 (Unix 秒)
    pub created_at: i64,
    /// 创建者标识 (e.g. `"manual"` / `"auto"`)
    pub created_by: String,
    /// 累计命中次数 (从启动到当前的总拦截次数)
    pub hit_count: i32,
    /// 上次命中时间 (Unix 秒);从未命中为 0
    pub last_hit_at: i64,
    /// 软删除标志:1 = 活跃,0 = 已软删 (记录保留)
    pub is_active: i32,
}

/// `SQLite` 连接句柄。`conn` 用 `Mutex` 保护,因为 `Connection` 不是 `Sync`。
///
/// 通常通过 `Arc<SqliteDb>` 跨函数 / 跨线程共享。
pub struct SqliteDb {
    conn: Mutex<Connection>,
}

// ============================================================================
// 内部辅助
// ============================================================================

/// 确保 db 父目录存在且安全。拒绝 `/`、`/etc`、`/usr`、`/bin`、`/sbin`。
///
/// # Arguments
/// - `db_path`: `SQLite` 数据库文件路径
///
/// # Errors
/// - 父目录是系统敏感路径
/// - 创建目录失败
fn ensure_db_dir(db_path: &str) -> Result<()> {
    if let Some(dir) = Path::new(db_path).parent() {
        let dir_str = dir.to_string_lossy();
        // 拒绝敏感路径, 防止误把数据库建到系统目录
        if matches!(dir_str.as_ref(), "/" | "/etc" | "/usr" | "/bin" | "/sbin") {
            bail!("Unsafe database directory path: {dir_str}");
        }
        if !dir.exists() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("Failed to create database directory {dir_str}"))?;
        }
    }
    Ok(())
}

// ============================================================================
// 公共接口
// ============================================================================

/// 初始化数据库 (打开 + 启用 WAL + 迁移表结构)。
///
/// # Arguments
/// - `db_path`: `SQLite` 数据库文件路径。父目录不存在时自动创建 (但拒绝系统目录)
///
/// # Returns
/// `Arc<SqliteDb>` 可跨模块共享,`ban` 模块通过 [`with_global_db`] 间接访问
///
/// # Errors
/// - 父目录是敏感系统目录
/// - 打开 / 创建 db 文件失败
/// - 启用 WAL 失败
/// - 表结构迁移失败
pub fn sqlite_init(db_path: &str) -> Result<Arc<SqliteDb>> {
    ensure_db_dir(db_path)?;

    let mut conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )
    .with_context(|| format!("Failed to open SQLite database {db_path}"))?;

    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
        .context("Failed to enable WAL mode")?;

    init_db_schema(&mut conn)?;

    let db = Arc::new(SqliteDb {
        conn: Mutex::new(conn),
    });

    Ok(db)
}

/// 优雅关闭:触发 WAL checkpoint (TRUNCATE) 后让 `Connection` 随 `Arc` drop 自动关闭。
///
/// # Arguments
/// - `db`: 待关闭的 db (通常来自 `sqlite_init` 的返回值)
pub fn sqlite_close(db: &Arc<SqliteDb>) {
    // Connection 随 Arc drop 自动关闭, 显式 flush WAL
    if let Some(conn) = db.conn.try_lock() {
        let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    }
}

// ============================================================================
// 全局 DB 注册
// ============================================================================
// ban 模块在 Permanent/UnbanPerm 时通过 with_global_db() 回调访问 main.rs 注册的 db
// 守护进程目前单线程, 保留 Mutex 是为未来扩展及与 parking_lot 风格统一

// 用 std::sync::OnceLock (Rust 1.70+) 替代 once_cell crate
use std::sync::OnceLock;

static GLOBAL_DB: OnceLock<Mutex<Option<Arc<SqliteDb>>>> = OnceLock::new();

/// 将 `db` 注册为全局单例,供 [`with_global_db`] 回调访问。`main()` 启动
/// `SQLite` 成功后调用一次。
///
/// # Arguments
/// - `db`: 来自 [`sqlite_init`] 的 `Arc<SqliteDb>`
pub fn set_global_db(db: Arc<SqliteDb>) {
    let cell = GLOBAL_DB.get_or_init(|| Mutex::new(None));
    *cell.lock() = Some(db);
}

/// 清空全局 db 注册。`main()` 的 `cleanup` 阶段调,确保收尾期间 ban 模块
/// 不再访问 db。
pub fn clear_global_db() {
    if let Some(cell) = GLOBAL_DB.get() {
        *cell.lock() = None;
    }
}

/// 若全局 db 已注册,以回调方式借用;否则返回 `None`。
///
/// # Arguments
/// - `f`: 接受 `&Arc<SqliteDb>` 的闭包,执行所需操作
///
/// # Returns
/// - `Some(R)`: 回调返回值
/// - `None`: 全局 db 未注册 (`SQLite` 未启用或已 clear)
pub fn with_global_db<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&Arc<SqliteDb>) -> R,
{
    let cell = GLOBAL_DB.get()?;
    let guard = cell.lock();
    guard.as_ref().map(f)
}

/// 添加单条永久封禁。
///
/// # Arguments
/// - `db`: db 句柄
/// - `ip`: 已通过 [`crate::ban::validate_ip`] 的字符串
/// - `ip_num`: IPv4 网络字节序;IPv6 传 0
/// - `reason`: 封禁原因
/// - `created_by`: 创建者标识
///
/// # Returns
/// - `Ok(0)`: 新插入成功
/// - `Ok(-2)`: 已存在 (UNIQUE 约束冲突,静默忽略)
/// - `Err`: 其他 `SQLite` 错误
///
/// # Errors
/// 非约束冲突的 `SQLite` 错误(如磁盘满)会被 `bail!` 透传
///
/// # Panics
/// `SystemTime::now().duration_since(UNIX_EPOCH)` 仅在系统时钟早于
/// 1970-01-01 时 panic,实际不可能
pub fn sqlite_add_permanent_ban(
    db: &SqliteDb,
    ip: &str,
    ip_num: u32,
    reason: &str,
    created_by: &str,
) -> Result<i64> {
    let conn = db.conn.lock();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let result = conn.execute(
        "INSERT INTO permanent_banlist (ip, ip_num, reason, created_at, created_by, hit_count, last_hit_at, is_active)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, 1)",
        params![ip, i64::from(ip_num), reason, now, created_by],
    );

    match result {
        Ok(_) => Ok(0),
        Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::ConstraintViolation,
                ..
            },
            _,
        )) => Ok(-2),
        Err(e) => {
            bail!("SQLite insert failed: {e}");
        }
    }
}

/// 批量添加永久封禁:遇 UNIQUE 冲突跳过,遇其他错误立即回滚事务。
///
/// # Arguments
/// - `db`: db 句柄
/// - `ips` / `ip_nums` / `reasons` / `created_bys`: 4 个并行切片,长度必须一致
///
/// # Returns
/// 成功插入的条数 (跳过冲突的不计)
///
/// # Errors
/// - 切片长度不一致
/// - 非 UNIQUE 冲突的 `SQLite` 错误 (整个事务回滚)
///
/// # Panics
/// `SystemTime::now().duration_since(UNIX_EPOCH)` 仅在系统时钟早于
/// 1970-01-01 时 panic,实际不可能
pub fn sqlite_add_permanent_bans_batch(
    db: &SqliteDb,
    ips: &[&str],
    ip_nums: &[u32],
    reasons: &[&str],
    created_bys: &[&str],
) -> Result<i32> {
    if ips.is_empty()
        || ips.len() != ip_nums.len()
        || ips.len() != reasons.len()
        || ips.len() != created_bys.len()
    {
        bail!("sqlite_add_permanent_bans_batch: invalid parameter");
    }

    let mut conn = db.conn.lock();
    let mut success_count: i32 = 0;
    let tx = conn.transaction()?;

    for i in 0..ips.len() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let result = tx.execute(
            "INSERT INTO permanent_banlist (ip, ip_num, reason, created_at, created_by, hit_count, last_hit_at, is_active)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, 1)",
            params![ips[i], i64::from(ip_nums[i]), reasons[i], now, created_bys[i]],
        );

        match result {
            Ok(_) => success_count += 1,
            Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code: rusqlite::ErrorCode::ConstraintViolation,
                    ..
                },
                _,
            )) => {}
            Err(e) => {
                let _ = tx.rollback();
                bail!("Batch insert failed at index {i}: {e}");
            }
        }
    }

    tx.commit()?;
    Ok(success_count)
}

/// 检查 IPv4 是否在永久黑名单中 (按 `ip_num` 查索引)。
///
/// # Arguments
/// - `db`: db 句柄
/// - `ip_num`: IPv4 网络字节序
///
/// # Returns
/// - `Ok(1)`: 在黑名单
/// - `Ok(0)`: 不在
///
/// # Errors
/// - `prepare_cached` / `query_row` 失败
pub fn sqlite_is_permanent_banned(db: &SqliteDb, ip_num: u32) -> Result<i32> {
    let conn = db.conn.lock();
    let mut stmt = conn.prepare_cached(
        "SELECT 1 FROM permanent_banlist WHERE ip_num = ?1 AND is_active = 1 LIMIT 1",
    )?;

    let exists: Option<i32> = stmt
        .query_row(params![i64::from(ip_num)], |row| row.get(0))
        .ok();
    Ok(exists.unwrap_or(0))
}

/// 检查 IPv6 字符串是否在永久黑名单中 (按 `ip` 文本查)。
///
/// # Arguments
/// - `db`: db 句柄
/// - `ip`: 完整 IPv6 字符串 (e.g. `"2001:db8::1"`)
///
/// # Errors
/// - `prepare_cached` / `query_row` 失败
pub fn sqlite_is_permanent_banned_ipv6(db: &SqliteDb, ip: &str) -> Result<i32> {
    let conn = db.conn.lock();
    let mut stmt = conn.prepare_cached(
        "SELECT 1 FROM permanent_banlist WHERE ip = ?1 AND is_active = 1 LIMIT 1",
    )?;

    let exists: Option<i32> = stmt.query_row(params![ip], |row| row.get(0)).ok();
    Ok(exists.unwrap_or(0))
}

/// 软删除 (`is_active=0`),实际记录保留供审计。
///
/// # Arguments
/// - `db`: db 句柄
/// - `ip`: 待解封的 IP 字符串
///
/// # Returns
/// - `Ok(0)`: 成功软删
/// - `Ok(-2)`: 未找到 (或已软删)
///
/// # Errors
/// - `conn.execute` 失败
pub fn sqlite_remove_permanent_ban(db: &SqliteDb, ip: &str) -> Result<i32> {
    let conn = db.conn.lock();
    let changes = conn.execute(
        "UPDATE permanent_banlist SET is_active = 0 WHERE ip = ?1 AND is_active = 1",
        params![ip],
    )?;

    if changes > 0 {
        Ok(0)
    } else {
        Ok(-2)
    }
}

/// 加载所有活跃永久封禁。`main()` 启动时调,把条目逐个 `ban::ban_ip_permanent`
/// 恢复到内核。
///
/// # Arguments
/// - `db`: db 句柄
///
/// # Returns
/// 按 `created_at` 升序排列的活跃条目
///
/// # Errors
/// - `prepare` / `query_map` 失败
pub fn sqlite_load_all_permanent_bans(db: &SqliteDb) -> Result<Vec<PermanentBanEntry>> {
    let conn = db.conn.lock();
    let mut stmt = conn.prepare(
        "SELECT id, ip, ip_num, reason, created_at, created_by, hit_count, last_hit_at, is_active
         FROM permanent_banlist WHERE is_active = 1 ORDER BY created_at",
    )?;

    let entries = stmt
        .query_map([], |row| {
            Ok(PermanentBanEntry {
                id: row.get(0)?,
                ip: row.get(1)?,
                ip_num: row.get::<_, i64>(2)? as u32,
                reason: row.get(3)?,
                created_at: row.get(4)?,
                created_by: row.get(5)?,
                hit_count: row.get(6)?,
                last_hit_at: row.get(7)?,
                is_active: row.get(8)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(entries)
}

/// 累加 `hit_count` + 更新 `last_hit_at`。每次拦截命中永久黑名单的 IP 时调。
///
/// # Arguments
/// - `db`: db 句柄
/// - `ip_num`: 命中的 IPv4 网络字节序
///
/// # Errors
/// - `conn.execute` 失败
///
/// # Panics
/// `SystemTime::now().duration_since(UNIX_EPOCH)` 仅在系统时钟早于
/// 1970-01-01 时 panic,实际不可能
pub fn sqlite_update_hit_stats(db: &SqliteDb, ip_num: u32) -> Result<()> {
    let conn = db.conn.lock();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    conn.execute(
        "UPDATE permanent_banlist SET hit_count = hit_count + 1, last_hit_at = ?1 WHERE ip_num = ?2 AND is_active = 1",
        params![now, i64::from(ip_num)],
    )?;

    Ok(())
}

/// 统计 (总条数, 活跃条数)。`/metrics` 或管理命令用。
///
/// # Arguments
/// - `db`: db 句柄
///
/// # Errors
/// - `query_row` 失败 (数据库损坏或迁移异常)
pub fn sqlite_get_stats(db: &SqliteDb) -> Result<(i32, i32)> {
    let conn = db.conn.lock();
    let total: i32 = conn.query_row("SELECT COUNT(*) FROM permanent_banlist", [], |row| {
        row.get(0)
    })?;
    let active: i32 = conn.query_row(
        "SELECT COUNT(*) FROM permanent_banlist WHERE is_active = 1",
        [],
        |row| row.get(0),
    )?;
    Ok((total, active))
}

/// 清理软删除记录。
///
/// # Arguments
/// - `db`: db 句柄
/// - `days`: `0` = 立即清理所有 `is_active=0` 记录;`> 0` = 只清理
///   `last_hit_at < now - days*86400` 的软删除记录
///
/// # Returns
/// 实际删除的行数
///
/// # Errors
/// - `conn.execute` 失败
///
/// # Panics
/// `SystemTime::now().duration_since(UNIX_EPOCH)` 仅在系统时钟早于
/// 1970-01-01 时 panic,实际不可能
pub fn sqlite_purge_deleted(db: &SqliteDb, days: i32) -> Result<i32> {
    let conn = db.conn.lock();
    if days > 0 {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - (i64::from(days) * 86400);

        let changes = conn.execute(
            "DELETE FROM permanent_banlist WHERE is_active = 0 AND last_hit_at < ?1",
            params![cutoff],
        )?;
        Ok(changes as i32)
    } else {
        let changes = conn.execute("DELETE FROM permanent_banlist WHERE is_active = 0", [])?;
        Ok(changes as i32)
    }
}

// ============================================================================
// 表结构初始化 + 迁移
// ============================================================================
// 旧表 permanent_banlist 无 UNIQUE 约束, 存在重复 IP; 启动时检测到旧表数据则:
//   1. 去重 (保留 rowid 最小的)
//   2. 复制到带 UNIQUE(ip) 的新表
//   3. 原子 DROP 旧表 + RENAME 新表

fn init_db_schema(conn: &mut Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS permanent_banlist_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            ip_num INTEGER NOT NULL DEFAULT 0,
            reason TEXT DEFAULT 'auto-ban',
            created_at INTEGER NOT NULL,
            created_by TEXT DEFAULT 'auto',
            hit_count INTEGER DEFAULT 0,
            last_hit_at INTEGER,
            is_active INTEGER DEFAULT 1
        );",
    )
    .context("Failed to create permanent_banlist_new table")?;

    let new_table_empty: bool = conn.query_row(
        "SELECT COUNT(*) = 0 FROM permanent_banlist_new",
        [],
        |row| row.get(0),
    )?;

    let old_table_exists: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='permanent_banlist'",
        [],
        |row| row.get(0),
    )?;

    if new_table_empty && old_table_exists {
        let tx = conn.transaction()?;

        tx.execute(
            "DELETE FROM permanent_banlist WHERE rowid NOT IN (
                SELECT MIN(rowid) FROM permanent_banlist GROUP BY ip
            )",
            [],
        )?;

        tx.execute(
            "INSERT OR IGNORE INTO permanent_banlist_new
             (ip, ip_num, reason, created_at, created_by, hit_count, last_hit_at, is_active)
             SELECT ip, ip_num, reason, created_at, created_by, hit_count, last_hit_at, is_active
             FROM permanent_banlist",
            [],
        )?;

        tx.execute_batch(
            "DROP TABLE IF EXISTS permanent_banlist;
             ALTER TABLE permanent_banlist_new RENAME TO permanent_banlist;",
        )?;

        tx.commit()?;
    } else if !new_table_empty {
        // 迁移已完成的二次启动, 清理临时新表
        let _ = conn.execute_batch("DROP TABLE IF EXISTS permanent_banlist_new;");
    } else {
        // 全新库, 重命名新表
        let _ = conn.execute_batch(
            "DROP TABLE IF EXISTS permanent_banlist;
             ALTER TABLE permanent_banlist_new RENAME TO permanent_banlist;",
        );
    }

    let _ = conn.execute_batch("DROP INDEX IF EXISTS idx_ip_num_unique;");

    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_ip_num ON permanent_banlist(ip_num);
         CREATE INDEX IF NOT EXISTS idx_is_active ON permanent_banlist(is_active);",
    )
    .context("Failed to create indexes")?;

    Ok(())
}

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_db_path() -> String {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let tmpdir =
            std::env::temp_dir().join(format!("fw_sqlite_test_{}_{}", std::process::id(), n));
        fs::create_dir_all(&tmpdir).unwrap();
        let path = tmpdir.join("test.db").to_string_lossy().to_string();
        let _ = fs::remove_file(&path);
        path
    }

    fn cleanup(path: &str) {
        let _ = fs::remove_file(path);
        if let Some(dir) = Path::new(path).parent() {
            let _ = fs::remove_dir(dir);
        }
    }

    #[test]
    fn sqlite_init_creates_db() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();
        assert!(Path::new(&path).exists());
        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn sqlite_add_and_query_ban() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        let rc =
            sqlite_add_permanent_ban(&db, "192.168.1.100", 0xC0A80164, "test ban", "auto").unwrap();
        assert_eq!(rc, 0);

        let banned = sqlite_is_permanent_banned(&db, 0xC0A80164).unwrap();
        assert_eq!(banned, 1);

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn sqlite_duplicate_ban_returns_minus2() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        let rc1 = sqlite_add_permanent_ban(&db, "10.0.0.1", 0x0A000001, "test", "auto").unwrap();
        assert_eq!(rc1, 0);

        let rc2 = sqlite_add_permanent_ban(&db, "10.0.0.1", 0x0A000001, "test2", "auto").unwrap();
        assert_eq!(rc2, -2);

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn sqlite_remove_ban() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        sqlite_add_permanent_ban(&db, "10.0.0.2", 0x0A000002, "test", "auto").unwrap();
        let rc = sqlite_remove_permanent_ban(&db, "10.0.0.2").unwrap();
        assert_eq!(rc, 0);

        let banned = sqlite_is_permanent_banned(&db, 0x0A000002).unwrap();
        assert_eq!(banned, 0);

        let rc2 = sqlite_remove_permanent_ban(&db, "10.0.0.2").unwrap();
        assert_eq!(rc2, -2);

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn sqlite_load_all_bans() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        sqlite_add_permanent_ban(&db, "1.1.1.1", 0x01010101, "ban1", "auto").unwrap();
        sqlite_add_permanent_ban(&db, "2.2.2.2", 0x02020202, "ban2", "manual").unwrap();

        let entries = sqlite_load_all_permanent_bans(&db).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ip, "1.1.1.1");
        assert_eq!(entries[1].ip, "2.2.2.2");

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn sqlite_stats() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        sqlite_add_permanent_ban(&db, "3.3.3.3", 0x03030303, "test", "auto").unwrap();
        let (total, active) = sqlite_get_stats(&db).unwrap();
        assert_eq!(total, 1);
        assert_eq!(active, 1);

        sqlite_remove_permanent_ban(&db, "3.3.3.3").unwrap();
        let (total2, active2) = sqlite_get_stats(&db).unwrap();
        assert_eq!(total2, 1); // 软删除, 记录仍在
        assert_eq!(active2, 0);

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn sqlite_add_permanent_bans_batch_success() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        let ips = vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"];
        let ip_nums = vec![0x0A000001, 0x0A000002, 0x0A000003];
        let reasons = vec!["reason1", "reason2", "reason3"];
        let created_bys = vec!["auto", "auto", "manual"];

        let success_count =
            sqlite_add_permanent_bans_batch(&db, &ips, &ip_nums, &reasons, &created_bys).unwrap();
        assert_eq!(success_count, 3);

        let entries = sqlite_load_all_permanent_bans(&db).unwrap();
        assert_eq!(entries.len(), 3);

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn sqlite_add_permanent_bans_batch_skips_duplicates() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        sqlite_add_permanent_ban(&db, "10.0.0.1", 0x0A000001, "first", "auto").unwrap();

        let ips = vec!["10.0.0.1", "10.0.0.2"];
        let ip_nums = vec![0x0A000001, 0x0A000002];
        let reasons = vec!["dup", "new"];
        let created_bys = vec!["auto", "auto"];

        let success_count =
            sqlite_add_permanent_bans_batch(&db, &ips, &ip_nums, &reasons, &created_bys).unwrap();
        assert_eq!(success_count, 1);

        let entries = sqlite_load_all_permanent_bans(&db).unwrap();
        assert_eq!(entries.len(), 2);

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn sqlite_add_permanent_bans_batch_invalid_length() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        let ips = vec!["10.0.0.1", "10.0.0.2"];
        let ip_nums = vec![0x0A000001];
        let reasons = vec!["r1", "r2"];
        let created_bys = vec!["auto", "auto"];

        let result = sqlite_add_permanent_bans_batch(&db, &ips, &ip_nums, &reasons, &created_bys);
        assert!(result.is_err());

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn test_update_hit_stats() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        sqlite_add_permanent_ban(&db, "4.4.4.4", 0x04040404, "test", "auto").unwrap();
        sqlite_update_hit_stats(&db, 0x04040404).unwrap();

        let entries = sqlite_load_all_permanent_bans(&db).unwrap();
        assert_eq!(entries[0].hit_count, 1);

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn test_purge_deleted() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        sqlite_add_permanent_ban(&db, "5.5.5.5", 0x05050505, "test", "auto").unwrap();
        sqlite_remove_permanent_ban(&db, "5.5.5.5").unwrap();

        let purged = sqlite_purge_deleted(&db, 0).unwrap();
        assert_eq!(purged, 1);

        let (total, _) = sqlite_get_stats(&db).unwrap();
        assert_eq!(total, 0);

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn ensure_db_dir_rejects_sensitive_paths() {
        assert!(ensure_db_dir("/etc/test.db").is_err());
        assert!(ensure_db_dir("/bin/test.db").is_err());
        assert!(ensure_db_dir("/sbin/test.db").is_err());
    }
}
