//! SQLite 连接管理模块
//!
//! # 核心职责
//!
//! - 初始化数据库（打开 + 启用 WAL + 迁移表结构）
//! - 全局 DB 注册（`set_global_db` / `clear_global_db` / `with_global_db`）
//! - 优雅关闭（触发 WAL checkpoint）

use std::path::Path;
use std::sync::Arc;
use std::sync::OnceLock;

use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use rusqlite::{Connection, OpenFlags};

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

// ============================================================================
// SqliteDb 结构
// ============================================================================

/// `SQLite` 连接句柄。`conn` 用 `Mutex` 保护,因为 `Connection` 不是 `Sync`。
///
/// 通常通过 `Arc<SqliteDb>` 跨函数 / 跨线程共享。
pub struct SqliteDb {
    pub(crate) conn: Mutex<Connection>,
    pub db_path: String,
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
pub(crate) fn ensure_db_dir(db_path: &str) -> Result<()> {
    if let Some(dir) = Path::new(db_path).parent() {
        let dir_str = dir.to_string_lossy();
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

/// 初始化数据库 schema + 迁移旧表
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
        let _ = conn.execute_batch("DROP TABLE IF EXISTS permanent_banlist_new;");
    } else {
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
        db_path: db_path.to_string(),
    });

    Ok(db)
}

/// 获取数据库连接的只读引用
pub fn get_conn(db: &Arc<SqliteDb>) -> parking_lot::MutexGuard<'_, Connection> {
    db.conn.lock()
}

/// 优雅关闭：触发 WAL checkpoint (TRUNCATE) 后让 `Connection` 随 `Arc` drop 自动关闭。
///
/// # Arguments
/// - `db`: 待关闭的 db（通常来自 `sqlite_init` 的返回值）
pub fn sqlite_close(db: &Arc<SqliteDb>) {
    if let Some(conn) = db.conn.try_lock() {
        let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    }
}

// ============================================================================
// 全局 DB 注册
// ============================================================================

static GLOBAL_DB: OnceLock<Mutex<Option<Arc<SqliteDb>>>> = OnceLock::new();

/// 将 `db` 注册为全局单例，供 [`with_global_db`] 回调访问。`main()` 启动
/// `SQLite` 成功后调用一次。
///
/// # Arguments
/// - `db`：来自 [`sqlite_init`] 的 `Arc<SqliteDb>`
pub fn set_global_db(db: Arc<SqliteDb>) {
    let cell = GLOBAL_DB.get_or_init(|| Mutex::new(None));
    *cell.lock() = Some(db);
}

/// 清空全局 db 注册。`main()` 的 `cleanup` 阶段调，确保收尾期间 ban 模块
/// 不再访问 db。
pub fn clear_global_db() {
    if let Some(cell) = GLOBAL_DB.get() {
        *cell.lock() = None;
    }
}

/// 若全局 db 已注册，以回调方式借用；否则返回 `None`。
///
/// # Arguments
/// - `f`：接受 `&Arc<SqliteDb>` 的闭包，执行所需操作
///
/// # Returns
/// - `Some(R)`：回调返回值
/// - `None`：全局 db 未注册（`SQLite` 未启用或已 clear）
pub fn with_global_db<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&Arc<SqliteDb>) -> R,
{
    let cell = GLOBAL_DB.get()?;
    let guard = cell.lock();
    guard.as_ref().map(f)
}

/// 获取全局数据库引用的克隆
pub fn get_global_db() -> Option<Arc<SqliteDb>> {
    let cell = GLOBAL_DB.get()?;
    let guard = cell.lock();
    guard.as_ref().cloned()
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
            std::env::temp_dir().join(format!("fw_sqlite_conn_test_{}_{}", std::process::id(), n));
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
    fn ensure_db_dir_rejects_sensitive_paths() {
        assert!(ensure_db_dir("/etc/test.db").is_err());
        assert!(ensure_db_dir("/bin/test.db").is_err());
        assert!(ensure_db_dir("/sbin/test.db").is_err());
    }
}
