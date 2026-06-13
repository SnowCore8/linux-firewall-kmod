//! 永久封禁表结构初始化 + 迁移

use anyhow::{Context, Result};
use rusqlite::Connection;

// ============================================================================
// 表结构初始化 + 迁移
// ============================================================================

pub(crate) fn init_db_schema(conn: &mut Connection) -> Result<()> {
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
