package persist

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	conn   *sql.DB
	logger *slog.Logger
	path   string
}

type Config struct {
	Path   string
	Logger *slog.Logger
}

func NewDB(cfg Config) (*DB, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("database path required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	conn, err := sql.Open("sqlite", cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("open database %s: %w", cfg.Path, err)
	}

	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)
	conn.SetConnMaxLifetime(0)

	if _, err := conn.Exec("PRAGMA journal_mode=WAL"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	if _, err := conn.Exec("PRAGMA synchronous=NORMAL"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("set synchronous: %w", err)
	}
	if _, err := conn.Exec("PRAGMA busy_timeout=5000"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("set busy_timeout: %w", err)
	}

	db := &DB{
		conn:   conn,
		logger: cfg.Logger,
		path:   cfg.Path,
	}

	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return db, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) migrate() error {
	schema := `
		CREATE TABLE IF NOT EXISTS ban_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL,
			jail_name TEXT NOT NULL,
			banned_at INTEGER NOT NULL,
			ban_count INTEGER NOT NULL DEFAULT 1,
			is_permanent INTEGER NOT NULL DEFAULT 0,
			duration_secs INTEGER,
			created_at INTEGER NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_ban_events_ip ON ban_events(ip);
		CREATE INDEX IF NOT EXISTS idx_ban_events_jail ON ban_events(jail_name);
		CREATE INDEX IF NOT EXISTS idx_ban_events_banned_at ON ban_events(banned_at);
		CREATE INDEX IF NOT EXISTS idx_ban_events_created_at ON ban_events(created_at);

		CREATE TABLE IF NOT EXISTS ip_reputation (
			ip TEXT PRIMARY KEY,
			score INTEGER NOT NULL DEFAULT 100,
			last_updated INTEGER NOT NULL,
			last_failure INTEGER,
			last_ban INTEGER,
			total_failures INTEGER NOT NULL DEFAULT 0,
			total_bans INTEGER NOT NULL DEFAULT 0
		);

		CREATE INDEX IF NOT EXISTS idx_ip_reputation_score ON ip_reputation(score);

		CREATE TABLE IF NOT EXISTS ban_history (
			ip TEXT PRIMARY KEY,
			ban_count INTEGER NOT NULL DEFAULT 0,
			last_banned_at INTEGER NOT NULL,
			is_permanent INTEGER NOT NULL DEFAULT 0,
			last_unbanned_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_ban_history_ban_count ON ban_history(ban_count);
		CREATE INDEX IF NOT EXISTS idx_ban_history_last_banned ON ban_history(last_banned_at);
	`

	if _, err := db.conn.Exec(schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}

	// 已在现场的库由 CREATE TABLE IF NOT EXISTS 跳过，新加的列只能靠 ALTER 补上。
	// 这里的表名与列名都是常量，不接调用方输入。
	//
	// 迁移只补列、**不补史**，两列的缺省形状各自说明为什么：
	//   - ban_events.duration_secs 用 NULL 而不是 0：旧行的计划时长已经无从追究，填 0 会被
	//     时长直方图读成「封了 0 秒」那一桶，等于凭空造出一批读数；
	//   - ip_reputation 的两个计数从 0 起算，语义是「本列开始记录以来的累计」，契约的
	//     字段注释按这个口径写。
	for _, col := range []struct{ table, name, definition string }{
		{"ban_history", "last_unbanned_at", "INTEGER NOT NULL DEFAULT 0"},
		{"ban_events", "duration_secs", "INTEGER"},
		{"ip_reputation", "total_failures", "INTEGER NOT NULL DEFAULT 0"},
		{"ip_reputation", "total_bans", "INTEGER NOT NULL DEFAULT 0"},
	} {
		if err := db.ensureColumn(col.table, col.name, col.definition); err != nil {
			return fmt.Errorf("migrate %s.%s: %w", col.table, col.name, err)
		}
	}

	db.logger.Info("database schema migrated", "path", db.path)
	return nil
}

// ensureColumn 在列不存在时补上它（幂等：重复执行不报错）。
//
// 不能直接跑 `ALTER TABLE … ADD COLUMN`：SQLite 对已存在的列报 duplicate column name，
// 而 migrate() 每次启动都会执行，第二次启动 daemon 就再也起不来了。
//
// 表名走**绑定参数**而不是拼进 SQL：pragma_table_info 是表值函数，它的入参可以按
// 普通占位符传（与下面那条 ALTER 里只能拼接的标识符不同——标识符不是值，绑定不了，
// 所以那里的三个实参必须是调用方写死的常量，不接受任何来自配置的字符串）。
func (db *DB) ensureColumn(table, column, definition string) error {
	rows, err := db.conn.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return fmt.Errorf("inspect table %s: %w", table, err)
	}
	defer rows.Close()

	existing := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("scan column name: %w", err)
		}
		existing[name] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate columns of %s: %w", table, err)
	}
	if existing[column] {
		return nil
	}

	_, err = db.conn.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition))
	if err != nil {
		return fmt.Errorf("add column %s.%s: %w", table, column, err)
	}
	db.logger.Info("added column", "table", table, "column", column)
	return nil
}

// CleanupExpired 清理超过保留期的封禁事件、信誉分与历史记录，防止数据库无限增长。
func (db *DB) CleanupExpired(retentionDays int) error {
	if retentionDays <= 0 {
		retentionDays = 7
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays).Unix()

	result, err := db.conn.Exec("DELETE FROM ban_events WHERE created_at < ?", cutoff)
	if err != nil {
		return fmt.Errorf("cleanup ban_events: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		db.logger.Info("cleaned up expired ban_events", "count", rows, "retention_days", retentionDays)
	}

	result, err = db.conn.Exec("DELETE FROM ip_reputation WHERE last_updated < ?", cutoff)
	if err != nil {
		return fmt.Errorf("cleanup ip_reputation: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		db.logger.Info("cleaned up expired ip_reputation", "count", rows, "retention_days", retentionDays)
	}

	result, err = db.conn.Exec("DELETE FROM ban_history WHERE last_banned_at < ?", cutoff)
	if err != nil {
		return fmt.Errorf("cleanup ban_history: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		db.logger.Info("cleaned up expired ban_history", "count", rows, "retention_days", retentionDays)
	}

	return nil
}

func (db *DB) StartCleanupScheduler(interval time.Duration, retentionDays int, stopCh <-chan struct{}) {
	if interval <= 0 {
		interval = 1 * time.Hour
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				if err := db.CleanupExpired(retentionDays); err != nil {
					db.logger.Error("cleanup failed", "error", err)
				}
			}
		}
	}()
}
