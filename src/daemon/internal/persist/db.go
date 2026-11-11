package persist

import (
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/risk"
)

type DB struct {
	conn   *sql.DB
	logger *slog.Logger
	path   string

	// riskWeights 是风险向量衰减/清理判据使用的维度权重，由装配多维引擎的一方
	// 通过 SetRiskVectorWeights 写入，保证库侧的后台衰减与引擎读的是同一份权重。
	riskWeightsMu  sync.RWMutex
	riskWeights    risk.DimensionWeights
	riskWeightsSet bool
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

		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS attack_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL,
			event_type TEXT NOT NULL,
			increment REAL NOT NULL,
			occurred_at INTEGER NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_attack_events_ip ON attack_events(ip, occurred_at DESC);
		CREATE INDEX IF NOT EXISTS idx_attack_events_type ON attack_events(event_type);
		CREATE INDEX IF NOT EXISTS idx_attack_events_occurred_at ON attack_events(occurred_at);

		CREATE TABLE IF NOT EXISTS ip_risk_vectors (
			ip TEXT PRIMARY KEY,
			failure REAL NOT NULL DEFAULT 0,
			ban REAL NOT NULL DEFAULT 0,
			scan REAL NOT NULL DEFAULT 0,
			bruteforce REAL NOT NULL DEFAULT 0,
			ddos REAL NOT NULL DEFAULT 0,
			geo REAL NOT NULL DEFAULT 0,
			cluster REAL NOT NULL DEFAULT 0,
			last_event_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_ip_risk_vectors_updated ON ip_risk_vectors(updated_at);
	`

	if _, err := db.conn.Exec(schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}

	if err := db.applyMigrations(); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
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

// applyMigrations 按版本号顺序执行增量迁移。
//
// 每次启动检查当前版本，依次执行未应用的迁移。迁移失败时报错且不记录该版本，
// 下次启动会重试。注意：本函数不把单个迁移包进事务——当前 v1 为空操作，不存在
// 半完成状态；未来新增含多条语句的迁移时，必须自带 BEGIN/COMMIT，否则中途失败
// 会留下半完成状态且不会自动回滚。
func (db *DB) applyMigrations() error {
	migrations := []struct {
		version int
		up      func() error
	}{
		{1, db.migrationV1},
	}

	for _, m := range migrations {
		applied, err := db.isMigrationApplied(m.version)
		if err != nil {
			return fmt.Errorf("check migration v%d: %w", m.version, err)
		}
		if applied {
			continue
		}

		db.logger.Info("applying migration", "version", m.version)
		if err := m.up(); err != nil {
			return fmt.Errorf("apply migration v%d: %w", m.version, err)
		}
		if err := db.recordMigration(m.version); err != nil {
			return fmt.Errorf("record migration v%d: %w", m.version, err)
		}
		db.logger.Info("migration applied", "version", m.version)
	}

	return nil
}

// isMigrationApplied 检查指定版本的迁移是否已应用。
func (db *DB) isMigrationApplied(version int) (bool, error) {
	var count int
	err := db.conn.QueryRow(
		"SELECT COUNT(*) FROM schema_migrations WHERE version = ?",
		version,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("query schema_migrations: %w", err)
	}
	return count > 0, nil
}

// recordMigration 记录已应用的迁移版本。
func (db *DB) recordMigration(version int) error {
	_, err := db.conn.Exec(
		"INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
		version, time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("insert schema_migrations: %w", err)
	}
	return nil
}

// migrationV1 初始化多维风险向量表（首次部署时表已存在，此迁移为空操作）。
//
// 保留此迁移是为了版本号一致性：未来新增迁移从 v2 开始。
func (db *DB) migrationV1() error {
	return nil
}

// CleanupExpired 清理超过保留期的封禁事件、信誉分与历史记录，防止数据库无限增长。
func (db *DB) CleanupExpired(retentionDays int) error {
	if retentionDays <= 0 {
		retentionDays = 7
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays).Unix()

	// 五条 DELETE 放进一个事务：中途失败若已提交前几条，会留下「清了一半」的状态，
	// 既不好解释也无法与后续清理对齐，故整体成功才提交。
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("begin cleanup transaction: %w", err)
	}
	defer tx.Rollback()

	statements := []struct {
		table string
		query string
	}{
		{"ban_events", "DELETE FROM ban_events WHERE created_at < ?"},
		{"ip_reputation", "DELETE FROM ip_reputation WHERE last_updated < ?"},
		{"ban_history", "DELETE FROM ban_history WHERE last_banned_at < ?"},
		{"attack_events", "DELETE FROM attack_events WHERE occurred_at < ?"},
		{"ip_risk_vectors", "DELETE FROM ip_risk_vectors WHERE updated_at < ?"},
	}
	counts := make([]int64, len(statements))
	for i, st := range statements {
		result, err := tx.Exec(st.query, cutoff)
		if err != nil {
			return fmt.Errorf("cleanup %s: %w", st.table, err)
		}
		counts[i], _ = result.RowsAffected()
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit cleanup transaction: %w", err)
	}

	// 日志在提交后打：回滚掉的行不该出现在「已清理」的记录里。
	for i, st := range statements {
		if counts[i] > 0 {
			db.logger.Info("cleaned up expired "+st.table, "count", counts[i], "retention_days", retentionDays)
		}
	}

	return nil
}

// StartCleanupScheduler 启动周期性清理过期记录的后台任务。
// 返回的通道在 goroutine 退出后关闭；调用方应先等它关闭再关数据库，防止清理操作写到已关闭的连接。
func (db *DB) StartCleanupScheduler(interval time.Duration, retentionDays int, stopCh <-chan struct{}) <-chan struct{} {
	if interval <= 0 {
		interval = 1 * time.Hour
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
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
	return done
}
