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
			last_ban INTEGER
		);

		CREATE INDEX IF NOT EXISTS idx_ip_reputation_score ON ip_reputation(score);

		CREATE TABLE IF NOT EXISTS ban_history (
			ip TEXT PRIMARY KEY,
			ban_count INTEGER NOT NULL DEFAULT 0,
			last_banned_at INTEGER NOT NULL,
			is_permanent INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_ban_history_ban_count ON ban_history(ban_count);
		CREATE INDEX IF NOT EXISTS idx_ban_history_last_banned ON ban_history(last_banned_at);
	`

	if _, err := db.conn.Exec(schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}

	db.logger.Info("database schema migrated", "path", db.path)
	return nil
}

func (db *DB) cleanupExpired(retentionDays int) error {
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
				if err := db.cleanupExpired(retentionDays); err != nil {
					db.logger.Error("cleanup failed", "error", err)
				}
			}
		}
	}()
}
