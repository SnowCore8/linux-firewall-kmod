package persist

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewDB_CreatesSchema(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := NewDB(Config{
		Path:   dbPath,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

	tables := []string{
		"ban_events",
		"ip_reputation",
		"ban_history",
		"schema_migrations",
		"attack_events",
		"ip_risk_vectors",
	}

	for _, table := range tables {
		var name string
		err := db.conn.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?",
			table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %s not created: %v", table, err)
		}
		if name != table {
			t.Errorf("table name mismatch: got %q, want %q", name, table)
		}
	}
}

func TestNewDB_AppliesMigrations(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := NewDB(Config{
		Path:   dbPath,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

	var version int
	err = db.conn.QueryRow("SELECT version FROM schema_migrations WHERE version=1").Scan(&version)
	if err != nil {
		t.Errorf("migration v1 not recorded: %v", err)
	}
	if version != 1 {
		t.Errorf("migration version mismatch: got %d, want 1", version)
	}
}

func TestNewDB_IdempotentMigration(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db1, err := NewDB(Config{
		Path:   dbPath,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		t.Fatalf("first NewDB failed: %v", err)
	}
	db1.Close()

	db2, err := NewDB(Config{
		Path:   dbPath,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		t.Fatalf("second NewDB failed: %v", err)
	}
	defer db2.Close()

	var count int
	err = db2.conn.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if err != nil {
		t.Fatalf("query schema_migrations failed: %v", err)
	}
	if count != 1 {
		t.Errorf("migration applied multiple times: got %d rows, want 1", count)
	}
}

func TestCleanupExpired_NewTables(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := NewDB(Config{
		Path:   dbPath,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

	_, err = db.conn.Exec(
		"INSERT INTO attack_events (ip, event_type, increment, occurred_at) VALUES (?, ?, ?, ?)",
		"192.168.1.1", "failure", 10.0, 1000000,
	)
	if err != nil {
		t.Fatalf("insert attack_events failed: %v", err)
	}

	_, err = db.conn.Exec(
		"INSERT INTO ip_risk_vectors (ip, failure, last_event_at, updated_at) VALUES (?, ?, ?, ?)",
		"192.168.1.1", 10.0, 1000000, 1000000,
	)
	if err != nil {
		t.Fatalf("insert ip_risk_vectors failed: %v", err)
	}

	err = db.CleanupExpired(7)
	if err != nil {
		t.Fatalf("CleanupExpired failed: %v", err)
	}

	var attackCount, vectorCount int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM attack_events").Scan(&attackCount)
	if err != nil {
		t.Fatalf("query attack_events count failed: %v", err)
	}
	if attackCount != 0 {
		t.Errorf("attack_events not cleaned up: got %d rows, want 0", attackCount)
	}

	err = db.conn.QueryRow("SELECT COUNT(*) FROM ip_risk_vectors").Scan(&vectorCount)
	if err != nil {
		t.Fatalf("query ip_risk_vectors count failed: %v", err)
	}
	if vectorCount != 0 {
		t.Errorf("ip_risk_vectors not cleaned up: got %d rows, want 0", vectorCount)
	}
}

func TestCleanupScheduler_ReturnsDoneChannel(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := NewDB(Config{
		Path:   dbPath,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

	stopCh := make(chan struct{})
	done := db.StartCleanupScheduler(50*time.Millisecond, 7, stopCh)

	// Let the ticker fire at least once.
	time.Sleep(100 * time.Millisecond)

	close(stopCh)

	select {
	case <-done:
		// goroutine exited as expected.
	case <-time.After(2 * time.Second):
		t.Fatal("done channel not closed within 2s after stopCh closed")
	}
}

func TestReputationRecoveryScheduler_ReturnsDoneChannel(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := NewDB(Config{
		Path:   dbPath,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

	stopCh := make(chan struct{})
	done := db.StartReputationRecoveryScheduler(50*time.Millisecond, 1, 100, stopCh)

	// Let the ticker fire at least once.
	time.Sleep(100 * time.Millisecond)

	close(stopCh)

	select {
	case <-done:
		// goroutine exited as expected.
	case <-time.After(2 * time.Second):
		t.Fatal("done channel not closed within 2s after stopCh closed")
	}
}
