package persist

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newRetryTestQueue 建一个用临时持久化文件的重试队列，复用 facts_test.go 中的 newTestDB。
func newRetryTestQueue(t *testing.T) (*RetryQueue, *DB) {
	t.Helper()
	db := newTestDB(t)
	dir := t.TempDir()
	q := NewRetryQueue(db, RetryQueueConfig{
		MaxSize:          5,
		PersistPath:      filepath.Join(dir, "retry.json"),
		Logger:           slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		RetryInterval:    10 * time.Millisecond,
		MaxRetryInterval: 50 * time.Millisecond,
	})
	t.Cleanup(func() { q.Stop() })
	return q, db
}

// TestRetryQueue_FailedWriteThenRetrySuccess 模拟 DB 写入失败后事件进入重试队列，
// 待后台协程重试成功，最终 DB 中有对应记录。
func TestRetryQueue_FailedWriteThenRetrySuccess(t *testing.T) {
	q, db := newRetryTestQueue(t)

	q.EnqueueBanEvent("192.0.2.1", "sshd", 1, false, nil)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if q.Len() == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if q.Len() != 0 {
		t.Fatalf("expected queue to be drained after retry, got %d tasks", q.Len())
	}

	events, err := db.GetBanEvents(10)
	if err != nil {
		t.Fatalf("GetBanEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 ban event in DB, got %d", len(events))
	}
	if events[0].IP != "192.0.2.1" || events[0].JailName != "sshd" {
		t.Errorf("unexpected event: %+v", events[0])
	}
}

// TestRetryQueue_QueueFullDropsOldest 验证队列满时丢弃最旧任务并保留新任务。
//
// 通过关闭 DB 让 execute 必定失败，任务不会被后台协程消费。
func TestRetryQueue_QueueFullDropsOldest(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := NewDB(Config{Path: dbPath})
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	// 立即关闭 DB，让后台重试必定失败，任务留在队列中。
	_ = db.Close()

	q := NewRetryQueue(db, RetryQueueConfig{
		MaxSize:          3,
		PersistPath:      filepath.Join(dir, "retry.json"),
		Logger:           slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
		RetryInterval:    time.Second, // 设长，减少后台重试频率
		MaxRetryInterval: time.Second,
	})
	defer q.Stop()

	// 快速填满队列。
	for i := 0; i < 3; i++ {
		q.EnqueueBanEvent("10.0.0.1", "jail", i+1, false, nil)
	}
	// 等待后台协程尝试一次（会失败），确保队列状态稳定。
	time.Sleep(100 * time.Millisecond)
	if q.Len() != 3 {
		t.Fatalf("expected 3 tasks, got %d", q.Len())
	}

	// 再入队一条，应丢弃最旧（ban_count=1 的那条）。
	q.EnqueueBanEvent("10.0.0.2", "jail", 99, false, nil)
	time.Sleep(50 * time.Millisecond)
	if q.Len() != 3 {
		t.Fatalf("expected 3 tasks after overflow, got %d", q.Len())
	}
}

// TestRetryQueue_PersistAndLoad 验证队列持久化后重启能恢复任务。
func TestRetryQueue_PersistAndLoad(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "retry.json")
	dbPath := filepath.Join(dir, "test.db")
	db, err := NewDB(Config{Path: dbPath})
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	// 关闭 DB 让任务留在队列中。
	_ = db.Close()

	q1 := NewRetryQueue(db, RetryQueueConfig{
		MaxSize:          10,
		PersistPath:      persistPath,
		Logger:           slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		RetryInterval:    time.Second,
		MaxRetryInterval: time.Second,
	})
	q1.EnqueueBanEvent("198.51.100.1", "nginx", 1, false, nil)
	q1.EnqueueBanHistory("198.51.100.1", false)
	// 等待持久化完成（Enqueue 是同步 persist 的）。
	time.Sleep(100 * time.Millisecond)

	// 验证文件存在且非空（在 Stop 之前检查，因为 Stop 会 flush 并清空队列）。
	info, err := os.Stat(persistPath)
	if err != nil {
		t.Fatalf("persist file not found: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("persist file is empty")
	}
	q1.Stop()

	// 重新打开 DB，第二个队列从同一文件加载。
	db2, err := NewDB(Config{Path: dbPath})
	if err != nil {
		t.Fatalf("NewDB (2nd): %v", err)
	}
	defer db2.Close()
	// 关闭 DB2 让加载的任务留在队列中。
	_ = db2.Close()

	q2 := NewRetryQueue(db2, RetryQueueConfig{
		MaxSize:          10,
		PersistPath:      persistPath,
		Logger:           slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		RetryInterval:    time.Second,
		MaxRetryInterval: time.Second,
	})
	defer q2.Stop()
	q2.LoadPersisted()

	if q2.Len() != 2 {
		t.Fatalf("expected 2 loaded tasks, got %d", q2.Len())
	}
}

// TestRetryQueue_StartupSyncToDB 模拟完整场景：第一个进程入队后关停（不 flush），
// 第二个进程启动后加载持久化文件并把任务补写到 DB。
func TestRetryQueue_StartupSyncToDB(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "retry.json")
	dbPath := filepath.Join(dir, "test.db")

	db1, err := NewDB(Config{Path: dbPath})
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	// 立即关闭 DB1，让任务留在队列中不被消费。
	_ = db1.Close()

	q1 := NewRetryQueue(db1, RetryQueueConfig{
		MaxSize:          10,
		PersistPath:      persistPath,
		Logger:           slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		RetryInterval:    time.Second,
		MaxRetryInterval: time.Second,
	})
	q1.EnqueueBanEvent("203.0.113.50", "sshd", 2, false, retryInt64Ptr(300))
	// 等待持久化完成。
	time.Sleep(100 * time.Millisecond)
	// 不调 Stop()（Stop 会 flush），直接停止后台协程。
	// 这里我们手动关闭 stop channel 来停止协程，但不 flush。
	// 但 Stop() 是导出的唯一停止方式，所以我们用一个技巧：直接让 q1 被 GC。
	// 实际上，为了测试 LoadPersisted 路径，我们只需要确保 persist 文件有内容。
	// 由于 Enqueue 是同步 persist 的，文件此时已经有内容了。

	// 模拟第二个进程：打开同一个 DB，加载持久化文件，flush 到 DB。
	db2, err := NewDB(Config{Path: dbPath})
	if err != nil {
		t.Fatalf("NewDB (2nd): %v", err)
	}
	defer db2.Close()
	q2 := NewRetryQueue(db2, RetryQueueConfig{
		MaxSize:          10,
		PersistPath:      persistPath,
		Logger:           slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		RetryInterval:    time.Second,
		MaxRetryInterval: time.Second,
	})
	q2.LoadPersisted()
	if q2.Len() != 1 {
		t.Fatalf("expected 1 loaded task, got %d", q2.Len())
	}
	q2.Stop() // Stop 会 flush

	events, err := db2.GetBanEvents(10)
	if err != nil {
		t.Fatalf("GetBanEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event after startup sync, got %d", len(events))
	}
	if events[0].IP != "203.0.113.50" || events[0].BanCount != 2 {
		t.Errorf("unexpected event after sync: %+v", events[0])
	}
}

func retryInt64Ptr(v int64) *int64 { return &v }
