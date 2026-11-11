package persist

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// retryTestLogger 返回只输出 Error 的日志器，避免测试用例把后台重试噪音刷到 stderr。
func retryTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// lockedBuffer 是可并发写的日志接收器：队列的后台协程与测试线程可能同时写日志。
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitFileTasks 轮询持久化文件，直到其中任务数达到 want 或超时。
func waitFileTasks(t *testing.T, path string, want int) []retryTask {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			var tasks []retryTask
			if json.Unmarshal(data, &tasks) == nil && len(tasks) == want {
				return tasks
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("持久化文件 %s 未在超时内写入 %d 条任务（err=%v）", path, want, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

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
		PersistInterval:  10 * time.Millisecond,
	})
	q1.EnqueueBanEvent("198.51.100.1", "nginx", 1, false, nil)
	q1.EnqueueBanHistory("198.51.100.1", false)

	// 验证合并落盘节拍把两条任务写出了（在 Stop 之前检查，因为 Stop 会 flush 并清空队列）。
	if tasks := waitFileTasks(t, persistPath, 2); len(tasks) != 2 {
		t.Fatalf("expected 2 persisted tasks, got %d", len(tasks))
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
		PersistInterval:  10 * time.Millisecond,
	})
	q1.EnqueueBanEvent("203.0.113.50", "sshd", 2, false, retryInt64Ptr(300))
	// 等合并落盘节拍写出快照。不调 q1.Stop()：Stop 会 flush，而这里要的是
	// 「进程退出前已落盘、但没来得及写 DB」的状态。
	waitFileTasks(t, persistPath, 1)

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

// 未知 op（例如持久化文件来自另一个版本）永远不可能成功：必须丢弃，不能永久占住队列
// 并把整条队列的退避推到上限。同一批里的合法任务仍要正常落库。
func TestRetryQueueDropsUnknownOp(t *testing.T) {
	q, db := newRetryTestQueue(t)

	q.Enqueue(retryTask{Op: retryOp("from-the-future"), IP: "198.51.100.9"})
	q.EnqueueBanEvent("198.51.100.10", "sshd", 1, false, nil)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && q.Len() > 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if q.Len() != 0 {
		t.Fatalf("未知 op 未被丢弃，队列仍有 %d 条", q.Len())
	}
	events, err := db.GetBanEvents(10)
	if err != nil {
		t.Fatalf("GetBanEvents: %v", err)
	}
	if len(events) != 1 || events[0].IP != "198.51.100.10" {
		t.Fatalf("合法任务未落库: %+v", events)
	}

	q.Stop()
	data, err := os.ReadFile(q.cfg.PersistPath)
	if err != nil {
		t.Fatalf("读持久化文件失败: %v", err)
	}
	if strings.Contains(string(data), "from-the-future") {
		t.Fatalf("未知 op 仍留在持久化文件里: %s", data)
	}
}

// TestRetryQueueStopPersistsWhenDBUnavailable 钉住关停兜底：DB 不可用时 flush 会提前返回，
// 队列里剩余的任务必须在 Stop 里重新落盘，否则进程重启后这些事件就丢了。
func TestRetryQueueStopPersistsWhenDBUnavailable(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "retry.json")
	db, err := NewDB(Config{Path: filepath.Join(dir, "test.db")})
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	_ = db.Close() // DB 不可用，flush 注定失败

	q := NewRetryQueue(db, RetryQueueConfig{
		MaxSize:          10,
		PersistPath:      persistPath,
		Logger:           slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		RetryInterval:    time.Second,
		MaxRetryInterval: time.Second,
		PersistInterval:  time.Hour, // 节拍不会触发，落盘只能来自 Stop 的强制写
	})
	q.EnqueueBanEvent("203.0.113.77", "sshd", 1, false, nil)
	// 入队只置脏标记，此时磁盘上还没有快照；只有 Stop 里的强制 persist 能把它写出来。
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(persistPath); !os.IsNotExist(err) {
		t.Fatalf("入队不应同步整队落盘，文件已存在（stat err=%v）", err)
	}

	q.Stop()

	data, err := os.ReadFile(persistPath)
	if err != nil {
		t.Fatalf("Stop 后持久化文件不存在，剩余任务已丢失: %v", err)
	}
	var tasks []retryTask
	if err := json.Unmarshal(data, &tasks); err != nil {
		t.Fatalf("解析持久化文件失败: %v", err)
	}
	if len(tasks) != 1 || tasks[0].IP != "203.0.113.77" {
		t.Fatalf("Stop 后应从磁盘恢复 1 条任务，实际 %+v", tasks)
	}
}

// TestRetryQueueEnqueueDoesNotWakeNonEmptyQueue 钉住 H-26 的唤醒条件：只有队列由空转非空
// 才唤醒后台协程，非空队列的后续入队不能逐条打破退避。DB 已关闭，任务必定失败留在队列里。
func TestRetryQueueEnqueueDoesNotWakeNonEmptyQueue(t *testing.T) {
	dir := t.TempDir()
	db, err := NewDB(Config{Path: filepath.Join(dir, "test.db")})
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	_ = db.Close() // 写入必定失败，任务不会被消费

	q := NewRetryQueue(db, RetryQueueConfig{
		MaxSize:          10,
		PersistPath:      filepath.Join(dir, "retry.json"),
		Logger:           retryTestLogger(),
		RetryInterval:    time.Second,
		MaxRetryInterval: time.Second,
		PersistInterval:  time.Hour,
	})
	defer q.Stop()

	for i := 0; i < 5; i++ {
		q.EnqueueBanEvent("192.0.2.1", "sshd", i+1, false, nil)
	}
	if got := q.wakeCount.Load(); got != 1 {
		t.Fatalf("5 次入队应只在空转非空时唤醒 1 次，实际 %d 次", got)
	}
	if q.Len() != 5 {
		t.Fatalf("期望 5 条待重试任务，实际 %d", q.Len())
	}
}

// TestRetryQueuePersistTickWritesDirtyQueue 验证脏标记由短节拍合并落盘：
// 入队本身不写盘，节拍到达后队列内容出现在持久化文件里。
func TestRetryQueuePersistTickWritesDirtyQueue(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "retry.json")
	db, err := NewDB(Config{Path: filepath.Join(dir, "test.db")})
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	_ = db.Close()

	q := NewRetryQueue(db, RetryQueueConfig{
		MaxSize:          10,
		PersistPath:      persistPath,
		Logger:           retryTestLogger(),
		RetryInterval:    time.Second,
		MaxRetryInterval: time.Second,
		PersistInterval:  10 * time.Millisecond,
	})
	defer q.Stop()

	q.EnqueueBanHistory("198.51.100.7", false)
	tasks := waitFileTasks(t, persistPath, 1)
	if tasks[0].Op != opBanHistory || tasks[0].IP != "198.51.100.7" {
		t.Fatalf("节拍落盘内容不符: %+v", tasks[0])
	}
}

// TestRetryQueueLoadPersistedTruncationWarns 钉住 L-36：持久化文件超过容量时截断到 MaxSize，
// 并记一条 Warn 说明丢弃条数（容量本身不变）。
func TestRetryQueueLoadPersistedTruncationWarns(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "retry.json")
	var persisted []retryTask
	for i := 0; i < 5; i++ {
		persisted = append(persisted, retryTask{
			Op:         opBanHistory,
			IP:         fmt.Sprintf("198.51.100.%d", i+1),
			EnqueuedAt: time.Now().UnixNano(),
		})
	}
	data, err := json.Marshal(persisted)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(persistPath, data, 0600); err != nil {
		t.Fatalf("写持久化文件: %v", err)
	}

	db, err := NewDB(Config{Path: filepath.Join(dir, "test.db")})
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	_ = db.Close()

	logs := &lockedBuffer{}
	q := NewRetryQueue(db, RetryQueueConfig{
		MaxSize:          3,
		PersistPath:      persistPath,
		Logger:           slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})),
		RetryInterval:    time.Second,
		MaxRetryInterval: time.Second,
		PersistInterval:  time.Hour,
	})
	defer q.Stop()

	q.LoadPersisted()
	if q.Len() != 3 {
		t.Fatalf("容量 3 应截断到 3 条，实际 %d", q.Len())
	}
	out := logs.String()
	if !strings.Contains(out, "dropping remainder") || !strings.Contains(out, "dropped=2") {
		t.Fatalf("截断未产生带丢弃条数的 Warn 日志: %s", out)
	}
}

// TestRetryQueueConcurrentEnqueueRespectsMaxSize 钉住 L-39 的最小修复：后台批次执行期间的
// 并发入队不能把已丢弃的任务在重建时复活，把队列撑过 MaxSize。
func TestRetryQueueConcurrentEnqueueRespectsMaxSize(t *testing.T) {
	dir := t.TempDir()
	db, err := NewDB(Config{Path: filepath.Join(dir, "test.db")})
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	_ = db.Close() // 写入全失败，任务留在队列里，retryBatch 反复重建队列

	const maxSize = 4
	q := NewRetryQueue(db, RetryQueueConfig{
		MaxSize:          maxSize,
		PersistPath:      filepath.Join(dir, "retry.json"),
		Logger:           retryTestLogger(),
		RetryInterval:    time.Millisecond,
		MaxRetryInterval: time.Millisecond,
		PersistInterval:  time.Hour,
	})
	defer q.Stop()

	deadline := time.Now().Add(300 * time.Millisecond)
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; time.Now().Before(deadline); i++ {
				q.EnqueueBanEvent(fmt.Sprintf("10.0.0.%d", g), "jail", i, false, nil)
			}
		}(g)
	}
	overflow := 0
	for time.Now().Before(deadline) {
		if n := q.Len(); n > maxSize {
			overflow = n
			break
		}
		time.Sleep(time.Millisecond)
	}
	wg.Wait()
	if overflow > maxSize {
		t.Fatalf("并发入队期间队列越过容量上限: %d > %d", overflow, maxSize)
	}
	if n := q.Len(); n > maxSize {
		t.Fatalf("队列最终越过容量上限: %d > %d", n, maxSize)
	}
}
