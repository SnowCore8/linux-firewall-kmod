package persist

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// retryOp 标识待重试的数据库写入操作类型。
type retryOp string

const (
	opBanEvent      retryOp = "ban_event"
	opBanHistory    retryOp = "ban_history"
	opBanReputation retryOp = "ban_reputation"
)

// retryTask 是一条待重试的数据库写入操作。
//
// 字段与对应的 DB 方法参数一一匹配；Op 决定回放时调用哪个方法。
// id 是内存中递增分配的唯一标识，用于 retryBatch 并发合并时区分新旧任务，不参与 JSON 序列化。
type retryTask struct {
	id           uint64
	Op           retryOp `json:"op"`
	IP           string  `json:"ip"`
	JailName     string  `json:"jail_name,omitempty"`
	BanCount     int     `json:"ban_count,omitempty"`
	IsPermanent  bool    `json:"is_permanent,omitempty"`
	DurationSecs *int64  `json:"duration_secs,omitempty"`
	Penalty      int     `json:"penalty,omitempty"`
	EnqueuedAt   int64   `json:"enqueued_at"` // Unix 纳秒
}

// RetryQueueConfig 控制重试队列的行为。
type RetryQueueConfig struct {
	// MaxSize 是队列最大容量；超出时丢弃最旧的任务。
	MaxSize int
	// PersistPath 是队列持久化文件路径；空串表示不持久化。
	PersistPath string
	// Logger 用于记录重试成功/丢弃日志；nil 时回退到 slog.Default。
	Logger *slog.Logger
	// RetryInterval 是两次重试之间的基础间隔；实际间隔按指数退避叠加抖动。
	RetryInterval time.Duration
	// MaxRetryInterval 是退避上限。
	MaxRetryInterval time.Duration
}

// RetryQueue 把失败的数据库写入放入有界内存队列，由后台协程按指数退避重试。
//
// 队列满时丢弃最旧任务并记日志。可选地把队列内容持久化到 JSON 文件，进程重启后
// 由 LoadPersisted 读回，保证 graceful shutdown 后不丢事件。
type RetryQueue struct {
	cfg RetryQueueConfig
	db  *DB
	log *slog.Logger

	mu    sync.Mutex
	tasks []retryTask

	wake       chan struct{}
	stop       chan struct{}
	done       chan struct{}
	nextID     uint64
	persistSeq uint64
}

// NewRetryQueue 建队列并启动后台重试协程。
//
// 调用方需在进程退出时调用 Stop 以等待后台协程结束并触发最后一次持久化。
func NewRetryQueue(db *DB, cfg RetryQueueConfig) *RetryQueue {
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 1000
	}
	if cfg.RetryInterval <= 0 {
		cfg.RetryInterval = time.Second
	}
	if cfg.MaxRetryInterval <= 0 {
		cfg.MaxRetryInterval = time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	q := &RetryQueue{
		cfg:   cfg,
		db:    db,
		log:   cfg.Logger,
		tasks: make([]retryTask, 0, cfg.MaxSize),
		wake:  make(chan struct{}, 1),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go q.run()
	return q
}

// Enqueue 把一条失败任务放入队列。
//
// 队列满时丢弃最旧任务并记日志。成功入队后触发持久化与后台协程唤醒。
func (q *RetryQueue) Enqueue(task retryTask) {
	if task.EnqueuedAt == 0 {
		task.EnqueuedAt = time.Now().UnixNano()
	}
	q.mu.Lock()
	task.id = q.nextID
	q.nextID++
	if len(q.tasks) >= q.cfg.MaxSize {
		dropped := q.tasks[0]
		q.tasks = q.tasks[1:]
		q.log.Warn("retry queue full, dropping oldest task",
			"op", string(dropped.Op),
			"ip", dropped.IP,
			"enqueued_at", time.Unix(0, dropped.EnqueuedAt).UTC().Format(time.RFC3339),
		)
	}
	q.tasks = append(q.tasks, task)
	q.mu.Unlock()
	q.persist()
	q.notify()
}

// Len 返回当前队列中的任务数（测试用）。
func (q *RetryQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.tasks)
}

// Stop 通知后台协程退出，等待其结束，并执行最后一次持久化与 flush。
func (q *RetryQueue) Stop() {
	close(q.stop)
	<-q.done
	// 最后一次 flush：尝试把队列中剩余的任务写入 DB。
	q.flush(context.Background())
	q.persist()
}

// Flush 导出供组合根在关停时显式调用，把队列中的任务尽力写入 DB。
func (q *RetryQueue) Flush(ctx context.Context) {
	q.flush(ctx)
}

// notify 唤醒后台协程（非阻塞）。
func (q *RetryQueue) notify() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// run 是后台重试协程的主循环。
func (q *RetryQueue) run() {
	defer close(q.done)
	consecutiveFailures := 0
	for {
		backoff := q.backoff(consecutiveFailures)
		select {
		case <-q.stop:
			return
		case <-q.wake:
			// 有新任务入队，立即尝试重试。
		case <-time.After(backoff):
			// 定时重试。
		}
		retried, failed := q.retryBatch()
		if retried > 0 {
			q.log.Info("retry queue batch", "succeeded", retried, "failed", failed)
		}
		if failed > 0 {
			consecutiveFailures++
		} else {
			consecutiveFailures = 0
		}
	}
}

// backoff 按指数退避计算下次重试间隔，叠加 ±25% 抖动。
func (q *RetryQueue) backoff(consecutive int) time.Duration {
	if consecutive == 0 {
		return q.cfg.RetryInterval
	}
	d := q.cfg.RetryInterval
	for i := 0; i < consecutive; i++ {
		// 防溢出：d 接近 MaxInt64/2 时翻倍会溢出成负数
		if d > q.cfg.MaxRetryInterval/2 {
			d = q.cfg.MaxRetryInterval
			break
		}
		d *= 2
		if d > q.cfg.MaxRetryInterval {
			d = q.cfg.MaxRetryInterval
			break
		}
	}
	// ±25% 抖动，避免多个任务同时重试。
	// d/2 保证为正数（d >= RetryInterval > 0），Int63n 不会 panic。
	jitter := time.Duration(rand.Int63n(int64(d/2)+1)) - d/4
	d += jitter
	if d < q.cfg.RetryInterval {
		d = q.cfg.RetryInterval
	}
	return d
}

// retryBatch 尝试执行队列中的所有任务，返回成功与失败计数。
//
// 成功执行的任务从队列中移除；失败的任务保留在队列中等待下次重试。
// 通过递增 id 区分 batch 拷贝期间新入队的任务，避免并发替换导致丢失。
func (q *RetryQueue) retryBatch() (succeeded, failed int) {
	q.mu.Lock()
	if len(q.tasks) == 0 {
		q.mu.Unlock()
		return 0, 0
	}
	// 拷贝一份，避免长时间持锁。
	batch := make([]retryTask, len(q.tasks))
	copy(batch, q.tasks)
	// maxID 是拷贝时刻的 nextID；batch 中所有任务的 id < maxID。
	// 锁释放期间新入队的任务 id >= maxID，重新加锁后据此保留。
	maxID := q.nextID
	q.mu.Unlock()

	var remaining []retryTask
	for _, task := range batch {
		if err := q.execute(task); err != nil {
			remaining = append(remaining, task)
			failed++
			continue
		}
		q.log.Info("retry queue: task succeeded",
			"op", string(task.Op),
			"ip", task.IP,
		)
		succeeded++
	}

	q.mu.Lock()
	// 收集在 batch 拷贝之后新入队的任务（id >= maxID）。
	var newTasks []retryTask
	for i := range q.tasks {
		if q.tasks[i].id >= maxID {
			newTasks = append(newTasks, q.tasks[i])
		}
	}
	q.tasks = append(remaining, newTasks...)
	q.mu.Unlock()
	if succeeded > 0 {
		q.persist()
	}
	return succeeded, failed
}

// execute 执行单条重试任务。
func (q *RetryQueue) execute(task retryTask) error {
	switch task.Op {
	case opBanEvent:
		return q.db.RecordBanEvent(task.IP, task.JailName, task.BanCount, task.IsPermanent, task.DurationSecs)
	case opBanHistory:
		_, err := q.db.RecordBanHistory(task.IP, task.IsPermanent)
		return err
	case opBanReputation:
		return q.db.RecordBan(task.IP, task.Penalty)
	default:
		return fmt.Errorf("unknown retry op: %s", task.Op)
	}
}

// flush 尽力把队列中所有任务写入 DB（关停时调用）。
func (q *RetryQueue) flush(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		retried, failed := q.retryBatch()
		if retried == 0 && failed == 0 {
			return
		}
		if failed > 0 && retried == 0 {
			// DB 仍不可用，停止 flush 避免阻塞关停。
			return
		}
	}
}

// persist 把当前队列写入持久化文件。
//
// 使用原子递增的序号生成唯一临时文件名，避免多协程并发 persist 时互相覆盖。
func (q *RetryQueue) persist() {
	if q.cfg.PersistPath == "" {
		return
	}
	q.mu.Lock()
	tasks := make([]retryTask, len(q.tasks))
	copy(tasks, q.tasks)
	q.mu.Unlock()

	data, err := json.Marshal(tasks)
	if err != nil {
		q.log.Error("retry queue: marshal for persist", "error", err)
		return
	}
	seq := atomic.AddUint64(&q.persistSeq, 1)
	tmp := fmt.Sprintf("%s.tmp.%d", q.cfg.PersistPath, seq)
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		q.log.Error("retry queue: write persist file", "error", err)
		return
	}
	if err := os.Rename(tmp, q.cfg.PersistPath); err != nil {
		q.log.Error("retry queue: rename persist file", "error", err)
		_ = os.Remove(tmp)
	}
}

// LoadPersisted 从持久化文件加载待重试任务并入队。
//
// 启动时调用一次；文件不存在或为空时静默返回。
func (q *RetryQueue) LoadPersisted() {
	if q.cfg.PersistPath == "" {
		return
	}
	data, err := os.ReadFile(q.cfg.PersistPath)
	if err != nil {
		if !os.IsNotExist(err) {
			q.log.Error("retry queue: read persist file", "error", err)
		}
		return
	}
	if len(data) == 0 {
		return
	}
	var tasks []retryTask
	if err := json.Unmarshal(data, &tasks); err != nil {
		q.log.Error("retry queue: unmarshal persist file", "error", err)
		return
	}
	if len(tasks) == 0 {
		return
	}
	q.mu.Lock()
	actualCount := 0
	for _, t := range tasks {
		if len(q.tasks) >= q.cfg.MaxSize {
			break
		}
		t.id = q.nextID
		q.nextID++
		q.tasks = append(q.tasks, t)
		actualCount++
	}
	q.mu.Unlock()
	q.log.Info("retry queue: loaded persisted tasks", "count", actualCount)
}

// EnqueueBanEvent 把失败的 RecordBanEvent 放入重试队列。
func (q *RetryQueue) EnqueueBanEvent(ip, jailName string, banCount int, isPermanent bool, durationSecs *int64) {
	q.Enqueue(retryTask{
		Op:           opBanEvent,
		IP:           ip,
		JailName:     jailName,
		BanCount:     banCount,
		IsPermanent:  isPermanent,
		DurationSecs: durationSecs,
	})
}

// EnqueueBanHistory 把失败的 RecordBanHistory 放入重试队列。
func (q *RetryQueue) EnqueueBanHistory(ip string, isPermanent bool) {
	q.Enqueue(retryTask{
		Op:          opBanHistory,
		IP:          ip,
		IsPermanent: isPermanent,
	})
}

// EnqueueBanReputation 把失败的 RecordBan 放入重试队列。
func (q *RetryQueue) EnqueueBanReputation(ip string, penalty int) {
	q.Enqueue(retryTask{
		Op:      opBanReputation,
		IP:      ip,
		Penalty: penalty,
	})
}
