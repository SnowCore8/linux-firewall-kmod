package persist

import (
	"context"
	"encoding/json"
	"errors"
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
	// PersistInterval 是把脏队列合并落盘的节拍；<=0 时取 300ms。
	// 入队只置脏标记，落盘由该节拍合并，避免后端持续失败时每次入队都全量写盘。
	PersistInterval time.Duration
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
	// dirty 表示内存队列相对持久化文件有未落盘的变更；只在 mu 内读写，
	// 使「取快照并清脏」与「入队置脏」在同一把锁上定序，节拍协程因此不会漏写。
	dirty bool
	// stopped 在 Stop 内部置位；Enqueue 读到它说明节拍协程已退出，必须自己落盘。
	// 只在 mu 内读写，保证「Stop 已经取过快照」与「入队是否需要自持久化」不会交错丢失。
	stopped bool

	// persistMu 串行化「取快照 + 落文件」。没有它，两个并发 persist 会各自写临时文件，
	// rename 的先后与快照的新旧无关——旧快照后落盘就会覆盖掉刚入队的任务。
	persistMu sync.Mutex

	wake        chan struct{}
	stop        chan struct{}
	done        chan struct{}
	persistDone chan struct{}
	stopOnce    sync.Once
	nextID      uint64
	persistSeq  uint64

	// wakeCount 是测试用观测点：统计 notify 被调用的次数。
	wakeCount atomic.Uint64
}

// NewRetryQueue 建队列并启动后台重试协程与合并落盘协程。
//
// 调用方需在进程退出时调用 Stop 以等待后台协程结束并触发最后一次强制落盘。
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
	if cfg.PersistInterval <= 0 {
		cfg.PersistInterval = 300 * time.Millisecond
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	q := &RetryQueue{
		cfg:         cfg,
		db:          db,
		log:         cfg.Logger,
		tasks:       make([]retryTask, 0, cfg.MaxSize),
		wake:        make(chan struct{}, 1),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
		persistDone: make(chan struct{}),
	}
	go q.run()
	go q.persistLoop()
	return q
}

// Enqueue 把一条失败任务放入队列。
//
// 只有队列由空转非空才唤醒后台协程：队列非空时后端正在退避，逐条唤醒会把退避清零、
// 让每个入队都触发一次立即重试。落盘同理交给脏标记 + 节拍合并，不在入队路径上写全量快照。
func (q *RetryQueue) Enqueue(task retryTask) {
	if task.EnqueuedAt == 0 {
		task.EnqueuedAt = time.Now().UnixNano()
	}
	q.mu.Lock()
	task.id = q.nextID
	q.nextID++
	wasEmpty := len(q.tasks) == 0
	q.tasks = append(q.tasks, task)
	q.trimLocked()
	q.dirty = true
	stopped := q.stopped
	q.mu.Unlock()

	if wasEmpty {
		q.notify()
	}
	if stopped {
		// 节拍协程已退出，没人会再消费脏标记，这里自己落盘。
		q.persist()
	}
}

// trimLocked 在锁内把队列裁到 MaxSize，丢弃最旧任务并记日志，返回丢弃条数。
//
// 调用方必须持有 q.mu。入队与 retryBatch 重建队列都在同一锁周期内裁剪：批次执行期间
// 入队丢弃的条目只从 q.tasks 里消失，重建时却会从 batch 拷贝中复活，若不在此再裁一次，
// 队列会越过 MaxSize 并不停增长。
func (q *RetryQueue) trimLocked() (dropped int) {
	for len(q.tasks) > q.cfg.MaxSize {
		oldest := q.tasks[0]
		q.tasks = q.tasks[1:]
		q.log.Warn("retry queue full, dropping oldest task",
			"op", string(oldest.Op),
			"ip", oldest.IP,
			"enqueued_at", time.Unix(0, oldest.EnqueuedAt).UTC().Format(time.RFC3339),
		)
		dropped++
	}
	return dropped
}

// Len 返回当前队列中的任务数（测试用）。
func (q *RetryQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.tasks)
}

// Stop 通知后台协程退出，等待其结束，并执行最后一次持久化与 flush。
//
// 可重复调用：关停路径上「显式调用」与「defer 兜底」并存时，第二次调用不能 panic
// （close of closed channel），也不能重复等待一个已结束的协程。
func (q *RetryQueue) Stop() {
	q.stopOnce.Do(func() { close(q.stop) })
	<-q.done
	<-q.persistDone
	// 节拍协程已退出：置 stopped 让后续 Enqueue 自己落盘，再强制落盘一次，
	// 把脏标记里还没写出的任务补上，保证关停不丢数据。
	q.mu.Lock()
	q.stopped = true
	q.mu.Unlock()
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
	q.wakeCount.Add(1)
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
			// 队列由空转非空，立即尝试一次。
		case <-time.After(backoff):
			// 定时重试。
		}
		retried, failed := q.retryBatch()
		if retried > 0 {
			q.log.Info("retry queue batch", "succeeded", retried, "failed", failed)
		}
		if failed > 0 {
			consecutiveFailures++
			continue
		}
		if consecutiveFailures > 0 {
			// 退避归零：失败期间入队的任务一直没被唤醒，补一次立即重试，
			// 否则它们要白等一个已经不需要的长退避。
			q.notify()
		}
		consecutiveFailures = 0
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
	dropped := 0
	for _, task := range batch {
		if err := q.execute(task); err != nil {
			if errors.Is(err, errRetryTaskPermanent) {
				// 未知 op 永远不可能成功：丢弃并记一条错误日志，不让它拖住整条队列。
				q.log.Error("retry queue: dropping task that can never succeed",
					"op", string(task.Op),
					"ip", task.IP,
					"error", err,
				)
				dropped++
				continue
			}
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
	// 收集在 batch 拷贝之后新入队的任务（id >= maxID）。更早的条目要么在 remaining 里，
	// 要么已被成功消费。
	rebuilt := remaining
	for i := range q.tasks {
		if q.tasks[i].id >= maxID {
			rebuilt = append(rebuilt, q.tasks[i])
		}
	}
	q.tasks = rebuilt
	// 批次期间入队触发的丢弃只削掉了 q.tasks 的头部，重建会把它从 batch 里带回来；
	// 在同一锁周期内再裁一次，容量上限始终成立。
	trimmed := q.trimLocked()
	q.mu.Unlock()
	if succeeded > 0 || dropped > 0 || trimmed > 0 {
		q.persist()
	}
	return succeeded, failed
}

// errRetryTaskPermanent 标记「重试多少次都不可能成功」的任务（如持久化文件里来自其他
// 版本的未知 op）。这类任务不能按普通失败计入退避，否则它会永久占住队列并让所有任务
// 的重试频率一路降到上限。
var errRetryTaskPermanent = errors.New("retry task can never succeed")

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
		return fmt.Errorf("%w: %s", errRetryTaskPermanent, task.Op)
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
		q.mu.Lock()
		before := len(q.tasks)
		q.mu.Unlock()
		retried, failed := q.retryBatch()
		if retried == 0 && failed == 0 {
			return
		}
		if failed > 0 && retried == 0 {
			// DB 仍不可用，停止 flush 避免阻塞关停。
			return
		}
		q.mu.Lock()
		after := len(q.tasks)
		q.mu.Unlock()
		if after >= before {
			// 队列未缩短说明有任务持续失败（如畸形数据），继续循环无意义，停止。
			return
		}
	}
}

// persist 强制把当前队列写入持久化文件。
//
// 快照与写入都在 persistMu 内完成，落盘顺序因此与快照顺序一致，最后一次写入必然是
// 最新快照。临时文件名仍用递增序号，避免极端情况下与残留文件重名。
// 快照与清脏在同一把 mu 内完成：此后入队的任务会重新置脏，不会被这次写盘吞掉。
func (q *RetryQueue) persist() {
	if q.cfg.PersistPath == "" {
		return
	}
	q.persistMu.Lock()
	defer q.persistMu.Unlock()

	q.mu.Lock()
	tasks := make([]retryTask, len(q.tasks))
	copy(tasks, q.tasks)
	q.dirty = false
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
		_ = os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, q.cfg.PersistPath); err != nil {
		q.log.Error("retry queue: rename persist file", "error", err)
		_ = os.Remove(tmp)
	}
}

// persistIfDirty 仅在队列有未落盘变更时写盘，供节拍协程调用。
func (q *RetryQueue) persistIfDirty() {
	q.mu.Lock()
	dirty := q.dirty
	q.mu.Unlock()
	if dirty {
		q.persist()
	}
}

// persistLoop 按 PersistInterval 节拍把脏队列合并落盘。
//
// 与 run 分离：run 的 select 每轮都会重算退避定时器，把落盘节拍塞进去会被重试唤醒打乱。
func (q *RetryQueue) persistLoop() {
	defer close(q.persistDone)
	if q.cfg.PersistPath == "" {
		return
	}
	ticker := time.NewTicker(q.cfg.PersistInterval)
	defer ticker.Stop()
	for {
		select {
		case <-q.stop:
			return
		case <-ticker.C:
			q.persistIfDirty()
		}
	}
}

// LoadPersisted 从持久化文件加载待重试任务并入队。
//
// 启动时调用一次；文件不存在或为空时静默返回。文件里的任务超过 MaxSize 时按容量截断，
// 并记一条 Warn 说明丢弃条数。
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
	if truncated := len(tasks) - actualCount; truncated > 0 {
		// 容量由 MaxSize 决定，这里不改容量，只把被丢弃的条数说清楚。
		q.log.Warn("retry queue: persisted tasks exceed capacity, dropping remainder",
			"dropped", truncated,
			"max_size", q.cfg.MaxSize,
		)
	}
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
