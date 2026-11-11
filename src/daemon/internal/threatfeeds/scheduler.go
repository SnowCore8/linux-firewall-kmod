package threatfeeds

import (
	"context"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// Scheduler 是定时调度器，支持抖动防惊群。
//
// 设计目标：
//   - 定时触发：按配置的间隔定期刷新
//   - 抖动防惊群：添加随机抖动，避免多个实例同时拉取
//   - 优雅停止：支持 context 取消和 Stop 信号，Stop 等到调度循环退出
type Scheduler struct {
	interval time.Duration
	jitter   time.Duration
	stopCh   chan struct{}
	doneCh   chan struct{} // Run 退出（含当前 fn 已返回）时关闭
	once     sync.Once     // 关 stopCh
	doneOnce sync.Once     // 关 doneCh
	started  atomic.Bool   // 是否经 Start 启动过，决定 Stop 是否需要等 doneCh
}

// NewScheduler 创建新的调度器。
//
// interval: 刷新间隔
// jitter: 抖动范围（实际延迟 = interval ± jitter）
func NewScheduler(interval, jitter time.Duration) *Scheduler {
	return &Scheduler{
		interval: interval,
		jitter:   jitter,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// Start 在后台启动 Run，并标记调度器已启动，使 Stop() 能等到 Run 退出。
//
// 直接 go Run(...) 启动的调用方不经过这里：从未启动过的调度器上 Stop() 不能等
// doneCh，否则永远不会有人关闭它。
func (s *Scheduler) Start(ctx context.Context, fn func()) {
	s.started.Store(true)
	go s.Run(ctx, fn)
}

// Run 启动调度循环。
//
// 每次触发时调用 fn()。支持通过 context 或 Stop() 停止。
// 抖动通过每次动态重建 timer 实现，避免与 ticker 双重触发。
// 所有退出路径都会关闭 doneCh；fn 是同步调用的，因此 Run 退出即意味着当前这轮
// fn 已经返回，不会留下在跑的刷新 goroutine。
func (s *Scheduler) Run(ctx context.Context, fn func()) {
	defer s.doneOnce.Do(func() { close(s.doneCh) })

	// 已停止或已取消时不再执行首次触发：否则关停流程里还会再拉一轮情报。
	select {
	case <-s.stopCh:
		return
	case <-ctx.Done():
		return
	default:
	}

	// 首次立即触发
	fn()

	for {
		// 每次循环重建 timer，实现 interval ± jitter 的抖动
		delay := s.calculateJitter()
		if delay <= 0 {
			// interval 非正（构造时未兜底）时不能把 timer 设成非正值：那会立刻
			// 到期并进入连续触发。退到一分钟，避免调度退化成忙循环。
			delay = time.Minute
		}
		timer := time.NewTimer(delay)

		select {
		case <-timer.C:
			// 抖动延迟到期，触发刷新
			fn()
		case <-s.stopCh:
			// 收到停止信号，清理 timer 后退出
			timer.Stop()
			return
		case <-ctx.Done():
			// context 取消，清理 timer 后退出
			timer.Stop()
			return
		}
	}
}

// Stop 停止调度器，等待调度循环退出。
//
// 幂等：重复调用关闭的是同一条 stopCh，doneCh 也只关一次，第二次直接返回。
// 经 Start 启动过的调度器，Stop 返回时 Run 已经退出，当前这轮 fn 也已返回；
// 未经 Start 启动（比如只构造未运行）时不等 doneCh，避免永远阻塞。
// 若 fn 不响应 context 取消，Stop 会等它跑完——调用方负责让 fn 有界。
func (s *Scheduler) Stop() {
	s.once.Do(func() {
		close(s.stopCh)
	})
	if s.started.Load() {
		<-s.doneCh
	}
}

// calculateJitter 计算抖动延迟。
//
// 返回 interval ± jitter 范围内的随机延迟。抖动被压到间隔的一半以内：
// 配置允许 refresh_interval 低至 60s，而管理器固定用 30 分钟抖动，若直接相减
// interval-jitter 为负，timer 会立刻到期，定时刷新退化成连续拉取情报源。
func (s *Scheduler) calculateJitter() time.Duration {
	if s.interval <= 0 {
		return 0
	}
	jitter := s.jitter
	// 抖动不超过 interval/2，保证延迟落在 [interval/2, 3*interval/2]
	if half := s.interval / 2; jitter > half {
		jitter = half
	}
	if jitter <= 0 {
		return s.interval
	}
	// 防止 2*jitter 溢出 int64：jitter 超过 MaxInt64/2 时截断
	if jitter > time.Duration(math.MaxInt64/2) {
		jitter = time.Duration(math.MaxInt64 / 2)
	}
	// 随机范围：[-jitter, +jitter]
	offset := rand.Int63n(int64(2*jitter)) - int64(jitter)
	return s.interval + time.Duration(offset)
}

// Interval 返回配置的刷新间隔。
func (s *Scheduler) Interval() time.Duration {
	return s.interval
}

// Jitter 返回配置的抖动范围。
func (s *Scheduler) Jitter() time.Duration {
	return s.jitter
}
