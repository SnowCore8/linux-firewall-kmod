package threatfeeds

import (
	"context"
	"math"
	"math/rand"
	"sync"
	"time"
)

// Scheduler 是定时调度器，支持抖动防惊群。
//
// 设计目标：
//   - 定时触发：按配置的间隔定期刷新
//   - 抖动防惊群：添加随机抖动，避免多个实例同时拉取
//   - 优雅停止：支持 context 取消和 Stop 信号
type Scheduler struct {
	interval time.Duration
	jitter   time.Duration
	stopCh   chan struct{}
	once     sync.Once
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
	}
}

// Run 启动调度循环。
//
// 每次触发时调用 fn()。支持通过 context 或 Stop() 停止。
// 抖动通过每次动态重建 timer 实现，避免与 ticker 双重触发。
func (s *Scheduler) Run(ctx context.Context, fn func()) {
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

// Stop 停止调度器。
func (s *Scheduler) Stop() {
	s.once.Do(func() {
		close(s.stopCh)
	})
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
