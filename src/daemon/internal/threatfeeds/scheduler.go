package threatfeeds

import (
	"context"
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
func (s *Scheduler) Run(ctx context.Context, fn func()) {
	// 首次立即触发
	fn()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		// 计算抖动延迟
		delay := s.calculateJitter()

		select {
		case <-time.After(delay):
			// 抖动延迟到期，触发刷新
			fn()
		case <-ticker.C:
			// 定时间隔到期，触发刷新
			fn()
		case <-s.stopCh:
			// 收到停止信号
			return
		case <-ctx.Done():
			// context 取消
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
// 返回 interval ± jitter 范围内的随机延迟。
func (s *Scheduler) calculateJitter() time.Duration {
	if s.jitter == 0 {
		return s.interval
	}
	// 随机范围：[-jitter, +jitter]
	offset := rand.Int63n(int64(2*s.jitter)) - int64(s.jitter)
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
