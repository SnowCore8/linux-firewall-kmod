package threatfeeds

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestScheduler_Run(t *testing.T) {
	scheduler := NewScheduler(100*time.Millisecond, 0)

	var count atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()

	go scheduler.Run(ctx, func() {
		count.Add(1)
	})

	<-ctx.Done()
	scheduler.Stop()

	// 应该触发至少 3 次（0ms, 100ms, 200ms, 300ms）
	if got := count.Load(); got < 3 {
		t.Errorf("触发次数 = %d，想要 >= 3", got)
	}
}

func TestScheduler_Stop(t *testing.T) {
	scheduler := NewScheduler(100*time.Millisecond, 0)

	var count atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())

	go scheduler.Run(ctx, func() {
		count.Add(1)
	})

	// 等待几次触发
	time.Sleep(250 * time.Millisecond)
	scheduler.Stop()
	cancel()

	// 记录停止时的计数
	stoppedCount := count.Load()

	// 等待一段时间，确认不再触发
	time.Sleep(200 * time.Millisecond)

	if got := count.Load(); got != stoppedCount {
		t.Errorf("Stop() 后仍触发：停止时 = %d，之后 = %d", stoppedCount, got)
	}
}

func TestScheduler_Jitter(t *testing.T) {
	scheduler := NewScheduler(100*time.Millisecond, 50*time.Millisecond)

	// 测试抖动计算
	jitter := scheduler.calculateJitter()
	minJitter := 50 * time.Millisecond
	maxJitter := 150 * time.Millisecond

	if jitter < minJitter || jitter > maxJitter {
		t.Errorf("calculateJitter() = %v，想要在 [%v, %v] 范围内", jitter, minJitter, maxJitter)
	}
}

func TestScheduler_Interval(t *testing.T) {
	scheduler := NewScheduler(24*time.Hour, 30*time.Minute)

	if got := scheduler.Interval(); got != 24*time.Hour {
		t.Errorf("Interval() = %v，想要 24h", got)
	}

	if got := scheduler.Jitter(); got != 30*time.Minute {
		t.Errorf("Jitter() = %v，想要 30m", got)
	}
}

func TestScheduler_ContextCancel(t *testing.T) {
	scheduler := NewScheduler(1*time.Hour, 0) // 长间隔

	var count atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())

	go scheduler.Run(ctx, func() {
		count.Add(1)
	})

	// 等待首次触发
	time.Sleep(50 * time.Millisecond)
	cancel()

	// 等待 goroutine 退出
	time.Sleep(50 * time.Millisecond)

	// 应该只触发 1 次（首次立即触发）
	if got := count.Load(); got != 1 {
		t.Errorf("Context 取消后触发次数 = %d，想要 1", got)
	}
}

func BenchmarkScheduler_calculateJitter(b *testing.B) {
	scheduler := NewScheduler(24*time.Hour, 30*time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scheduler.calculateJitter()
	}
}
