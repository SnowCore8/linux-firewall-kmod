package runtime

import (
	"sync"
	"testing"
	"time"
)

// TestSupervisorShutdownIsReverseOfRegistration 验证关停按登记逆序进行。
func TestSupervisorShutdownIsReverseOfRegistration(t *testing.T) {
	sup := NewSupervisor()
	var (
		mu    sync.Mutex
		order []string
	)
	for _, name := range []string{"A", "B", "C"} {
		token := NewShutdown()
		n := name
		sup.Spawn(n, token, func() {
			for !token.IsShutdown() {
				time.Sleep(time.Millisecond)
			}
			mu.Lock()
			order = append(order, n)
			mu.Unlock()
		})
	}

	results := sup.Shutdown(2 * time.Second)

	if len(results) != 3 {
		t.Fatalf("期望 3 个关停结果，实际 %d", len(results))
	}
	got := []string{results[0].Name, results[1].Name, results[2].Name}
	want := []string{"C", "B", "A"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("关停顺序 = %v，期望 %v", got, want)
		}
	}
	for _, r := range results {
		if r.Outcome != Joined {
			t.Fatalf("%s 应正常退出，实际 %v", r.Name, r.Outcome)
		}
	}
	// 逐段串行 ⇒ 退出顺序严格为 C、B、A。
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 3 || order[0] != "C" || order[1] != "B" || order[2] != "A" {
		t.Fatalf("实际退出顺序 = %v，期望 [C B A]", order)
	}
}

// TestSupervisorUpstreamStopsBeforeDownstream 验证下游停止时上游已完全停止。
func TestSupervisorUpstreamStopsBeforeDownstream(t *testing.T) {
	sup := NewSupervisor()
	downstreamToken := NewShutdown()
	upstreamToken := NewShutdown()

	var (
		mu              sync.Mutex
		upstreamStopped bool
		downstreamSawUp bool
	)

	// 下游：先登记 → 最后停，停止时应观察到上游已停。
	sup.Spawn("downstream", downstreamToken, func() {
		for !downstreamToken.IsShutdown() {
			time.Sleep(time.Millisecond)
		}
		mu.Lock()
		downstreamSawUp = upstreamStopped
		mu.Unlock()
	})
	// 上游：后登记 → 最先停，停止时置标志。
	sup.Spawn("upstream", upstreamToken, func() {
		for !upstreamToken.IsShutdown() {
			time.Sleep(time.Millisecond)
		}
		mu.Lock()
		upstreamStopped = true
		mu.Unlock()
	})

	sup.Shutdown(2 * time.Second)

	mu.Lock()
	defer mu.Unlock()
	if !downstreamSawUp {
		t.Fatal("下游停止时上游必须已完全停止")
	}
}

// TestSupervisorReportsTimeoutForStuckExecutor 验证卡死执行体超时返回。
func TestSupervisorReportsTimeoutForStuckExecutor(t *testing.T) {
	sup := NewSupervisor()
	block := make(chan struct{})
	defer close(block)
	// 不监视关停令牌的执行体：模拟卡死。
	sup.Spawn("stuck", NewShutdown(), func() { <-block })

	start := time.Now()
	results := sup.Shutdown(50 * time.Millisecond)
	if len(results) != 1 {
		t.Fatalf("期望 1 个结果，实际 %d", len(results))
	}
	if results[0].Outcome != TimedOut {
		t.Fatalf("期望 TimedOut，实际 %v", results[0].Outcome)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("超时应快速返回，实际 %v", elapsed)
	}
}

// TestSupervisorShutdownSharesOneDeadline 验证关停链共用一个截止时间。
//
// 每段各等一个 timeout 时，总时长随执行体数量叠加：两个卡死执行体会各耗满一个
// timeout。共用截止时间后，第二个只在截止时间前等剩余预算，到点后直接标 TimedOut。
func TestSupervisorShutdownSharesOneDeadline(t *testing.T) {
	sup := NewSupervisor()
	block := make(chan struct{})
	defer close(block)
	// 两个都不监视关停令牌：都走超时路径。
	sup.Spawn("stuck-a", NewShutdown(), func() { <-block })
	sup.Spawn("stuck-b", NewShutdown(), func() { <-block })

	start := time.Now()
	results := sup.Shutdown(80 * time.Millisecond)
	elapsed := time.Since(start)

	if len(results) != 2 {
		t.Fatalf("期望 2 个结果，实际 %d", len(results))
	}
	for _, r := range results {
		if r.Outcome != TimedOut {
			t.Fatalf("%s 应报告 TimedOut，实际 %v", r.Name, r.Outcome)
		}
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("两段各等一个 timeout：总耗时 %v", elapsed)
	}
}

// TestSupervisorEmptyShutsDownCleanly 验证空登记表关停无副作用。
func TestSupervisorEmptyShutsDownCleanly(t *testing.T) {
	sup := NewSupervisor()
	if !sup.IsEmpty() || sup.Len() != 0 {
		t.Fatal("新建登记表应为空")
	}
	results := sup.Shutdown(10 * time.Millisecond)
	if len(results) != 0 {
		t.Fatalf("空登记表关停应无结果，实际 %d", len(results))
	}
}
