package threatfeeds

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// mockSource 实现 FeedSource 接口，用于测试。
type mockSource struct {
	name    string
	url     string
	parseFn func(data []byte) ([]FeedEntry, error)
}

func (s *mockSource) Name() string { return s.name }
func (s *mockSource) URL() string  { return s.url }
func (s *mockSource) Parse(data []byte) ([]FeedEntry, error) {
	if s.parseFn != nil {
		return s.parseFn(data)
	}
	return nil, nil
}

// newTestManager 创建一个使用 mockSource 的测试管理器。
func newTestManager(t *testing.T, threshold int, cooldown time.Duration, sources ...FeedSource) *FeedManager {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	mgr := &FeedManager{
		cfg: Config{
			Enabled:          true,
			FailureThreshold: threshold,
			CooldownDuration: cooldown,
		},
		cache:     NewFeedCache(),
		http:      NewHTTPClient(30*time.Second, 0),
		stats:     make(map[string]*SourceStats),
		ctx:       ctx,
		cancel:    cancel,
		scheduler: NewScheduler(24*time.Hour, 0),
	}
	for _, src := range sources {
		mgr.sources = append(mgr.sources, src)
		mgr.stats[src.Name()] = &SourceStats{
			Name:    src.Name(),
			Enabled: true,
		}
	}
	return mgr
}

// TestCircuitBreaker_TripsAfterThreshold 验收标准 1：
// 模拟某源连续失败 3 次 → 第 4 次调用 RefreshAll 时该源不被调用。
func TestCircuitBreaker_TripsAfterThreshold(t *testing.T) {
	callCount := 0
	src := &mockSource{name: "test-src", url: "https://example.com"}

	mgr := newTestManager(t, 3, 1*time.Hour, src)
	defer mgr.Stop()

	// 模拟 3 次连续失败
	for i := 0; i < 3; i++ {
		mgr.updateSourceStats(RefreshResult{
			Source: "test-src",
			Err:    errors.New("模拟失败"),
		})
	}

	// 验证熔断器已触发
	mgr.mu.RLock()
	stats := mgr.stats["test-src"]
	if stats.ConsecutiveFailures != 3 {
		t.Errorf("ConsecutiveFailures = %d，想要 3", stats.ConsecutiveFailures)
	}
	if stats.CircuitBrokenUntil.IsZero() {
		t.Error("CircuitBrokenUntil 应该非零（熔断已触发）")
	}
	if !mgr.isCircuitBroken("test-src") {
		t.Error("isCircuitBroken() 应该返回 true")
	}
	mgr.mu.RUnlock()

	// 验证 RefreshAll 会跳过该源（通过检查 callCount 不变）
	// 由于 refreshOne 会实际调用 http.Fetch，我们只验证 isCircuitBroken 逻辑
	_ = callCount
}

// TestCircuitBreaker_RecoverAfterCooldown 验收标准 2：
// 冷却期过后 → 下一次 RefreshAll 恢复调用该源。
func TestCircuitBreaker_RecoverAfterCooldown(t *testing.T) {
	src := &mockSource{name: "test-src", url: "https://example.com"}

	// 使用极短冷却期便于测试
	mgr := newTestManager(t, 2, 50*time.Millisecond, src)
	defer mgr.Stop()

	// 模拟 2 次连续失败触发熔断
	for i := 0; i < 2; i++ {
		mgr.updateSourceStats(RefreshResult{
			Source: "test-src",
			Err:    errors.New("模拟失败"),
		})
	}

	mgr.mu.RLock()
	if !mgr.isCircuitBroken("test-src") {
		t.Error("应该处于熔断状态")
	}
	mgr.mu.RUnlock()

	// 等待冷却期结束
	time.Sleep(100 * time.Millisecond)

	mgr.mu.RLock()
	if mgr.isCircuitBroken("test-src") {
		t.Error("冷却期过后 isCircuitBroken() 应该返回 false")
	}
	mgr.mu.RUnlock()
}

// TestCircuitBreaker_SuccessResetsCounter 验收标准 3：
// 成功刷新一次 → ConsecutiveFailures 归零。
func TestCircuitBreaker_SuccessResetsCounter(t *testing.T) {
	src := &mockSource{name: "test-src", url: "https://example.com"}
	mgr := newTestManager(t, 3, 1*time.Hour, src)
	defer mgr.Stop()

	// 先累积 2 次失败
	for i := 0; i < 2; i++ {
		mgr.updateSourceStats(RefreshResult{
			Source: "test-src",
			Err:    errors.New("模拟失败"),
		})
	}

	mgr.mu.RLock()
	if mgr.stats["test-src"].ConsecutiveFailures != 2 {
		t.Errorf("ConsecutiveFailures = %d，想要 2", mgr.stats["test-src"].ConsecutiveFailures)
	}
	mgr.mu.RUnlock()

	// 一次成功
	mgr.updateSourceStats(RefreshResult{
		Source:   "test-src",
		Entries:  []FeedEntry{{IP: netip.MustParsePrefix("1.2.3.4/32"), Source: "test-src"}},
		Duration: time.Millisecond,
	})

	mgr.mu.RLock()
	stats := mgr.stats["test-src"]
	if stats.ConsecutiveFailures != 0 {
		t.Errorf("成功后 ConsecutiveFailures = %d，想要 0", stats.ConsecutiveFailures)
	}
	if !stats.CircuitBrokenUntil.IsZero() {
		t.Error("成功后 CircuitBrokenUntil 应该为零值")
	}
	mgr.mu.RUnlock()
}

// TestCircuitBreaker_SkipsRefreshAll 端到端验证：
// 熔断的源在 RefreshAll 中被跳过。
func TestCircuitBreaker_SkipsRefreshAll(t *testing.T) {
	src := &mockSource{name: "test-src", url: "https://example.com"}
	mgr := newTestManager(t, 1, 1*time.Hour, src)
	defer mgr.Stop()

	// 触发熔断（阈值=1，一次失败即熔断）
	mgr.updateSourceStats(RefreshResult{
		Source: "test-src",
		Err:    errors.New("模拟失败"),
	})

	mgr.mu.RLock()
	if !mgr.isCircuitBroken("test-src") {
		t.Error("应该处于熔断状态")
	}
	mgr.mu.RUnlock()

	// RefreshAll 应该跳过该源（不会 panic 或卡住）
	ctx := context.Background()
	_ = mgr.RefreshAll(ctx)

	// 验证 RefreshCount 没有增加（因为被跳过了）
	mgr.mu.RLock()
	if mgr.stats["test-src"].RefreshCount != 1 {
		t.Errorf("RefreshCount = %d，想要 1（只有手动 updateSourceStats 那一次）",
			mgr.stats["test-src"].RefreshCount)
	}
	mgr.mu.RUnlock()
}

// TestCircuitBreaker_CanRetripAfterCooldown 验证熔断器可重复触发：
// 冷却期过后，如果源继续失败，熔断器应能再次触发。
func TestCircuitBreaker_CanRetripAfterCooldown(t *testing.T) {
	src := &mockSource{name: "test-src", url: "https://example.com"}
	mgr := newTestManager(t, 2, 50*time.Millisecond, src)
	defer mgr.Stop()

	// 第一次触发熔断
	for i := 0; i < 2; i++ {
		mgr.updateSourceStats(RefreshResult{
			Source: "test-src",
			Err:    errors.New("模拟失败"),
		})
	}

	mgr.mu.RLock()
	firstTripped := !mgr.stats["test-src"].CircuitBrokenUntil.IsZero()
	mgr.mu.RUnlock()
	if !firstTripped {
		t.Fatal("第一次熔断应该触发")
	}

	// 等待冷却期结束
	time.Sleep(100 * time.Millisecond)

	// RefreshAll 会重置已过期的熔断状态
	_ = mgr.RefreshAll(context.Background())

	// 再次累积失败，应该能重新触发熔断
	for i := 0; i < 2; i++ {
		mgr.updateSourceStats(RefreshResult{
			Source: "test-src",
			Err:    errors.New("模拟失败"),
		})
	}

	mgr.mu.RLock()
	stats := mgr.stats["test-src"]
	canRetrip := !stats.CircuitBrokenUntil.IsZero() && stats.ConsecutiveFailures >= 2
	mgr.mu.RUnlock()

	if !canRetrip {
		t.Errorf("冷却期过后熔断器应能重新触发：CircuitBrokenUntil=%v, ConsecutiveFailures=%d",
			stats.CircuitBrokenUntil, stats.ConsecutiveFailures)
	}
}
