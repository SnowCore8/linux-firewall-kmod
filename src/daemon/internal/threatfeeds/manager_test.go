package threatfeeds

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestNewFeedManager_Disabled(t *testing.T) {
	cfg := Config{Enabled: false}
	mgr, err := NewFeedManager(cfg)
	if err != nil {
		t.Fatalf("NewFeedManager() 错误 = %v", err)
	}
	if mgr != nil {
		t.Error("禁用时应该返回 nil")
	}
}

// TestNewFeedManager_UnknownSource 核对「启用的源全是未知源」时仍返回错误，
// 让配置问题在启动日志里显性化，而不是静默跑一个没有任何源的管理器。
func TestNewFeedManager_UnknownSource(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		RefreshInterval: 24 * time.Hour,
		HTTPTimeout:     30 * time.Second,
		MaxRetries:      3,
		Sources: []SourceConfig{
			{
				Name:    "unknown_source",
				URL:     "https://example.com",
				Enabled: true,
			},
		},
	}
	_, err := NewFeedManager(cfg)
	if err == nil {
		t.Error("未知源应该返回错误")
	}
}

// TestNewFeedManager_SkipsUnknownSource 核对一个源名写错只跳过该源：
// 其余已知源照常装配，不会因拼写错误让整个子系统下线（三个接口全 503）。
func TestNewFeedManager_SkipsUnknownSource(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		RefreshInterval: 24 * time.Hour,
		HTTPTimeout:     30 * time.Second,
		MaxRetries:      3,
		Sources: []SourceConfig{
			{Name: "unknown_source", URL: "https://example.com", Enabled: true},
			{Name: "ipsum", URL: "https://example.com/ipsum.txt", Enabled: true},
		},
	}
	mgr, err := NewFeedManager(cfg)
	if err != nil {
		t.Fatalf("NewFeedManager() 错误 = %v", err)
	}
	if mgr == nil {
		t.Fatal("存在可用源时不应返回 nil 管理器")
	}
	defer mgr.Stop()

	if got := mgr.SourceCount(); got != 1 {
		t.Errorf("SourceCount() = %d，想要 1（只装配已知源）", got)
	}
	stats := mgr.Stats()
	if len(stats) != 1 || stats[0].Name != "ipsum" {
		t.Errorf("Stats() = %+v，想要只含 ipsum", stats)
	}
}

func TestFeedManager_Lookup(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		RefreshInterval: 24 * time.Hour,
		HTTPTimeout:     30 * time.Second,
		MaxRetries:      3,
		Sources:         []SourceConfig{}, // 无源
	}
	mgr, err := NewFeedManager(cfg)
	if err != nil {
		t.Fatalf("NewFeedManager() 错误 = %v", err)
	}
	defer mgr.Stop()

	// 手动添加测试数据
	entries := []FeedEntry{
		{
			IP:         netip.MustParsePrefix("192.168.1.1/32"),
			Source:     "test",
			Category:   "abuse",
			Confidence: 0.8,
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		},
	}
	mgr.cache.Merge(entries)

	// 查询存在的 IP
	ip := netip.MustParseAddr("192.168.1.1")
	entry, ok := mgr.Lookup(ip)
	if !ok {
		t.Error("Lookup() 未命中")
	}
	if entry.Source != "test" {
		t.Errorf("Source = %s，想要 test", entry.Source)
	}

	// 查询不存在的 IP
	ip2 := netip.MustParseAddr("10.0.0.1")
	_, ok = mgr.Lookup(ip2)
	if ok {
		t.Error("Lookup() 不应命中")
	}
}

func TestFeedManager_Stats(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		RefreshInterval: 24 * time.Hour,
		HTTPTimeout:     30 * time.Second,
		MaxRetries:      3,
		Sources: []SourceConfig{
			{Name: "ipsum", URL: "https://example.com", Enabled: true},
			{Name: "firehol", URL: "https://example.com", Enabled: true},
		},
	}
	mgr, err := NewFeedManager(cfg)
	if err != nil {
		t.Fatalf("NewFeedManager() 错误 = %v", err)
	}
	defer mgr.Stop()

	stats := mgr.Stats()
	if len(stats) != 2 {
		t.Errorf("Stats() 返回 %d 个源，想要 2", len(stats))
	}

	for _, s := range stats {
		if !s.Enabled {
			t.Errorf("源 %s 的 Enabled = false，想要 true", s.Name)
		}
	}
}

func TestFeedManager_SourceCount(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		RefreshInterval: 24 * time.Hour,
		HTTPTimeout:     30 * time.Second,
		MaxRetries:      3,
		Sources: []SourceConfig{
			{Name: "ipsum", URL: "https://example.com", Enabled: true},
			{Name: "firehol", URL: "https://example.com", Enabled: false}, // 禁用
			{Name: "dshield", URL: "https://example.com", Enabled: true},
		},
	}
	mgr, err := NewFeedManager(cfg)
	if err != nil {
		t.Fatalf("NewFeedManager() 错误 = %v", err)
	}
	defer mgr.Stop()

	// 只有 2 个启用的源
	if got := mgr.SourceCount(); got != 2 {
		t.Errorf("SourceCount() = %d，想要 2", got)
	}
}

func TestFeedManager_CacheStats(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		RefreshInterval: 24 * time.Hour,
		HTTPTimeout:     30 * time.Second,
		MaxRetries:      3,
		Sources:         []SourceConfig{},
	}
	mgr, err := NewFeedManager(cfg)
	if err != nil {
		t.Fatalf("NewFeedManager() 错误 = %v", err)
	}
	defer mgr.Stop()

	// 添加测试数据
	entries := []FeedEntry{
		{
			IP:         netip.MustParsePrefix("192.168.1.1/32"),
			Source:     "test",
			Category:   "abuse",
			Confidence: 0.8,
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		},
	}
	mgr.cache.Merge(entries)

	stats := mgr.CacheStats()
	if stats.TotalEntries != 1 {
		t.Errorf("TotalEntries = %d，想要 1", stats.TotalEntries)
	}
	if stats.ActiveEntries != 1 {
		t.Errorf("ActiveEntries = %d，想要 1", stats.ActiveEntries)
	}
}

func TestFeedManager_RefreshAll_Empty(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		RefreshInterval: 24 * time.Hour,
		HTTPTimeout:     30 * time.Second,
		MaxRetries:      3,
		Sources:         []SourceConfig{}, // 无源
	}
	mgr, err := NewFeedManager(cfg)
	if err != nil {
		t.Fatalf("NewFeedManager() 错误 = %v", err)
	}
	defer mgr.Stop()

	ctx := context.Background()
	err = mgr.RefreshAll(ctx)
	if err != nil {
		t.Errorf("RefreshAll() 错误 = %v", err)
	}
}

func TestFeedManager_LastUpdate(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		RefreshInterval: 24 * time.Hour,
		HTTPTimeout:     30 * time.Second,
		MaxRetries:      3,
		Sources:         []SourceConfig{},
	}
	mgr, err := NewFeedManager(cfg)
	if err != nil {
		t.Fatalf("NewFeedManager() 错误 = %v", err)
	}
	defer mgr.Stop()

	// 初始时 LastUpdate 为零值
	if !mgr.LastUpdate().IsZero() {
		t.Error("初始 LastUpdate() 应该为零值")
	}
}

func TestFeedManager_Stop(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		RefreshInterval: 24 * time.Hour,
		HTTPTimeout:     30 * time.Second,
		MaxRetries:      3,
		Sources:         []SourceConfig{},
	}
	mgr, err := NewFeedManager(cfg)
	if err != nil {
		t.Fatalf("NewFeedManager() 错误 = %v", err)
	}

	// 启动调度器
	mgr.StartScheduler()

	// 停止应该不 panic
	mgr.Stop()

	// 多次停止应该安全
	mgr.Stop()
}

// roundTripFunc 让测试不触网就能给 HTTPClient 返回预置响应。
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestRefreshAll_EmptyParseCountsAsFailure 核对「HTTP 200 但解析 0 条」按失败处理：
// 累计连续失败并最终熔断，且不刷新源的 LastUpdate 与管理器的 lastUpdate。
// 若当成功，会清零失败计数、解除熔断、刷新同步时间，面板显示同步成功 0 条而源已失效。
func TestRefreshAll_EmptyParseCountsAsFailure(t *testing.T) {
	// mockSource 未设 parseFn 时 Parse 返回 (nil, nil)，等价于「响应体解析不出条目」；
	// URL 取白名单域名，请求由下面的假 Transport 应答，不出网。
	src := &mockSource{name: "empty-src", url: "https://lists.blocklist.de/lists/all.txt"}
	mgr := newTestManager(t, 3, 1*time.Hour, src)
	defer mgr.Stop()
	mgr.http = &HTTPClient{
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("# 只有注释，没有任何条目\n")),
			}, nil
		})},
	}

	for i := 1; i <= 3; i++ {
		if err := mgr.RefreshAll(context.Background()); err == nil {
			t.Fatalf("第 %d 轮 0 条目刷新应返回错误", i)
		}

		mgr.mu.RLock()
		stats := mgr.stats["empty-src"]
		failures := stats.ConsecutiveFailures
		lastUpdate := stats.LastUpdate
		statsErr := stats.Error
		mgr.mu.RUnlock()

		if failures != i {
			t.Fatalf("第 %d 轮后 ConsecutiveFailures = %d，想要 %d", i, failures, i)
		}
		if statsErr == nil {
			t.Errorf("第 %d 轮后 Error 应非空", i)
		}
		if !lastUpdate.IsZero() {
			t.Errorf("第 %d 轮后源 LastUpdate 不应刷新，得到 %v", i, lastUpdate)
		}
		if !mgr.LastUpdate().IsZero() {
			t.Errorf("第 %d 轮后管理器 LastUpdate 不应刷新，得到 %v", i, mgr.LastUpdate())
		}
	}

	mgr.mu.RLock()
	broken := !mgr.stats["empty-src"].CircuitBrokenUntil.IsZero()
	mgr.mu.RUnlock()
	if !broken {
		t.Error("连续 3 轮 0 条目后应触发熔断")
	}
}
