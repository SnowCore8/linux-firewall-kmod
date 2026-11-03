package threatfeeds

import (
	"context"
	"net/netip"
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
