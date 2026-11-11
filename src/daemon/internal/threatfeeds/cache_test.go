package threatfeeds

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestFeedCache_Merge(t *testing.T) {
	cache := NewFeedCache()

	entries := []FeedEntry{
		{
			IP:         netip.MustParsePrefix("192.168.1.1/32"),
			Source:     "test",
			Category:   "abuse",
			Confidence: 0.8,
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		},
		{
			IP:         netip.MustParsePrefix("10.0.0.0/8"),
			Source:     "test",
			Category:   "scanner",
			Confidence: 0.7,
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		},
	}

	cache.Merge(entries)

	if cache.Size() != 2 {
		t.Errorf("Size() = %d，想要 2", cache.Size())
	}

	stats := cache.Stats()
	if stats.TotalEntries != 2 {
		t.Errorf("TotalEntries = %d，想要 2", stats.TotalEntries)
	}
	if stats.ActiveEntries != 2 {
		t.Errorf("ActiveEntries = %d，想要 2", stats.ActiveEntries)
	}
}

func TestFeedCache_Lookup_Exact(t *testing.T) {
	cache := NewFeedCache()

	entries := []FeedEntry{
		{
			IP:         netip.MustParsePrefix("192.168.1.1/32"),
			Source:     "test",
			Category:   "abuse",
			Confidence: 0.8,
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		},
	}
	cache.Merge(entries)

	// 精确匹配
	ip := netip.MustParseAddr("192.168.1.1")
	entry, ok := cache.Lookup(ip)
	if !ok {
		t.Error("Lookup() 未命中")
	}
	if entry.Source != "test" {
		t.Errorf("Source = %s，想要 test", entry.Source)
	}

	// 未命中
	ip2 := netip.MustParseAddr("192.168.1.2")
	_, ok = cache.Lookup(ip2)
	if ok {
		t.Error("Lookup() 不应命中")
	}
}

func TestFeedCache_Lookup_CIDR(t *testing.T) {
	cache := NewFeedCache()

	entries := []FeedEntry{
		{
			IP:         netip.MustParsePrefix("192.168.1.0/24"),
			Source:     "test",
			Category:   "abuse",
			Confidence: 0.8,
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		},
	}
	cache.Merge(entries)

	// CIDR 匹配
	ip := netip.MustParseAddr("192.168.1.100")
	entry, ok := cache.Lookup(ip)
	if !ok {
		t.Error("Lookup() 未命中 CIDR")
	}
	if entry.Source != "test" {
		t.Errorf("Source = %s，想要 test", entry.Source)
	}

	// CIDR 外
	ip2 := netip.MustParseAddr("192.168.2.1")
	_, ok = cache.Lookup(ip2)
	if ok {
		t.Error("Lookup() 不应命中 CIDR 外地址")
	}
}

func TestFeedCache_Lookup_ExactUsesExactIndex(t *testing.T) {
	// 全长条目必须走精确索引：查询一次就记一次 ExactHits，而不是退化到网段遍历
	// （旧实现把 prefix.String() 当键，永远匹配不上 ip.String()）。
	cache := NewFeedCache()
	entries := []FeedEntry{
		{
			IP:         netip.MustParsePrefix("192.168.1.1/32"),
			Source:     "exact",
			Category:   "abuse",
			Confidence: 0.8,
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		},
		{
			IP:         netip.MustParsePrefix("10.0.0.0/8"),
			Source:     "cidr",
			Category:   "abuse",
			Confidence: 0.8,
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		},
	}
	cache.Merge(entries)

	if _, ok := cache.Lookup(netip.MustParseAddr("192.168.1.1")); !ok {
		t.Fatal("精确条目应命中")
	}
	if _, ok := cache.Lookup(netip.MustParseAddr("10.1.2.3")); !ok {
		t.Fatal("网段条目应命中")
	}

	stats := cache.Stats()
	if stats.ExactHits != 1 {
		t.Errorf("ExactHits = %d，想要 1", stats.ExactHits)
	}
	if stats.CIDRHits != 1 {
		t.Errorf("CIDRHits = %d，想要 1", stats.CIDRHits)
	}
}

func TestFeedCache_Expired(t *testing.T) {
	cache := NewFeedCache()

	entries := []FeedEntry{
		{
			IP:         netip.MustParsePrefix("192.168.1.1/32"),
			Source:     "test",
			Category:   "abuse",
			Confidence: 0.8,
			ExpiresAt:  time.Now().Add(-1 * time.Hour), // 已过期
		},
	}
	cache.Merge(entries)

	// 过期条目不应命中
	ip := netip.MustParseAddr("192.168.1.1")
	_, ok := cache.Lookup(ip)
	if ok {
		t.Error("Lookup() 不应命中过期条目")
	}
}

func TestFeedCache_Merge_Overwrite(t *testing.T) {
	cache := NewFeedCache()

	// 第一次合并
	entries1 := []FeedEntry{
		{
			IP:         netip.MustParsePrefix("192.168.1.1/32"),
			Source:     "old",
			Category:   "abuse",
			Confidence: 0.5,
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		},
	}
	cache.Merge(entries1)

	// 第二次合并（覆盖）
	entries2 := []FeedEntry{
		{
			IP:         netip.MustParsePrefix("192.168.1.1/32"),
			Source:     "new",
			Category:   "scanner",
			Confidence: 0.9,
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		},
	}
	cache.Merge(entries2)

	// 验证新数据覆盖旧数据
	ip := netip.MustParseAddr("192.168.1.1")
	entry, ok := cache.Lookup(ip)
	if !ok {
		t.Fatal("Lookup() 未命中")
	}
	if entry.Source != "new" {
		t.Errorf("Source = %s，想要 new", entry.Source)
	}
	if entry.Confidence != 0.9 {
		t.Errorf("Confidence = %f，想要 0.9", entry.Confidence)
	}
}

func TestFeedCache_Clear(t *testing.T) {
	cache := NewFeedCache()

	entries := []FeedEntry{
		{
			IP:         netip.MustParsePrefix("192.168.1.1/32"),
			Source:     "test",
			Category:   "abuse",
			Confidence: 0.8,
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		},
	}
	cache.Merge(entries)

	cache.Clear()

	if cache.Size() != 0 {
		t.Errorf("Clear() 后 Size() = %d，想要 0", cache.Size())
	}
}

func TestFeedCache_Cleanup(t *testing.T) {
	cache := NewFeedCache()

	entries := []FeedEntry{
		{
			IP:         netip.MustParsePrefix("192.168.1.1/32"),
			Source:     "test",
			Category:   "abuse",
			Confidence: 0.8,
			ExpiresAt:  time.Now().Add(-1 * time.Hour), // 已过期
		},
		{
			IP:         netip.MustParsePrefix("192.168.1.2/32"),
			Source:     "test",
			Category:   "abuse",
			Confidence: 0.8,
			ExpiresAt:  time.Now().Add(24 * time.Hour), // 未过期
		},
	}
	cache.Merge(entries)

	cache.Cleanup()

	if cache.Size() != 1 {
		t.Errorf("Cleanup() 后 Size() = %d，想要 1", cache.Size())
	}
}

func TestFeedCache_Concurrent(t *testing.T) {
	cache := NewFeedCache()

	// 并发写入
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			entries := []FeedEntry{
				{
					IP:         netip.MustParsePrefix("192.168.1.1/32"),
					Source:     "test",
					Category:   "abuse",
					Confidence: 0.8,
					ExpiresAt:  time.Now().Add(24 * time.Hour),
				},
			}
			cache.Merge(entries)
		}(i)
	}

	// 并发读取
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := netip.MustParseAddr("192.168.1.1")
			cache.Lookup(ip)
		}()
	}

	wg.Wait()

	// 验证缓存状态一致
	if cache.Size() != 1 {
		t.Errorf("并发操作后 Size() = %d，想要 1", cache.Size())
	}
}

func BenchmarkFeedCache_Lookup_Exact(b *testing.B) {
	cache := NewFeedCache()
	entries := []FeedEntry{
		{
			IP:         netip.MustParsePrefix("192.168.1.1/32"),
			Source:     "test",
			Category:   "abuse",
			Confidence: 0.8,
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		},
	}
	cache.Merge(entries)

	ip := netip.MustParseAddr("192.168.1.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Lookup(ip)
	}
}

func BenchmarkFeedCache_Lookup_CIDR(b *testing.B) {
	cache := NewFeedCache()
	// 添加 1000 个 CIDR 条目
	entries := make([]FeedEntry, 1000)
	for i := 0; i < 1000; i++ {
		entries[i] = FeedEntry{
			IP:         netip.MustParsePrefix("10.0.0.0/8"),
			Source:     "test",
			Category:   "abuse",
			Confidence: 0.8,
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		}
	}
	cache.Merge(entries)

	ip := netip.MustParseAddr("10.1.2.3")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Lookup(ip)
	}
}
