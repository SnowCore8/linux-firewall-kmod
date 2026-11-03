package threatfeeds

import (
	"net/netip"
	"sync"
	"time"
)

// FeedCache 是情报缓存，支持并发安全的读写。
//
// 设计目标：
//   - 原子更新：Merge 时构建新 map，避免长时间持有写锁
//   - 精确匹配 + CIDR 匹配：先查精确 IP，再遍历 CIDR
//   - 过期清理：Lookup 时跳过已过期条目
type FeedCache struct {
	mu      sync.RWMutex
	entries map[string]*FeedEntry // key: IP.String() 或 CIDR.String()
	stats   CacheStats
}

// CacheStats 是缓存统计信息。
type CacheStats struct {
	// TotalEntries 是总条目数（包括已过期）。
	TotalEntries int
	// ActiveEntries 是有效条目数（未过期）。
	ActiveEntries int
	// ExactHits 是精确匹配命中次数。
	ExactHits uint64
	// CIDRHits 是 CIDR 匹配命中次数。
	CIDRHits uint64
	// Misses 是未命中次数。
	Misses uint64
	// LastUpdate 是上次更新时间。
	LastUpdate time.Time
}

// NewFeedCache 创建新的缓存。
func NewFeedCache() *FeedCache {
	return &FeedCache{
		entries: make(map[string]*FeedEntry),
	}
}

// Merge 合并新条目到缓存。
//
// 原子更新：构建新 map 后一次性替换，避免长时间持有写锁。
// 已存在的条目会被新条目覆盖（新数据优先）。
func (c *FeedCache) Merge(newEntries []FeedEntry) {
	if len(newEntries) == 0 {
		return
	}

	// 构建新 map
	merged := make(map[string]*FeedEntry)

	// 复制未过期的旧条目
	c.mu.RLock()
	now := time.Now()
	for k, v := range c.entries {
		if now.Before(v.ExpiresAt) {
			merged[k] = v
		}
	}
	c.mu.RUnlock()

	// 添加新条目
	for i := range newEntries {
		e := &newEntries[i]
		key := e.IP.String()
		merged[key] = e
	}

	// 原子替换
	c.mu.Lock()
	c.entries = merged
	c.stats.TotalEntries = len(merged)
	c.stats.LastUpdate = time.Now()
	c.mu.Unlock()

	// 更新有效条目数
	c.updateActiveCount()
}

// Lookup 查询 IP 是否在缓存中。
//
// 先精确匹配，再 CIDR 匹配。跳过已过期条目。
func (c *FeedCache) Lookup(ip netip.Addr) (*FeedEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()

	// 精确匹配
	key := ip.String()
	if e, ok := c.entries[key]; ok {
		if now.Before(e.ExpiresAt) {
			c.stats.ExactHits++
			return e, true
		}
	}

	// CIDR 匹配
	for _, e := range c.entries {
		if now.After(e.ExpiresAt) {
			continue
		}
		if e.IP.Contains(ip) {
			c.stats.CIDRHits++
			return e, true
		}
	}

	c.stats.Misses++
	return nil, false
}

// Stats 返回缓存统计信息。
func (c *FeedCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	c.updateActiveCountLocked()
	return c.stats
}

// Clear 清空缓存。
func (c *FeedCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*FeedEntry)
	c.stats = CacheStats{}
}

// updateActiveCount 更新有效条目数（带锁版本）。
func (c *FeedCache) updateActiveCount() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.updateActiveCountLocked()
}

// updateActiveCountLocked 更新有效条目数（假设已持有锁）。
func (c *FeedCache) updateActiveCountLocked() {
	now := time.Now()
	count := 0
	for _, e := range c.entries {
		if now.Before(e.ExpiresAt) {
			count++
		}
	}
	c.stats.ActiveEntries = count
}

// Cleanup 清理已过期条目。
func (c *FeedCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for k, e := range c.entries {
		if now.After(e.ExpiresAt) {
			delete(c.entries, k)
		}
	}
	c.stats.TotalEntries = len(c.entries)
	c.updateActiveCountLocked()
}

// Size 返回缓存总条目数（包括已过期）。
func (c *FeedCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
