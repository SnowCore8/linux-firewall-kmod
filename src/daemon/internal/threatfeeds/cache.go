package threatfeeds

import (
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// MaxCacheEntries 是缓存条目上限，防止恶意/错误配置的源导致内存耗尽。
// 100 万条约 100-200 MB，覆盖已知大型情报源（如 IPsum 聚合多源）。
const MaxCacheEntries = 1_000_000

// FeedCache 是情报缓存，支持并发安全的读写。
//
// 设计目标：
//   - 原子更新：Merge 时构建新 map，避免长时间持有写锁
//   - 精确匹配 + CIDR 匹配：精确条目按地址直查；网段按前缀长度分桶，
//     查询时只对「实际出现过的长度」各做一次 map 查找，不遍历全部条目
//   - 过期清理：Lookup 时跳过已过期条目
type FeedCache struct {
	mu      sync.RWMutex
	entries map[string]*FeedEntry // key: 全长条目用地址，网段条目用掩码后的 prefix
	// cidr 按前缀长度分桶，桶键是掩码后的网段字符串。分桶的原因：判定层每行日志都
	// 查一次缓存，网段条目有数千条，逐条 Contains 会让热路径变成 O(条目数)。
	cidr     map[uint8]map[string]*FeedEntry
	cidrLens []uint8
	stats    CacheStats
	// 命中/未命中计数器用 atomic，避免在读锁下修改 stats 导致数据竞争
	exactHits atomic.Uint64
	cidrHits  atomic.Uint64
	misses    atomic.Uint64
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
	c := &FeedCache{
		entries: make(map[string]*FeedEntry),
		cidr:    make(map[uint8]map[string]*FeedEntry),
	}
	return c
}

// canonicalPrefix 把 IPv4-mapped IPv6 前缀归一成 IPv4 前缀，其余原样返回。
//
// 情报源偶尔用 `::ffff:a.b.c.d` 写 IPv4。Lookup 会把查询地址 Unmap 成 IPv4，
// 若不在这里归一，这类条目的键是 v6 形态、前缀桶长度是 120 以上，永远不会命中。
func canonicalPrefix(p netip.Prefix) netip.Prefix {
	p = p.Masked()
	addr := p.Addr()
	if !addr.Is4In6() {
		return p
	}
	bits := p.Bits() - 96
	if bits < 0 {
		bits = 0
	}
	return netip.PrefixFrom(addr.Unmap(), bits)
}

// entryKey 返回条目在缓存里的规范键：全长条目用裸地址，网段用掩码后的 prefix。
//
// 全长条目必须落到裸地址键上，否则 Lookup 的 `ip.String()` 永远对不上
// `prefix.String()`（带 `/32`），精确快路径会退化成全表遍历。
func entryKey(p netip.Prefix) (key string, isCIDR bool, bits uint8) {
	p = canonicalPrefix(p)
	addr := p.Addr()
	if (addr.Is4() && p.Bits() == 32) || (addr.Is6() && p.Bits() == 128) {
		return addr.String(), false, 0
	}
	return p.String(), true, uint8(p.Bits())
}

// rebuildIndexLocked 按 entries 重建网段索引；调用方必须持有写锁。
func (c *FeedCache) rebuildIndexLocked() {
	cidr := make(map[uint8]map[string]*FeedEntry)
	for key, e := range c.entries {
		if _, isCIDR, bits := entryKey(e.IP); isCIDR {
			if cidr[bits] == nil {
				cidr[bits] = make(map[string]*FeedEntry)
			}
			cidr[bits][key] = e
		}
	}
	lens := make([]uint8, 0, len(cidr))
	for bits := range cidr {
		lens = append(lens, bits)
	}
	sort.Slice(lens, func(i, j int) bool { return lens[i] < lens[j] })
	c.cidr = cidr
	c.cidrLens = lens
}

// Merge 合并新条目到缓存。
//
// 原子更新：构建新 map 后一次性替换，避免长时间持有写锁。
// 已存在的条目会被新条目覆盖（新数据优先）。
func (c *FeedCache) Merge(newEntries []FeedEntry) {
	if len(newEntries) == 0 {
		return
	}

	// 构建新 map —— 全程持有写锁，避免 RUnlock→Lock 间隙导致并发 Merge 丢失更新
	c.mu.Lock()
	now := time.Now()
	merged := make(map[string]*FeedEntry)

	// 复制未过期的旧条目
	for k, v := range c.entries {
		if now.Before(v.ExpiresAt) {
			merged[k] = v
		}
	}

	// 添加新条目（受上限保护）
	for i := range newEntries {
		if len(merged) >= MaxCacheEntries {
			break
		}
		e := &newEntries[i]
		key, _, _ := entryKey(e.IP)
		merged[key] = e
	}

	// 替换并更新统计
	c.entries = merged
	c.rebuildIndexLocked()
	c.stats.TotalEntries = len(merged)
	c.stats.LastUpdate = time.Now()
	c.mu.Unlock()

	// 更新有效条目数
	c.updateActiveCount()
}

// Lookup 查询 IP 是否在缓存中。
//
// 先查精确索引，再按出现过的前缀长度逐桶查网段（桶数即前缀种类数，通常个位数）。
// 跳过已过期条目。
func (c *FeedCache) Lookup(ip netip.Addr) (*FeedEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	ip = ip.Unmap()

	// 精确匹配
	if e, ok := c.entries[ip.String()]; ok {
		if now.Before(e.ExpiresAt) {
			c.exactHits.Add(1)
			return e, true
		}
	}

	// CIDR 匹配：按前缀长度分桶，每桶一次 map 查找
	for _, bits := range c.cidrLens {
		p := netip.PrefixFrom(ip, int(bits))
		if !p.IsValid() {
			// 前缀长度超出该地址族（v4 地址遇到 >32 的桶）时跳过。
			continue
		}
		if e, ok := c.cidr[bits][p.Masked().String()]; ok {
			if now.Before(e.ExpiresAt) {
				c.cidrHits.Add(1)
				return e, true
			}
		}
	}

	c.misses.Add(1)
	return nil, false
}

// Stats 返回缓存统计信息。
func (c *FeedCache) Stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.updateActiveCountLocked()
	// 从 atomic 计数器读取，避免与 Lookup 的数据竞争
	c.stats.ExactHits = c.exactHits.Load()
	c.stats.CIDRHits = c.cidrHits.Load()
	c.stats.Misses = c.misses.Load()
	return c.stats
}

// Clear 清空缓存。
func (c *FeedCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*FeedEntry)
	c.cidr = make(map[uint8]map[string]*FeedEntry)
	c.cidrLens = nil
	c.stats = CacheStats{}
	c.exactHits.Store(0)
	c.cidrHits.Store(0)
	c.misses.Store(0)
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
	removed := false
	for k, e := range c.entries {
		if now.After(e.ExpiresAt) {
			delete(c.entries, k)
			removed = true
		}
	}
	if removed {
		c.rebuildIndexLocked()
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
