package bans

import "sync"

// ActiveBanCache 是活跃封禁的内存权威存储。
//
// 旧实现用两个独立锁分别保护「IP → 封禁信息」主表与「jail → IP 集合」反向索引，
// 写入时要同时更新两张表，两者之间的短暂不一致对外可见。这里用单锁把两张表绑成
// 一次原子更新：读方永不会看到「主表有、反向索引没有」的中间态。
type ActiveBanCache struct {
	mu     sync.RWMutex
	bans   map[string]BanInfo
	byJail map[string]map[string]struct{}
}

// NewActiveBanCache 新建空缓存。
func NewActiveBanCache() *ActiveBanCache {
	return &ActiveBanCache{
		bans:   make(map[string]BanInfo),
		byJail: make(map[string]map[string]struct{}),
	}
}

// TryInsert 原子地插入主表与反向索引，返回「本调用是否为赢家」。
//
// 与旧实现 `try_insert` 语义一致：同一 IP 已存在则返回 false（并发去重、防止重复
// 封禁与统计双计）。主表与反向索引在同一次加锁内更新，读方不会看到中间态。
func (c *ActiveBanCache) TryInsert(info BanInfo) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.bans[info.IP]; exists {
		return false
	}
	c.bans[info.IP] = info
	set := c.byJail[info.JailName]
	if set == nil {
		set = make(map[string]struct{})
		c.byJail[info.JailName] = set
	}
	set[info.IP] = struct{}{}
	return true
}

// Remove 从两张表里同时摘除一个 IP，返回是否确实存在。
func (c *ActiveBanCache) Remove(ip string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	info, ok := c.bans[ip]
	if !ok {
		return false
	}
	delete(c.bans, ip)
	if set := c.byJail[info.JailName]; set != nil {
		delete(set, ip)
		if len(set) == 0 {
			delete(c.byJail, info.JailName)
		}
	}
	return true
}

// Get 按 IP 取封禁信息。
func (c *ActiveBanCache) Get(ip string) (BanInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	info, ok := c.bans[ip]
	return info, ok
}

// Len 返回当前活跃封禁数。
func (c *ActiveBanCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.bans)
}

// All 返回全部封禁信息的副本。
func (c *ActiveBanCache) All() []BanInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]BanInfo, 0, len(c.bans))
	for _, info := range c.bans {
		out = append(out, info)
	}
	return out
}

// List 返回全部封禁信息的副本（All 的别名）。
func (c *ActiveBanCache) List() []BanInfo {
	return c.All()
}

// UnbanTemporary 解封所有非永久封禁，返回解封数量。
func (c *ActiveBanCache) UnbanTemporary() int {
	ips := c.UnbanTemporaryWithIPs()
	return len(ips)
}

// UnbanTemporaryWithIPs 解封所有非永久封禁，返回被解封的 IP 列表。
func (c *ActiveBanCache) UnbanTemporaryWithIPs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var ips []string
	for ip, info := range c.bans {
		if !info.IsPermanent {
			delete(c.bans, ip)
			if set := c.byJail[info.JailName]; set != nil {
				delete(set, ip)
				if len(set) == 0 {
					delete(c.byJail, info.JailName)
				}
			}
			ips = append(ips, ip)
		}
	}
	return ips
}

// Stats 返回缓存统计信息。
func (c *ActiveBanCache) Stats() map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	permanent := 0
	temporary := 0
	for _, info := range c.bans {
		if info.IsPermanent {
			permanent++
		} else {
			temporary++
		}
	}
	return map[string]any{
		"total":     len(c.bans),
		"permanent": permanent,
		"temporary": temporary,
	}
}
