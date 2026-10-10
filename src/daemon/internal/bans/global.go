package bans

import (
	"net/netip"
	"sync"
)

// 本文件是进程级镜像单例：活跃封禁表与白名单镜像。
//
// 之所以允许全局：内核侧的封禁/白名单本身就是进程级事实，读侧（HTTP handler、判定链路、
// 事件泵）分散在多个 goroutine，逐个传递一份引用只会让组合根多出一串装配参数而没有任何
// 额外约束。所有权仍在组合根——单例只在这份文件里建立一次，测试可以另建实例而不必碰全局。
var (
	globalCache     *ActiveBanCache
	globalWhitelist *Whitelist
	globalOnce      sync.Once
)

func initGlobals() {
	globalCache = NewActiveBanCache()
	globalWhitelist = NewWhitelist()
}

// GlobalCache 返回活跃封禁镜像。
func GlobalCache() *ActiveBanCache {
	globalOnce.Do(initGlobals)
	return globalCache
}

// GlobalWhitelist 返回白名单镜像。
func GlobalWhitelist() *Whitelist {
	globalOnce.Do(initGlobals)
	return globalWhitelist
}

// Whitelist 是白名单的内存镜像，键是**已归一化**的 CIDR 文本。
//
// 归一化只有一处（key 函数）：网络地址（主机位清零）+ 恒带 /prefix。这条规则必须与内核
// 一致（`fw_addr_normalize`），否则同一个子网会有两个键——LIST 回来的已归一键打不中本地
// 按裸输入建的键，表现为「白名单里看到两条同一个网段」或「删了还在」。
type Whitelist struct {
	mu      sync.RWMutex
	entries map[string]netip.Prefix
}

// NewWhitelist 新建空白名单镜像。
func NewWhitelist() *Whitelist {
	return &Whitelist{
		entries: make(map[string]netip.Prefix),
	}
}

// whitelistKey 将前缀归一为键：主机位清零后取文本形式。
//
// 裸地址（无 /prefix）在构造 Prefix 时即按 /32·/128 处理，因此键恒带前缀长度，
// 与内核 LIST 的输出形状一致。
func whitelistKey(prefix netip.Prefix) string {
	if !prefix.IsValid() {
		return prefix.String()
	}
	return prefix.Masked().String()
}

// Add 加入一个前缀；已存在（归一后同键）时返回 false。
//
// 存的是掩码后的前缀而不是原始输入：键已归一，值若带主机位，Contains 与键就不是同一个
// 网段的两种表述了——读侧（列表、命中判断）必须与键同源。
func (w *Whitelist) Add(prefix netip.Prefix) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	key := whitelistKey(prefix)
	if _, exists := w.entries[key]; exists {
		return false
	}
	w.entries[key] = prefix.Masked()
	return true
}

// Remove 按归一后的键移除；不存在时返回 false。
func (w *Whitelist) Remove(prefix netip.Prefix) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	key := whitelistKey(prefix)
	if _, exists := w.entries[key]; !exists {
		return false
	}
	delete(w.entries, key)
	return true
}

// Contains 报告地址是否落在任一已记录的前缀内。
func (w *Whitelist) Contains(addr netip.Addr) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, prefix := range w.entries {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// List 返回全部键（归一后的 CIDR 文本）。
func (w *Whitelist) List() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	result := make([]string, 0, len(w.entries))
	for key := range w.entries {
		result = append(result, key)
	}
	return result
}

// Stats 返回镜像统计信息。
func (w *Whitelist) Stats() map[string]any {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return map[string]any{
		"count": len(w.entries),
	}
}
