package bans

import (
	"net/netip"
	"sync"
)

var (
	globalCache     *ActiveBanCache
	globalWhitelist *Whitelist
	globalOnce      sync.Once
)

func initGlobals() {
	globalCache = NewActiveBanCache()
	globalWhitelist = NewWhitelist()
}

func GlobalCache() *ActiveBanCache {
	globalOnce.Do(initGlobals)
	return globalCache
}

func GlobalWhitelist() *Whitelist {
	globalOnce.Do(initGlobals)
	return globalWhitelist
}

type Whitelist struct {
	mu      sync.RWMutex
	entries map[string]netip.Prefix
}

func NewWhitelist() *Whitelist {
	return &Whitelist{
		entries: make(map[string]netip.Prefix),
	}
}

func (w *Whitelist) Add(prefix netip.Prefix) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	key := prefix.String()
	if _, exists := w.entries[key]; exists {
		return false
	}
	w.entries[key] = prefix
	return true
}

func (w *Whitelist) Remove(prefix netip.Prefix) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	key := prefix.String()
	if _, exists := w.entries[key]; !exists {
		return false
	}
	delete(w.entries, key)
	return true
}

func (w *Whitelist) List() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	result := make([]string, 0, len(w.entries))
	for key := range w.entries {
		result = append(result, key)
	}
	return result
}

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

func (w *Whitelist) Stats() map[string]any {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return map[string]any{
		"count": len(w.entries),
	}
}
