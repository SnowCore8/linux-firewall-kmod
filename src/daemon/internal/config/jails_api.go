package config

import (
	"sync"
)

var (
	activeJails   []Jail
	activeJailsMu sync.RWMutex
	jailStats     = make(map[string]*JailRuntimeStats)
	jailStatsMu   sync.RWMutex
)

type JailRuntimeStats struct {
	LinesParsed    uint64 `json:"lines_parsed"`
	RegexMatches   uint64 `json:"regex_matches"`
	IPsExtracted   uint64 `json:"ips_extracted"`
	FailedAttempts uint64 `json:"failed_attempts"`
	BansTriggered  uint64 `json:"bans_triggered"`
}

// SetActiveJails 发布当前生效的 jail 配置快照。
//
// 存**副本**而不是调用方给的那条切片：写入方（入站执行体）之后还会原地改元素的
// Enabled（Web UI 的启用状态桥接），与读侧的拷贝就是同一块内存上的裸数据竞争；
// 更糟的是读侧会看到「配置里已经变了、但还没重建监视集合」的中间形状。副本让快照一旦
// 发布就不可变，启用状态的变化靠下一次 SetActiveJails 显式推上来。
//
// 只拷到元素这一层：LogFiles/Regexes 在配置编译之后就固定了，没有写入方。
func SetActiveJails(jails []Jail) {
	activeJailsMu.Lock()
	defer activeJailsMu.Unlock()
	copied := make([]Jail, len(jails))
	copy(copied, jails)
	activeJails = copied
}

func GetActiveJails() []Jail {
	activeJailsMu.RLock()
	defer activeJailsMu.RUnlock()
	result := make([]Jail, len(activeJails))
	copy(result, activeJails)
	return result
}

func GetJail(name string) (Jail, bool) {
	activeJailsMu.RLock()
	defer activeJailsMu.RUnlock()
	for _, j := range activeJails {
		if j.Name == name {
			return j, true
		}
	}
	return Jail{}, false
}

func GetJailStats(name string) (*JailRuntimeStats, bool) {
	jailStatsMu.RLock()
	defer jailStatsMu.RUnlock()
	stats, ok := jailStats[name]
	if !ok {
		return nil, false
	}
	return stats, true
}

func UpdateJailStats(name string, parsed, regexes, ips, failures, bans uint64) {
	jailStatsMu.Lock()
	defer jailStatsMu.Unlock()
	if jailStats[name] == nil {
		jailStats[name] = &JailRuntimeStats{}
	}
	stats := jailStats[name]
	stats.LinesParsed += parsed
	stats.RegexMatches += regexes
	stats.IPsExtracted += ips
	stats.FailedAttempts += failures
	stats.BansTriggered += bans
}
