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

func SetActiveJails(jails []Jail) {
	activeJailsMu.Lock()
	defer activeJailsMu.Unlock()
	activeJails = jails
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
