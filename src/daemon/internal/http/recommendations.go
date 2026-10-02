package http

import (
	"net/http"
	"net/netip"
	"sort"
	"strconv"
)

// WhitelistRecommendation 是一条白名单推荐。
type WhitelistRecommendation struct {
	CIDR      string `json:"cidr"`
	BanCount  int    `json:"ban_count"`
	UniqueIPs int    `json:"unique_ips"`
	Reason    string `json:"reason"`
}

// GetWhitelistRecommendations 基于封禁历史推荐白名单。
//
// 分析 ban_history 表，找出频繁临时封禁的 IP/子网，按 /24（IPv4）或 /48（IPv6）
// 聚合后排序返回。频繁被封禁的网段可能是误伤的正常用户集中区域。
//
// 查询参数：
//   - min_bans: 最小封禁次数阈值（默认 5）
//   - limit: 返回条数上限（默认 20，最大 100）
func (h *APIHandlers) GetWhitelistRecommendations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}

	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}

	minBans := 5
	if mb := r.URL.Query().Get("min_bans"); mb != "" {
		if n, err := strconv.Atoi(mb); err == nil && n > 0 {
			minBans = n
		}
	}
	limit := parseLimit(r, 20, 100)

	histories, err := h.db.GetFrequentBans(minBans, 10000)
	if err != nil {
		h.server.logger.Error("查询封禁历史失败", "error", err)
		WriteInternalError(w, "查询封禁历史失败")
		return
	}

	// 按子网聚合
	type subnetStats struct {
		banCount int
		ips      map[string]bool
	}
	subnets := make(map[string]*subnetStats)

	for _, h := range histories {
		addr, err := netip.ParseAddr(h.IP)
		if err != nil {
			continue
		}
		// 聚合前缀：IPv4 /24, IPv6 /48
		prefixLen := 24
		if addr.Is6() {
			prefixLen = 48
		}
		prefix := netip.PrefixFrom(addr, prefixLen).Masked()
		key := prefix.String()

		if subnets[key] == nil {
			subnets[key] = &subnetStats{ips: make(map[string]bool)}
		}
		subnets[key].banCount += h.BanCount
		subnets[key].ips[h.IP] = true
	}

	// 过滤并排序
	var recommendations []WhitelistRecommendation
	for cidr, stats := range subnets {
		if stats.banCount < minBans {
			continue
		}
		recommendations = append(recommendations, WhitelistRecommendation{
			CIDR:      cidr,
			BanCount:  stats.banCount,
			UniqueIPs: len(stats.ips),
			Reason:    "频繁临时封禁，可能为误伤网段",
		})
	}

	sort.Slice(recommendations, func(i, j int) bool {
		return recommendations[i].BanCount > recommendations[j].BanCount
	})

	if len(recommendations) > limit {
		recommendations = recommendations[:limit]
	}

	WriteSuccess(w, map[string]any{
		"recommendations": recommendations,
		"total":           len(recommendations),
		"min_bans":        minBans,
	})
}
