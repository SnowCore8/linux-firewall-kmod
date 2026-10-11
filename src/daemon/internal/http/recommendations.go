package http

import (
	"net/http"
	"net/netip"
	"sort"
	"strconv"
)

// WhitelistRecommendation 是一条白名单推荐（契约同名 type 块，字段即线上 key）。
//
// 旧版字段名按 Go 的读法写（ban_count / unique_ips），与契约的 total_bans / affected_ips
// 不一致，跨层字段核对因此对不上；这里按契约改名，不再保留两套说法。
type WhitelistRecommendation struct {
	// RecType 是推荐的类型。本实现只把频繁被封的**网段**聚合成条目（IPv4 /24、IPv6 /48），
	// 因此恒为 "subnet"；单地址加白没有推荐路径，不产 "ip"。
	RecType string `json:"rec_type"`
	CIDR    string `json:"cidr"`
	Reason  string `json:"reason"`
	// AffectedIPs 是该网段里被封禁过的**唯一地址数**，TotalBans 是这些地址的累计封禁次数。
	// 两个数分开才有信息量：一个 /24 被封 40 次可能是 1 台机器抽风，也可能是 20 台正常
	// 用户被误伤——只有次数看不出该不该整段加白。
	AffectedIPs uint32 `json:"affected_ips"`
	TotalBans   uint32 `json:"total_bans"`
	// Confidence 是证据强度（u8 百分数）。
	//
	// 只按样本量分档（≥50→90、≥20→70、≥10→50、其余 30），与
	// analysis.RecommendThresholds 的置信度阶梯同一套刻度：两个面板说的都是
	// 「这条建议底下垫了多少件事」，各用一套刻度就会让「70」在两处含义不同。
	Confidence uint8 `json:"confidence"`
}

// GetWhitelistRecommendations 基于封禁历史推荐白名单。
//
// 分析 ban_history 表，找出频繁临时封禁的 IP/子网，按 /24（IPv4）或 /48（IPv6）
// 聚合后排序返回。频繁被封禁的网段可能是误伤的正常用户集中区域。
//
// 载荷按契约是**数组本身**（不是 {recommendations, total, min_bans} 那个信封）：
// 条数由 limit 决定、阈值由查询参数决定，读侧不需要服务端再报一遍。
//
// 查询参数：
//   - min_bans: 最小封禁次数阈值（默认 5）
//   - limit: 返回条数上限（默认 20，最大 100）
func (h *APIHandlers) GetWhitelistRecommendations(w http.ResponseWriter, r *http.Request) {
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
			RecType:     "subnet",
			CIDR:        cidr,
			AffectedIPs: uint32(len(stats.ips)),
			TotalBans:   uint32(stats.banCount),
			Reason:      "频繁临时封禁，可能为误伤网段",
			Confidence:  whitelistConfidence(stats.banCount),
		})
	}

	sort.Slice(recommendations, func(i, j int) bool {
		if recommendations[i].TotalBans != recommendations[j].TotalBans {
			return recommendations[i].TotalBans > recommendations[j].TotalBans
		}
		// 次数相同按 CIDR 文本升序：map 的遍历顺序随机，不写这条 tie-break
		// 同一条推荐两次刷新会换个位置，面板上的列表会无故跳动。
		return recommendations[i].CIDR < recommendations[j].CIDR
	})

	if len(recommendations) > limit {
		recommendations = recommendations[:limit]
	}

	if recommendations == nil {
		// 契约是数组：没有推荐时给 []，不给 null——前端对载荷直接 .map()，null 会让整页崩。
		recommendations = []WhitelistRecommendation{}
	}
	WriteSuccess(w, recommendations)
}

// whitelistConfidence 把封禁次数折成 u8 的证据强度。
func whitelistConfidence(banCount int) uint8 {
	switch {
	case banCount >= 50:
		return 90
	case banCount >= 20:
		return 70
	case banCount >= 10:
		return 50
	default:
		return 30
	}
}
