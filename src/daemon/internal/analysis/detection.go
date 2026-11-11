package analysis

import (
	"math"
	"sort"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

// PeriodicAttackFinding 是一个地址的「等间隔复现」读数。
//
// 名字刻意与契约的载荷类型 `PeriodicAttacker` 不同：这里是**计算结果**，字段按分析层
// 自己的口径命名（regularity/jitter/event_count），载荷字段名由 internal/http 的具名
// struct 承载。两层同名会让契约门禁的「按类型名找 struct」撞上错误的那一个（它按文件
// 顺序取第一个命中），字段核对就变成看运气。
type PeriodicAttackFinding struct {
	IP       string `json:"ip"`
	JailName string `json:"jail_name"`
	// Regularity 是规则度 0-100：变异系数 <0.3 时取 (1-cv)×100，否则记 0。
	//
	// 给 0 而不是给一个低分是**有意的**：cv≥0.3 意味着间隔本身没有可外推的周期，
	// 一个「35 分」会被读成「有点周期」，而这里想说的是「没有」。
	Regularity  float64 `json:"regularity_score"`
	AvgInterval float64 `json:"avg_interval_seconds"`
	// Jitter 是变异系数（stddev/avg），不是标准差本身；载荷要的两项都有。
	Jitter float64 `json:"jitter_rate"`
	StdDev float64 `json:"stddev_seconds"`
	// EventCount 参与计算的时刻数，Timestamps 是那些时刻（升序，Unix 秒）。
	//
	// 带上原始时刻：面板要画「第 n 次封禁落在哪一天」，只给均值就把证据抹成了结论。
	EventCount int     `json:"event_count"`
	Timestamps []int64 `json:"timestamps"`
}

func DetectPeriodicAttackers(db *persist.DB, minEvents int, limit int, eventLimit int) ([]PeriodicAttackFinding, error) {
	if minEvents < 3 {
		minEvents = 3
	}
	if limit <= 0 {
		limit = 20
	}
	// eventLimit 保留在签名里供既有调用方使用；间隔统计已按地址在 SQL 内聚合，
	// 不再需要用它截断事件行数。
	_ = eventLimit

	ipStats, err := db.GetIPBanIntervalStats()
	if err != nil {
		return nil, err
	}

	var attackers []PeriodicAttackFinding
	for _, stats := range ipStats {
		if stats.EventCount < minEvents {
			continue
		}

		avg := stats.AvgInterval
		if avg <= 0 {
			// 全部事件落在同一秒（同一 IP 被多个 jail 同时封禁等），间隔恒为 0。
			// 这不是「完美等间隔」：零均值下变异系数无定义，继续算会把重复数据
			// 报成最规律的攻击者，并挤掉真正的周期目标。
			continue
		}

		cv := stats.StdDev / avg

		regularity := 0.0
		if cv < 0.3 {
			regularity = (1 - cv) * 100
		}

		attackers = append(attackers, PeriodicAttackFinding{
			IP:          stats.IP,
			JailName:    stats.JailName,
			Regularity:  regularity,
			AvgInterval: avg,
			Jitter:      cv,
			StdDev:      stats.StdDev,
			EventCount:  stats.EventCount,
		})
	}

	// 规则度相同（尤其满分）是常态，只按它排序会让 limit 截断结果随 map 遍历顺序变化。
	sort.Slice(attackers, func(i, j int) bool {
		if attackers[i].Regularity != attackers[j].Regularity {
			return attackers[i].Regularity > attackers[j].Regularity
		}
		if attackers[i].EventCount != attackers[j].EventCount {
			return attackers[i].EventCount > attackers[j].EventCount
		}
		return attackers[i].IP < attackers[j].IP
	})

	if len(attackers) > limit {
		attackers = attackers[:limit]
	}

	// 原始时刻只为最终入选的地址取回：载荷要的是证据，先把候选缩到 limit 条，
	// 避免为整张表搬明细。
	ips := make([]string, 0, len(attackers))
	for _, a := range attackers {
		ips = append(ips, a.IP)
	}
	timestamps, err := db.BanTimestampsByIPs(ips)
	if err != nil {
		return nil, err
	}
	for i := range attackers {
		// 交副本而不是内部切片：调用方（含未来的缓存）排序或截断它不能改到本层的账。
		attackers[i].Timestamps = append([]int64(nil), timestamps[attackers[i].IP]...)
	}

	return attackers, nil
}

// CollaborativeAttackFinding 是一个 jail 在一个时间窗内的多源联动读数。
//
// 命名理由同 PeriodicAttackFinding：计算结果的字段名不属于契约，载荷形状由
// internal/http 的具名 struct 承载。
type CollaborativeAttackFinding struct {
	JailName    string `json:"jail_name"`
	WindowStart int64  `json:"window_start"`
	WindowEnd   int64  `json:"window_end"`
	// IPs 是**落在本窗口内**的来源地址（升序，最多 MaxWindowIPs 个）。
	//
	// 旧实现带出的是「这个 jail 历史上所有地址」——窗口只用来判定有没有联动，参与者
	// 列表却与窗口无关，等于在载荷里宣称「这些 IP 同时动手」而实际拿不出对应关系。
	IPs []string `json:"ips"`
	// UniqueIPs 是窗口内的唯一地址数：IPs 可能被截断，读侧要靠它才知道截掉了多少。
	UniqueIPs int     `json:"unique_ips"`
	BanCount  int     `json:"ban_count"`
	Score     float64 `json:"collaboration_score"`
}

// MaxWindowIPs 是一条协同读数带出的地址数上限（面板只画前若干项，全量靠 UniqueIPs 报数）。
const MaxWindowIPs = 10

func DetectCollaborativeAttacks(db *persist.DB, windowSeconds int, minIPs int, limit int, eventLimit int) ([]CollaborativeAttackFinding, error) {
	if windowSeconds <= 0 {
		windowSeconds = 300
	}
	if minIPs < 2 {
		minIPs = 3
	}
	if limit <= 0 {
		limit = 20
	}
	// eventLimit 保留在签名里供既有调用方使用；滑窗改为按 (jail, 时间) 排序流式扫描，
	// 内存上界是「一个窗口内的事件数」，不再需要按行数截断输入。
	_ = eventLimit

	type candidateWindow struct {
		start   int64
		end     int64
		records []persist.JailBanRecord
	}

	var attacks []CollaborativeAttackFinding
	var (
		curJail   string
		window    []persist.JailBanRecord
		ipCounts  map[string]int
		candidate *candidateWindow
		found     bool
	)

	resetJail := func(jail string) {
		curJail = jail
		window = nil
		ipCounts = make(map[string]int)
		candidate = nil
		found = false
	}

	finalizeCandidate := func() {
		if candidate == nil {
			return
		}
		seen := make(map[string]bool, len(candidate.records))
		for _, r := range candidate.records {
			seen[r.IP] = true
		}
		ips := make([]string, 0, len(seen))
		for ip := range seen {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		count := len(candidate.records)
		attacks = append(attacks, CollaborativeAttackFinding{
			JailName:    curJail,
			WindowStart: candidate.start,
			WindowEnd:   candidate.end,
			IPs:         ips[:min(len(ips), MaxWindowIPs)],
			UniqueIPs:   len(seen),
			BanCount:    count,
			// 强度按窗口内的封禁事件数线性放大，10 次封顶 100：保持旧口径不变，
			// 换判据（改按地址数）会让面板上同一根柱子的含义前后对不上。
			Score: math.Min(100, float64(count)/10*100),
		})
		candidate = nil
		found = true
	}

	err := db.StreamJailBans(func(r persist.JailBanRecord) error {
		if r.JailName != curJail {
			finalizeCandidate()
			resetJail(r.JailName)
		}
		if found {
			return nil
		}
		// 已锁定起点：只继续收集起点窗口内的证据，窗口右边界之后的行不再考虑——
		// 每个 jail 只报**第一个**达标窗口（同一批攻击在滑窗里会命中几十个起点）。
		if candidate != nil {
			if r.BannedAt <= candidate.end {
				candidate.records = append(candidate.records, r)
			} else {
				finalizeCandidate()
			}
			return nil
		}

		window = append(window, r)
		ipCounts[r.IP]++
		// 起点早于「当前时刻 - 窗口」的行，其窗口已经闭合且当时未达标，可以丢弃。
		for len(window) > 0 && window[0].BannedAt < r.BannedAt-int64(windowSeconds) {
			old := window[0]
			window = window[1:]
			ipCounts[old.IP]--
			if ipCounts[old.IP] == 0 {
				delete(ipCounts, old.IP)
			}
		}
		if len(ipCounts) >= minIPs {
			start := window[0].BannedAt
			candidate = &candidateWindow{
				start:   start,
				end:     start + int64(windowSeconds),
				records: append([]persist.JailBanRecord(nil), window...),
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	finalizeCandidate()

	sort.Slice(attacks, func(i, j int) bool {
		if attacks[i].Score != attacks[j].Score {
			return attacks[i].Score > attacks[j].Score
		}
		return attacks[i].JailName < attacks[j].JailName
	})

	if len(attacks) > limit {
		attacks = attacks[:limit]
	}

	return attacks, nil
}
