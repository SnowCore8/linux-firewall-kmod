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
	if eventLimit <= 0 {
		eventLimit = 10000
	}

	events, err := db.GetBanEvents(eventLimit)
	if err != nil {
		return nil, err
	}

	ipEvents := make(map[string][]int64)
	ipJail := make(map[string]string)
	latestBan := make(map[string]int64)
	for _, e := range events {
		ipEvents[e.IP] = append(ipEvents[e.IP], e.BannedAt)
		// jail_name 取该地址**最近一次**封禁所属的 jail：事件按 banned_at 降序读入，
		// 直接覆盖会停在最早那条的归属上（同一个地址换了 jail 时就会报错来源）。
		if at, ok := latestBan[e.IP]; !ok || e.BannedAt >= at {
			latestBan[e.IP] = e.BannedAt
			ipJail[e.IP] = e.JailName
		}
	}

	var attackers []PeriodicAttackFinding
	for ip, timestamps := range ipEvents {
		if len(timestamps) < minEvents {
			continue
		}

		sort.Slice(timestamps, func(i, j int) bool { return timestamps[i] < timestamps[j] })

		var intervals []float64
		for i := 1; i < len(timestamps); i++ {
			intervals = append(intervals, float64(timestamps[i]-timestamps[i-1]))
		}

		if len(intervals) == 0 {
			continue
		}

		var sum float64
		for _, v := range intervals {
			sum += v
		}
		avg := sum / float64(len(intervals))

		var varianceSum float64
		for _, v := range intervals {
			diff := v - avg
			varianceSum += diff * diff
		}
		stddev := math.Sqrt(varianceSum / float64(len(intervals)))

		cv := 0.0
		if avg > 0 {
			cv = stddev / avg
		}

		regularity := 0.0
		if cv < 0.3 {
			regularity = (1 - cv) * 100
		}

		attackers = append(attackers, PeriodicAttackFinding{
			IP:          ip,
			JailName:    ipJail[ip],
			Regularity:  regularity,
			AvgInterval: avg,
			Jitter:      cv,
			StdDev:      stddev,
			EventCount:  len(timestamps),
			// 交副本而不是内部切片：调用方（含未来的缓存）排序或截断它不能改到本层的账。
			Timestamps: append([]int64(nil), timestamps...),
		})
	}

	sort.Slice(attackers, func(i, j int) bool {
		return attackers[i].Regularity > attackers[j].Regularity
	})

	if len(attackers) > limit {
		attackers = attackers[:limit]
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
	if eventLimit <= 0 {
		eventLimit = 10000
	}

	events, err := db.GetBanEvents(eventLimit)
	if err != nil {
		return nil, err
	}

	// 时间戳要和地址一起排：只看时刻就无法回答「这个窗口里有谁」。
	type jailBan struct {
		ts int64
		ip string
	}
	jailEvents := make(map[string][]jailBan)
	for _, e := range events {
		jailEvents[e.JailName] = append(jailEvents[e.JailName], jailBan{ts: e.BannedAt, ip: e.IP})
	}

	var attacks []CollaborativeAttackFinding
	for jail, bans := range jailEvents {
		sort.Slice(bans, func(i, j int) bool {
			if bans[i].ts != bans[j].ts {
				return bans[i].ts < bans[j].ts
			}
			return bans[i].ip < bans[j].ip
		})

		for i := 0; i < len(bans); i++ {
			windowEnd := bans[i].ts + int64(windowSeconds)
			seen := make(map[string]bool)
			var count int
			for j := i; j < len(bans) && bans[j].ts <= windowEnd; j++ {
				count++
				seen[bans[j].ip] = true
			}

			// 判据是**窗口内的唯一地址数**（参数名就叫 minIPs）：旧实现拿事件数去比，
			// 于是同一个 IP 在窗口里被封 3 次会被读成「3 个源联动」。
			if len(seen) < minIPs {
				continue
			}

			ips := make([]string, 0, len(seen))
			for ip := range seen {
				ips = append(ips, ip)
			}
			sort.Strings(ips)

			attacks = append(attacks, CollaborativeAttackFinding{
				JailName:    jail,
				WindowStart: bans[i].ts,
				WindowEnd:   windowEnd,
				IPs:         ips[:min(len(ips), MaxWindowIPs)],
				UniqueIPs:   len(seen),
				BanCount:    count,
				// 强度按窗口内的封禁事件数线性放大，10 次封顶 100：保持旧口径不变，
				// 换判据（改按地址数）会让面板上同一根柱子的含义前后对不上。
				Score: math.Min(100, float64(count)/10*100),
			})
			// 每个 jail 只报**第一个**达标窗口：同一批攻击在滑窗里会命中几十个起点，
			// 全列出来等于把一次事件复制成一排，而 limit 会把别的 jail 挤出载荷。
			break
		}
	}

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
