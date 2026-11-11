package persist

import (
	"database/sql"
	"fmt"
	"math"
	"strings"
	"time"
)

type BanEvent struct {
	ID       int64  `json:"id"`
	IP       string `json:"ip"`
	JailName string `json:"jail_name"`
	BannedAt int64  `json:"banned_at"`
	BanCount int    `json:"ban_count"`
	// IsPermanent 标记这次封禁有没有到期时刻。永久封禁的 DurationSecs 为 nil，
	// 「有多长」这个问题对它没有答案，不是 0 秒。
	IsPermanent bool `json:"is_permanent"`
	// DurationSecs 是**下发时计划**的封禁时长（秒），nil = 没有这个读数。
	//
	// 两种 nil：这一行写于 duration_secs 列加入之前（迁移只补列不补史，旧行的时长
	// 已经无从追究），或这次封禁本身就是永久的。直方图把前者排除在各桶之外，正是为了
	// 不把「不知道」画成「封了 0 秒」。
	DurationSecs *int64 `json:"duration_secs,omitempty"`
	CreatedAt    int64  `json:"created_at"`
}

// banEventColumns 是 BanEvent 各字段对应的列名（顺序与 scanBanEvent 一致）。
//
// 三条查询共用它：常量不是外部输入，拼进 SELECT 没有注入面，换来的是「加一列只要改
// 一处」——曾经各写一遍时，新增列会只补进其中一两条，另一条扫不到就默默给零值。
const banEventColumns = "id, ip, jail_name, banned_at, ban_count, is_permanent, created_at, duration_secs"

// scanBanEvent 把一行（按 banEventColumns 的顺序）扫成 BanEvent。
//
// is_permanent 在库里是 0/1（SQLite 没有布尔列），duration_secs 可为 NULL。
func scanBanEvent(rows interface{ Scan(dest ...any) error }) (BanEvent, error) {
	var (
		e           BanEvent
		isPermanent int
		duration    sql.NullInt64
	)
	if err := rows.Scan(&e.ID, &e.IP, &e.JailName, &e.BannedAt, &e.BanCount, &isPermanent, &e.CreatedAt, &duration); err != nil {
		return BanEvent{}, err
	}
	e.IsPermanent = isPermanent != 0
	if duration.Valid {
		v := duration.Int64
		e.DurationSecs = &v
	}
	return e, nil
}

// RecordBanEvent 记一次封禁。durationSecs 传 nil 表示「时长未知或永久」——
// 永久封禁由 isPermanent 表达，这里同样写 NULL，两者不靠 0 这个值区分。
func (db *DB) RecordBanEvent(ip, jailName string, banCount int, isPermanent bool, durationSecs *int64) error {
	now := time.Now().Unix()
	// 绑成 NullInt64 而不是直接传 *int64：database/sql 不会替驱动解指针，传 *int64
	// 会在运行时报 unsupported type，而这条路径只有真封禁时才会走到。
	var duration sql.NullInt64
	if durationSecs != nil {
		duration = sql.NullInt64{Int64: *durationSecs, Valid: true}
	}
	_, err := db.conn.Exec(
		`INSERT INTO ban_events (ip, jail_name, banned_at, ban_count, is_permanent, created_at, duration_secs)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ip, jailName, now, banCount, boolToInt(isPermanent), now, duration,
	)
	if err != nil {
		return fmt.Errorf("insert ban_event: %w", err)
	}
	return nil
}

// BanDurationSamples 取回近 limit 条封禁事件的时长与永久标记，供时长直方图归桶。
//
// 只取需要的两列：直方图不读 IP、不读 jail，把整行 BanEvent 拉出来会让一次上限 10000
// 行的查询白白带上地址文本。
func (db *DB) BanDurationSamples(limit int) ([]BanEvent, error) {
	if limit <= 0 {
		limit = 10000
	}
	rows, err := db.conn.Query(
		`SELECT is_permanent, duration_secs FROM ban_events ORDER BY banned_at DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query ban durations: %w", err)
	}
	defer rows.Close()

	var out []BanEvent
	for rows.Next() {
		var isPermanent int
		var duration sql.NullInt64
		if err := rows.Scan(&isPermanent, &duration); err != nil {
			return nil, fmt.Errorf("scan ban duration: %w", err)
		}
		e := BanEvent{IsPermanent: isPermanent != 0}
		if duration.Valid {
			v := duration.Int64
			e.DurationSecs = &v
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ban durations: %w", err)
	}
	return out, nil
}

// BanLevelRow 是「某地址在某一个封禁等级上的一次封禁」的读数。
//
// 同一 (ip, ban_count) 的多行（重复事件、崩溃重放）已折叠成一行，IsPermanent 取
// MAX(is_permanent)：只要该级有过一次永久封禁就算永久。
type BanLevelRow struct {
	IP          string
	BanCount    int
	IsPermanent bool
}

// GetBanLevelRows 取回「地址 × 封禁等级」的成效底账，供分级封禁成效统计。
//
// ban_events.ban_count 是该次封禁时这个地址的**累计次数**，所以 (ip, ban_count) 的一行
// 就代表「它被封到了第 ban_count 级」。分级成效问的是「封到第 L 级的地址里有多少还得
// 再升到下一级」，这份底账足够回答，不需要把全表搬回 Go 侧。
func (db *DB) GetBanLevelRows() ([]BanLevelRow, error) {
	rows, err := db.conn.Query(
		`SELECT ip, ban_count, MAX(is_permanent) FROM ban_events
		 WHERE ban_count > 0
		 GROUP BY ip, ban_count`,
	)
	if err != nil {
		return nil, fmt.Errorf("query ban level rows: %w", err)
	}
	defer rows.Close()

	var out []BanLevelRow
	for rows.Next() {
		var (
			r           BanLevelRow
			isPermanent int
		)
		if err := rows.Scan(&r.IP, &r.BanCount, &isPermanent); err != nil {
			return nil, fmt.Errorf("scan ban level row: %w", err)
		}
		r.IsPermanent = isPermanent != 0
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ban level rows: %w", err)
	}
	return out, nil
}

// JailBanStats 是某个 jail 在时间窗内的封禁聚合。
//
// RecidivistIPs 的口径是「本 jail 内被封 ≥2 次的地址数」——判定按地址、按 jail，
// 不读 ban_events.ban_count（那是跨 jail 的全局累计次数）。
type JailBanStats struct {
	JailName      string
	TotalBans     int
	UniqueIPs     int
	RecidivistIPs int
	LastBannedAt  int64
}

// BanJailStatsSince 按 jail 聚合 banned_at >= since 的封禁事件。
//
// 聚合在 SQL 内完成：先把窗口内的事件折成「地址 × jail」的计数，再按 jail 汇总。
// 调用方拿到的计数覆盖整个窗口，不受任何行数上限截断，也不需要把明细读进内存。
func (db *DB) BanJailStatsSince(since int64) ([]JailBanStats, error) {
	rows, err := db.conn.Query(
		`SELECT jail_name, SUM(per_ip), COUNT(*),
		        SUM(CASE WHEN per_ip >= 2 THEN 1 ELSE 0 END), MAX(last_banned)
		 FROM (
			SELECT jail_name, ip, COUNT(*) AS per_ip, MAX(banned_at) AS last_banned
			FROM ban_events
			WHERE banned_at >= ?
			GROUP BY jail_name, ip
		 )
		 GROUP BY jail_name`,
		since,
	)
	if err != nil {
		return nil, fmt.Errorf("query ban jail stats since %d: %w", since, err)
	}
	defer rows.Close()

	var out []JailBanStats
	for rows.Next() {
		var s JailBanStats
		if err := rows.Scan(&s.JailName, &s.TotalBans, &s.UniqueIPs, &s.RecidivistIPs, &s.LastBannedAt); err != nil {
			return nil, fmt.Errorf("scan ban jail stats: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ban jail stats: %w", err)
	}
	return out, nil
}

// JailDurationStats 是某个 jail 在时间窗内的复发间隔聚合。
//
// MedianInterval 是该 jail 内所有相邻封禁间隔的中位数（秒）。窗口左边界之前的那一条
// 不参与：它在窗口内没有「上一条」，硬凑一个跨窗口的间隔会把统计拖到窗口之外。
type JailDurationStats struct {
	JailName        string
	RecidivistCount int
	MedianInterval  float64
}

// BanDurationStatsSince 按 jail 聚合 banned_at >= since 的封禁复发间隔。
//
// 间隔用 LAG 在 SQL 内按 (jail, ip) 求出，中位数用 ROW_NUMBER 定位中间一两行后取均值：
// 两步都只把聚合结果带回 Go，事件明细不出库。
func (db *DB) BanDurationStatsSince(since int64) ([]JailDurationStats, error) {
	rows, err := db.conn.Query(
		`WITH gaps AS (
			SELECT jail_name,
			       banned_at - LAG(banned_at) OVER (PARTITION BY jail_name, ip ORDER BY banned_at) AS gap
			FROM ban_events
			WHERE banned_at >= ?
		 ),
		 ranked AS (
			SELECT jail_name, gap,
			       ROW_NUMBER() OVER (PARTITION BY jail_name ORDER BY gap) AS rn,
			       COUNT(*) OVER (PARTITION BY jail_name) AS cnt
			FROM gaps
			WHERE gap IS NOT NULL
		 ),
		 medians AS (
			SELECT jail_name, AVG(gap) AS median
			FROM ranked
			WHERE rn IN ((cnt + 1) / 2, (cnt + 2) / 2)
			GROUP BY jail_name
		 ),
		 recidivists AS (
			SELECT jail_name, COUNT(*) AS n
			FROM (
				SELECT jail_name, ip
				FROM ban_events
				WHERE banned_at >= ?
				GROUP BY jail_name, ip
				HAVING COUNT(*) >= 2
			)
			GROUP BY jail_name
		 )
		 SELECT m.jail_name, m.median, COALESCE(r.n, 0)
		 FROM medians m
		 LEFT JOIN recidivists r ON r.jail_name = m.jail_name`,
		since, since,
	)
	if err != nil {
		return nil, fmt.Errorf("query ban duration stats since %d: %w", since, err)
	}
	defer rows.Close()

	var out []JailDurationStats
	for rows.Next() {
		var s JailDurationStats
		if err := rows.Scan(&s.JailName, &s.MedianInterval, &s.RecidivistCount); err != nil {
			return nil, fmt.Errorf("scan ban duration stats: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ban duration stats: %w", err)
	}
	return out, nil
}

// IPBanAggregate 是单个地址在时间窗内的封禁聚合。
type IPBanAggregate struct {
	IP           string
	Bans         int
	LastBannedAt int64
}

// BanAggregatesByIPSince 按地址聚合 banned_at >= since 的封禁事件。
//
// 每行是一个**地址**而不是一条事件：网段分布只需要「每个地址被封了几次、最后一次何时」，
// 事件明细搬回来只会让内存随攻击量线性增长。
func (db *DB) BanAggregatesByIPSince(since int64) ([]IPBanAggregate, error) {
	rows, err := db.conn.Query(
		`SELECT ip, COUNT(*), MAX(banned_at)
		 FROM ban_events
		 WHERE banned_at >= ?
		 GROUP BY ip`,
		since,
	)
	if err != nil {
		return nil, fmt.Errorf("query ban aggregates by ip since %d: %w", since, err)
	}
	defer rows.Close()

	var out []IPBanAggregate
	for rows.Next() {
		var a IPBanAggregate
		if err := rows.Scan(&a.IP, &a.Bans, &a.LastBannedAt); err != nil {
			return nil, fmt.Errorf("scan ban aggregate by ip: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ban aggregates by ip: %w", err)
	}
	return out, nil
}

// IPBanIntervalStats 是单个地址的封禁间隔读数（全历史，由保留期兜住表的大小）。
//
// JailName 取该地址**最近一次**封禁所属的 jail；EventCount 是该地址的全部封禁次数。
type IPBanIntervalStats struct {
	IP             string
	JailName       string
	EventCount     int
	LastBannedAt   int64
	MedianInterval float64
	AvgInterval    float64
	StdDev         float64
}

// IPBanIntervalStats 按地址计算封禁间隔的中位数、均值与标准差。
//
// 只返回被封 ≥2 次的地址（一次封禁没有间隔可算）。所有间隔统计都在 SQL 内按地址聚合，
// Go 侧拿到的是一行一个地址，不会随事件总量增长。
func (db *DB) GetIPBanIntervalStats() ([]IPBanIntervalStats, error) {
	rows, err := db.conn.Query(
		`WITH ordered AS (
			SELECT id, ip, jail_name, banned_at,
			       LAG(banned_at) OVER (PARTITION BY ip ORDER BY banned_at, id) AS prev
			FROM ban_events
		 ),
		 gaps AS (
			SELECT ip, banned_at - prev AS gap
			FROM ordered
			WHERE prev IS NOT NULL
		 ),
		 stats AS (
			SELECT ip, AVG(gap) AS avg_gap, AVG(gap * gap) AS avg_sq
			FROM gaps
			GROUP BY ip
		 ),
		 ranked AS (
			SELECT ip, gap,
			       ROW_NUMBER() OVER (PARTITION BY ip ORDER BY gap) AS rn,
			       COUNT(*) OVER (PARTITION BY ip) AS cnt
			FROM gaps
		 ),
		 medians AS (
			SELECT ip, AVG(gap) AS median
			FROM ranked
			WHERE rn IN ((cnt + 1) / 2, (cnt + 2) / 2)
			GROUP BY ip
		 ),
		 latest AS (
			SELECT ip, jail_name, banned_at
			FROM (
				SELECT ip, jail_name, banned_at,
				       ROW_NUMBER() OVER (PARTITION BY ip ORDER BY banned_at DESC, id DESC) AS rn
				FROM ban_events
			)
			WHERE rn = 1
		 ),
		 counts AS (
			SELECT ip, COUNT(*) AS n FROM ban_events GROUP BY ip
		 )
		 SELECT l.ip, l.jail_name, c.n, l.banned_at, m.median, s.avg_gap, s.avg_sq
		 FROM stats s
		 JOIN medians m ON m.ip = s.ip
		 JOIN latest l ON l.ip = s.ip
		 JOIN counts c ON c.ip = s.ip`,
	)
	if err != nil {
		return nil, fmt.Errorf("query ip ban interval stats: %w", err)
	}
	defer rows.Close()

	var out []IPBanIntervalStats
	for rows.Next() {
		var (
			s     IPBanIntervalStats
			avgSq float64
		)
		if err := rows.Scan(&s.IP, &s.JailName, &s.EventCount, &s.LastBannedAt,
			&s.MedianInterval, &s.AvgInterval, &avgSq); err != nil {
			return nil, fmt.Errorf("scan ip ban interval stats: %w", err)
		}
		// 单遍算法（E[x²] − E[x]²）在常数序列上可能得到极小的负数，钳到 0。
		if variance := avgSq - s.AvgInterval*s.AvgInterval; variance > 0 {
			s.StdDev = math.Sqrt(variance)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ip ban interval stats: %w", err)
	}
	return out, nil
}

// JailBanWindowCounts 是某个 jail 在最近 24 小时、前一日同一段与最近 7 天的封禁量。
type JailBanWindowCounts struct {
	JailName    string
	Bans24h     int
	BansPrev24h int
	Bans7d      int
}

// JailBanWindowCounts 按 jail 统计 now 之前 7 天内的封禁量（含 24 小时与前一日两段）。
//
// 三个窗口在一次 GROUP BY 里数完：趋势图与「24 小时预计再动手」要并排读，分开查询会让
// 同一张图上的两列来自不同时刻。
func (db *DB) GetJailBanWindowCounts(now int64) ([]JailBanWindowCounts, error) {
	dayAgo := now - 86400
	prevDayAgo := now - 2*86400
	weekAgo := now - 7*86400
	rows, err := db.conn.Query(
		`SELECT jail_name,
		        SUM(CASE WHEN banned_at >= ? THEN 1 ELSE 0 END),
		        SUM(CASE WHEN banned_at >= ? AND banned_at < ? THEN 1 ELSE 0 END),
		        COUNT(*)
		 FROM ban_events
		 WHERE banned_at >= ?
		 GROUP BY jail_name`,
		dayAgo, prevDayAgo, dayAgo, weekAgo,
	)
	if err != nil {
		return nil, fmt.Errorf("query jail ban window counts: %w", err)
	}
	defer rows.Close()

	var out []JailBanWindowCounts
	for rows.Next() {
		var c JailBanWindowCounts
		if err := rows.Scan(&c.JailName, &c.Bans24h, &c.BansPrev24h, &c.Bans7d); err != nil {
			return nil, fmt.Errorf("scan jail ban window counts: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate jail ban window counts: %w", err)
	}
	return out, nil
}

// JailBanRecord 是协同检测需要的最小事件形状：时间、地址、jail。
type JailBanRecord struct {
	JailName string
	BannedAt int64
	IP       string
}

// StreamJailBans 按 (jail_name, banned_at, ip) 升序逐行回调封禁事件。
//
// 协同检测要在每个 jail 的时间轴上滑窗，但窗口只有几百秒，把整表读进内存没有必要：
// 回调期间调用方只保留当前窗口内的行，内存上界是「一个窗口内的封禁数」而不是表大小。
func (db *DB) StreamJailBans(fn func(JailBanRecord) error) error {
	rows, err := db.conn.Query(
		`SELECT jail_name, banned_at, ip
		 FROM ban_events
		 ORDER BY jail_name, banned_at, ip`,
	)
	if err != nil {
		return fmt.Errorf("stream ban events by jail: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var r JailBanRecord
		if err := rows.Scan(&r.JailName, &r.BannedAt, &r.IP); err != nil {
			return fmt.Errorf("scan jail ban record: %w", err)
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate jail ban records: %w", err)
	}
	return nil
}

// BanTimestampsByIPs 取回指定地址的全部封禁时刻（升序），用于周期性攻击者的证据列。
//
// 只在最终入选的地址上调用：先在聚合层筛出候选，再按名单取原始时刻，避免为整表搬明细。
func (db *DB) BanTimestampsByIPs(ips []string) (map[string][]int64, error) {
	const chunkSize = 500
	out := make(map[string][]int64, len(ips))
	for start := 0; start < len(ips); start += chunkSize {
		end := start + chunkSize
		if end > len(ips) {
			end = len(ips)
		}
		chunk := ips[start:end]
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]any, 0, len(chunk))
		for _, ip := range chunk {
			args = append(args, ip)
		}
		rows, err := db.conn.Query(
			`SELECT ip, banned_at FROM ban_events
			 WHERE ip IN (`+placeholders+`)
			 ORDER BY ip, banned_at`,
			args...,
		)
		if err != nil {
			return nil, fmt.Errorf("query ban timestamps: %w", err)
		}
		for rows.Next() {
			var (
				ip string
				at int64
			)
			if err := rows.Scan(&ip, &at); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scan ban timestamp: %w", err)
			}
			out[ip] = append(out[ip], at)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("iterate ban timestamps: %w", err)
		}
		rows.Close()
	}
	return out, nil
}

func (db *DB) GetBanEvents(limit int) ([]BanEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.conn.Query(
		`SELECT `+banEventColumns+`
		 FROM ban_events
		 ORDER BY banned_at DESC
		 LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query ban_events: %w", err)
	}
	defer rows.Close()

	var events []BanEvent
	for rows.Next() {
		e, err := scanBanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan ban_event: %w", err)
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ban_events: %w", err)
	}
	return events, nil
}

func (db *DB) GetBanEventsByIP(ip string, limit int) ([]BanEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := db.conn.Query(
		`SELECT `+banEventColumns+`
		 FROM ban_events
		 WHERE ip = ?
		 ORDER BY banned_at DESC
		 LIMIT ?`,
		ip, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query ban_events by IP: %w", err)
	}
	defer rows.Close()

	var events []BanEvent
	for rows.Next() {
		e, err := scanBanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan ban_event: %w", err)
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ban_events: %w", err)
	}
	return events, nil
}

func (db *DB) GetBanEventsByJail(jailName string, limit int) ([]BanEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := db.conn.Query(
		`SELECT `+banEventColumns+`
		 FROM ban_events
		 WHERE jail_name = ?
		 ORDER BY banned_at DESC
		 LIMIT ?`,
		jailName, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query ban_events by jail: %w", err)
	}
	defer rows.Close()

	var events []BanEvent
	for rows.Next() {
		e, err := scanBanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan ban_event: %w", err)
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ban_events: %w", err)
	}
	return events, nil
}

func (db *DB) CountBanEventsSince(since time.Time) (int, error) {
	var count int
	err := db.conn.QueryRow(
		`SELECT COUNT(*) FROM ban_events WHERE banned_at >= ?`,
		since.Unix(),
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count ban_events: %w", err)
	}
	return count, nil
}

func (db *DB) GetRecidivismStats() (totalIPs int, recidivistIPs int, recidivismRate float64, err error) {
	err = db.conn.QueryRow(`
		SELECT 
			COUNT(DISTINCT ip) as total_ips,
			COUNT(DISTINCT CASE WHEN ban_count > 1 THEN ip END) as recidivist_ips
		FROM ban_events
	`).Scan(&totalIPs, &recidivistIPs)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("query recidivism stats: %w", err)
	}
	if totalIPs > 0 {
		recidivismRate = float64(recidivistIPs) / float64(totalIPs) * 100
	}
	return totalIPs, recidivistIPs, recidivismRate, nil
}

func (db *DB) GetTopRecidivists(limit int) ([]BanEvent, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := db.conn.Query(
		`SELECT ip, jail_name, MAX(banned_at) as banned_at, MAX(ban_count) as ban_count, 
		        MAX(is_permanent) as is_permanent, MIN(created_at) as created_at
		 FROM ban_events
		 WHERE ban_count > 1
		 GROUP BY ip
		 ORDER BY ban_count DESC, banned_at DESC
		 LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query top recidivists: %w", err)
	}
	defer rows.Close()

	var events []BanEvent
	for rows.Next() {
		var e BanEvent
		var isPermanent int
		if err := rows.Scan(&e.IP, &e.JailName, &e.BannedAt, &e.BanCount, &isPermanent, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan recidivist: %w", err)
		}
		e.IsPermanent = isPermanent != 0
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate recidivists: %w", err)
	}
	return events, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
