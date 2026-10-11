package persist

import (
	"database/sql"
	"fmt"
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
