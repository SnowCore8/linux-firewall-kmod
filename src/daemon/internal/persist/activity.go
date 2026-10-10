// 封禁活动的读取面：趋势、热力图与「今日」窗口共用的三条查询。
//
// 一律**只读**：契约把 /api/v1/stats* 全归在只读面（缺陷 HTTP_READ_PATH_WRITES_STATE
// 的门禁会扫这些 handler，读到写点就红）。清扫与过期保留由 CleanupExpired 的定时器负责。
//
// 为什么不把分桶下推到 SQL：桶边界是**本地时区**的自然日与自然小时（契约把 today_bans
// 的窗口定义写死成「本地时区 00:00 起」，看板上的「今日」跟运维日历走而不是 UTC），
// SQLite 的 strftime(...,'localtime') 依赖宿主的 TZ 环境，而守护进程的时区在 main 里
// 就已经解析成本地 Location。跨层两种口径必然在 UTC+8/夏令时边界上算错一个桶，
// 因此这里取原始时间戳，归桶交给调用方用同一个 time.Location 做。
package persist

import (
	"fmt"
	"time"
)

// BanActivity 是 ban_events 的一行精简读数。
//
// 只带聚合要用的三列：一条封禁活动行本来还有 reason/duration 等列，全量取回会让趋势
// 这种「每天跑一次」的查询白搬几十倍的数据。
type BanActivity struct {
	BannedAt    int64
	JailName    string
	IsPermanent bool
}

// GetBanActivitySince 取回 banned_at >= since 的封禁活动，按 banned_at 升序。
//
// 条数由保留期兜住（CleanupExpired 按 retention_days 删旧行），所以趋势查询的成本上界是
// 「保留期内的封禁总数」，不随运行时长无限增长。
func (db *DB) GetBanActivitySince(since time.Time) ([]BanActivity, error) {
	rows, err := db.conn.Query(
		`SELECT banned_at, jail_name, is_permanent
		 FROM ban_events
		 WHERE banned_at >= ?
		 ORDER BY banned_at ASC`,
		since.Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("query ban activity: %w", err)
	}
	defer rows.Close()

	var out []BanActivity
	for rows.Next() {
		var a BanActivity
		var permanent int
		if err := rows.Scan(&a.BannedAt, &a.JailName, &permanent); err != nil {
			return nil, fmt.Errorf("scan ban activity: %w", err)
		}
		a.IsPermanent = permanent != 0
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ban activity: %w", err)
	}
	return out, nil
}

// CountBanEventsBetween 统计 banned_at 落在 [start, end) 内的封禁条数。
//
// 半开区间是必须的：闭区间会让午夜那条恰好被两个窗口各数一次（「今日」与「昨日」之和
// 大于总数）。today_bans 与 recent_bans 都用它，窗口由调用方算。
func (db *DB) CountBanEventsBetween(start, end time.Time) (uint64, error) {
	var count uint64
	err := db.conn.QueryRow(
		`SELECT COUNT(*) FROM ban_events WHERE banned_at >= ? AND banned_at < ?`,
		start.Unix(), end.Unix(),
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count ban events in [%d,%d): %w", start.Unix(), end.Unix(), err)
	}
	return count, nil
}
