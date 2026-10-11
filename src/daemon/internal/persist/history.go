package persist

import (
	"database/sql"
	"fmt"
	"time"
)

type BanHistory struct {
	IP           string `json:"ip"`
	BanCount     int    `json:"ban_count"`
	LastBannedAt int64  `json:"last_banned_at"`
	IsPermanent  bool   `json:"is_permanent"`
	// LastUnbannedAt 是最近一次**显式解封**的时刻（Unix 秒），0 = 从来没有。
	//
	// 只记显式解封：临时封禁自行到期不写这里——到期是「这次封禁按计划结束了」，
	// 解封是「运维把还没到期的规则撤了」，把两者混进同一列会让详情面板上的
	// 「上次解封时间」说不出它真正的含义。
	LastUnbannedAt int64 `json:"last_unbanned_at"`
	CreatedAt      int64 `json:"created_at"`
}

func (db *DB) GetBanHistory(ip string) (*BanHistory, error) {
	var h BanHistory
	var isPermanent int
	err := db.conn.QueryRow(
		`SELECT ip, ban_count, last_banned_at, is_permanent, last_unbanned_at, created_at
		 FROM ban_history
		 WHERE ip = ?`,
		ip,
	).Scan(&h.IP, &h.BanCount, &h.LastBannedAt, &isPermanent, &h.LastUnbannedAt, &h.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query ban_history: %w", err)
	}
	h.IsPermanent = isPermanent != 0
	return &h, nil
}

// RecordBanHistory 落一次封禁并返回**写入后**的累计次数。
//
// 返回值是给调用方的：ban_events.ban_count 记的是「这次是第几封」，而底账里唯一权威
// 的那个序号就是这里加完之后的 ban_count。手工封禁路径（POST /bans 与 /bans/batch）
// 没有判定层给它喂这个数，早先硬写 1，于是重复手工封禁的地址在分级成效里永远停在
// 第 1 级、复发统计也认不出它——面板把「被封过三次」读成「只被封过一次」。
func (db *DB) RecordBanHistory(ip string, isPermanent bool) (int, error) {
	now := time.Now().Unix()
	var count int
	err := db.conn.QueryRow(
		`INSERT INTO ban_history (ip, ban_count, last_banned_at, is_permanent, created_at)
		 VALUES (?, 1, ?, ?, ?)
		 ON CONFLICT(ip) DO UPDATE SET 
			ban_count = ban_count + 1,
			last_banned_at = excluded.last_banned_at,
			is_permanent = excluded.is_permanent
		 RETURNING ban_count`,
		ip, now, boolToInt(isPermanent), now,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("upsert ban_history: %w", err)
	}
	return count, nil
}

// RecordUnbanHistory 把某个 IP 的最近一次显式解封时刻写进 ban_history。
//
// 只 UPDATE、不 INSERT：这一行只在封禁发生时建立（RecordBanHistory），从来没有被封过的
// IP 没有「解封时间」可记，凭空造一行 ban_count=0 的记录会进 GetFrequentBans 与
// 「独立 IP 数」统计。行不存在时受影响 0 行，正是想要的结果。
func (db *DB) RecordUnbanHistory(ip string) error {
	_, err := db.conn.Exec(
		`UPDATE ban_history SET last_unbanned_at = ? WHERE ip = ?`,
		time.Now().Unix(), ip,
	)
	if err != nil {
		return fmt.Errorf("update ban_history last_unbanned_at: %w", err)
	}
	return nil
}

func (db *DB) GetAllBanHistory() ([]BanHistory, error) {
	rows, err := db.conn.Query(
		`SELECT ip, ban_count, last_banned_at, is_permanent, last_unbanned_at, created_at
		 FROM ban_history
		 ORDER BY last_banned_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("query all ban_history: %w", err)
	}
	defer rows.Close()

	var histories []BanHistory
	for rows.Next() {
		var h BanHistory
		var isPermanent int
		if err := rows.Scan(&h.IP, &h.BanCount, &h.LastBannedAt, &isPermanent, &h.LastUnbannedAt, &h.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan ban_history: %w", err)
		}
		h.IsPermanent = isPermanent != 0
		histories = append(histories, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ban_history: %w", err)
	}
	return histories, nil
}

func (db *DB) GetFrequentBans(minCount int, limit int) ([]BanHistory, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := db.conn.Query(
		`SELECT ip, ban_count, last_banned_at, is_permanent, last_unbanned_at, created_at
		 FROM ban_history
		 WHERE ban_count >= ?
		 ORDER BY ban_count DESC, last_banned_at DESC
		 LIMIT ?`,
		minCount, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query frequent bans: %w", err)
	}
	defer rows.Close()

	var histories []BanHistory
	for rows.Next() {
		var h BanHistory
		var isPermanent int
		if err := rows.Scan(&h.IP, &h.BanCount, &h.LastBannedAt, &isPermanent, &h.LastUnbannedAt, &h.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan ban_history: %w", err)
		}
		h.IsPermanent = isPermanent != 0
		histories = append(histories, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ban_history: %w", err)
	}
	return histories, nil
}

func (db *DB) DeleteBanHistory(ip string) error {
	_, err := db.conn.Exec("DELETE FROM ban_history WHERE ip = ?", ip)
	if err != nil {
		return fmt.Errorf("delete ban_history: %w", err)
	}
	return nil
}

func (db *DB) GetBanHistoryStats() (totalIPs int, totalBans int, permanentBans int, err error) {
	err = db.conn.QueryRow(`
		SELECT 
			COUNT(*) as total_ips,
			COALESCE(SUM(ban_count), 0) as total_bans,
			COALESCE(SUM(CASE WHEN is_permanent = 1 THEN 1 ELSE 0 END), 0) as permanent_bans
		FROM ban_history
	`).Scan(&totalIPs, &totalBans, &permanentBans)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("query ban_history stats: %w", err)
	}
	return totalIPs, totalBans, permanentBans, nil
}
