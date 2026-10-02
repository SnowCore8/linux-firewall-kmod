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
	CreatedAt    int64  `json:"created_at"`
}

func (db *DB) GetBanHistory(ip string) (*BanHistory, error) {
	var h BanHistory
	var isPermanent int
	err := db.conn.QueryRow(
		`SELECT ip, ban_count, last_banned_at, is_permanent, created_at
		 FROM ban_history
		 WHERE ip = ?`,
		ip,
	).Scan(&h.IP, &h.BanCount, &h.LastBannedAt, &isPermanent, &h.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query ban_history: %w", err)
	}
	h.IsPermanent = isPermanent != 0
	return &h, nil
}

func (db *DB) RecordBanHistory(ip string, isPermanent bool) error {
	now := time.Now().Unix()
	_, err := db.conn.Exec(
		`INSERT INTO ban_history (ip, ban_count, last_banned_at, is_permanent, created_at)
		 VALUES (?, 1, ?, ?, ?)
		 ON CONFLICT(ip) DO UPDATE SET 
			ban_count = ban_count + 1,
			last_banned_at = excluded.last_banned_at,
			is_permanent = excluded.is_permanent`,
		ip, now, boolToInt(isPermanent), now,
	)
	if err != nil {
		return fmt.Errorf("upsert ban_history: %w", err)
	}
	return nil
}

func (db *DB) GetAllBanHistory() ([]BanHistory, error) {
	rows, err := db.conn.Query(
		`SELECT ip, ban_count, last_banned_at, is_permanent, created_at
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
		if err := rows.Scan(&h.IP, &h.BanCount, &h.LastBannedAt, &isPermanent, &h.CreatedAt); err != nil {
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
		`SELECT ip, ban_count, last_banned_at, is_permanent, created_at
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
		if err := rows.Scan(&h.IP, &h.BanCount, &h.LastBannedAt, &isPermanent, &h.CreatedAt); err != nil {
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
