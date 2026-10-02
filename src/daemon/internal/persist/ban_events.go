package persist

import (
	"fmt"
	"time"
)

type BanEvent struct {
	ID          int64  `json:"id"`
	IP          string `json:"ip"`
	JailName    string `json:"jail_name"`
	BannedAt    int64  `json:"banned_at"`
	BanCount    int    `json:"ban_count"`
	IsPermanent bool   `json:"is_permanent"`
	CreatedAt   int64  `json:"created_at"`
}

func (db *DB) RecordBanEvent(ip, jailName string, banCount int, isPermanent bool) error {
	now := time.Now().Unix()
	_, err := db.conn.Exec(
		`INSERT INTO ban_events (ip, jail_name, banned_at, ban_count, is_permanent, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		ip, jailName, now, banCount, boolToInt(isPermanent), now,
	)
	if err != nil {
		return fmt.Errorf("insert ban_event: %w", err)
	}
	return nil
}

func (db *DB) GetBanEvents(limit int) ([]BanEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.conn.Query(
		`SELECT id, ip, jail_name, banned_at, ban_count, is_permanent, created_at
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
		var e BanEvent
		var isPermanent int
		if err := rows.Scan(&e.ID, &e.IP, &e.JailName, &e.BannedAt, &e.BanCount, &isPermanent, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan ban_event: %w", err)
		}
		e.IsPermanent = isPermanent != 0
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
		`SELECT id, ip, jail_name, banned_at, ban_count, is_permanent, created_at
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
		var e BanEvent
		var isPermanent int
		if err := rows.Scan(&e.ID, &e.IP, &e.JailName, &e.BannedAt, &e.BanCount, &isPermanent, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan ban_event: %w", err)
		}
		e.IsPermanent = isPermanent != 0
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
		`SELECT id, ip, jail_name, banned_at, ban_count, is_permanent, created_at
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
		var e BanEvent
		var isPermanent int
		if err := rows.Scan(&e.ID, &e.IP, &e.JailName, &e.BannedAt, &e.BanCount, &isPermanent, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan ban_event: %w", err)
		}
		e.IsPermanent = isPermanent != 0
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
