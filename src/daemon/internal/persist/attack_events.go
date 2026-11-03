package persist

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/risk"
)

// AttackEvent 表示一次攻击事件（事件溯源的原子记录）。
type AttackEvent struct {
	ID         int64          `json:"id"`
	IP         string         `json:"ip"`
	EventType  risk.EventType `json:"event_type"`
	Increment  float64        `json:"increment"`
	OccurredAt int64          `json:"occurred_at"`
}

// InsertEvent 记录一次攻击事件。
//
// 事件溯源：每次攻击行为都持久化为一条记录，向量可从此重算。
func (db *DB) InsertEvent(ip string, eventType risk.EventType, increment float64, occurredAt int64) error {
	if occurredAt == 0 {
		occurredAt = time.Now().Unix()
	}
	_, err := db.conn.Exec(
		`INSERT INTO attack_events (ip, event_type, increment, occurred_at)
		 VALUES (?, ?, ?, ?)`,
		ip, string(eventType), increment, occurredAt,
	)
	if err != nil {
		return fmt.Errorf("insert attack_event: %w", err)
	}
	return nil
}

// GetEventsSince 查询指定 IP 自 since（Unix 秒）以来的所有攻击事件。
//
// 用于向量重算：从事件列表重新累加增量并施加衰减。
func (db *DB) GetEventsSince(ip string, since int64) ([]AttackEvent, error) {
	rows, err := db.conn.Query(
		`SELECT id, ip, event_type, increment, occurred_at
		 FROM attack_events
		 WHERE ip = ? AND occurred_at >= ?
		 ORDER BY occurred_at ASC`,
		ip, since,
	)
	if err != nil {
		return nil, fmt.Errorf("query attack_events: %w", err)
	}
	defer rows.Close()

	var events []AttackEvent
	for rows.Next() {
		var (
			e         AttackEvent
			eventType string
		)
		if err := rows.Scan(&e.ID, &e.IP, &eventType, &e.Increment, &e.OccurredAt); err != nil {
			return nil, fmt.Errorf("scan attack_event: %w", err)
		}
		e.EventType = risk.EventType(eventType)
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate attack_events: %w", err)
	}
	return events, nil
}

// GetEventsByType 查询指定事件类型的所有记录（用于统计、审计）。
func (db *DB) GetEventsByType(eventType risk.EventType, limit int) ([]AttackEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.conn.Query(
		`SELECT id, ip, event_type, increment, occurred_at
		 FROM attack_events
		 WHERE event_type = ?
		 ORDER BY occurred_at DESC
		 LIMIT ?`,
		string(eventType), limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query attack_events by type: %w", err)
	}
	defer rows.Close()

	var events []AttackEvent
	for rows.Next() {
		var (
			e         AttackEvent
			eventType string
		)
		if err := rows.Scan(&e.ID, &e.IP, &eventType, &e.Increment, &e.OccurredAt); err != nil {
			return nil, fmt.Errorf("scan attack_event: %w", err)
		}
		e.EventType = risk.EventType(eventType)
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate attack_events: %w", err)
	}
	return events, nil
}

// CountEventsByIP 统计指定 IP 的事件总数（用于风控阈值判定）。
func (db *DB) CountEventsByIP(ip string) (int, error) {
	var count int
	err := db.conn.QueryRow(
		"SELECT COUNT(*) FROM attack_events WHERE ip = ?",
		ip,
	).Scan(&count)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, fmt.Errorf("count attack_events: %w", err)
	}
	return count, nil
}

// DeleteEventsBefore 清理指定时间之前的事件（定期归档）。
func (db *DB) DeleteEventsBefore(before int64) (int64, error) {
	result, err := db.conn.Exec(
		"DELETE FROM attack_events WHERE occurred_at < ?",
		before,
	)
	if err != nil {
		return 0, fmt.Errorf("delete old attack_events: %w", err)
	}
	rows, _ := result.RowsAffected()
	return rows, nil
}
