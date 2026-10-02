package persist

import (
	"database/sql"
	"fmt"
	"time"
)

type IPReputation struct {
	IP          string `json:"ip"`
	Score       int    `json:"score"`
	LastUpdated int64  `json:"last_updated"`
	LastFailure *int64 `json:"last_failure,omitempty"`
	LastBan     *int64 `json:"last_ban,omitempty"`
}

func (db *DB) GetIPReputation(ip string) (*IPReputation, error) {
	var rep IPReputation
	var lastFailure, lastBan sql.NullInt64
	err := db.conn.QueryRow(
		`SELECT ip, score, last_updated, last_failure, last_ban
		 FROM ip_reputation
		 WHERE ip = ?`,
		ip,
	).Scan(&rep.IP, &rep.Score, &rep.LastUpdated, &lastFailure, &lastBan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query ip_reputation: %w", err)
	}
	if lastFailure.Valid {
		rep.LastFailure = &lastFailure.Int64
	}
	if lastBan.Valid {
		rep.LastBan = &lastBan.Int64
	}
	return &rep, nil
}

func (db *DB) SetIPReputation(ip string, score int) error {
	now := time.Now().Unix()
	_, err := db.conn.Exec(
		`INSERT INTO ip_reputation (ip, score, last_updated)
		 VALUES (?, ?, ?)
		 ON CONFLICT(ip) DO UPDATE SET score = excluded.score, last_updated = excluded.last_updated`,
		ip, score, now,
	)
	if err != nil {
		return fmt.Errorf("upsert ip_reputation: %w", err)
	}
	return nil
}

func (db *DB) RecordFailure(ip string, penalty int) error {
	now := time.Now().Unix()
	_, err := db.conn.Exec(
		`INSERT INTO ip_reputation (ip, score, last_updated, last_failure)
		 VALUES (?, MAX(0, 100 - ?), ?, ?)
		 ON CONFLICT(ip) DO UPDATE SET 
			score = MAX(0, score - ?),
			last_updated = excluded.last_updated,
			last_failure = excluded.last_failure`,
		ip, penalty, now, now, penalty,
	)
	if err != nil {
		return fmt.Errorf("record failure: %w", err)
	}
	return nil
}

func (db *DB) RecordBan(ip string, penalty int) error {
	now := time.Now().Unix()
	_, err := db.conn.Exec(
		`INSERT INTO ip_reputation (ip, score, last_updated, last_ban)
		 VALUES (?, MAX(0, 100 - ?), ?, ?)
		 ON CONFLICT(ip) DO UPDATE SET 
			score = MAX(0, score - ?),
			last_updated = excluded.last_updated,
			last_ban = excluded.last_ban`,
		ip, penalty, now, now, penalty,
	)
	if err != nil {
		return fmt.Errorf("record ban: %w", err)
	}
	return nil
}

func (db *DB) RecoverReputation(recoveryRate int, maxScore int) (int, error) {
	if recoveryRate <= 0 {
		recoveryRate = 1
	}
	if maxScore <= 0 {
		maxScore = 100
	}
	now := time.Now().Unix()
	result, err := db.conn.Exec(
		`UPDATE ip_reputation 
		 SET score = MIN(?, score + ?), last_updated = ?
		 WHERE score < ? AND (last_failure IS NULL OR last_failure < ? - 3600)`,
		maxScore, recoveryRate, now, maxScore, now,
	)
	if err != nil {
		return 0, fmt.Errorf("recover reputation: %w", err)
	}
	rows, _ := result.RowsAffected()
	return int(rows), nil
}

func (db *DB) GetAllReputations() ([]IPReputation, error) {
	rows, err := db.conn.Query(
		`SELECT ip, score, last_updated, last_failure, last_ban
		 FROM ip_reputation
		 ORDER BY score ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("query all reputations: %w", err)
	}
	defer rows.Close()

	var reps []IPReputation
	for rows.Next() {
		var rep IPReputation
		var lastFailure, lastBan sql.NullInt64
		if err := rows.Scan(&rep.IP, &rep.Score, &rep.LastUpdated, &lastFailure, &lastBan); err != nil {
			return nil, fmt.Errorf("scan reputation: %w", err)
		}
		if lastFailure.Valid {
			rep.LastFailure = &lastFailure.Int64
		}
		if lastBan.Valid {
			rep.LastBan = &lastBan.Int64
		}
		reps = append(reps, rep)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate reputations: %w", err)
	}
	return reps, nil
}

func (db *DB) GetLowReputationIPs(threshold int, limit int) ([]IPReputation, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := db.conn.Query(
		`SELECT ip, score, last_updated, last_failure, last_ban
		 FROM ip_reputation
		 WHERE score < ?
		 ORDER BY score ASC
		 LIMIT ?`,
		threshold, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query low reputation IPs: %w", err)
	}
	defer rows.Close()

	var reps []IPReputation
	for rows.Next() {
		var rep IPReputation
		var lastFailure, lastBan sql.NullInt64
		if err := rows.Scan(&rep.IP, &rep.Score, &rep.LastUpdated, &lastFailure, &lastBan); err != nil {
			return nil, fmt.Errorf("scan reputation: %w", err)
		}
		if lastFailure.Valid {
			rep.LastFailure = &lastFailure.Int64
		}
		if lastBan.Valid {
			rep.LastBan = &lastBan.Int64
		}
		reps = append(reps, rep)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate reputations: %w", err)
	}
	return reps, nil
}

func (db *DB) DeleteIPReputation(ip string) error {
	_, err := db.conn.Exec("DELETE FROM ip_reputation WHERE ip = ?", ip)
	if err != nil {
		return fmt.Errorf("delete ip_reputation: %w", err)
	}
	return nil
}
