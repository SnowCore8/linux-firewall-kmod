package persist

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/risk"
)

// RiskVectorRow 表示 ip_risk_vectors 表的一行（向量快照）。
type RiskVectorRow struct {
	IP          string `json:"ip"`
	Vector      risk.RiskVector
	LastEventAt int64 `json:"last_event_at"`
	UpdatedAt   int64 `json:"updated_at"`
}

// GetRiskVector 查询指定 IP 的当前风险向量。
//
// 返回 nil 表示该 IP 无记录（风险为 0）。
func (db *DB) GetRiskVector(ip string) (*RiskVectorRow, error) {
	var row RiskVectorRow
	err := db.conn.QueryRow(
		`SELECT ip, failure, ban, scan, bruteforce, ddos, geo, cluster, last_event_at, updated_at
		 FROM ip_risk_vectors
		 WHERE ip = ?`,
		ip,
	).Scan(
		&row.IP,
		&row.Vector.Failure,
		&row.Vector.Ban,
		&row.Vector.Scan,
		&row.Vector.Bruteforce,
		&row.Vector.DDoS,
		&row.Vector.Geo,
		&row.Vector.Cluster,
		&row.LastEventAt,
		&row.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("query risk_vector: %w", err)
	}
	return &row, nil
}

// UpsertRiskVector 插入或更新指定 IP 的风险向量。
//
// 向量快照：每次事件后更新，避免每次查询都从事件重算。
func (db *DB) UpsertRiskVector(ip string, vec risk.RiskVector, lastEventAt int64) error {
	now := time.Now().Unix()
	_, err := db.conn.Exec(
		`INSERT INTO ip_risk_vectors
		 (ip, failure, ban, scan, bruteforce, ddos, geo, cluster, last_event_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(ip) DO UPDATE SET
			failure = excluded.failure,
			ban = excluded.ban,
			scan = excluded.scan,
			bruteforce = excluded.bruteforce,
			ddos = excluded.ddos,
			geo = excluded.geo,
			cluster = excluded.cluster,
			last_event_at = excluded.last_event_at,
			updated_at = excluded.updated_at`,
		ip,
		vec.Failure,
		vec.Ban,
		vec.Scan,
		vec.Bruteforce,
		vec.DDoS,
		vec.Geo,
		vec.Cluster,
		lastEventAt,
		now,
	)
	if err != nil {
		return fmt.Errorf("upsert risk_vector: %w", err)
	}
	return nil
}

// defaultRiskVectorDecayInterval 是风险向量衰减的节拍。半衰期以天计，1 小时足够让
// 「没有新事件的 IP」也按 7 天半衰期收敛，又不至于每秒扫一遍向量表。
const defaultRiskVectorDecayInterval = time.Hour

// SetRiskVectorWeights 设置后台衰减与近零判据使用的维度权重。
//
// 由装配多维引擎的一方（Facts）写入：引擎按配置权重判定风险，库侧的衰减与清理必须
// 读同一份权重，否则两处对「同一个向量算多高风险」给出不同答案。全零权重没有意义
// （会把所有记录判成近零），按未设置处理。
func (db *DB) SetRiskVectorWeights(weights risk.DimensionWeights) {
	if weights.Failure <= 0 && weights.Ban <= 0 && weights.Scan <= 0 &&
		weights.Bruteforce <= 0 && weights.DDoS <= 0 && weights.Geo <= 0 && weights.Cluster <= 0 {
		return
	}
	db.riskWeightsMu.Lock()
	db.riskWeights = weights
	db.riskWeightsSet = true
	db.riskWeightsMu.Unlock()
}

// riskDecayWeights 返回衰减与近零判据使用的权重，未设置时用引擎默认值。
func (db *DB) riskDecayWeights() risk.DimensionWeights {
	db.riskWeightsMu.RLock()
	defer db.riskWeightsMu.RUnlock()
	if !db.riskWeightsSet {
		return risk.DefaultDimensionWeights()
	}
	return db.riskWeights
}

// BatchDecayVectors 对所有向量施加衰减（定期调用，如每小时一次）。
//
// 衰减公式：vec *= 0.5^(自上次快照写入以来的天数 / 半衰期)。
//
// 衰减在**一条 UPDATE 里**按各行自己的 updated_at 计算因子，不再「先全表读、再逐行
// 全列回写」：后者会把写回期间事件 worker 刚写入的新快照覆盖成旧值的衰减结果，谁后写
// 谁赢。单条语句与删除同处一个事务，读到的行与写回的行不会错位。
//
// 基准取 updated_at 而不是 last_event_at：向量值代表「上次写库时的风险」，每拍衰减的
// 只能是这段间隔；若每拍都按「距事件的天数」重算，一小时的节拍会把同一个衰减因子反复
// 乘上去，向量在半天内就被压到零，7 天半衰期名存实亡。last_event_at 保持原值，
// updated_at 刷成当前时刻，下一拍从这里继续。
//
// 衰减后加权和接近 0 的向量直接删除，避免数据库无限增长；权重与引擎同源。
func (db *DB) BatchDecayVectors(now int64) error {
	weights := db.riskDecayWeights()

	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("begin risk vector decay: %w", err)
	}
	defer tx.Rollback()

	decayExpr := "pow(0.5, MAX(0, ? - updated_at) / 86400.0 / ?)"
	if _, err := tx.Exec(
		`UPDATE ip_risk_vectors SET
			failure = failure * `+decayExpr+`,
			ban = ban * `+decayExpr+`,
			scan = scan * `+decayExpr+`,
			bruteforce = bruteforce * `+decayExpr+`,
			ddos = ddos * `+decayExpr+`,
			geo = geo * `+decayExpr+`,
			cluster = cluster * `+decayExpr+`,
			updated_at = ?
		 WHERE updated_at <= ?`,
		now, risk.HalfLifeDays,
		now, risk.HalfLifeDays,
		now, risk.HalfLifeDays,
		now, risk.HalfLifeDays,
		now, risk.HalfLifeDays,
		now, risk.HalfLifeDays,
		now, risk.HalfLifeDays,
		now, now,
	); err != nil {
		return fmt.Errorf("decay risk vectors: %w", err)
	}

	// 删除只处理衰减后的近零行：用衰减后的字段值判断，不依赖 updated_at 匹配，
	// 避免误删衰减期间新写入的向量（新行的 updated_at 也是 now，但字段值未被衰减）。
	if _, err := tx.Exec(
		`DELETE FROM ip_risk_vectors
		 WHERE failure * ? + ban * ? + scan * ? + bruteforce * ? + ddos * ? + geo * ? + cluster * ? < 0.01`,
		weights.Failure, weights.Ban, weights.Scan, weights.Bruteforce,
		weights.DDoS, weights.Geo, weights.Cluster,
	); err != nil {
		return fmt.Errorf("delete decayed risk vectors: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit risk vector decay: %w", err)
	}
	return nil
}

// StartRiskVectorDecayScheduler 启动周期性风险向量衰减任务。
//
// 为什么需要：内存引擎只在事件到达时衰减，而库里的旧向量没有别的写者；没有这条节拍，
// 契约声明的 7 天半衰期对「不再被命中的 IP」完全不生效，向量会一直停在最后一次事件的
// 读数上。失败只记日志不退出：衰减是后台维护，不该拖垮进程。
//
// 返回的通道在 goroutine 退出后关闭；调用方应先等它关闭再关数据库，
// 防止衰减操作写到已关闭的连接。
func (db *DB) StartRiskVectorDecayScheduler(interval time.Duration, stopCh <-chan struct{}) <-chan struct{} {
	if interval <= 0 {
		interval = defaultRiskVectorDecayInterval
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				if err := db.BatchDecayVectors(time.Now().Unix()); err != nil {
					db.logger.Error("risk vector decay failed", "error", err)
				}
			}
		}
	}()
	return done
}

// DeleteRiskVector 删除指定 IP 的向量记录。
func (db *DB) DeleteRiskVector(ip string) error {
	_, err := db.conn.Exec("DELETE FROM ip_risk_vectors WHERE ip = ?", ip)
	if err != nil {
		return fmt.Errorf("delete risk_vector: %w", err)
	}
	return nil
}

// GetAllRiskVectors 查询 IP 的风险向量（用于面板展示、导出）。
// limit <= 0 时退化为默认上限 1000，避免无界查询导致内存耗尽。
func (db *DB) GetAllRiskVectors(limit int) ([]RiskVectorRow, error) {
	const defaultLimit = 1000
	if limit <= 0 {
		limit = defaultLimit
	}
	rows, err := db.conn.Query(
		`SELECT ip, failure, ban, scan, bruteforce, ddos, geo, cluster, last_event_at, updated_at
		 FROM ip_risk_vectors
		 ORDER BY (failure + ban + scan + bruteforce + ddos + geo + cluster) DESC
		 LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query all risk_vectors: %w", err)
	}
	defer rows.Close()

	var result []RiskVectorRow
	for rows.Next() {
		var row RiskVectorRow
		if err := rows.Scan(
			&row.IP,
			&row.Vector.Failure,
			&row.Vector.Ban,
			&row.Vector.Scan,
			&row.Vector.Bruteforce,
			&row.Vector.DDoS,
			&row.Vector.Geo,
			&row.Vector.Cluster,
			&row.LastEventAt,
			&row.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan risk_vector: %w", err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate risk_vectors: %w", err)
	}
	return result, nil
}

// CountRiskVectors 返回风险向量表的总行数（与 GetAllRiskVectors 的筛选条件一致：
// 当前表没有额外过滤，COUNT(*) 即全集）。
//
// 列表接口的 total 要用它：拿本次返回的条数当 total，会在记录超过一页时把「共 N 条」
// 永远钉在页大小上。
func (db *DB) CountRiskVectors() (int, error) {
	var count int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM ip_risk_vectors`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count risk_vectors: %w", err)
	}
	return count, nil
}

// GetHighRiskIPs 查询风险值超过阈值的 IP（用于自动封禁）。
//
// threshold 是加权和阈值，limit 限制返回数量。
func (db *DB) GetHighRiskIPs(threshold float64, limit int) ([]RiskVectorRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.conn.Query(
		`SELECT ip, failure, ban, scan, bruteforce, ddos, geo, cluster, last_event_at, updated_at
		 FROM ip_risk_vectors
		 WHERE (failure + ban + scan + bruteforce + ddos + geo + cluster) >= ?
		 ORDER BY (failure + ban + scan + bruteforce + ddos + geo + cluster) DESC
		 LIMIT ?`,
		threshold, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query high risk IPs: %w", err)
	}
	defer rows.Close()

	var result []RiskVectorRow
	for rows.Next() {
		var row RiskVectorRow
		if err := rows.Scan(
			&row.IP,
			&row.Vector.Failure,
			&row.Vector.Ban,
			&row.Vector.Scan,
			&row.Vector.Bruteforce,
			&row.Vector.DDoS,
			&row.Vector.Geo,
			&row.Vector.Cluster,
			&row.LastEventAt,
			&row.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan risk_vector: %w", err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate risk_vectors: %w", err)
	}
	return result, nil
}
