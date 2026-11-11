package persist

import (
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/risk"
)

// ageVector 把快照写入时间改到 age 之前：UpsertRiskVector 总是把 updated_at 记成当前
// 时刻，而衰减的基准正是它，测试只能直接改库来模拟「这些向量放了多久没人碰」。
func ageVector(t *testing.T, db *DB, ip string, age time.Duration) {
	t.Helper()
	if _, err := db.conn.Exec(
		`UPDATE ip_risk_vectors SET updated_at = ? WHERE ip = ?`,
		time.Now().Add(-age).Unix(), ip,
	); err != nil {
		t.Fatalf("调整向量更新时间失败: %v", err)
	}
}

// 7 天半衰期要真的把库里的读数减半，衰减到接近零的记录也要删掉。
func TestBatchDecayVectorsAppliesHalfLife(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().Unix()
	ip := "198.51.100.10"
	if err := db.UpsertRiskVector(ip, risk.RiskVector{Failure: 8, Ban: 2}, now); err != nil {
		t.Fatalf("写向量失败: %v", err)
	}
	ageVector(t, db, ip, 7*24*time.Hour)

	oldIP := "198.51.100.11"
	if err := db.UpsertRiskVector(oldIP, risk.RiskVector{Failure: 1}, now); err != nil {
		t.Fatalf("写旧向量失败: %v", err)
	}
	ageVector(t, db, oldIP, 100*24*time.Hour)

	if err := db.BatchDecayVectors(now); err != nil {
		t.Fatalf("衰减失败: %v", err)
	}

	row, err := db.GetRiskVector(ip)
	if err != nil || row == nil {
		t.Fatalf("读衰减后的向量失败: %v（row=%v）", err, row)
	}
	if row.Vector.Failure < 3.9 || row.Vector.Failure > 4.1 {
		t.Fatalf("7 天后 failure = %v，期望 ~4（半衰期减半）", row.Vector.Failure)
	}
	if row.Vector.Ban < 0.9 || row.Vector.Ban > 1.1 {
		t.Fatalf("7 天后 ban = %v，期望 ~1", row.Vector.Ban)
	}
	if row.LastEventAt != now {
		t.Fatalf("last_event_at = %d，期望保持事件时刻 %d（衰减不改事件时间）", row.LastEventAt, now)
	}

	gone, err := db.GetRiskVector(oldIP)
	if err != nil {
		t.Fatalf("读已删除向量失败: %v", err)
	}
	if gone != nil {
		t.Fatalf("百年未更新的向量仍存在（total=%v），期望衰减到阈值下被删除", gone.Vector.Failure)
	}
}

// 衰减必须被调度器真的跑起来：BatchDecayVectors 此前没有任何调用者，半衰期不生效。
func TestRiskVectorDecaySchedulerRuns(t *testing.T) {
	db := newTestDB(t)
	ip := "198.51.100.12"
	if err := db.UpsertRiskVector(ip, risk.RiskVector{Failure: 8}, time.Now().Unix()); err != nil {
		t.Fatalf("写向量失败: %v", err)
	}
	ageVector(t, db, ip, 7*24*time.Hour)

	stop := make(chan struct{})
	done := db.StartRiskVectorDecayScheduler(10*time.Millisecond, stop)
	defer func() {
		close(stop)
		<-done
	}()

	waitUntil(t, 2*time.Second, func() bool {
		row, err := db.GetRiskVector(ip)
		return err == nil && row != nil && row.Vector.Failure > 3.9 && row.Vector.Failure < 4.1
	})
}
