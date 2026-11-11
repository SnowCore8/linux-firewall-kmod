package persist

import (
	"fmt"
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

// CountRiskVectors 是全表条数，不是本次列表查询的返回条数。
func TestCountRiskVectors(t *testing.T) {
	db := newTestDB(t)
	now := time.Now().Unix()
	for i := 1; i <= 3; i++ {
		ip := "203.0.113." + string(rune('0'+i))
		if err := db.UpsertRiskVector(ip, risk.RiskVector{Failure: float64(i)}, now); err != nil {
			t.Fatalf("写向量 %s 失败: %v", ip, err)
		}
	}
	got, err := db.CountRiskVectors()
	if err != nil {
		t.Fatalf("CountRiskVectors 失败: %v", err)
	}
	if got != 3 {
		t.Fatalf("CountRiskVectors = %d，期望 3", got)
	}
}

// 衰减与事件写入并发时，进程内的新快照不能被「读旧值再全列写回」覆盖掉。
//
// 旧实现先全表读、再逐行把读到的旧值衰减后写回；这中间 worker 写入的新向量会被后写
// 的旧值盖掉，谁后写谁赢。这里让衰减循环与 upsert 循环并行，每次 upsert 之后立刻读回：
// 新实现是一条原子 UPDATE（按各行 updated_at 现算因子），读到的只会是刚写入的 100
// 或它的同秒衰减（≈100），不会退回旧快照的 0/1。
func TestBatchDecayVectorsDoesNotOverwriteConcurrentUpsert(t *testing.T) {
	db := newTestDB(t)
	const target = "203.0.113.70"
	if err := db.UpsertRiskVector(target, risk.RiskVector{Failure: 1}, time.Now().Unix()); err != nil {
		t.Fatalf("预置向量失败: %v", err)
	}
	ageVector(t, db, target, 7*24*time.Hour)

	// 拉长旧实现的读-写窗口：表里多放一些行，衰减一趟需要更久。
	for i := 0; i < 200; i++ {
		ip := fmt.Sprintf("203.0.114.%d", i)
		if err := db.UpsertRiskVector(ip, risk.RiskVector{Failure: 100}, time.Now().Unix()); err != nil {
			t.Fatalf("填充向量 %s 失败: %v", ip, err)
		}
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := db.BatchDecayVectors(time.Now().Unix()); err != nil {
				t.Errorf("并发衰减失败: %v", err)
				return
			}
		}
	}()

	const rounds = 300
	var lost bool
	for i := 0; i < rounds; i++ {
		if err := db.UpsertRiskVector(target, risk.RiskVector{Failure: 100}, time.Now().Unix()); err != nil {
			t.Errorf("第 %d 轮写向量失败: %v", i, err)
			break
		}
		row, err := db.GetRiskVector(target)
		if err != nil {
			t.Errorf("第 %d 轮读向量失败: %v", i, err)
			break
		}
		if row == nil || row.Vector.Failure < 99 {
			got := 0.0
			if row != nil {
				got = row.Vector.Failure
			}
			t.Errorf("第 %d 轮 upsert 后 failure = %v，期望 ≈100：并发衰减把旧快照写了回来", i, got)
			lost = true
			break
		}
	}
	close(stop)
	<-done
	if lost {
		t.Log("并发窗口内出现过旧快照覆盖")
	}
}

// 近零清理由注入的权重决定：权重只算 ban 时，只剩 failure 的记录就是近零。
//
// 权重必须与引擎同源，库里再写死一份默认值会让同一向量在判定与清理两处得到不同答案。
func TestBatchDecayVectorsUsesInjectedWeights(t *testing.T) {
	db := newTestDB(t)
	ip := "203.0.113.71"
	if err := db.UpsertRiskVector(ip, risk.RiskVector{Failure: 100}, time.Now().Unix()); err != nil {
		t.Fatalf("写向量失败: %v", err)
	}
	db.SetRiskVectorWeights(risk.DimensionWeights{Ban: 1})

	if err := db.BatchDecayVectors(time.Now().Unix()); err != nil {
		t.Fatalf("衰减失败: %v", err)
	}
	row, err := db.GetRiskVector(ip)
	if err != nil {
		t.Fatalf("读向量失败: %v", err)
	}
	if row != nil {
		t.Fatalf("failure=100 但权重只算 ban 时应判近零删除，实际 failure=%v", row.Vector.Failure)
	}
}
