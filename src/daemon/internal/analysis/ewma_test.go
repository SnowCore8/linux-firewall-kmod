package analysis

import (
	"math"
	"testing"
	"time"
)

// TestDecayAlphaScalesWithInterval 回归：5 秒采样必须用 5 秒的等效系数，
// 否则 5s/60s/300s 三个窗口会被放大成约 25s/5min/25min。
func TestDecayAlphaScalesWithInterval(t *testing.T) {
	if got := decayAlpha(1, ShortWindow); math.Abs(got-1.0/3) > 0.01 {
		t.Fatalf("dt=1s 的短期系数 = %v，期望约 0.333", got)
	}
	if got := decayAlpha(5, ShortWindow); got < 0.7 {
		t.Fatalf("dt=5s 的短期系数 = %v，期望 > 0.7", got)
	}
	if got := decayAlpha(5, LongWindow); got > 0.05 {
		t.Fatalf("dt=5s 的长期系数 = %v，期望 < 0.05", got)
	}
}

// feedAt 模拟「上一个样本在 at 时刻」，使 Sample 的 dt 可预测。
func feedAt(s *EWMASmoother, rate float64, at time.Time) {
	s.mu.Lock()
	s.lastSampleAt = at
	s.mu.Unlock()
	s.Sample(rate)
}

// TestZeroBaselineDoesNotFreeze 回归：启动即空闲（首样本为 0）后，第一个非零样本
// 不能因为「超过 0×3」而被判成异常并冻结基线。
func TestZeroBaselineDoesNotFreeze(t *testing.T) {
	s := NewEWMASmoother()
	s.Sample(0)
	feedAt(s, 10, time.Now().Add(-5*time.Second))

	if s.Snapshot().Frozen {
		t.Fatal("零基线的首个非零样本不应触发冻结")
	}
	if s.Snapshot().Baseline <= 0 {
		t.Fatal("非零样本应被学习进基线")
	}
}

// TestAnomalySuppressedDuringWarmup 回归：预热期内不报异常；基线收敛后可正常报警。
func TestAnomalySuppressedDuringWarmup(t *testing.T) {
	s := NewEWMASmoother()
	s.Sample(0)

	// 预热期内喂 60 个 5 秒间隔的稳定样本，让长期窗口收敛（300 秒 ≈ 60 个样本）。
	// 预热期内样本不得冻结基线，否则后续的「稳定流量」读数建立在未收敛的基线上。
	for i := 0; i < 60; i++ {
		feedAt(s, 10, time.Now().Add(-5*time.Second))
	}
	if s.Snapshot().Frozen {
		t.Fatal("预热期内基线更新不应被冻结")
	}

	// 预热期结束（把首样本时间提前到 10 分钟前），稳定流量不应报异常。
	s.mu.Lock()
	s.firstSampleAt = time.Now().Add(-10 * time.Minute)
	s.mu.Unlock()
	if lvl := s.AnomalyLevel(); lvl != 0 {
		t.Fatalf("稳定流量下异常级别 = %d，期望 0", lvl)
	}

	// 突发：短期远超已收敛的基线。
	feedAt(s, 200, time.Now().Add(-5*time.Second))
	if lvl := s.AnomalyLevel(); lvl < 2 {
		t.Fatalf("突发下异常级别 = %d，期望 >= 2", lvl)
	}
}

// TestWarmupSuppressesColdStartAlarm 回归：刚启动时 short/baseline 天然偏大，
// 预热期内必须返回 0。
func TestWarmupSuppressesColdStartAlarm(t *testing.T) {
	s := NewEWMASmoother()
	s.Sample(0)
	feedAt(s, 50, time.Now().Add(-5*time.Second))
	if lvl := s.AnomalyLevel(); lvl != 0 {
		t.Fatalf("预热期内异常级别 = %d，期望 0", lvl)
	}
}
