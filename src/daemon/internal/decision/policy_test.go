package decision

import (
	"net/netip"
	"testing"
)

func addr(t *testing.T, text string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(text)
	if err != nil {
		t.Fatalf("测试地址 %q 非法: %v", text, err)
	}
	return a
}

func TestIsPeakHoursCoversNineToEighteenExclusive(t *testing.T) {
	cases := map[uint32]bool{
		0: false, 8: false, 9: true, 12: true, 17: true, 18: false, 23: false,
	}
	for hour, want := range cases {
		if got := IsPeakHours(hour); got != want {
			t.Errorf("IsPeakHours(%d)=%v, want %v", hour, got, want)
		}
	}
}

func TestReputationMultiplierLadder(t *testing.T) {
	cases := map[uint32]float64{
		0: 0.5, 49: 0.5, 50: 0.8, 79: 0.8, 80: 1.0, 100: 1.0,
	}
	for score, want := range cases {
		if got := ReputationMultiplier(score); got != want {
			t.Errorf("ReputationMultiplier(%d)=%v, want %v", score, got, want)
		}
	}
}

func TestIsInternalAcceptsOnlyPrivateRanges(t *testing.T) {
	internal := []string{
		"10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255",
		"192.168.0.1", "192.168.255.255",
		"fc00::1", "fd12:3456::1",
	}
	for _, text := range internal {
		if !IsInternal(addr(t, text)) {
			t.Errorf("%s 应判定为内网", text)
		}
	}

	external := []string{
		"9.255.255.255", "11.0.0.1",
		"172.15.255.255", "172.32.0.1",
		"192.167.255.255", "192.169.0.1",
		"8.8.8.8", "100.64.0.1",
		"fb00::1", "fe80::1", "2001:db8::1",
	}
	for _, text := range external {
		if IsInternal(addr(t, text)) {
			t.Errorf("%s 不应判定为内网", text)
		}
	}
}

func TestEffectiveThresholdScalesAndNeverReachesZero(t *testing.T) {
	cases := []struct {
		name       string
		maxRetries uint32
		peak       bool
		internal   bool
		score      uint32
		want       uint32
	}{
		{"基准", 3, false, false, 100, 3},
		{"高峰 ×1.5", 3, true, false, 100, 5},
		{"内网 ×2.0", 3, false, true, 100, 6},
		{"高峰 + 内网 = ×3.0", 3, true, true, 100, 9},
		{"信誉 50 档 ×0.8", 3, false, false, 50, 3},
		{"信誉低档 ×0.5", 3, false, false, 0, 2},
		{"低信誉 + 高峰 + 内网", 3, true, true, 0, 5},
		{"阈值 0 仍至少为 1", 0, false, false, 100, 1},
		{"阈值 1 且系数小于 1 时上取整为 1", 1, false, false, 0, 1},
	}
	for _, c := range cases {
		got := EffectiveThreshold(c.maxRetries, c.peak, c.internal, c.score)
		if got != c.want {
			t.Errorf("%s: EffectiveThreshold=%d, want %d", c.name, got, c.want)
		}
		if got == 0 {
			t.Errorf("%s: 阈值不得为 0，否则封禁触发点无定义", c.name)
		}
	}
}

func TestProgressiveDurationLadder(t *testing.T) {
	cases := map[uint32]uint32{0: 600, 1: 1800, 2: 86400, 3: 0, 99: 0}
	for prior, want := range cases {
		if got := ProgressiveDuration(600, prior); got != want {
			t.Errorf("ProgressiveDuration(600, %d)=%d, want %d", prior, got, want)
		}
	}
}

func TestPlanBanFirstOffenseUsesBaseDuration(t *testing.T) {
	plan := PlanBan(600, 0, 1_000_000, 5)
	if plan.Duration != 600 || plan.IsPermanent {
		t.Fatalf("首次封禁应非永久且时长 600: %+v", plan)
	}
	if plan.ExpiresAt != 1_000_600 {
		t.Errorf("ExpiresAt=%d, want 1000600", plan.ExpiresAt)
	}
	if plan.BanCount != 1 || plan.FailCount != 5 {
		t.Errorf("计数不符: BanCount=%d FailCount=%d", plan.BanCount, plan.FailCount)
	}
	if plan.ProgressiveDuration != 600 {
		t.Errorf("ProgressiveDuration=%d, want 600", plan.ProgressiveDuration)
	}
}

func TestPlanBanEscalatesThenGoesPermanent(t *testing.T) {
	second := PlanBan(600, 1, 0, 5)
	if second.Duration != 1800 || second.IsPermanent {
		t.Errorf("第 2 次应为 1800 秒非永久: %+v", second)
	}
	third := PlanBan(600, 2, 0, 5)
	if third.Duration != 86400 || third.IsPermanent {
		t.Errorf("第 3 次应为 86400 秒非永久: %+v", third)
	}
	fourth := PlanBan(600, 3, 0, 5)
	if !fourth.IsPermanent || fourth.Duration != 0 || fourth.ExpiresAt != 0 {
		t.Errorf("第 4 次应升级为永久且无过期时刻: %+v", fourth)
	}
	if fourth.BanCount != 4 {
		t.Errorf("第 4 次后累计封禁数应为 4: %d", fourth.BanCount)
	}
}

func TestPlanBanNegativeBanTimeIsConfigLevelPermanent(t *testing.T) {
	plan := PlanBan(-1, 0, 123, 5)
	if !plan.IsPermanent || plan.Duration != 0 || plan.ExpiresAt != 0 {
		t.Errorf("ban_time<0 应为配置级永久: %+v", plan)
	}
}

// ban_time == 0 且首次：progressive == base == 0，非永久，过期时刻用 base.max(1) 兜底，
// 避免「0 秒即过期」。
//
// duration 在此退化情形下同样为 0（与 Rust 版逐字段一致，见 decision/policy.rs 的
// `duration: if is_permanent { 0 } else { progressive }`）。这里显式钉住它，避免后来者
// 把它当作笔误「顺手修正」而与 Rust 版判定产生分歧。
func TestPlanBanZeroBanTimeFallsBackToOneSecond(t *testing.T) {
	plan := PlanBan(0, 0, 500, 5)
	if plan.IsPermanent {
		t.Errorf("ban_time == 0 不是永久封禁: %+v", plan)
	}
	if plan.ExpiresAt != 501 {
		t.Errorf("ExpiresAt=%d, want 501", plan.ExpiresAt)
	}
	if plan.ProgressiveDuration != 0 {
		t.Errorf("ProgressiveDuration=%d, want 0", plan.ProgressiveDuration)
	}
	if plan.Duration != 0 {
		t.Errorf("Duration=%d, want 0（与 Rust 版一致）", plan.Duration)
	}
}
