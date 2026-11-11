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

func TestReputationAdjustmentLadder(t *testing.T) {
	cases := map[uint32]int{
		0: -2, 49: -2, 50: -1, 79: -1, 80: 0, 100: 0,
	}
	for score, want := range cases {
		if got := ReputationAdjustment(score); got != want {
			t.Errorf("ReputationAdjustment(%d)=%v, want %v", score, got, want)
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

// TestIsInternal_IPv4Mapped 验证 IPv4-mapped IPv6 地址先 Unmap 再走 IPv4 判据，
// 否则 ::ffff:10.0.0.1 这类内网地址无法获得阈值放宽，易被误封。
func TestIsInternal_IPv4Mapped(t *testing.T) {
	internal := []string{
		"::ffff:10.0.0.1",
		"::ffff:10.255.255.255",
		"::ffff:172.16.0.1",
		"::ffff:172.31.255.255",
		"::ffff:192.168.0.1",
		"::ffff:192.168.1.1",
		"::ffff:192.168.255.255",
	}
	for _, s := range internal {
		if !IsInternal(addr(t, s)) {
			t.Errorf("%s 应判定为内网（Unmap 后走 IPv4 判据）", s)
		}
	}

	// IPv4-mapped 的外网地址不应判为内网
	external := []string{
		"::ffff:8.8.8.8",
		"::ffff:9.255.255.255",
		"::ffff:11.0.0.1",
		"::ffff:172.15.255.255",
		"::ffff:172.32.0.1",
		"::ffff:192.167.255.255",
		"::ffff:192.169.0.1",
	}
	for _, s := range external {
		if IsInternal(addr(t, s)) {
			t.Errorf("%s 不应判定为内网", s)
		}
	}
}

func TestEffectiveThresholdScalesAndNeverReachesZero(t *testing.T) {
	// 加法模型：base + peak(+2) + internal(+3) + reputation(-2/−1/0)
	cases := []struct {
		name       string
		maxRetries uint32
		peak       bool
		internal   bool
		score      uint32
		want       uint32
	}{
		{"基准", 3, false, false, 100, 3},
		{"高峰 +2", 3, true, false, 100, 5},
		{"内网 +3", 3, false, true, 100, 6},
		{"高峰 + 内网 = +5", 3, true, true, 100, 8},
		{"信誉 50 档 -1", 3, false, false, 50, 2},
		{"信誉低档 -2", 3, false, false, 0, 1},
		{"低信誉 + 高峰 + 内网", 3, true, true, 0, 6},
		{"阈值 0 仍至少为 1", 0, false, false, 100, 1},
		{"阈值 1 且调整为负时至少为 1", 1, false, false, 0, 1},
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
// duration 在此退化情形下同样为 0（草案字段对照：非永久时 `duration = progressive`）。
// 这里显式钉住它，避免后来者把它当作笔误「顺手修正」而改变判定。
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
		t.Errorf("Duration=%d, want 0", plan.Duration)
	}
}

func TestReputationAdjustment(t *testing.T) {
	cases := map[uint32]int{
		0: -2, 49: -2, 50: -1, 79: -1, 80: 0, 100: 0,
	}
	for score, want := range cases {
		if got := ReputationAdjustment(score); got != want {
			t.Errorf("ReputationAdjustment(%d)=%d, want %d", score, got, want)
		}
	}
}

func TestEffectiveThresholdAdditiveModel(t *testing.T) {
	cases := []struct {
		name       string
		maxRetries uint32
		peak       bool
		internal   bool
		score      uint32
		want       uint32
	}{
		{"基准", 5, false, false, 100, 5},
		{"高峰期 +2", 5, true, false, 100, 7},
		{"内网 +3", 5, false, true, 100, 8},
		{"高峰 + 内网 = +5", 5, true, true, 100, 10},
		{"中信誉 -1", 5, false, false, 60, 4},
		{"低信誉 -2", 5, false, false, 30, 3},
		{"内网 + 低信誉 (Bug 修复)", 5, false, true, 30, 6},
		{"高峰 + 内网 + 低信誉", 5, true, true, 30, 8},
		{"阈值 0 仍至少为 1", 0, false, false, 100, 1},
		{"最小阈值 1", 1, false, false, 0, 1},
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

// TestInternalLowReputationOutranksExternal 验证加法模型下系数不会互相抵消。
//
// 内网(+3) + 低信誉(-2) = +1，内网低信誉 IP 的阈值高于外网低信誉 IP。
func TestInternalLowReputationOutranksExternal(t *testing.T) {
	base := uint32(5)

	// 外网低信誉
	externalLowRep := EffectiveThreshold(base, false, false, 30)

	// 内网低信誉
	internalLowRep := EffectiveThreshold(base, false, true, 30)

	if internalLowRep <= externalLowRep {
		t.Errorf("内网低信誉 IP 阈值(%d)应大于外网低信誉 IP 阈值(%d)",
			internalLowRep, externalLowRep)
	}

	// 验证具体数值
	if externalLowRep != 3 {
		t.Errorf("外网低信誉阈值=%d, want 3 (base=5, adj=-2)", externalLowRep)
	}
	if internalLowRep != 6 {
		t.Errorf("内网低信誉阈值=%d, want 6 (base=5, internal=+3, adj=-2)", internalLowRep)
	}
}
