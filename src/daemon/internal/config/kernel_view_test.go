package config

import (
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
)

// TestKernelConfigChangeProjectsDefaultConfig 是投影表的主干：默认配置投出十个位、
// 每个位带上对应配置项的值。
func TestKernelConfigChangeProjectsDefaultConfig(t *testing.T) {
	cfg := Default()
	change := cfg.KernelConfigChange()

	want := contract.ConfigFlagBanTime | contract.ConfigFlagRateWindow | contract.ConfigFlagMaxPPS |
		contract.ConfigFlagMaxSYN | contract.ConfigFlagMaxUDP | contract.ConfigFlagMaxICMP |
		contract.ConfigFlagMaxACK | contract.ConfigFlagMaxRST | contract.ConfigFlagMaxFIN |
		contract.ConfigFlagDdosBanDuration
	if change.Flags != want {
		t.Errorf("Flags = %s，期望 %s", change.Flags, want)
	}
	if change.BanTime != uint32(cfg.DefaultBanTime) {
		t.Errorf("BanTime = %d，期望 defaults.ban_time %d", change.BanTime, cfg.DefaultBanTime)
	}
	if change.RateWindowSeconds != cfg.Ddos.CheckInterval {
		t.Errorf("RateWindowSeconds = %d，期望 ddos.check_interval %d", change.RateWindowSeconds, cfg.Ddos.CheckInterval)
	}
	pairs := []struct {
		name string
		got  uint64
		want uint32
	}{
		{"max_packets_per_second", change.MaxPacketsPerSecond, cfg.Ddos.GlobalConnRate},
		{"max_syn_per_second", change.MaxSynPerSecond, cfg.Ddos.MaxSynPerSecond},
		{"max_udp_per_second", change.MaxUDPPerSecond, cfg.Ddos.MaxUDPPerSecond},
		{"max_icmp_per_second", change.MaxICMPPerSecond, cfg.Ddos.MaxICMPPerSecond},
		{"max_ack_per_second", change.MaxACKPerSecond, cfg.Ddos.MaxACKPerSecond},
		{"max_rst_per_second", change.MaxRSTPerSecond, cfg.Ddos.MaxRSTPerSecond},
		{"max_fin_per_second", change.MaxFINPerSecond, cfg.Ddos.MaxFINPerSecond},
	}
	for _, p := range pairs {
		if p.got != uint64(p.want) {
			t.Errorf("%s = %d，期望配置里的 %d", p.name, p.got, p.want)
		}
	}
	if change.DdosBanDuration != cfg.Ddos.AutoBanDuration {
		t.Errorf("DdosBanDuration = %d，期望 ddos.auto_ban_duration %d", change.DdosBanDuration, cfg.Ddos.AutoBanDuration)
	}
	// 投影不改动被投影的配置：下发的是这份 cfg 的读数，而 cfg 在执行体手里继续被用。
	if cfg.DefaultBanTime != Default().DefaultBanTime {
		t.Errorf("投影改掉了源配置：DefaultBanTime = %d", cfg.DefaultBanTime)
	}
}

// TestKernelConfigChangeSkipsUnrepresentableBanTime 盯住 -1（永久封禁）。
//
// 内核的 fw_ban_time 是 u32 秒数，没有「永久」这个取值；把 -1 转成 42 亿发过去，收到的
// 拒绝位说的是一个不存在的 bug。永久语义留在每条封禁指令的 duration 里。
func TestKernelConfigChangeSkipsUnrepresentableBanTime(t *testing.T) {
	cfg := Default()
	cfg.DefaultBanTime = -1
	change := cfg.KernelConfigChange()

	if change.Flags&contract.ConfigFlagBanTime != 0 {
		t.Error("ban_time = -1 仍然带着 ConfigFlagBanTime 下发")
	}
	if change.BanTime != 0 {
		t.Errorf("不带位时载荷里也该是零值，实际 %d", change.BanTime)
	}
	// 其余位不受影响：速率上限与窗口照样是配置里的值。
	if change.Flags&contract.ConfigFlagMaxPPS == 0 {
		t.Error("跳过 ban_time 把无关的位也一起丢了")
	}
}

// TestKernelConfigChangeSkipsZeroDdosBanDuration：这一位内核**不做校验**，0 的含义是
// 「回落到 fw_ban_time」，不会被拒绝位图挡回来，所以只能在投影这里不发。
func TestKernelConfigChangeSkipsZeroDdosBanDuration(t *testing.T) {
	cfg := Default()
	cfg.Ddos.AutoBanDuration = 0
	change := cfg.KernelConfigChange()

	if change.Flags&contract.ConfigFlagDdosBanDuration != 0 {
		t.Error("auto_ban_duration = 0 仍然带着该位下发（内核会把 0 写成「回落到 fw_ban_time」）")
	}
	if change.Flags&contract.ConfigFlagBanTime == 0 {
		t.Error("跳过 ddos 时长把 ban_time 位也丢了")
	}
}

// TestKernelConfigChangeNeverCarriesBitsWithoutSource 定住三个刻意缺席的位：
// 即便把配置里所有能填的值都填满，它们也不该出现。
func TestKernelConfigChangeNeverCarriesBitsWithoutSource(t *testing.T) {
	cfg := Default()
	cfg.DefaultBanTime = 3600
	cfg.Ddos = DefaultDdosConfig()
	cfg.Ddos.DynamicThreshold = true
	cfg.Ddos.StaticThreshold = true
	change := cfg.KernelConfigChange()

	for _, bit := range []contract.ConfigFlags{
		contract.ConfigFlagMaxBPS,
		contract.ConfigFlagDynamicThreshold,
		contract.ConfigFlagBaselineUpdate,
	} {
		if change.Flags&bit != 0 {
			t.Errorf("投影带上了 %s（理由见 KernelConfigChange 的注释）", bit.Names())
		}
	}
	if change.MaxBytesPerSecond != 0 || change.BaselinePPS != 0 || change.BaselineBPS != 0 ||
		change.DynamicThresholdFlags != 0 || change.DynamicThresholdRatioX100 != 0 {
		t.Errorf("缺席的位在载荷里也必须是零值，实际 %+v", change.ConfigPayload)
	}
}
