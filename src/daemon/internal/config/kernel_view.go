package config

import "github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"

// KernelConfigChange 把这份配置投影成内核 SET_CONFIG 载荷。
//
// # 为什么投影长在配置模型上
//
// 配置的权威在守护进程，而它有两个下发时刻：API 写入（组合根同步发给内核，好把内核的
// 采纳结论带回响应）与执行体的重载/回滚（手工编辑文件、SIGHUP、SIGUSR1 都走这条路）。
// 两条路必须投出同一个形状，否则同一份配置文件会因为「谁先看见它」而在内核里落成两种值。
//
// # 带上的位（十个）
//
// ban_time ← defaults.ban_time；rate_window_seconds ← ddos.check_interval；
// max_packets_per_second ← ddos.global_conn_rate；六个协议上限 ← ddos.max_*_per_second；
// ddos_ban_duration ← ddos.auto_ban_duration。
//
// 越界的取值不在这里预筛：内核的校验规则（ban_time 1..31536000、rate_window 1..60、
// 八个速率上限非零）会用 ConfigAck.RejectedFlags 逐位回答「哪条没收下」，那份回包就是
// 运维要看的诊断。在这里替内核把位剔掉，等于把一个配置错误变成「响应里没有提到它」。
//
// # 刻意不带的位
//
//   - max_bytes_per_second：配置模型里没有对应字段（ddos 段只有包速率，没有字节速率）。
//     零值会被内核拒绝，硬凑一个来源等于替用户决定字节上限。
//   - dynamic_threshold：内核把 ratio_x100 与启用位捆在同一位上——ratio 为 0 时整位被拒，
//     ratio 非 0 时**同时**覆写 dynamic_threshold_enabled。配置里的 ddos.dynamic_threshold
//     只是一个布尔、没有倍数，因此无论带什么 ratio 都会顺改掉内核的启用状态。等配置模型
//     补上倍数再进这张表。
//   - baseline：载荷里那两个字段是 EWMA 的**采样输入**（fw_rate_update_baseline，α=1/100），
//     不是配置项。从配置发一次等于往滑动平均里注一个样本，发 0 会把已学到的基线拉向 0。
//     它属于测量循环，不属于配置写入。
//   - ban_time 的永久取值：defaults.ban_time = -1 在守护进程侧表示永久封禁，而内核的
//     fw_ban_time 是 u32 秒数，没有「永久」这个取值。把 -1 转成 42 亿发过去，收到的拒绝位
//     说的是一个不存在的 bug；这一位直接不发，永久语义留在每条封禁指令的 duration 里。
//
// 其余配置项（ddos.enabled / static_threshold / ddos_detection / max_bans_per_second /
// max_rate_entries / auto_ban_threshold / baseline_warmup_samples / protect_open_ports）
// 在契约的 ConfigFlags 表里根本没有对应位，所以不是「这条路没接通」，而是这条路上没有门。
// 其中几个还是模块参数：内核只在 init 时读一次，运行期写 sysfs 不会改变已生效的容量。
func (c *Config) KernelConfigChange() contract.SetConfig {
	flags := contract.ConfigFlagRateWindow |
		contract.ConfigFlagMaxPPS |
		contract.ConfigFlagMaxSYN |
		contract.ConfigFlagMaxUDP |
		contract.ConfigFlagMaxICMP |
		contract.ConfigFlagMaxACK |
		contract.ConfigFlagMaxRST |
		contract.ConfigFlagMaxFIN

	change := contract.SetConfig{
		ConfigPayload: contract.ConfigPayload{
			RateWindowSeconds:   c.Ddos.CheckInterval,
			MaxPacketsPerSecond: uint64(c.Ddos.GlobalConnRate),
			MaxSynPerSecond:     uint64(c.Ddos.MaxSynPerSecond),
			MaxUDPPerSecond:     uint64(c.Ddos.MaxUDPPerSecond),
			MaxICMPPerSecond:    uint64(c.Ddos.MaxICMPPerSecond),
			MaxACKPerSecond:     uint64(c.Ddos.MaxACKPerSecond),
			MaxRSTPerSecond:     uint64(c.Ddos.MaxRSTPerSecond),
			MaxFINPerSecond:     uint64(c.Ddos.MaxFINPerSecond),
		},
	}

	if c.DefaultBanTime >= 0 {
		flags |= contract.ConfigFlagBanTime
		change.BanTime = uint32(c.DefaultBanTime)
	}
	// ddos_ban_duration 在内核侧没有任何校验（fw_nl_apply_config 直接 WRITE_ONCE），而 0 的
	// 含义是「回落到 fw_ban_time」。它不会被拒绝位图挡回来，所以只能不发：配置没给出时长时
	// 保留内核现状，比把它清零更接近用户的意图。
	if c.Ddos.AutoBanDuration != 0 {
		flags |= contract.ConfigFlagDdosBanDuration
		change.DdosBanDuration = c.Ddos.AutoBanDuration
	}
	change.Flags = flags
	return change
}
