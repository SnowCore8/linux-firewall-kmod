// Package jail 承载 jail 的配置后处理：智能默认、完整性校验、正则编译与规则集构建。
//
// 与 Rust 版的分工一致：`config` 只负责把 YAML 解析成结构体，凡是「需要跨字段
// 知识或需要编译」的步骤都放在这里，并由启动流程按固定顺序调用。
package jail

import (
	"fmt"
	"strings"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

// MinPrefixV4 是集群检测允许的最短 IPv4 聚合前缀。
//
// 命中后封的是整个聚合网段，前缀过短会一次封掉远超预期的地址范围（`/1` 即半个
// IPv4 空间）。`/16` 是「至少一个机构级网段」的保守下限，实际用途（`/24`、`/16`）
// 都在其上。
const MinPrefixV4 uint8 = 16

// MinPrefixV6 是集群检测允许的最短 IPv6 聚合前缀（与 IPv4 同理，`/32` 对应一个站点级网段）。
const MinPrefixV6 uint8 = 32

// Validate 校验配置完整性。
//
// 调用时机固定：在 ApplySmartDefaults 之后、启动采集之前。智能默认可能填上
// 校验所依赖的字段，顺序颠倒会把「本该推断出的合法值」判成缺失。
func Validate(cfg *config.Config) error {
	if len(cfg.Jails) == 0 || len(cfg.Jails) > config.MaxJails {
		return fmt.Errorf("invalid jail_count=%d (must be 1..%d)", len(cfg.Jails), config.MaxJails)
	}
	if cfg.Interval == 0 || cfg.Interval > 60 {
		return fmt.Errorf("invalid interval=%d (must be 1..60)", cfg.Interval)
	}
	// log_max_files 含当前文件，0 意味着「一片都不留」；log_max_size_mb=0 表示关闭轮转。
	if cfg.LogMaxFiles == 0 {
		return fmt.Errorf("log_max_files is 0 (must be >= 1)")
	}
	// metrics_port 是 u16，范围由类型系统保证：0 = 禁用，1..=65535 = 监听。
	if cfg.DefaultMaxRetries == 0 {
		return fmt.Errorf("default_max_retries is 0")
	}
	if cfg.DefaultFindTime == 0 {
		return fmt.Errorf("default_findtime is 0")
	}

	for i := range cfg.Jails {
		j := &cfg.Jails[i]
		if !j.Enabled {
			continue
		}
		if len(j.LogFiles) == 0 {
			return fmt.Errorf("Jail '%s' has no log files", j.Name)
		}
		if j.MaxRetries == 0 {
			return fmt.Errorf("Jail '%s' has max_retries=0", j.Name)
		}
		if j.FindTime == 0 {
			return fmt.Errorf("Jail '%s' has findtime=0", j.Name)
		}
		if j.BanTime == 0 || j.BanTime < -1 {
			return fmt.Errorf(
				"Jail '%s' has invalid ban_time=%d (use -1 for permanent or >0 for timed)",
				j.Name, j.BanTime)
		}
		if err := validateCluster(j); err != nil {
			return err
		}
	}
	return nil
}

// validateCluster 校验集群检测参数。
//
// `window` / `min_ips` 为 0 会让检测直接返回空（退化分支），用户以为开着而实际
// 永不触发，故按硬错误拒绝而非静默接受。
func validateCluster(j *config.Jail) error {
	c := j.Cluster
	if !c.Enabled {
		return nil
	}
	if c.Window == 0 {
		return fmt.Errorf("Jail '%s' has cluster.window=0 (must be >0 when cluster.enabled)", j.Name)
	}
	if c.MinIPs == 0 {
		return fmt.Errorf("Jail '%s' has cluster.min_ips=0 (must be >0 when cluster.enabled)", j.Name)
	}
	if c.PrefixV4 > 32 {
		return fmt.Errorf("Jail '%s' has cluster.prefix_v4=%d (must be <=32)", j.Name, c.PrefixV4)
	}
	if c.PrefixV6 > 128 {
		return fmt.Errorf("Jail '%s' has cluster.prefix_v6=%d (must be <=128)", j.Name, c.PrefixV6)
	}
	// 下界是安全约束而非风格约束：命中后封的是整个聚合网段，`prefix_v4=1` 会把
	// `203.0.113.7` 归一到 `128.0.0.0/1`。
	if c.PrefixV4 < MinPrefixV4 {
		return fmt.Errorf(
			"Jail '%s' has cluster.prefix_v4=%d (must be >=%d): 封禁按整个聚合网段下发，前缀过短会波及远超预期的地址范围",
			j.Name, c.PrefixV4, MinPrefixV4)
	}
	if c.PrefixV6 < MinPrefixV6 {
		return fmt.Errorf(
			"Jail '%s' has cluster.prefix_v6=%d (must be >=%d): 封禁按整个聚合网段下发，前缀过短会波及远超预期的地址范围",
			j.Name, c.PrefixV6, MinPrefixV6)
	}
	return nil
}

// ClusterWarning 返回集群配置中「合法但会失去区分度」的项，供调用方记警告。
//
// `max_per_ip` 超过 `min_ips` 时不拒绝（仍是合法配置），但第二条判据「每 IP 失败
// 数 ≤ max_per_ip」会失去区分度：每 IP 允许的失败数一旦赶上命中门槛，高频出口
// （CGNAT、单出口多用户）也会被算作低频而误封。
func ClusterWarning(j *config.Jail) string {
	if !j.Cluster.Enabled {
		return ""
	}
	if j.Cluster.MaxPerIP <= j.Cluster.MinIPs {
		return ""
	}
	return fmt.Sprintf(
		"jail=%s cluster.max_per_ip=%d 大于 min_ips=%d，判定会误纳高频出口（建议 max_per_ip <= min_ips）",
		j.Name, j.Cluster.MaxPerIP, j.Cluster.MinIPs)
}

// JoinErrors 把多条错误正文合并为一条，用 `; ` 连接。
//
// 用于「尽力而为 + 汇总失败」的流程：单个 jail 失败不应连带其他 jail 一起放弃，
// 但整体结果必须如实反应失败，不能吞掉。
func JoinErrors(errs []string) error {
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(errs, "; "))
}
