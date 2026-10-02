package decision

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/detect"
)

// ClusterHit 是一次集群命中。
type ClusterHit struct {
	// CIDR 是命中的网段（已按前缀归一化，主机位为零）。
	CIDR detect.CidrKey
	// IPs 是网段内被计为「低频」的源 IP（升序，即参与判定的那些）。
	IPs []netip.Addr
	// Peak 是该网段内观测到的最大单 IP 失败数（用于日志与诊断）。判定与诊断共用
	// 「截断在 MaxPerIP+1」的读数，故它只证明「越过了上限」，不是精确计数。
	Peak uint32
}

// Summary 返回供日志与封禁原因使用的一行摘要。
func (h ClusterHit) Summary() string {
	return fmt.Sprintf("集群扫描: %s 命中 %d 个源 IP（峰值 %d 次）", h.CIDR, len(h.IPs), h.Peak)
}

// SubnetKey 返回 ip 在 cfg 规定的聚合前缀下的网段键。
func SubnetKey(ip netip.Addr, cfg config.ClusterConfig) detect.CidrKey {
	return detect.SubnetKey(ip, cfg.PrefixFor(config.FamilyOf(ip)))
}

type clusterMember struct {
	ip    netip.Addr
	count uint32
}

// DetectCluster 在失败窗口中检出集群扫描，返回命中的网段（按网段升序，结果可复现）。
//
// 判定：网段内「失败数 ≤ cfg.MaxPerIP」的不同源 IP 数 ≥ cfg.MinIPs。
//
// 单 IP 计数的形状是「同一 IP 在 findtime 内失败 ≥ N 次即封」，这恰好与扫描/暴破
// 的形态相反：扫描器每个源 IP 只用一两次，永远碰不到单 IP 阈值；而频繁访问的正常
// 访客（浏览器加载页面、单出口多用户）反而会被封。真实流量上的可分性是「网段内
// 不同 IP 数」而非「每 IP 失败数」，第二条判据（每 IP 失败数 ≤ MaxPerIP）把 CGNAT
// 与正常高频访客排除在外，是不误伤的关键。
//
// 本函数是纯计算：不碰封禁表、不下发报文、不写全局态；是否处置由调用方决定。
// window 只读，函数内部不改动它。
func DetectCluster(window *detect.FailureWindow, now int64, cfg config.ClusterConfig) []ClusterHit {
	if !cfg.Enabled || cfg.Window == 0 || cfg.MinIPs == 0 {
		return nil
	}

	// Peek 把计数截断在 cap；取 MaxPerIP + 1 即可判定「是否超过上限」，无需拿到
	// 精确计数（与 FailureWindow.Observe 的 cap 语义一致）。
	cap := cfg.MaxPerIP
	if cap < ^uint32(0) {
		cap++
	}
	groups := groupBySubnet(window, now, cfg, cap)

	hits := make([]ClusterHit, 0, len(groups))
	for i := range groups {
		group := &groups[i]
		quiet := countQuiet(group.members, cfg.MaxPerIP)
		if uint64(quiet) < uint64(cfg.MinIPs) {
			continue
		}
		ips := make([]netip.Addr, 0, len(group.members))
		var peak uint32
		for _, m := range group.members {
			if m.count > peak {
				peak = m.count
			}
			if m.count <= cfg.MaxPerIP {
				ips = append(ips, m.ip)
			}
		}
		sortAddrs(ips)
		hits = append(hits, ClusterHit{CIDR: group.cidr, IPs: ips, Peak: peak})
	}
	return hits
}

type subnetGroup struct {
	cidr    detect.CidrKey
	members []clusterMember
}

// groupBySubnet 把窗口中「窗口内有失败」的 IP 按网段分组，网段按 key 升序排列。
func groupBySubnet(window *detect.FailureWindow, now int64, cfg config.ClusterConfig, cap uint32) []subnetGroup {
	index := make(map[string]int)
	var groups []subnetGroup

	window.Iter(func(ip netip.Addr, _latest int64, tracked bool) {
		if !tracked {
			return
		}
		count := window.Peek(ip, now, cfg.Window, cap)
		if count == 0 {
			return
		}
		key := SubnetKey(ip, cfg)
		groupIdx, ok := index[key.Key()]
		if !ok {
			groupIdx = len(groups)
			index[key.Key()] = groupIdx
			groups = append(groups, subnetGroup{cidr: key})
		}
		groups[groupIdx].members = append(groups[groupIdx].members, clusterMember{ip: ip, count: count})
	})

	sortGroups(groups)
	return groups
}

// countQuiet 统计组内「失败数 ≤ 上限」的 IP 个数。
func countQuiet(members []clusterMember, maxPerIP uint32) int {
	n := 0
	for _, m := range members {
		if m.count <= maxPerIP {
			n++
		}
	}
	return n
}

// sortAddrs 按数值顺序排序地址，保证结果可复现。
func sortAddrs(addrs []netip.Addr) {
	slices.SortFunc(addrs, netip.Addr.Compare)
}

// sortGroups 按网段键升序排序，保证输出顺序稳定（结果可复现，便于对照测试）。
func sortGroups(groups []subnetGroup) {
	slices.SortFunc(groups, func(a, b subnetGroup) int {
		switch {
		case a.cidr.Key() < b.cidr.Key():
			return -1
		case a.cidr.Key() > b.cidr.Key():
			return 1
		default:
			return 0
		}
	})
}
