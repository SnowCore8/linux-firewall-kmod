package decision

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/detect"
)

// clusterCfg 构造一份 v4/v6 前缀都显式给出的检测配置，便于逐条断言。
func clusterCfg(minIPs, maxPerIP uint32) config.ClusterConfig {
	return config.ClusterConfig{
		Enabled:   true,
		AuditOnly: true,
		PrefixV4:  24,
		PrefixV6:  48,
		Window:    60,
		MinIPs:    minIPs,
		MaxPerIP:  maxPerIP,
		BanTime:   3600,
	}
}

// observe 向窗口投喂 count 次同一 IP 的失败，时间戳都取 now。
func observe(t *testing.T, w *detect.FailureWindow, ipText string, count int, now int64) {
	t.Helper()
	ip := addr(t, ipText)
	for i := 0; i < count; i++ {
		w.Observe(ip, now, 60, 1000)
	}
}

func TestDetectClusterDisabledOrDegenerateConfigReturnsNothing(t *testing.T) {
	w := detect.NewFailureWindow()
	for _, ipText := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		observe(t, w, ipText, 1, 1000)
	}

	disabled := clusterCfg(3, 1)
	disabled.Enabled = false
	if hits := DetectCluster(w, 1000, disabled); hits != nil {
		t.Errorf("检测关闭时不应返回命中: %+v", hits)
	}

	zeroWindow := clusterCfg(3, 1)
	zeroWindow.Window = 0
	if hits := DetectCluster(w, 1000, zeroWindow); hits != nil {
		t.Errorf("窗口为 0 时不应返回命中: %+v", hits)
	}

	zeroMinIPs := clusterCfg(0, 1)
	if hits := DetectCluster(w, 1000, zeroMinIPs); hits != nil {
		t.Errorf("MinIPs 为 0 时不应返回命中: %+v", hits)
	}
}

func TestDetectClusterNeedsDistinctIPsInOneSubnet(t *testing.T) {
	w := detect.NewFailureWindow()
	observe(t, w, "203.0.113.1", 1, 1000)
	observe(t, w, "203.0.113.2", 1, 1000)

	if hits := DetectCluster(w, 1000, clusterCfg(3, 1)); len(hits) != 0 {
		t.Fatalf("同网段 2 个静默 IP 未达 MinIPs=3，不应命中: %+v", hits)
	}

	observe(t, w, "203.0.113.3", 1, 1000)
	hits := DetectCluster(w, 1000, clusterCfg(3, 1))
	if len(hits) != 1 {
		t.Fatalf("同网段 3 个静默 IP 应命中 1 个网段: %+v", hits)
	}
	if got := hits[0].CIDR.Key(); got != "203.0.113.0/24" {
		t.Errorf("命中的网段键=%q, want 203.0.113.0/24", got)
	}
	if len(hits[0].IPs) != 3 {
		t.Errorf("参与判定的 IP 数=%d, want 3", len(hits[0].IPs))
	}
}

// 高频 IP 不参与计数：它是「正常高频访客/CGNAT 出口」的形状，正是第二条判据要排除的对象。
func TestDetectClusterExcludesHeavyHittersFromTheQuorum(t *testing.T) {
	w := detect.NewFailureWindow()
	observe(t, w, "203.0.113.1", 1, 1000)
	observe(t, w, "203.0.113.2", 1, 1000)
	observe(t, w, "203.0.113.3", 1, 1000)
	observe(t, w, "203.0.113.200", 5, 1000)

	hits := DetectCluster(w, 1000, clusterCfg(3, 1))
	if len(hits) != 1 {
		t.Fatalf("应命中 1 个网段: %+v", hits)
	}
	if len(hits[0].IPs) != 3 {
		t.Fatalf("高频 IP 不应计入静默配额: %+v", hits[0].IPs)
	}
	for _, ip := range hits[0].IPs {
		if ip.String() == "203.0.113.200" {
			t.Errorf("高频 IP 不得出现在参与判定的集合中: %+v", hits[0].IPs)
		}
	}
	// Peek 的计数在 MaxPerIP+1 处截断，故 Peak 是截断值而非真实值——这里钉住该语义，
	// 避免把「诊断用的峰值」误读为精确计数。
	if hits[0].Peak != 2 {
		t.Errorf("Peak=%d, want 2（受 MaxPerIP+1 截断）", hits[0].Peak)
	}
}

func TestDetectClusterHeavyHitterAloneNeverFormsAQuorum(t *testing.T) {
	w := detect.NewFailureWindow()
	observe(t, w, "203.0.113.200", 9, 1000)

	if hits := DetectCluster(w, 1000, clusterCfg(3, 1)); len(hits) != 0 {
		t.Errorf("单个高频 IP 不构成集群扫描: %+v", hits)
	}
}

// 网段之间不合并：MinIPs 是「单个网段内」的不同源 IP 数，不是全局。
func TestDetectClusterGroupsPerSubnetWithoutMerging(t *testing.T) {
	w := detect.NewFailureWindow()
	observe(t, w, "203.0.113.1", 1, 1000)
	observe(t, w, "203.0.113.2", 1, 1000)
	observe(t, w, "198.51.100.1", 1, 1000)
	observe(t, w, "198.51.100.2", 1, 1000)

	if hits := DetectCluster(w, 1000, clusterCfg(3, 1)); len(hits) != 0 {
		t.Errorf("两个网段各 2 个 IP，均未达 MinIPs=3，不应命中: %+v", hits)
	}

	observe(t, w, "198.51.100.3", 1, 1000)
	hits := DetectCluster(w, 1000, clusterCfg(3, 1))
	if len(hits) != 1 {
		t.Fatalf("仅 198.51.100.0/24 达标: %+v", hits)
	}
	if got := hits[0].CIDR.Key(); got != "198.51.100.0/24" {
		t.Errorf("命中的网段键=%q, want 198.51.100.0/24", got)
	}
}

func TestDetectClusterSkipsEntriesOutsideTheWindow(t *testing.T) {
	w := detect.NewFailureWindow()
	// 三条失败都落在窗口之外（now-100，窗口 60 秒）。
	for _, ipText := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		observe(t, w, ipText, 1, 900)
	}

	if hits := DetectCluster(w, 1000, clusterCfg(3, 1)); len(hits) != 0 {
		t.Errorf("窗口外的落后时间戳不应计入当前判定: %+v", hits)
	}
	if w.Len() != 3 {
		t.Errorf("DetectCluster 不得改动窗口: Len=%d, want 3", w.Len())
	}
}

func TestDetectClusterAggregatesIPv6ByConfiguredPrefix(t *testing.T) {
	w := detect.NewFailureWindow()
	for _, ipText := range []string{"2001:db8:1::1", "2001:db8:1::2", "2001:db8:1::3"} {
		observe(t, w, ipText, 1, 1000)
	}

	hits := DetectCluster(w, 1000, clusterCfg(3, 1))
	if len(hits) != 1 {
		t.Fatalf("应命中 1 个 v6 网段: %+v", hits)
	}
	if got := hits[0].CIDR.Key(); got != "2001:db8:1::/48" {
		t.Errorf("命中的 v6 网段键=%q, want 2001:db8:1::/48", got)
	}
}

func TestDetectClusterOutputIsDeterministic(t *testing.T) {
	w := detect.NewFailureWindow()
	for _, ipText := range []string{
		"203.0.113.30", "203.0.113.4", "203.0.113.9",
		"198.51.100.1", "198.51.100.2", "198.51.100.3",
	} {
		observe(t, w, ipText, 1, 1000)
	}

	hits := DetectCluster(w, 1000, clusterCfg(3, 1))
	if len(hits) != 2 {
		t.Fatalf("应命中 2 个网段: %+v", hits)
	}
	if hits[0].CIDR.Key() != "198.51.100.0/24" || hits[1].CIDR.Key() != "203.0.113.0/24" {
		t.Errorf("网段应按键升序输出: %q, %q", hits[0].CIDR.Key(), hits[1].CIDR.Key())
	}

	got := make([]string, 0, len(hits[1].IPs))
	for _, ip := range hits[1].IPs {
		got = append(got, ip.String())
	}
	want := []string{"203.0.113.4", "203.0.113.9", "203.0.113.30"}
	if len(got) != len(want) {
		t.Fatalf("IP 数=%d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("网段内 IP 应按数值升序: got %v, want %v", got, want)
		}
	}
}

func TestClusterHitSummaryMentionsSubnetAndCount(t *testing.T) {
	hit := ClusterHit{
		CIDR: detect.MustCidrKey("203.0.113.0/24"),
		IPs:  []netip.Addr{addr(t, "203.0.113.1"), addr(t, "203.0.113.2")},
		Peak: 1,
	}
	got := hit.Summary()
	for _, want := range []string{"203.0.113.0/24", "2", "峰值 1 次"} {
		if !strings.Contains(got, want) {
			t.Errorf("摘要 %q 应含 %q", got, want)
		}
	}
}

func TestSubnetKeyFollowsAddressFamily(t *testing.T) {
	cfg := clusterCfg(3, 1)
	if got := SubnetKey(addr(t, "10.0.0.5"), cfg).Key(); got != "10.0.0.0/24" {
		t.Errorf("v4 应按 PrefixV4 聚合: %q", got)
	}
	if got := SubnetKey(addr(t, "2001:db8::5"), cfg).Key(); got != "2001:db8::/48" {
		t.Errorf("v6 应按 PrefixV6 聚合: %q", got)
	}
}
