package runtime

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/decision"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/detect"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/ingest"
)

// TestClusterDispatchReasonFitsWireField 钉住集群网段封禁的原因文本落在契约的定长
// 字段（BanIp.reason = str[32]，含结尾 NUL）之内。
//
// 这里原本是 `jail + ": " + hit.Summary()`，Summary 是中文带 CIDR 与统计的一句话，
// UTF-8 编码 72 字节，编码阶段直接报错，于是**整条网段封禁根本没下发**——虚机上的
// test_22.3 长期只有「检测到集群扫描」的告警而封禁表为空，就是这个原因。CIDR 本身
// 就是封禁条目（/proc 与面板都会显示），命中数与峰值在告警日志里，线上不需要重复。
func TestClusterDispatchReasonFitsWireField(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	logPath := filepath.Join(dir, "cluster.log")
	if err := os.WriteFile(logPath, nil, 0o644); err != nil {
		t.Fatalf("创建测试日志失败: %v", err)
	}

	sink := newAcceptingSink()
	ex, _ := directiveFixture(t, logPath, "probe", sink)

	ips := []netip.Addr{
		netip.MustParseAddr("203.0.113.11"),
		netip.MustParseAddr("203.0.113.12"),
		netip.MustParseAddr("203.0.113.13"),
		netip.MustParseAddr("203.0.113.14"),
	}
	hit := decision.ClusterHit{
		CIDR: detect.SubnetKey(ips[0], 24),
		IPs:  ips,
		Peak: 1,
	}
	ex.dispatchClusterHit("probe", hit, config.ClusterConfig{
		Enabled: true, PrefixV4: 24, Window: 600, MinIPs: 3, MaxPerIP: 1, BanTime: 300,
	})

	reason, ok := sink.lastReason()
	if !ok {
		t.Fatal("集群命中必须产生一次下发")
	}
	if len(reason) >= contract.FixedReasonLen {
		t.Errorf("原因 %q 占 %d 字节，超出定长字段 %d（含 NUL）——超长会让编码失败、整条封禁静默不下发",
			reason, len(reason), contract.FixedReasonLen)
	}
	if !strings.Contains(reason, "probe") || !strings.Contains(reason, "cluster") {
		t.Errorf("原因要能看出是哪个 jail 的集群判定: %q", reason)
	}
	if sink.sendCount() != 1 {
		t.Errorf("下发次数 = %d，期望 1", sink.sendCount())
	}
}

// 审计模式只观测：dispatchClusterHit 必须报告「未处置」，ScanClusters 才不清计数。
// 否则审计模式下真实来源的失败累计会被周期检测清空，而封禁根本没有发生。
func TestClusterAuditModeReportsHitAsUnhandled(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	logPath := filepath.Join(dir, "cluster-audit.log")
	if err := os.WriteFile(logPath, nil, 0o644); err != nil {
		t.Fatalf("创建测试日志失败: %v", err)
	}

	sink := newAcceptingSink()
	ex, _ := directiveFixture(t, logPath, "probe", sink)
	// 单 IP 阈值抬高到不可能达到，命中只可能来自集群判定。
	ex.cfg.Jails[0].MaxRetries = 100
	ex.cfg.Jails[0].Cluster = config.ClusterConfig{
		Enabled:   true,
		AuditOnly: true,
		PrefixV4:  24,
		PrefixV6:  48,
		Window:    600,
		MinIPs:    3,
		MaxPerIP:  1,
		BanTime:   300,
	}
	ex.refreshJails()

	now := nowSecs()
	batch := failedRec("203.0.113.21") + failedRec("203.0.113.22") + failedRec("203.0.113.23")
	if _, ok := ex.pipeline.OnChunk("probe", ingest.NewSourceID(1), []byte(batch),
		NewTick(now, false), NoHistory{}, nil); !ok {
		t.Fatal("jail 应已注册")
	}
	state := ex.pipeline.jails["probe"]
	if got := state.window.Len(); got != 3 {
		t.Fatalf("窗口应记下 3 个来源: Len=%d", got)
	}

	ex.pipeline.ScanClusters(now, ex.dispatchClusterHit)

	if got := state.window.Len(); got != 3 {
		t.Errorf("审计模式下命中不得清掉失败计数: Len=%d, want 3", got)
	}
	if got := sink.sendCount(); got != 0 {
		t.Errorf("审计模式不得下发网段封禁: %d", got)
	}
}
