package runtime

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/decision"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/detect"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/ingest"
)

// ledgerSink 在 fakeSink 之上记录网段封禁的底账调用。
type ledgerSink struct {
	fakeSink
	mu     sync.Mutex
	ledger []bans.BanInfo
}

func (s *ledgerSink) RecordClusterBan(info bans.BanInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ledger = append(s.ledger, info)
}

func (s *ledgerSink) ledgerSnapshot() []bans.BanInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]bans.BanInfo, len(s.ledger))
	copy(out, s.ledger)
	return out
}

// TestClusterDispatchRecordsBanLedger 钉住「集群网段封禁进底账」。
//
// 直接 sink.Send 的写法下，网段封禁在 ban_events / ban_history / 信誉表里完全缺失：
// 复发统计与分级成效都读不到它。底账键取 CIDR 文本，理由里必须能看出是 cluster。
func TestClusterDispatchRecordsBanLedger(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	logPath := filepath.Join(dir, "cluster-ledger.log")
	writeFile(t, logPath, "")

	sink := &ledgerSink{fakeSink: fakeSink{insertWinner: true}}
	ex, _ := directiveFixture(t, logPath, "probe", sink)

	ips := []netip.Addr{
		netip.MustParseAddr("203.0.113.11"),
		netip.MustParseAddr("203.0.113.12"),
		netip.MustParseAddr("203.0.113.13"),
	}
	cfg := config.ClusterConfig{
		Enabled: true, PrefixV4: 24, Window: 600, MinIPs: 3, MaxPerIP: 1, BanTime: 300,
	}
	hit := decision.ClusterHit{CIDR: detect.SubnetKey(ips[0], 24), IPs: ips, Peak: 1}
	if !ex.dispatchClusterHit("probe", hit, cfg) {
		t.Fatal("非审计模式必须报告已处置")
	}

	ledger := sink.ledgerSnapshot()
	if len(ledger) != 1 {
		t.Fatalf("网段封禁必须记一次底账，实得 %d 次", len(ledger))
	}
	info := ledger[0]
	if info.IP != "203.0.113.0" {
		t.Errorf("底账键 = %q，期望归一化的网络地址 203.0.113.0", info.IP)
	}
	if info.PrefixLen != 24 {
		t.Errorf("PrefixLen = %d，期望 24", info.PrefixLen)
	}
	if info.JailName != "probe" {
		t.Errorf("JailName = %q，期望 probe", info.JailName)
	}
	if !strings.Contains(info.Reason, "cluster") {
		t.Errorf("理由必须能看出是集群判定: %q", info.Reason)
	}
	if info.IsPermanent {
		t.Error("ban_time=300 不应记成永久")
	}
	if got := info.ExpiresAt - info.BannedAt; got != 300 {
		t.Errorf("计划时长 = %d 秒，期望 300", got)
	}
	if info.BanCount != 1 {
		t.Errorf("BanCount = %d，期望 1", info.BanCount)
	}
}

// TestClusterAuditModeRecordsNoLedger：审计模式不下发，也就不该有底账。
func TestClusterAuditModeRecordsNoLedger(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	logPath := filepath.Join(dir, "cluster-ledger-audit.log")
	writeFile(t, logPath, "")

	sink := &ledgerSink{fakeSink: fakeSink{insertWinner: true}}
	ex, _ := directiveFixture(t, logPath, "probe", sink)

	ips := []netip.Addr{
		netip.MustParseAddr("203.0.113.31"),
		netip.MustParseAddr("203.0.113.32"),
		netip.MustParseAddr("203.0.113.33"),
	}
	hit := decision.ClusterHit{CIDR: detect.SubnetKey(ips[0], 24), IPs: ips, Peak: 1}
	ex.dispatchClusterHit("probe", hit, config.ClusterConfig{
		Enabled: true, AuditOnly: true, PrefixV4: 24, Window: 600, MinIPs: 3, MaxPerIP: 1, BanTime: 300,
	})

	if got := len(sink.ledgerSnapshot()); got != 0 {
		t.Fatalf("审计模式不得记底账，实得 %d 次", got)
	}
}

// TestClusterSendFailureRecordsNoLedger：下发失败不是「封禁已发生」，不得进底账。
func TestClusterSendFailureRecordsNoLedger(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	logPath := filepath.Join(dir, "cluster-ledger-fail.log")
	writeFile(t, logPath, "")

	sink := &ledgerSink{fakeSink: fakeSink{insertWinner: true, sendErr: errors.New("表满")}}
	ex, _ := directiveFixture(t, logPath, "probe", sink)

	ips := []netip.Addr{
		netip.MustParseAddr("203.0.113.41"),
		netip.MustParseAddr("203.0.113.42"),
		netip.MustParseAddr("203.0.113.43"),
	}
	hit := decision.ClusterHit{CIDR: detect.SubnetKey(ips[0], 24), IPs: ips, Peak: 1}
	ex.dispatchClusterHit("probe", hit, config.ClusterConfig{
		Enabled: true, PrefixV4: 24, Window: 600, MinIPs: 3, MaxPerIP: 1, BanTime: 300,
	})

	if got := len(sink.ledgerSnapshot()); got != 0 {
		t.Fatalf("下发失败不得记底账，实得 %d 次", got)
	}
}

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
