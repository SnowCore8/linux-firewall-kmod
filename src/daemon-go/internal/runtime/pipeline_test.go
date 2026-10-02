package runtime

import (
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/decision"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/ingest"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/logparse"
)

// sshdRules 构造只含内置 sshd 正则的规则集，与生产默认态一致。
func sshdRules(t *testing.T) *logparse.RuleSet {
	t.Helper()
	rule, err := logparse.NewRule("default", logparse.DefaultSSHDPattern)
	if err != nil {
		t.Fatalf("内置 sshd 正则应可编译: %v", err)
	}
	return logparse.NewRuleSet("sshd", []*logparse.Rule{rule})
}

// failedLine 造一条命中 sshd 正则的失败行（**不带**换行，便于跨批切分）。
func failedLine(ip string) string {
	return fmt.Sprintf(
		"Feb  7 12:00:00 host sshd[1]: Failed password for root from %s port 22 ssh2", ip)
}

// failedRec 同 failedLine，但补上换行，可直接作为一条完整行喂入。
func failedRec(ip string) string { return failedLine(ip) + "\n" }

// fixedFacts 注入固定信誉分与历史封禁次数。
type fixedFacts struct {
	score uint32
	prior uint32
}

func (fixedFacts) RecordFailure(netip.Addr) {}

func (f fixedFacts) ReputationScore(netip.Addr) uint32 { return f.score }

func (f fixedFacts) PriorBanCount(netip.Addr) uint32 { return f.prior }

func mustAddr(t *testing.T, text string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(text)
	if err != nil {
		t.Fatalf("测试用 IP %q 应合法: %v", text, err)
	}
	return a
}

// 未注册的 jail 必须整批拒收，且不留任何痕迹——尤其是不能凭空建出分割器，
// 否则改错配置的 jail 会让缓冲表随日志量无限增长。
func TestUnregisteredJailIsRejectedWithoutSideEffects(t *testing.T) {
	p := NewPipeline()

	out := []BanIntent{}
	out, ok := p.OnChunk("sshd", ingest.NewSourceID(0), []byte("anything\n"),
		NewTick(1_000, false), NoHistory{}, out)

	if ok {
		t.Error("未注册的 jail 应被拒")
	}
	if len(out) != 0 {
		t.Errorf("被拒的批次不应产出意图: %d", len(out))
	}
	if got := p.PendingSources(); got != 0 {
		t.Errorf("被拒的批次不应留下 splitter: %d", got)
	}
	if got := p.Counters(); got != (Counters{}) {
		t.Errorf("被拒的批次不应累加计数: %+v", got)
	}
}

// 达到阈值时产出一条意图，参数取首次封禁的基础时长；触发后窗口清空，避免同一次
// 攻击在后续批次里重复触发。
func TestThresholdReachedProducesIntentWithBaseDuration(t *testing.T) {
	p := NewPipeline()
	p.RegisterJail(sshdRules(t), NewJailPolicy(3, 600, 600, config.DefaultClusterConfig()))

	src := ingest.NewSourceID(1)
	facts := fixedFacts{score: 100, prior: 0}
	tick := NewTick(10_000, false)
	var out []BanIntent

	two := failedRec("203.0.113.7") + failedRec("203.0.113.7")
	out, ok := p.OnChunk("sshd", src, []byte(two), tick, facts, out)
	if !ok {
		t.Fatal("已注册的 jail 应接收本批")
	}
	if len(out) != 0 {
		t.Fatalf("两次失败不应触发封禁: %d", len(out))
	}

	out, _ = p.OnChunk("sshd", src, []byte(failedRec("203.0.113.7")), tick, facts, out)
	if len(out) != 1 {
		t.Fatalf("第三次应触发恰好一条封禁意图: %d", len(out))
	}

	intent := out[0]
	if intent.Jail != "sshd" {
		t.Errorf("Jail=%q, want sshd", intent.Jail)
	}
	if intent.IP != mustAddr(t, "203.0.113.7") {
		t.Errorf("IP=%v, want 203.0.113.7", intent.IP)
	}
	if intent.Source != src {
		t.Errorf("意图应带上稳定源身份: %v, want %v", intent.Source, src)
	}
	if intent.Plan.Duration != 600 {
		t.Errorf("Duration=%d, want 600", intent.Plan.Duration)
	}
	if intent.Plan.IsPermanent {
		t.Error("首次封禁不应永久")
	}
	if intent.Plan.BanCount != 1 {
		t.Errorf("BanCount=%d, want 1", intent.Plan.BanCount)
	}
	if intent.Plan.FailCount != 3 {
		t.Errorf("FailCount=%d, want 3", intent.Plan.FailCount)
	}

	out = out[:0]
	out, _ = p.OnChunk("sshd", src, []byte(failedRec("203.0.113.7")), tick, facts, out)
	if len(out) != 0 {
		t.Errorf("封禁后窗口应被清空，避免重复计数: %d", len(out))
	}

	c := p.Counters()
	if c.LinesParsed != 4 {
		t.Errorf("LinesParsed=%d, want 4", c.LinesParsed)
	}
	if c.IPsExtracted != 4 {
		t.Errorf("IPsExtracted=%d, want 4", c.IPsExtracted)
	}
	if c.RegexMatches != 4 {
		t.Errorf("RegexMatches=%d, want 4", c.RegexMatches)
	}
	if c.BansIntent != 1 {
		t.Errorf("BansIntent=%d, want 1", c.BansIntent)
	}
}

// 内网(×2.0) + 高峰(×1.5) + 信誉满分(×1.0)：阈值 3 → ceil(9.0) = 9。
func TestInternalAndPeakMultipliersRaiseTheThreshold(t *testing.T) {
	p := NewPipeline()
	p.RegisterJail(sshdRules(t), NewJailPolicy(3, 600, 600, config.DefaultClusterConfig()))

	src := ingest.NewSourceID(2)
	facts := fixedFacts{score: 100, prior: 0}
	tick := NewTick(1_000, true)
	var out []BanIntent

	for i := 0; i < 8; i++ {
		out, _ = p.OnChunk("sshd", src, []byte(failedRec("10.0.0.9")), tick, facts, out)
	}
	if len(out) != 0 {
		t.Fatalf("内网+高峰下 8 次不应达到阈值 9: %d", len(out))
	}

	out, _ = p.OnChunk("sshd", src, []byte(failedRec("10.0.0.9")), tick, facts, out)
	if len(out) != 1 {
		t.Fatalf("第 9 次应达到内网+高峰阈值: %d", len(out))
	}
	if out[0].Plan.FailCount != 9 {
		t.Errorf("FailCount=%d, want 9", out[0].Plan.FailCount)
	}
}

// 半行必须在补全换行后才解析，且该源的半行缓冲跨批保留。
func TestLinesSplitAcrossChunksJoinBeforeParsing(t *testing.T) {
	p := NewPipeline()
	p.RegisterJail(sshdRules(t), NewJailPolicy(1, 600, 600, config.DefaultClusterConfig()))

	src := ingest.NewSourceID(3)
	facts := fixedFacts{score: 100, prior: 0}
	tick := NewTick(5, false)
	var out []BanIntent

	line := failedLine("198.51.100.4")
	head, tail := line[:20], line[20:]

	out, _ = p.OnChunk("sshd", src, []byte(head), tick, facts, out)
	if len(out) != 0 {
		t.Fatalf("前半段不成行，不应产出解析结果: %d", len(out))
	}
	if got := p.PendingSources(); got != 1 {
		t.Errorf("应挂起半行: PendingSources=%d", got)
	}

	out, _ = p.OnChunk("sshd", src, []byte(tail+"\n"), tick, facts, out)
	if len(out) != 1 {
		t.Fatalf("跨批拼接后应解析出 IP 并触发: %d", len(out))
	}
	if out[0].IP != mustAddr(t, "198.51.100.4") {
		t.Errorf("IP=%v, want 198.51.100.4", out[0].IP)
	}
}

// 收尾半行：feed 阶段不交出未终结的行，flush 阶段才当作完整行判定。
func TestFlushSourceHandlesTheFinalUnterminatedLine(t *testing.T) {
	p := NewPipeline()
	p.RegisterJail(sshdRules(t), NewJailPolicy(1, 600, 600, config.DefaultClusterConfig()))

	src := ingest.NewSourceID(4)
	facts := fixedFacts{score: 100, prior: 0}
	tick := NewTick(7, false)
	var out []BanIntent

	out, _ = p.OnChunk("sshd", src, []byte(failedLine("192.0.2.55")), tick, facts, out)
	if len(out) != 0 {
		t.Fatalf("未终结的行不应在 feed 阶段被解析: %d", len(out))
	}

	out, ok := p.FlushSource("sshd", src, tick, facts, out)
	if !ok {
		t.Fatal("已注册的 jail 应接受 flush")
	}
	if len(out) != 1 {
		t.Fatalf("flush 应处理最后的半行: %d", len(out))
	}
	if out[0].IP != mustAddr(t, "192.0.2.55") {
		t.Errorf("IP=%v, want 192.0.2.55", out[0].IP)
	}
	if got := p.PendingSources(); got != 1 {
		t.Errorf("flush 不删除 splitter 本身: PendingSources=%d", got)
	}
}

// 轮转必须丢弃旧半行：它不能与新文件的开头拼成一行。
func TestRotatedSourceDropsThePendingHalfLine(t *testing.T) {
	p := NewPipeline()
	p.RegisterJail(sshdRules(t), NewJailPolicy(1, 600, 600, config.DefaultClusterConfig()))

	src := ingest.NewSourceID(5)
	tick := NewTick(9, false)
	var out []BanIntent

	out, _ = p.OnChunk("sshd", src, []byte(failedLine("203.0.113.99")), tick, NoHistory{}, out)
	if len(out) != 0 {
		t.Fatalf("挂起半行不应产出意图: %d", len(out))
	}

	p.OnSourceRotated(src)
	out, _ = p.OnChunk("sshd", src, []byte("\n"), tick, NoHistory{}, out)
	if len(out) != 0 {
		t.Errorf("轮转后旧半行不应被补全解析: %d", len(out))
	}

	out, _ = p.FlushSource("sshd", src, tick, NoHistory{}, out)
	if len(out) != 0 {
		t.Errorf("flush 也拿不到任何东西（缓冲已清）: %d", len(out))
	}
}

func TestForgetSourceReleasesTheSplitter(t *testing.T) {
	p := NewPipeline()
	p.RegisterJail(sshdRules(t), NewJailPolicy(5, 600, 600, config.DefaultClusterConfig()))

	src := ingest.NewSourceID(6)
	var out []BanIntent
	out, _ = p.OnChunk("sshd", src, []byte("no newline yet"), NewTick(1, false), NoHistory{}, out)

	if got := p.PendingSources(); got != 1 {
		t.Fatalf("PendingSources=%d, want 1", got)
	}
	p.ForgetSource(src)
	if got := p.PendingSources(); got != 0 {
		t.Errorf("摘除源应释放其半行缓冲: PendingSources=%d", got)
	}
}

// 重载配置必须保留失败窗口，否则攻击者可用 SIGHUP 清零自己的失败计数。
func TestRegisterJailPreservesTheFailureWindowAcrossReload(t *testing.T) {
	p := NewPipeline()
	policy := NewJailPolicy(3, 600, 600, config.DefaultClusterConfig())
	p.RegisterJail(sshdRules(t), policy)

	src := ingest.NewSourceID(7)
	facts := fixedFacts{score: 100, prior: 0}
	tick := NewTick(100, false)
	var out []BanIntent

	two := failedRec("203.0.113.8") + failedRec("203.0.113.8")
	out, _ = p.OnChunk("sshd", src, []byte(two), tick, facts, out)
	if len(out) != 0 {
		t.Fatalf("两次失败不应触发: %d", len(out))
	}

	p.RegisterJail(sshdRules(t), policy)
	if !p.HasJail("sshd") {
		t.Fatal("重载后仍应有 sshd")
	}
	if got := p.JailCount(); got != 1 {
		t.Errorf("JailCount=%d, want 1", got)
	}

	out, _ = p.OnChunk("sshd", src, []byte(failedRec("203.0.113.8")), tick, facts, out)
	if len(out) != 1 {
		t.Fatalf("重载后第 3 次失败仍应达到阈值: %d", len(out))
	}
	if out[0].Plan.FailCount != 3 {
		t.Errorf("FailCount=%d, want 3", out[0].Plan.FailCount)
	}
}

// 维护周期必须清掉整条过期的失败记录（窗口内已无任何时间戳）。
func TestCleanupExpiresStaleEntries(t *testing.T) {
	p := NewPipeline()
	p.RegisterJail(sshdRules(t), NewJailPolicy(5, 100, 600, config.DefaultClusterConfig()))

	src := ingest.NewSourceID(8)
	var out []BanIntent
	out, _ = p.OnChunk("sshd", src, []byte(failedRec("203.0.113.10")), NewTick(1_000, false), NoHistory{}, out)
	if len(out) != 0 {
		t.Fatalf("阈值 5 下单次失败不应触发: %d", len(out))
	}

	if got := p.Cleanup(2_000); got != 1 {
		t.Errorf("距上次 1000 秒 > 窗口 100 秒，应清 1 条: %d", got)
	}
	if got := p.Cleanup(2_000); got != 0 {
		t.Errorf("再次清理应无条目可清: %d", got)
	}
}

// 只保留 keep 中的 jail：改过名的 jail 连同其失败窗口一并回收，避免长期运行中
// 表项只增不减。
func TestRetainJailsDropsTheOnesNoLongerConfigured(t *testing.T) {
	p := NewPipeline()
	p.RegisterJail(sshdRules(t), NewJailPolicy(3, 600, 600, config.DefaultClusterConfig()))

	webRules := logparse.NewRuleSet("web", []*logparse.Rule{})
	p.RegisterJail(webRules, NewJailPolicy(10, 300, 1800, config.DefaultClusterConfig()))

	// web 有两次失败，被摘除后该窗口也应一并消失。
	src := ingest.NewSourceID(12)
	var out []BanIntent
	two := failedRec("203.0.113.20") + failedRec("203.0.113.20")
	out, _ = p.OnChunk("sshd", src, []byte(two), NewTick(100, false), NoHistory{}, out)
	out, _ = p.OnChunk("web", src, []byte("no newline"), NewTick(100, false), NoHistory{}, out)

	if got := p.RetainJails([]string{"sshd"}); got != 1 {
		t.Errorf("应摘除 1 个 jail: %d", got)
	}
	if p.HasJail("web") {
		t.Error("web 已不在 keep 中，应被摘除")
	}
	if !p.HasJail("sshd") {
		t.Error("sshd 应在 keep 中，不应被摘除")
	}
	if got := p.Counters().LinesParsed; got != 2 {
		t.Errorf("摘除不得回退计数: LinesParsed=%d, want 2", got)
	}

	// 保留集合为空时全部摘除。
	if got := p.RetainJails(nil); got != 1 {
		t.Errorf("空 keep 应摘除剩余的 1 个 jail: %d", got)
	}
	if got := p.JailCount(); got != 0 {
		t.Errorf("JailCount=%d, want 0", got)
	}
}

// 周期检测是集群判定的唯一入口：单行判定只看得到一个源，凑不出「同一网段内有
// 多少个不同源」，故命中只能在 ScanClusters 里产生并通过回调上报。
func TestClusterScanReportsHits(t *testing.T) {
	p := NewPipeline()
	cluster := config.ClusterConfig{
		Enabled:   true,
		AuditOnly: false,
		PrefixV4:  24,
		PrefixV6:  48,
		Window:    600,
		MinIPs:    3,
		MaxPerIP:  1,
		BanTime:   300,
	}
	// 单 IP 阈值抬高到不可能达到，命中只可能来自集群判定。
	p.RegisterJail(sshdRules(t), NewJailPolicy(100, 600, 600, cluster))

	src := ingest.NewSourceID(11)
	var out []BanIntent

	for _, host := range []string{"21", "22", "23"} {
		out, _ = p.OnChunk("sshd", src, []byte(failedRec("203.0.113."+host)),
			NewTick(1_000, false), NoHistory{}, out)
	}
	if len(out) != 0 {
		t.Fatalf("单 IP 未达阈值，不应产出单点封禁意图: %d", len(out))
	}

	type hitRow struct {
		jail      string
		cidr      string
		ipCount   int
		peak      uint32
		auditOnly bool
	}
	var hits []hitRow
	p.ScanClusters(1_000, func(jail string, hit decision.ClusterHit, cfg config.ClusterConfig) {
		hits = append(hits, hitRow{
			jail:      jail,
			cidr:      hit.CIDR.Key(),
			ipCount:   len(hit.IPs),
			peak:      hit.Peak,
			auditOnly: cfg.AuditOnly,
		})
	})

	if len(hits) != 1 {
		t.Fatalf("三个不同源应触发一次集群命中: %d", len(hits))
	}
	got := hits[0]
	if got.jail != "sshd" {
		t.Errorf("jail=%q, want sshd", got.jail)
	}
	if got.cidr != "203.0.113.0/24" {
		t.Errorf("命中应给出归一后的网段键: %q", got.cidr)
	}
	if got.ipCount != 3 {
		t.Errorf("参与判定的源 IP 数=%d, want 3", got.ipCount)
	}
	if got.peak != 1 {
		t.Errorf("每个源只失败一次，Peak=%d, want 1", got.peak)
	}
	if got.auditOnly {
		t.Error("回调应把该 jail 的 cluster 配置一并传出（此处 audit_only=false）")
	}

	// 检测是纯读：不改动窗口，故未过期条目仍留在原地。
	if got := p.Cleanup(1_000); got != 0 {
		t.Errorf("检测不应清掉未过期的条目: %d", got)
	}
}

// 同一 IP 反复封禁时，时长按渐进阶梯走；第 4 次起转为永久。
func TestProgressiveEscalationAcrossBans(t *testing.T) {
	p := NewPipeline()
	p.RegisterJail(sshdRules(t), NewJailPolicy(1, 600, 600, config.DefaultClusterConfig()))

	src := ingest.NewSourceID(9)
	tick := NewTick(50, false)
	var out []BanIntent

	expected := []struct {
		duration  uint64
		permanent bool
	}{
		{600, false},
		{1800, false},
		{86400, false},
		{0, true},
	}

	for prior, want := range expected {
		facts := fixedFacts{score: 100, prior: uint32(prior)}
		out, _ = p.OnChunk("sshd", src, []byte(failedRec("203.0.113.11")), tick, facts, out)
		if len(out) != 1 {
			t.Fatalf("第 %d 次应触发封禁: %d", prior, len(out))
		}
		if out[0].Plan.Duration != want.duration {
			t.Errorf("第 %d 次时长=%d, want %d", prior, out[0].Plan.Duration, want.duration)
		}
		if out[0].Plan.IsPermanent != want.permanent {
			t.Errorf("第 %d 次永久标志=%v, want %v", prior, out[0].Plan.IsPermanent, want.permanent)
		}
		out = out[:0]
	}
}

// 含回退关键字但不匹配 sshd 正则的行仍应提取出 IP，且不计入正则命中。
func TestFallbackKeywordLineStillYieldsAnIP(t *testing.T) {
	p := NewPipeline()
	p.RegisterJail(sshdRules(t), NewJailPolicy(1, 600, 600, config.DefaultClusterConfig()))

	src := ingest.NewSourceID(10)
	var out []BanIntent
	line := "Feb  7 12:00:00 host sshd[1]: authentication failure; rhost=203.0.113.12\n"
	out, _ = p.OnChunk("sshd", src, []byte(line), NewTick(1, false), NoHistory{}, out)

	if len(out) != 1 {
		t.Fatalf("回退命中应产出封禁意图: %d", len(out))
	}
	if out[0].IP != mustAddr(t, "203.0.113.12") {
		t.Errorf("IP=%v, want 203.0.113.12", out[0].IP)
	}
	if got := p.Counters().RegexMatches; got != 0 {
		t.Errorf("回退命中不得计入正则命中: RegexMatches=%d", got)
	}
	if got := p.Counters().IPsExtracted; got != 1 {
		t.Errorf("IPsExtracted=%d, want 1", got)
	}
}

// decayingFacts 每记一次失败扣 10 分，与生产信誉分同规则。
type decayingFacts struct {
	score atomic.Uint32
}

func (d *decayingFacts) RecordFailure(netip.Addr) {
	d.score.Add(^uint32(0) - 9) // 等价于 -10（无符号递减）
}

func (d *decayingFacts) ReputationScore(netip.Addr) uint32 { return d.score.Load() }

func (d *decayingFacts) PriorBanCount(netip.Addr) uint32 { return 0 }

// 记账顺序必须是「先 RecordFailure，后 ReputationScore」。
//
// 算术（阈值基数 12、非高峰、外网、同批 6 行失败；信誉分自 100 起每记一次 -10）。
// FailureWindow.Observe 的 Recent 按阈值截断，故 FailCount 至多等于阈值——用「阈值 6
// 恰好等于行数」让两种顺序的产出可分辨：
//
//	| 第 n 行 | 先记账→取分 | 系数 | 有效阈值 | 先取分→记账 | 系数 | 有效阈值 |
//	| 5       | 50          | 0.8  | 10       | 60          | 0.8  | 10       |
//	| 6       | 40          | 0.5  | 6 → 达标 | 50          | 0.8  | 10 → 未达标 |
//
// 故「第 6 行产出封禁意图、FailCount == 6」唯一地分辨两种顺序。
func TestFailureIsRecordedBeforeTheScoreIsRead(t *testing.T) {
	p := NewPipeline()
	p.RegisterJail(sshdRules(t), NewJailPolicy(12, 600, 600, config.DefaultClusterConfig()))

	src := ingest.NewSourceID(13)
	facts := &decayingFacts{}
	facts.score.Store(100)
	var out []BanIntent

	var batch []byte
	for i := 0; i < 6; i++ {
		batch = append(batch, []byte(failedRec("203.0.113.13"))...)
	}
	out, _ = p.OnChunk("sshd", src, batch, NewTick(1_000, false), facts, out)

	if got := facts.score.Load(); got != 40 {
		t.Errorf("六行失败应各记一次账（100-60）: score=%d", got)
	}
	if len(out) != 1 {
		t.Fatalf("第 6 次失败应达到「记过账之后」的阈值 6；无产出即说明取分早于记账: %d", len(out))
	}
	if out[0].Plan.FailCount != 6 {
		t.Errorf("FailCount=%d, want 6", out[0].Plan.FailCount)
	}
}
