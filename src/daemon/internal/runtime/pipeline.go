// Package runtime 把采集、解析、判定、封禁四层装配成生产主链路。
//
// 它是设计文档「运行时模型」里 **pipeline 执行体** 的具体形态：单线程独占全部状态
// （每源分割器、每 jail 失败窗口、每 jail 规则集），因此内部不需要任何锁。
//
// 本包止于 BanIntent——判定做出「应当封禁」的结论，但不下发 netlink。下发是
// kernel 层的职责，装配成完整链路由组合根完成。这样主链路的可测性与内核层解耦：
// 喂字节进去，断言「是否产生封禁意图、意图参数是否正确」。
//
// 判定所依赖的两项外部事实（信誉分、历史封禁次数）经 DecisionFacts 注入，而不是去
// 读全局态——旧实现把它们与全局封禁历史纠缠在一起，导致主链路无法单独单测。
package runtime

import (
	"fmt"
	"net/netip"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/decision"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/detect"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/ingest"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/logparse"
)

// BanIntent 是一次封禁意图：判定做出「应当封禁」的结论，但尚未下发。
type BanIntent struct {
	// Jail 是归属的 jail 名。
	Jail string
	// IP 是触发封禁的来源地址。
	IP netip.Addr
	// Source 是产生该意图的日志源（轮转后仍是同一身份）。
	Source ingest.SourceID
	// Plan 是封禁参数（时长、是否永久、过期时刻、累计次数）。
	Plan decision.BanPlan
	// Reason 是下发给内核并写入历史的人类可读原因。
	Reason string
}

// JailPolicy 是一个 jail 的判定参数（来自配置，非 netlink）。
type JailPolicy struct {
	// MaxRetries 是失败阈值（未经系数放大的原始值）。
	MaxRetries uint32
	// FindTime 是滑动窗口（秒）。
	FindTime uint32
	// BanTime 是封禁时长（秒）；负值表示配置级永久封禁。
	BanTime int32
	// Cluster 是同一 jail 的集群扫描检测参数。
	Cluster config.ClusterConfig
}

// NewJailPolicy 构造判定参数。
func NewJailPolicy(maxRetries, findTime uint32, banTime int32, cluster config.ClusterConfig) JailPolicy {
	return JailPolicy{MaxRetries: maxRetries, FindTime: findTime, BanTime: banTime, Cluster: cluster}
}

// DecisionFacts 是判定所需的外部事实。由组合根注入真实实现，测试注入固定值。
//
// 把这两项挡在接口后面，是为了让判定算式保持纯粹：策略函数不查任何 store，本层也不查，
// 查什么由调用方决定。
//
// 调用契约：判定层对每一行识别出的来源 IP 调用 RecordFailure **恰好一次**，紧接着才
// 调用 ReputationScore 取分数。顺序是语义的一部分——旧实现就是「先记失败（信誉分 -10）
// 再取阈值乘数」，即本次失败已计入之后才决定阈值。反过来会让临界 IP（如刚好从 80 跌到
// 70 的那一次）用错乘数。
type DecisionFacts interface {
	// RecordFailure 记录一次失败尝试（生产实现：信誉分 -10）。
	//
	// 判定层每判定一行含合法 IP 的日志即调用一次。实现若不需要记账（测试、启动初期的
	// NoHistory）留空即可。
	RecordFailure(ip netip.Addr)
	// ReputationScore 返回该 IP 当前的信誉分（0–100）。
	//
	// 必须在同一行的 RecordFailure **之后**调用，返回值即「已计入本次失败」的分数。
	ReputationScore(ip netip.Addr) uint32
	// PriorBanCount 返回该 IP 此前已封禁次数（用于渐进式时长）。
	PriorBanCount(ip netip.Addr) uint32
	// RiskEngineEnabled 返回多维风险引擎是否启用。
	RiskEngineEnabled() bool
}

// NoHistory 是无历史、信誉满分的默认事实：用于启动初期与测试。
type NoHistory struct{}

// RecordFailure 不记账。
func (NoHistory) RecordFailure(netip.Addr) {}

// ReputationScore 恒为满分。
func (NoHistory) ReputationScore(netip.Addr) uint32 { return 100 }

// PriorBanCount 恒为 0。
func (NoHistory) PriorBanCount(netip.Addr) uint32 { return 0 }

// RiskEngineEnabled 恒为 false（无历史模式不启用风险引擎）。
func (NoHistory) RiskEngineEnabled() bool { return false }

// ThreatIntel 是威胁情报缓存查询口（可空）。
//
// 只暴露一次查询：判定层不关心缓存的刷新、统计与来源管理，那些属于威胁情报子系统。
// 返回的 confidence 是该条目的置信度（0–1），由情报源配置给出。
type ThreatIntel interface {
	// ThreatLookup 查询 ip 是否命中情报缓存，命中时返回来源名与置信度。
	ThreatLookup(ip netip.Addr) (source string, confidence float64, ok bool)
}

// feedBanConfidence 是「高置信度」的下限：命中且置信度不低于它的条目直接封禁，
// 跳过失败窗口计数。0.8 与默认 IPsum 源对齐；更保守的源（如 DShield 0.7）仍走
// 常规窗口判定，避免单一低质量名单直接封禁。调整源配置里的 confidence 即可改变
// 哪些源越过这条线。
const feedBanConfidence = 0.8

// Tick 是一轮处理的时间上下文。时钟与高峰判定都由调用方给出，本层不读系统时钟。
type Tick struct {
	// Now 是当前 Unix 秒。
	Now int64
	// PeakHours 表示是否处于业务高峰期（影响阈值系数）。
	PeakHours bool
}

// NewTick 构造时间上下文。
func NewTick(now int64, peakHours bool) Tick {
	return Tick{Now: now, PeakHours: peakHours}
}

// Counters 是主链路累计计数（供组合根发布到统计快照，本层不写全局态）。
type Counters struct {
	// LinesParsed 是已解析的非空日志行数。
	LinesParsed uint64
	// LinesSkipped 是分割期丢弃的超长行/残段数。
	LinesSkipped uint64
	// RegexMatches 是正则命中次数。
	RegexMatches uint64
	// IPsExtracted 是成功提取并校验的 IP 数。
	IPsExtracted uint64
	// BansIntent 是产生的封禁意图数。
	BansIntent uint64
}

// jailState 是单个 jail 的运行时状态（规则集 + 判定参数 + 失败窗口）。
type jailState struct {
	rules  *logparse.RuleSet
	policy JailPolicy
	window *detect.FailureWindow
}

// splitterKey 是一个源的分割器槽位。
//
// 必须带 jail：同一日志文件可被多个 jail 共享，执行体把同一批字节依次喂给每个 jail。
// 只按源索引会让第二个 jail 拿到「上一轮残行 + 本批首行」拼成的错行，并漏掉本批首行。
type splitterKey struct {
	jail   string
	source ingest.SourceID
}

// Pipeline 是主链路装配体，由执行体独占。
type Pipeline struct {
	jails     map[string]*jailState
	splitters map[splitterKey]*logparse.LineSplitter
	intel     ThreatIntel
	counters  Counters
}

// NewPipeline 新建空装配体。
func NewPipeline() *Pipeline {
	return &Pipeline{
		jails:     make(map[string]*jailState),
		splitters: make(map[splitterKey]*logparse.LineSplitter),
	}
}

// RegisterJail 注册（或替换）一个 jail 的规则集与判定参数。
//
// 重载语义：整份替换规则集与参数，但**保留失败窗口**——窗口是运行期观测，不属于配置，
// 重载配置不该抹掉已经积累的失败计数（旧实现会连缓冲一起清空）。
func (p *Pipeline) RegisterJail(rules *logparse.RuleSet, policy JailPolicy) {
	jail := rules.Jail()
	window := detect.NewFailureWindow()
	if prev, ok := p.jails[jail]; ok {
		window = prev.window
	}
	p.jails[jail] = &jailState{rules: rules, policy: policy, window: window}
}

// HasJail 报告是否已注册该 jail。
func (p *Pipeline) HasJail(jail string) bool {
	_, ok := p.jails[jail]
	return ok
}

// JailCount 返回已注册的 jail 数（诊断用）。
func (p *Pipeline) JailCount() int { return len(p.jails) }

// RetainJails 只保留 keep 中列出的 jail，返回被摘除的数量。
//
// 重载后配置里已消失的 jail 连同其失败窗口一并回收。旧实现靠整体替换配置达到同样效果；
// 本层状态与配置分离（配置在组合根、窗口在执行体），所以必须显式回收——否则长期运行中
// 改过名的 jail 会一直留在表里。
func (p *Pipeline) RetainJails(keep []string) int {
	keepSet := make(map[string]struct{}, len(keep))
	for _, k := range keep {
		keepSet[k] = struct{}{}
	}
	before := len(p.jails)
	for jail := range p.jails {
		if _, ok := keepSet[jail]; !ok {
			delete(p.jails, jail)
		}
	}
	return before - len(p.jails)
}

// Counters 返回累计计数快照。
func (p *Pipeline) Counters() Counters { return p.counters }

// PendingSources 返回当前挂起半行的源数（诊断用；同一源被多个 jail 共享时只计一次）。
func (p *Pipeline) PendingSources() int {
	seen := make(map[ingest.SourceID]struct{}, len(p.splitters))
	for key := range p.splitters {
		seen[key.source] = struct{}{}
	}
	return len(seen)
}

// collectLine 解析一行并收集结果。
//
// 空行（只有 \n）直接跳过，与旧实现一致；解析失败的行同样跳过。
func collectLine(rules *logparse.RuleSet, line []byte, out *[]parsedLine) {
	if len(line) == 0 {
		return
	}
	addr, via, ok := rules.Parse(string(line))
	if !ok {
		return
	}
	// 判定层的统一入口做一次 Unmap：`::ffff:1.2.3.4` 若不折回 IPv4，失败窗口会把
	// 同一来源记成两个 IP，集群聚合也会按 IPv6 取 /48 前缀把不同 /24 并成一簇。
	*out = append(*out, parsedLine{ip: addr.Unmap(), via: via})
}

// parsedLine 是一行解析结果。
type parsedLine struct {
	ip  netip.Addr
	via logparse.MatchVia
}

// lineCtx 是一批处理中不变的行级上下文：把 judgeLine 的参数收拢成一个结构，
// 避免长参数列表，也让「同一批的 jail/源/时钟/事实必须一致」成为显式约束。
type lineCtx struct {
	jail   string
	source ingest.SourceID
	tick   Tick
	facts  DecisionFacts
}

// OnChunk 处理一批来自 source 的新增字节，把判定产生的封禁意图追加到 out 并返回。
//
// 未注册的 jail 返回 ok=false（调用方据此记录并丢弃），已注册返回 true。
// 返回的切片是 out 追加后的结果，调用方可复用 out 的容量以避免每批分配。
func (p *Pipeline) OnChunk(
	jail string,
	source ingest.SourceID,
	bytes []byte,
	tick Tick,
	facts DecisionFacts,
	out []BanIntent,
) ([]BanIntent, bool) {
	state, ok := p.jails[jail]
	if !ok {
		return out, false
	}

	// 先把本批切出的 (ip, via) 收集到局部表，再统一走判定——避免在分割器的回调里
	// 同时访问 jail 表与计数器（分割器回调期间缓冲区归分割器所有）。
	var parsed []parsedLine
	{
		key := splitterKey{jail: jail, source: source}
		splitter := p.splitters[key]
		if splitter == nil {
			splitter = logparse.NewLineSplitter()
			p.splitters[key] = splitter
		}
		stats := logparse.SplitStats{}
		splitter.Feed(bytes, &stats, func(line []byte) {
			collectLine(state.rules, line, &parsed)
		})
		p.counters.LinesSkipped += stats.Oversized
		p.counters.LinesParsed += stats.Emitted
	}

	ctx := lineCtx{jail: jail, source: source, tick: tick, facts: facts}
	for _, pl := range parsed {
		out = p.judgeLine(&ctx, pl.ip, pl.via, out)
	}
	return out, true
}

// FlushSource 把某源挂起的半行当作完整行处理（不再等待换行）。
//
// 源关闭 / 轮转 / 截断之前调用，避免丢掉最后一个不完整行。与 LineSplitter.Flush
// 配套；未注册的 jail 返回 false。
func (p *Pipeline) FlushSource(
	jail string,
	source ingest.SourceID,
	tick Tick,
	facts DecisionFacts,
	out []BanIntent,
) ([]BanIntent, bool) {
	state, ok := p.jails[jail]
	if !ok {
		return out, false
	}

	splitter := p.splitters[splitterKey{jail: jail, source: source}]
	if splitter == nil {
		return out, true
	}

	var parsed []parsedLine
	stats := logparse.SplitStats{}
	splitter.Flush(&stats, func(line []byte) {
		collectLine(state.rules, line, &parsed)
	})
	p.counters.LinesSkipped += stats.Oversized
	p.counters.LinesParsed += stats.Emitted

	ctx := lineCtx{jail: jail, source: source, tick: tick, facts: facts}
	for _, pl := range parsed {
		out = p.judgeLine(&ctx, pl.ip, pl.via, out)
	}
	return out, true
}

// judgeLine 对一条已解析出 IP 的行做判定，必要时产出封禁意图。
//
// OnChunk 与 FlushSource 共用此路径，保证「完整行」与「收尾半行」走完全相同的判定
// 语义（时钟、系数、窗口、渐进时长都一致）。
func (p *Pipeline) judgeLine(ctx *lineCtx, ip netip.Addr, via logparse.MatchVia, out []BanIntent) []BanIntent {
	if via == logparse.MatchViaRegex {
		p.counters.RegexMatches++
	}
	p.counters.IPsExtracted++

	state := p.jails[ctx.jail]
	// 顺序是语义的一部分：先记这次失败，再取分数算阈值（见 DecisionFacts）。
	ctx.facts.RecordFailure(ip)

	// 情报命中：高置信度的已知恶意源直接封禁，跳过失败窗口计数。
	// 低置信度命中不特殊处理，继续走常规阈值——由本地行为决定是否封禁。
	if p.intel != nil {
		if source, confidence, ok := p.intel.ThreatLookup(ip); ok && confidence >= feedBanConfidence {
			plan := decision.PlanBan(
				state.policy.BanTime,
				ctx.facts.PriorBanCount(ip),
				ctx.tick.Now,
				1,
			)
			p.counters.BansIntent++
			return append(out, BanIntent{
				Jail:   ctx.jail,
				IP:     ip,
				Source: ctx.source,
				Plan:   plan,
				Reason: fmt.Sprintf("%s: 情报源 %s 命中（置信度 %.2f）", ctx.jail, source, confidence),
			})
		}
	}

	// 阈值走加法模型：内网与低信誉的系数不会互相抵消。
	threshold := decision.EffectiveThreshold(
		state.policy.MaxRetries,
		ctx.tick.PeakHours,
		decision.IsInternal(ip),
		ctx.facts.ReputationScore(ip),
	)

	verdict := state.window.Observe(ip, ctx.tick.Now, state.policy.FindTime, threshold)
	if !verdict.ReachedCap {
		return out
	}

	plan := decision.PlanBan(
		state.policy.BanTime,
		ctx.facts.PriorBanCount(ip),
		ctx.tick.Now,
		verdict.Recent,
	)
	p.counters.BansIntent++
	// 封禁意图已产出：清掉窗口，避免同一次攻击在下一批重复触发（与旧实现「封禁成功后
	// 移除条目」一致）。
	state.window.Forget(ip)
	return append(out, BanIntent{
		Jail:   ctx.jail,
		IP:     ip,
		Source: ctx.source,
		Plan:   plan,
		Reason: fmt.Sprintf("%s: %d 次失败达到阈值 %d", ctx.jail, verdict.Recent, threshold),
	})
}

// OnSourceRotated 处理源轮转/截断：丢弃该源在每个 jail 下挂起的半行。
//
// 旧文件的半行不该与新文件的开头拼接。与 ingest.Chunk.Rotated 配套使用。
func (p *Pipeline) OnSourceRotated(source ingest.SourceID) {
	for key, splitter := range p.splitters {
		if key.source == source {
			splitter.Clear()
		}
	}
}

// ForgetSource 摘除源，连同其在各 jail 下的半行缓冲一并清理，避免缓冲表随轮转/重载无限增长。
func (p *Pipeline) ForgetSource(source ingest.SourceID) {
	for key := range p.splitters {
		if key.source == source {
			delete(p.splitters, key)
		}
	}
}

// Cleanup 周期维护：清理各 jail 已完全过期的失败条目，返回清理条数。
//
// 应由 scheduler 按固定周期调用，而**不是**挂在事件回调上——维护与事件流量解耦。
func (p *Pipeline) Cleanup(now int64) int {
	removed := 0
	for _, state := range p.jails {
		removed += state.window.CleanupExpired(now, state.policy.FindTime)
	}
	return removed
}

// ScanClusters 周期维护：检出集群扫描，逐个命中回调 (jail, 命中, cluster 配置)。
//
// 由执行体决定下发网段封禁还是只记审计日志；onHit 返回「本次命中是否已处置」。
//
// 为什么单独一个周期，而不是跟着 Cleanup：集群检测的输入是跨 IP 的——单行判定只看得到
// 一个源，凑不出「同一网段内有多少个不同源」这个结论，故只能周期判定。而它必须比
// cluster.Window 明显更快地重复：计数按 now-ts <= window 判定，若检测恰好每 window 秒
// 跑一次，一批刚写入的失败会在下一次检测前滑出窗口，扫描永远凑不够 MinIPs。检测间隔应
// 远小于窗口，让窗口内任意相位开始的扫描都能被至少一次完整的检测看到。
//
// 只有 onHit 返回 true（确实处置过）才清除该集群涉及的 IP 失败记录，防止同一集群在
// 下一个检测周期被重复下发。审计模式或未装配下发通道时命中只是观测，清计数会让真实
// 来源 IP 的失败累计凭空消失，而封禁根本没有发生。
func (p *Pipeline) ScanClusters(now int64, onHit func(jail string, hit decision.ClusterHit, cfg config.ClusterConfig) bool) {
	for jail, state := range p.jails {
		for _, hit := range decision.DetectCluster(state.window, now, state.policy.Cluster) {
			if !onHit(jail, hit, state.policy.Cluster) {
				continue
			}
			// 清除已处置的集群 IP，防止下一周期重复检测同一集群
			for _, ip := range hit.IPs {
				state.window.Forget(ip)
			}
		}
	}
}
