// Package telemetry 承载内核链路的只读观测面：统计/速率/分析快照、速率窗口与最近事件环。
//
// 它是「内核 → 守护进程」方向的汇合点：internal/kernel 的事件泵是唯一写入者，HTTP 层
// 与诊断路径都是读取者。因此这里刻意做成单写多读——写侧在锁内更新状态并把整份快照发布到
// atomic.Pointer，读侧无锁且永远看到自洽的一刻，不会读到「stats 已换、rates 还是旧的」
// 这种跨字段撕裂。
//
// # 为什么不直接读内核
//
// 每次 HTTP 查询都去问内核会把控制面的往返成本摊到用户请求上，而 netlink 单守护进程注册
// 又决定了同一 socket 上只能有一串在途请求。快照把「问内核」收敛为泵的一个周期，读侧
// 因此与内核健康脱钩：内核失联时读到的是最后一刻的快照加上 Link 里的失败计数，而不是
// 每个请求各自超时。
package telemetry

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/analysis"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
)

// Rates 是速率表的一次全量采样。
//
// GlobalPPS/GlobalBPS 是内核按「自上次查询以来」算出的平均速率，因此一次查询恰好对应
// 一个 EWMA 样本（见 Windows 的说明）；Entries 是该时刻的每源计数。
type Rates struct {
	GlobalPPS uint64
	GlobalBPS uint64
	Entries   []contract.RateEntry
}

// Windows 是速率的多窗口 EWMA 派生量。
//
// 内核没有「窗口」语义，它只回答「自上次查询以来的平均速率」；短/中/长三档（5 秒 /
// 60 秒 / 300 秒，见 analysis.EWMASmoother）与异常判定都是守护进程侧的派生，故放在这里
// 而不是内核契约里。
type Windows struct {
	// PPS / BPS 是全局每秒包数与字节数的平滑结果。
	PPS analysis.EWMASnapshot `json:"pps"`
	BPS analysis.EWMASnapshot `json:"bps"`
	// PPSAnomalyLevel 是包速率的异常等级（0 正常 / 1 轻度 / 2 中度 / 3 严重）。
	PPSAnomalyLevel int `json:"pps_anomaly_level"`
	// Samples 是已喂入的样本数；为 0 表示窗口尚未初始化（读侧据此区分「零」与「无数据」）。
	Samples uint64 `json:"samples"`
	// SampledAt 是最后一个样本的时刻。
	SampledAt time.Time `json:"sampled_at"`
}

// LeaseState 是内核「单一守护进程注册租约」的状态，取值即线上 JSON 的字符串。
//
// 内核同一时刻只承认一个 portid：非 held 时本进程下发的每一条指令都会被静默丢弃。
// 五个取值的含义：
//
//	none     本进程还没发起过注册（内核链路未装配，或泵尚未启动）
//	idle     注册在尝试中，但从未持有过租约
//	held     内核已承认本进程为唯一守护进程
//	refused  内核明确拒绝（已有活跃守护进程）
//	lost     曾经持有、之后注册失败（模块重载、被判死、链路断开）
type LeaseState string

// 租约状态的五个取值。字符串就是契约（contract/http.fwidl 的 RuntimeSnapshot.lease_state）
// 与 /proc 侧文档共用的拼写，改任何一处都要同步另一处。
const (
	LeaseNone    LeaseState = "none"
	LeaseIdle    LeaseState = "idle"
	LeaseHeld    LeaseState = "held"
	LeaseRefused LeaseState = "refused"
	LeaseLost    LeaseState = "lost"
)

// Link 是内核链路自身的健康状态。
//
// 快照里的数字「新不新」只能由链路状态判断：链路断了以后 Stats 会一直停在最后一次成功
// 采样，读侧若看不到 Link 就会把陈旧值当成实时值。
type Link struct {
	// Registered 表示内核已把本进程认作唯一守护进程（未注册时内核丢弃一切指令）。
	Registered bool
	// Lease 是守护进程注册租约的状态机当前值（见 LeaseState）。它与 Registered 不是重复：
	// Registered 只说「最后一次注册成功了」，而运维要能区分「还没试」「被拒（已有别的
	// 守护进程）」与「曾经持有、后来丢了」——这三者对指令的下发含义完全不同。
	Lease LeaseState
	// LeaseLosses 是进入 lost 的累计次数：状态快照本身看不出一段时间内的反复失联，
	// 而这个数正是「内核模块被重载过 / 前一个守护进程被判死」的痕迹。
	LeaseLosses uint64
	// LinkDown 表示接收侧已退出，回复与事件都不会再来。
	LinkDown bool
	// LastRegisterAt / LastSampleAt / LastReconcileAt 是三类成功动作的最后时刻。
	LastRegisterAt  time.Time
	LastSampleAt    time.Time
	LastReconcileAt time.Time
	// SampleFailures / ReconcileFailures 是两类周期动作的累计失败次数。
	SampleFailures    uint64
	ReconcileFailures uint64
	// 以下五项镜像路由器计数：事件被丢弃、解码失败、头不合法、无人认领的回复、
	// 以及非内核 portid 发来的报文数（本机其他进程伪造的指令回执，必须可见）。
	EventsDropped    uint64
	DecodeErrors     uint64
	Malformed        uint64
	UnmatchedReplies uint64
	ForeignPortIDs   uint64
	// LastError 是最近一次链路失败的原文（含时刻，便于判断是持续失败还是偶发）。
	LastError   string
	LastErrorAt time.Time
}

// Snapshot 是一次完整的只读快照。指针语义上的值是不可变的。
type Snapshot struct {
	// SampledAt 是本快照最后一次被写入的时刻。
	SampledAt time.Time
	// Stats 是内核统计（零值表示从未采到）。
	Stats contract.StatsResponse
	// Rates 是速率表采样。
	Rates Rates
	// Analysis 是协议分布与 Top-N 采样。
	Analysis contract.AnalysisResponse
	// Windows 是速率派生窗口。
	Windows Windows
	// Link 是链路健康。
	Link Link
}

// Store 是快照的持有者。零值不可用，必须经 NewStore 构造。
type Store struct {
	// mu 只保护写侧：构造下一份快照期间独占 cur。
	mu sync.Mutex
	// cur 是写侧独占的最新状态。
	cur Snapshot
	// windows 与 cur.Windows 同步：每次 SetRates 喂一个样本并刷新快照字段。
	windows *windowsState
	// rateHistory 与 windows 同节奏（每次 SetRates 一个点），但它不进快照：快照的契约是
	// 「一次原子发布的自洽一刻」，而历史是一条随时间增长的时间序列。
	rateHistory *RateHistory
	// pub 是发布出去的那一份；读侧只碰它。
	pub atomic.Pointer[Snapshot]
}

// NewStore 建立空快照并开始发布（读侧因此永远不会拿到 nil）。
func NewStore() *Store {
	s := &Store{
		windows:     newWindows(),
		rateHistory: NewRateHistory(DefaultRateHistorySize),
		cur:         Snapshot{Link: Link{Lease: LeaseNone}},
	}
	s.publish()
	return s
}

// Snapshot 返回当前快照。无锁，返回值是发布出去的那份不可变副本。
func (s *Store) Snapshot() Snapshot { return *s.pub.Load() }

// RateSamples 返回最近 n 个速率采样点（按时间升序）；n <= 0 时返回环内全部。
//
// 读侧是 /api/v1/rates/history（画折线）与异常检测（取分位基线），两者的判据都要求
// 「这些点真的来自内核回答」，所以这里不做按墙上时钟补点：采样中断（链路断开）就是
// 空洞，图上表现为线段变长，而不是凭空多出一个零速率样本。
func (s *Store) RateSamples(n int) []RateSample { return s.rateHistory.Samples(n) }

// SetStats 发布内核统计并刷新采样时刻。
func (s *Store) SetStats(v contract.StatsResponse, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur.Stats = v
	s.touch(at)
}

// SetAnalysis 发布协议分布采样。
func (s *Store) SetAnalysis(v contract.AnalysisResponse, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur.Analysis = v
	s.touch(at)
}

// SetRates 发布速率采样，并把它作为**一个** EWMA 样本喂入窗口。
//
// entries 在发布前复制一份：内核的每源计数表可能上百条，每 5 秒一次全表拷贝可以接受，
// 换来的是「发布出去的快照里没有别人还在写的切片」。按引用共享会让读侧的遍历与写侧的
// 下一次解码并发访问同一底层数组——正是本包要消除的那类撕裂。
func (s *Store) SetRates(r Rates, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.Entries = append([]contract.RateEntry(nil), r.Entries...)
	s.cur.Rates = r
	s.cur.Windows = s.windows.sample(r.GlobalPPS, r.GlobalBPS, at)
	s.rateHistory.Push(rateSampleFrom(r, at))
	s.touch(at)
}

// SetLinkRegistered 记一次成功的守护进程注册：租约进入 held。
func (s *Store) SetLinkRegistered(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setLease(LeaseHeld)
	s.cur.Link.LastRegisterAt = at
	s.publish()
}

// SetLeaseRefused 记一次「内核明确拒绝注册」——已有别的守护进程持有租约。
//
// 这不是失联：指令被丢弃的原因是内核认的是另一个进程，运维动作是「找到并停掉那一个」。
func (s *Store) SetLeaseRefused() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setLease(LeaseRefused)
	s.publish()
}

// MarkLeaseAttemptFailed 记一次注册请求失败后的租约去向。
//
// 曾持有过就进入 lost 并累计一次失联（模块重载、被判死、链路断开）；从没持有过则停在
// idle。两者对运维的含义完全不同：前者意味着本进程曾经下发过、如今已经没人认领的封禁。
func (s *Store) MarkLeaseAttemptFailed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur.Link.Lease == LeaseHeld {
		s.setLease(LeaseLost)
	} else {
		s.setLease(LeaseIdle)
	}
	s.publish()
}

// setLease 推进租约状态。调用方必须持 mu，且不调 publish（由公开方法决定发布时机）。
//
// Registered 由这里跟着 Lease 一起走，而不是留给调用方各写一次：两个字段说的是同一件事，
// 分开写迟早会有一句漏掉，读侧就会看到「已注册但租约是 refused」。
func (s *Store) setLease(next LeaseState) {
	if s.cur.Link.Lease == LeaseHeld && next == LeaseLost {
		s.cur.Link.LeaseLosses++
	}
	s.cur.Link.Lease = next
	s.cur.Link.Registered = next == LeaseHeld
}

// SetLinkSampled 记一次成功的周期采样。
func (s *Store) SetLinkSampled(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur.Link.LastSampleAt = at
	s.publish()
}

// SetLinkReconciled 记一次成功的对账。
func (s *Store) SetLinkReconciled(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur.Link.LastReconcileAt = at
	s.publish()
}

// BumpSampleFailure 记一次采样失败（三个查询任一失败都算一次）。
func (s *Store) BumpSampleFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur.Link.SampleFailures++
	s.publish()
}

// BumpReconcileFailure 记一次对账失败。
func (s *Store) BumpReconcileFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur.Link.ReconcileFailures++
	s.publish()
}

// SetRouterCounters 把接收侧计数并入链路状态，并可宣告链路已断开。
func (s *Store) SetRouterCounters(c RouterCounters, down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur.Link.EventsDropped = c.EventsDropped
	s.cur.Link.DecodeErrors = c.DecodeErrors
	s.cur.Link.Malformed = c.Malformed
	s.cur.Link.UnmatchedReplies = c.UnmatchedReplies
	s.cur.Link.ForeignPortIDs = c.ForeignPortIDs
	s.cur.Link.LinkDown = down
	s.publish()
}

// SetLinkError 记一次链路失败的原文与时刻。
func (s *Store) SetLinkError(msg string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur.Link.LastError = msg
	s.cur.Link.LastErrorAt = at
	s.publish()
}

// touch 刷新快照时刻并发布；调用方必须持 mu。
func (s *Store) touch(at time.Time) {
	if !at.IsZero() {
		s.cur.SampledAt = at
	}
	s.publish()
}

// publish 把写侧状态整体发布。调用方必须持 mu。
func (s *Store) publish() {
	snap := s.cur
	s.pub.Store(&snap)
}

// RouterCounters 是接收侧计数的本地镜像。
//
// 定义在这里而不是直接收 kernel.RouterStats：telemetry 不能反向依赖 kernel（kernel 要
// 依赖本包发布快照），循环依赖由这张小表切断。
type RouterCounters struct {
	EventsDropped    uint64
	DecodeErrors     uint64
	Malformed        uint64
	UnmatchedReplies uint64
	ForeignPortIDs   uint64
}

// Windows 累加器。
//
// 内核给出的 global_pps 已经是「自上次查询以来的平均速率」，所以每查询一次就该喂一个
// 样本；再按 RateSampler 那样对累计计数做差分会把速率算成平方级。平滑器本身是线程安全
// 的，但这里由 Store 的写锁串行驱动，不额外加锁。
type windowsState struct {
	pps     *analysis.EWMASmoother
	bps     *analysis.EWMASmoother
	samples uint64
}

func newWindows() *windowsState {
	return &windowsState{pps: analysis.NewEWMASmoother(), bps: analysis.NewEWMASmoother()}
}

// sample 喂入一个样本并返回派生快照。
func (w *windowsState) sample(pps, bps uint64, at time.Time) Windows {
	w.pps.Sample(float64(pps))
	w.bps.Sample(float64(bps))
	w.samples++
	out := Windows{
		PPS:             w.pps.Snapshot(),
		BPS:             w.bps.Snapshot(),
		PPSAnomalyLevel: w.pps.AnomalyLevel(),
		Samples:         w.samples,
		SampledAt:       at,
	}
	return out
}
