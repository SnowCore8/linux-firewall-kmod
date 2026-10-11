// 事件泵：内核 → 守护进程方向的唯一消费者。
//
// 组合根把 NewEventChannel 的第二个返回值（事件流）交到这里。在此之前它没有任何消费者：
// 内核推送的封禁/解封/白名单/DDoS 事件在 4096 深度的队列里堆满后被静默丢弃，于是
// 「内核知道而守护进程不知道」成为常态——面板上的封禁表只是本进程下发过的子集，procfs
// 手工封禁、内核自动封禁、到期自动解封全都看不见。
//
// # 为什么必须先注册
//
// 内核在收到 DAEMON_REGISTER 之前会丢弃本 portid 的一切指令（见 fw_netlink.c 的
// 「无守护进程注册，丢弃类型」分支），并在 30 秒收不到消息后判守护进程死亡、允许新的
// portid 接管。因此注册不是可选的握手礼节：不注册，统计/速率/分析三个查询只会得到一串
// 超时，封禁下发石沉大海。租约由任意一条报文刷新，但泵仍按 RegisterInterval 主动续约，
// 使「链路仍在但空闲」时也保持注册状态，不依赖采样周期的副作用。
//
// # 所有权
//
// 泵是 Store/Ring 的唯一写入者，也是 ActiveBanCache 除了下发路径之外的写入者。
// 封禁域的对账（Reconcile）以内核为准：内核独有的条目补进镜像，镜像独有的幽灵剔除，
// 刚下发还没等到确认的条目由 pending 标记保护一个短窗口。
package kernel

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/runtime"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/telemetry"
)

// 泵的各类周期。命名常量而非配置项：它们的取值由内核侧的固定语义决定（30 秒判死、
// 5 秒一个 EWMA 样本粒度），配置化只会让部署把链路调成不自洽的样子。
const (
	// SampleInterval 是主动采样周期（统计 / 分析 / 速率三张表一并取回）。
	SampleInterval = 5 * time.Second
	// ReconcileInterval 是封禁表与内核的对账周期。
	ReconcileInterval = 30 * time.Second
	// RegisterInterval 是注册租约的主动续约周期，必须明显短于内核的 30 秒判死。
	RegisterInterval = 10 * time.Second
	// shutdownPollInterval 是关停轮询节拍：Shutdown 只有标志位而没有可 select 的通道，
	// 空闲时泵必须周期性醒来确认一次，否则关停要等到下一个采样周期才被发现。
	shutdownPollInterval = 500 * time.Millisecond
	// DefaultRequestTimeout 是单次 netlink 请求的超时上限。
	DefaultRequestTimeout = 2 * time.Second
)

// SSE 域名取值，与契约 /api/v1/events 的订阅域一致。
//
// 这里刻意没有 jails：jail 配置的所有权在入站执行体，本泵只是内核指令的搬运工
// （CONFIG_CHANGE 经 directives 队列交给执行体落地），它既不知道新形状也不拥有那张表，
// 凭空加一个域名只会造出一个由错误的一方触发的空域。jails 的变更触发点在
// runtime.InboundExecutor 的快照发布（见 JailSnapshotListener），载荷与 REST 同形。
const (
	// DomainBans 是封禁表变更通知。
	DomainBans = "bans"
	// DomainWhitelist 是白名单表变更通知。
	DomainWhitelist = "whitelist"
	// DomainStats 是内核统计快照。
	DomainStats = "stats"
	// DomainRates 是速率表快照。
	DomainRates = "rates"
)

// Sampler 是泵需要的客户端能力。
//
// 抽象成接口的理由是可测性：这六条请求都要真的把报文发到内核并等配对回复，单元测试里
// 没有内核。*Client 即其生产实现。
type Sampler interface {
	Register(timeout time.Duration) (contract.DaemonRegisterAck, error)
	QueryStats(timeout time.Duration) (contract.StatsResponse, error)
	QueryAnalysis(timeout time.Duration) (contract.AnalysisResponse, error)
	ListRatesAll(timeout time.Duration) (RateSnapshot, error)
	ListBansAll(timeout time.Duration) ([]contract.BanEntry, error)
}

// Publisher 是「某个域变了」的通知出口，由 http.SSEBroker 实现。
//
// 接口留在这里而不是直接依赖 http 包：kernel 层不得反向依赖表现层。
type Publisher interface {
	Publish(event string, data any)
}

// DomainMirror 把一次域变更落成该域的帧载荷，由 internal/http 的 SSEReplicas 实现。
//
// 为什么泵自己不定形状：载荷的结构体都住在表现层（StatsResponse、RateResponse、
// BanResponse、WhitelistEntryResponse），kernel 反过来依赖 http 就是循环依赖——http 要读
// 本包的观测快照。此前泵直接把内部形状发出去（stats 帧带的是内核统计结构、rates 帧带的
// 是快照条目），前端按 REST 的类型解析这些帧，同一页上 SSE 与 REST 的读数因此悄悄分叉。
// 现在泵只交出**变更时机**与**它自己拥有的镜像内容**（bans/whitelist 那两份表可能来自
// PumpDeps 注入的私有实例，所以按参数传），stats/rates 由镜像方从同一份 telemetry.Store
// 快照里现取——泵在 SetStats/SetRates 之后才发布，取到的就是这一轮的值。
//
// 返回值是 any：那些类型本层不认识，也不该认识。
type DomainMirror interface {
	// Bans 把封禁镜像整表折成 bans 域载荷。
	Bans(entries []bans.BanInfo) any
	// Whitelist 把白名单镜像的键折成 whitelist 域载荷。
	Whitelist(cidrs []string) any
	// Stats 从内核快照装配 stats 域载荷。
	Stats() any
	// Rates 从内核快照装配 rates 域载荷。
	Rates() any
}

// CounterHandle 是一个可累加的计数器句柄（*atomic.Int64 即满足）。
type CounterHandle interface {
	Add(delta int64)
}

// Metrics 是计数写入端，由组合根用 http.Metrics 适配。
//
// 泵只写两条内核侧计数：命中速率阈值的 DDoS 事件、以及内核拒绝执行的指令。二者此前都
// 只有读取方（/metrics 与降级快照），本泵即其写入端。
type Metrics interface {
	Counter(name string) CounterHandle
}

// 泵写入的计数名，与 http/metrics.go 的既有读取方逐字一致。
const (
	// CounterDdosEvents 是速率/协议阈值命中次数。
	CounterDdosEvents = "firewall_ddos_events_total"
	// CounterCommandRejected 是内核以 CmdResult 回执失败的指令次数。
	CounterCommandRejected = "firewall_kernel_commands_rejected_total"
)

// PumpDeps 是事件泵的装配参数。Sampler、Events、Store 必填，其余可选（nil 按不动作处理）。
type PumpDeps struct {
	Sampler Sampler
	Events  <-chan Incoming
	Store   *telemetry.Store
	// Router 用于并入接收侧计数；nil 时跳过（单元测试可用零值）。
	Router *Router
	// Ring 是最近事件环；nil 时泵自建 DefaultRingSize 容量。
	Ring *telemetry.Ring
	// Cache / Whitelist 是两份内存镜像；nil 时取进程级单例。
	Cache     *bans.ActiveBanCache
	Whitelist *bans.Whitelist
	Publish   Publisher
	// Mirror 把域变更折成帧载荷；nil 时**不推送**（载荷形状没有生产者，宁可不发也不发
	// 一份与 REST 不同形的帧）。组合根把它接到 http.SSEReplicas。
	Mirror  DomainMirror
	Metrics Metrics
	Logger  *slog.Logger

	// Directives 是内核→入站执行体的反向指令队列（非阻塞投递，见 runtime.Directive）。
	// nil 时 CONFIG_CHANGE 与封禁下发被拒只记日志，执行体不会收到。
	Directives chan<- runtime.Directive

	// 周期覆盖项：零值取上方常量，供测试缩短节拍。
	Timeout           time.Duration
	SampleEvery       time.Duration
	ReconcileEvery    time.Duration
	RegisterEvery     time.Duration
	ShutdownPollEvery time.Duration
}

// EventPump 消费内核事件流并按周期采样、对账。由单个 goroutine 独占。
type EventPump struct {
	sampler    Sampler
	events     <-chan Incoming
	store      *telemetry.Store
	ring       *telemetry.Ring
	router     *Router
	cache      *bans.ActiveBanCache
	whitelist  *bans.Whitelist
	publish    Publisher
	mirror     DomainMirror
	metrics    Metrics
	logger     *slog.Logger
	directives chan<- runtime.Directive

	timeout        time.Duration
	sampleEvery    time.Duration
	reconcileEvery time.Duration
	registerEvery  time.Duration
	shutdownPoll   time.Duration

	// 上次已成功取回的采样值，用于「只在变化时推送」：安静时段不重复序列化同样的内容。
	lastStats    contract.StatsResponse
	haveStats    bool
	lastRatesPPS uint64
	lastRatesBPS uint64
	haveRates    bool
}

// NewEventPump 校验必填依赖并装配泵。
func NewEventPump(deps PumpDeps) (*EventPump, error) {
	if deps.Sampler == nil {
		return nil, errors.New("kernel: 事件泵缺少 Sampler")
	}
	if deps.Events == nil {
		return nil, errors.New("kernel: 事件泵缺少事件流")
	}
	if deps.Store == nil {
		return nil, errors.New("kernel: 事件泵缺少快照存储")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	cache := deps.Cache
	if cache == nil {
		cache = bans.GlobalCache()
	}
	wl := deps.Whitelist
	if wl == nil {
		wl = bans.GlobalWhitelist()
	}
	ring := deps.Ring
	if ring == nil {
		ring = telemetry.NewRing(0)
	}
	return &EventPump{
		sampler:        deps.Sampler,
		events:         deps.Events,
		store:          deps.Store,
		ring:           ring,
		router:         deps.Router,
		cache:          cache,
		whitelist:      wl,
		publish:        deps.Publish,
		mirror:         deps.Mirror,
		metrics:        deps.Metrics,
		logger:         logger,
		directives:     deps.Directives,
		timeout:        orDefault(deps.Timeout, DefaultRequestTimeout),
		sampleEvery:    orDefault(deps.SampleEvery, SampleInterval),
		reconcileEvery: orDefault(deps.ReconcileEvery, ReconcileInterval),
		registerEvery:  orDefault(deps.RegisterEvery, RegisterInterval),
		shutdownPoll:   orDefault(deps.ShutdownPollEvery, shutdownPollInterval),
	}, nil
}

// Ring 返回事件环，供读侧（面板与诊断端点）取最近事件。
func (p *EventPump) Ring() *telemetry.Ring { return p.ring }

// Run 驱动泵直到关停被请求。
//
// 顺序是刻意的：先注册再采样。注册失败不终结本循环——内核模块可能刚重载、或前一个守护
// 进程还没被判死，此时每个周期都会重试，链路恢复后自动接上；反之若在此 return，组合根
// 只会在「内核曾经不可用」的情况下永久失去事件。
func (p *EventPump) Run(stop *runtime.Shutdown) {
	p.register("启动")

	sample := time.NewTicker(p.sampleEvery)
	defer sample.Stop()
	reconcile := time.NewTicker(p.reconcileEvery)
	defer reconcile.Stop()
	register := time.NewTicker(p.registerEvery)
	defer register.Stop()
	heartbeat := time.NewTicker(p.shutdownPoll)
	defer heartbeat.Stop()

	for {
		select {
		case msg := <-p.events:
			p.handle(msg)
		case <-sample.C:
			p.sample()
		case <-reconcile.C:
			p.reconcile()
		case <-register.C:
			p.register("续约")
		case <-heartbeat.C:
			if stop != nil && stop.IsShutdown() {
				return
			}
			p.syncRouterCounters()
		}
		if stop != nil && stop.IsShutdown() {
			return
		}
	}
}

// register 向内核注册为唯一守护进程并记录结论。
//
// 「发送成功」不等于「注册成功」：内核拒绝时（已有活跃守护进程）仍回 ack 并置
// Accepted=0，必须解析后才能区分二者。注册被拒是运维必须看见的状态——此时本进程的
// 所有指令都会被内核丢弃。
func (p *EventPump) register(why string) {
	ack, err := p.sampler.Register(p.timeout)
	now := time.Now()
	if err != nil {
		p.store.SetLinkError(fmt.Sprintf("注册失败（%s）：%v", why, err), now)
		p.store.MarkLeaseAttemptFailed()
		p.logger.Warn("内核守护进程注册失败", "reason", why, "error", err)
		p.syncRouterCounters()
		return
	}
	if !ack.Accepted {
		p.store.SetLinkError("注册被内核拒绝：已有活跃守护进程", now)
		p.store.SetLeaseRefused()
		p.logger.Error("内核拒绝本进程注册为守护进程，指令将被丢弃", "reason", why)
		p.syncRouterCounters()
		return
	}
	p.store.SetLinkRegistered(now)
	p.logger.Debug("内核守护进程注册已确认", "reason", why)
	p.syncRouterCounters()
}

// handle 分派一条内核事件。
//
// 每一条都进事件环（可回溯的原始事实），并按需改写镜像；镜像确实变化时才推送域通知，
// 避免「内核重发同一事实」把推送变成心跳。
func (p *EventPump) handle(msg Incoming) {
	switch {
	case msg.Ban != nil:
		p.handleBan(msg.Ban)
	case msg.WL != nil:
		p.handleWhitelist(msg.WL)
	case msg.Ddos != nil:
		p.handleDdos(msg.Ddos)
	case msg.Cmd != nil:
		p.handleCmdResult(msg.Cmd)
	case msg.CfgChg != nil:
		// 内核侧配置变更（procfs 写入）。本层不碰 cfg——配置的执行体副本由入站执行体独占，
		// 这里只把事实转成反向指令，采纳动作在 executor.adoptKernelConfig 里做。
		p.emit(runtime.Directive{
			Kind:                runtime.DirectiveKernelConfigChanged,
			ConfigFlags:         uint32(msg.CfgChg.Flags),
			BanTimeSecs:         msg.CfgChg.BanTime,
			DdosBanDurationSecs: msg.CfgChg.DdosBanDuration,
		})
	case msg.CfgAck != nil:
		// ConfigAck 是回显 seq 的回复类型，正常路径由路由器配对走，不会到这里。
		p.logger.Debug("收到未被认领的 ConfigAck，已忽略")
	default:
		p.logger.Debug("收到无已解载荷的事件", "msg_type", msg.MsgType)
	}
}

// handleBan 应用一条封禁状态变更。
func (p *EventPump) handleBan(ev *contract.BanStateChange) {
	addr, err := addrFromWire(ev.AF, ev.Addr)
	if err != nil {
		p.logger.Warn("封禁事件的地址无法解析", "af", uint8(ev.AF), "error", err)
		return
	}
	ip := addr.String()
	now := time.Now()

	switch ev.Action {
	case contract.BanActionBan:
		// 内核的确认到达：镜像按事件内容重建，待确认标记由 Upsert 一并撤销。
		info := p.banInfoFromChange(ev, addr, now)
		changed := p.cache.Upsert(info)
		p.ring.Push(telemetry.Event{
			Kind:      telemetry.EventBan,
			IP:        ip,
			PrefixLen: ev.PrefixLen,
			Jail:      ev.JailName,
			Reason:    ev.Reason,
			Value:     uint64(ev.DurationSecs),
			At:        now,
		})
		if changed {
			p.publishDomain(DomainBans, "封禁变更")
		}
	case contract.BanActionUnban:
		removed := p.cache.Remove(ip)
		p.ring.Push(telemetry.Event{
			Kind:      telemetry.EventUnban,
			IP:        ip,
			PrefixLen: ev.PrefixLen,
			Jail:      ev.JailName,
			Reason:    ev.Reason,
			At:        now,
		})
		if removed {
			p.publishDomain(DomainBans, "解封变更")
		}
	default:
		p.logger.Warn("未知的封禁动作", "action", uint8(ev.Action), "ip", ip)
	}
}

// handleWhitelist 应用一条白名单状态变更。
func (p *EventPump) handleWhitelist(ev *contract.WhitelistStateChange) {
	addr, err := addrFromWire(ev.AF, ev.Addr)
	if err != nil {
		p.logger.Warn("白名单事件的地址无法解析", "af", uint8(ev.AF), "error", err)
		return
	}
	prefix := prefixFromAddr(addr, ev.PrefixLen)
	key := prefix.String()
	kind := telemetry.EventWhitelistRemove
	changed := false

	switch ev.Action {
	case contract.WhitelistActionAdd:
		changed = p.whitelist.Add(prefix)
		kind = telemetry.EventWhitelistAdd
	case contract.WhitelistActionRemove:
		changed = p.whitelist.Remove(prefix)
	default:
		p.logger.Warn("未知的白名单动作", "action", uint8(ev.Action), "cidr", key)
		return
	}

	p.ring.Push(telemetry.Event{
		Kind:      kind,
		IP:        addr.String(),
		PrefixLen: ev.PrefixLen,
		Reason:    ev.Device,
		At:        time.Now(),
	})
	if changed {
		p.publishDomain(DomainWhitelist, "白名单变更")
	}
}

// handleDdos 记录一次速率/协议阈值命中。
func (p *EventPump) handleDdos(ev *contract.DdosEvent) {
	addr, err := addrFromWire(ev.AF, ev.Addr)
	if err != nil {
		p.logger.Warn("DDoS 事件的地址无法解析", "af", uint8(ev.AF), "error", err)
		return
	}
	ip := addr.String()
	p.ring.Push(telemetry.Event{
		Kind:   telemetry.EventDdos,
		IP:     ip,
		Reason: ev.Reason,
		Value:  uint64(ev.RatePPS),
		At:     time.Now(),
	})
	if p.metrics != nil {
		p.metrics.Counter(CounterDdosEvents).Add(1)
	}
	p.logger.Info("内核上报 DDoS 命中", "ip", ip, "rate_pps", ev.RatePPS, "reason", ev.Reason)
}

// handleCmdResult 处理内核对本进程指令的失败回执。
//
// 这是下发路径唯一的真实确认：Ban/Unban/白名单增删都是「投递即返回」，成功时内核不发
// 任何回复，只有失败才单播 CmdResult。此前失败完全不可见——镜像里留着一条内核拒绝的
// 封禁，面板显示成功，实际一个包都没被丢。
func (p *EventPump) handleCmdResult(ev *contract.CmdResult) {
	var ip string
	if addr, err := addrFromWire(ev.AF, ev.Addr); err == nil {
		ip = addr.String()
	}
	p.ring.Push(telemetry.Event{
		Kind:   telemetry.EventCommandError,
		IP:     ip,
		Reason: fmt.Sprintf("%s 失败：%d", ev.OriginalCmd, ev.ErrorCode),
		Value:  uint64(int64(ev.ErrorCode)),
		At:     time.Now(),
	})
	if p.metrics != nil {
		p.metrics.Counter(CounterCommandRejected).Add(1)
	}
	p.store.SetLinkError(fmt.Sprintf("内核拒绝指令 %s（errno=%d）", ev.OriginalCmd, ev.ErrorCode), time.Now())
	p.logger.Warn("内核拒绝指令", "cmd", ev.OriginalCmd, "errno", ev.ErrorCode, "ip", ip)

	switch ev.OriginalCmd {
	case contract.MsgBanIP:
		// 封禁指令被拒：镜像里那条（及其待确认标记）都不是内核事实，立即撤销，
		// 让下一次判定仍有机会重试，而不是等对账周期。
		if ip != "" {
			if p.cache.Remove(ip) {
				p.publishDomain(DomainBans, "封禁被内核拒绝")
			}
		}
		// 同时通知执行体：它才是发起下发的一方。条目从镜像里消失后，该 IP 的下一条失败
		// 日志会立刻重新占位并再发一次指令——不抑制的话内核表满时每行日志一个往返。
		p.emit(runtime.Directive{
			Kind:  runtime.DirectiveCommandRejected,
			IP:    ip,
			Cmd:   ev.OriginalCmd.String(),
			Errno: ev.ErrorCode,
		})
	case contract.MsgUnbanIP:
		// 解封指令被拒：内核仍在封禁。删除路径是「先删镜像再下发」，此刻镜像里已经没有
		// 这条，也无从重建它的时长与 jail，所以不做掩盖动作——下一次对账按内核列表补回，
		// 面板最多晚一个周期纠正。
		p.logger.Warn("解封被内核拒绝，条目将由对账按内核列表补回", "ip", ip)
	case contract.MsgAddWhitelist, contract.MsgRemoveWhitelist:
		// 白名单镜像与内核不一致的事实同样由事件流纠正。API 侧的白名单写入目前还没有
		// 下发内核（那是后续包的内容），这里不猜测内核状态。
		p.logger.Warn("白名单指令被内核拒绝", "cmd", ev.OriginalCmd, "cidr", ip)
	}
}

// emit 非阻塞投递一条反向指令。
//
// 队列满时记一条日志并丢弃，绝不因为等执行体而钉住事件流：事件流一堵，封禁与白名单的
// 状态变更就再也进不来了，比少一条指令严重得多。丢 CONFIG_CHANGE 的后果是配置继续按
// 文件生效，丢「下发被拒」的后果是该 IP 少一轮抑制——两者都会被下一条同类事件纠正。
func (p *EventPump) emit(d runtime.Directive) {
	if p.directives == nil {
		return
	}
	select {
	case p.directives <- d:
	default:
		p.logger.Warn("反向指令队列已满，指令已丢弃",
			"kind", uint8(d.Kind), "ip", d.IP, "flags", d.ConfigFlags)
	}
}

// sample 取回三张表并发布到快照。
//
// 三个请求各自独立成败：速率表可能因表大而超时，但统计与分析仍应更新。失败只累计计数
// 并留下原文，不把整轮采样判废。
func (p *EventPump) sample() {
	now := time.Now()
	anyErr := false

	stats, err := p.sampler.QueryStats(p.timeout)
	if err != nil {
		anyErr = true
		p.logger.Debug("统计采样失败", "error", err)
	} else if !p.haveStats || stats != p.lastStats {
		p.store.SetStats(stats, now)
		p.publishDomain(DomainStats, "统计更新")
		p.lastStats, p.haveStats = stats, true
	} else {
		p.store.SetStats(stats, now)
	}

	analysis, err := p.sampler.QueryAnalysis(p.timeout)
	if err != nil {
		anyErr = true
		p.logger.Debug("分析采样失败", "error", err)
	} else {
		p.store.SetAnalysis(analysis, now)
	}

	rates, err := p.sampler.ListRatesAll(p.timeout)
	if err != nil {
		anyErr = true
		p.logger.Debug("速率采样失败", "error", err)
	} else {
		p.store.SetRates(Rates(rates), now)
		if !p.haveRates || rates.GlobalPPS != p.lastRatesPPS || rates.GlobalBPS != p.lastRatesBPS {
			p.publishDomain(DomainRates, "速率更新")
			p.lastRatesPPS, p.lastRatesBPS, p.haveRates = rates.GlobalPPS, rates.GlobalBPS, true
		}
	}

	if anyErr {
		p.store.BumpSampleFailure()
	}
	p.store.SetLinkSampled(now)
	p.syncRouterCounters()
}

// Rates 是 kernel.RateSnapshot 到 telemetry.Rates 的同构转换。
//
// 两个类型字段一致但归属不同层：kernel 不能反过来被 telemetry 引用（后者要发布快照），
// 所以由泵做一次显式改名而不是让两层共用一个类型。
func Rates(s RateSnapshot) telemetry.Rates {
	return telemetry.Rates{GlobalPPS: s.GlobalPPS, GlobalBPS: s.GlobalBPS, Entries: s.Entries}
}

// reconcile 以内核封禁表为准纠正本地镜像。
//
// 双向都必做：只补不删会让镜像里残留「内核已解封但事件丢了」的条目，只删不补则看不到
// procfs 手工封禁与内核自动封禁。刚下发还没确认的条目由 pending 保护，避免对账把用户
// 几十秒前点下的封禁抹掉。
//
// 白名单不在对账范围内，只由事件驱动：API 侧的白名单写入目前还没有下发内核（那是 P6
// 的内容），按内核真相反建会把「镜像里有、内核没有」的条目抹掉，那是在掩盖缺口而不是
// 修它。等下发路径接好，对账自然可以两张表一起做。
func (p *EventPump) reconcile() {
	now := time.Now()
	entries, err := p.sampler.ListBansAll(p.timeout)
	if err != nil {
		p.store.BumpReconcileFailure()
		p.store.SetLinkError(fmt.Sprintf("封禁表对账失败：%v", err), now)
		p.logger.Warn("封禁表对账失败", "error", err)
		p.syncRouterCounters()
		return
	}

	secs := now.Unix()
	changed := false
	skipped := 0
	seen := make(map[string]struct{}, len(entries))
	for i := range entries {
		info, ok := banInfoFromEntry(&entries[i], secs)
		if !ok {
			// 内核表里有本进程校验规则不接受的地址（只可能是 procfs 手工写入）。静默跳过
			// 会让「内核有、面板没有」再次变成无从解释的现象，故计数后记一条调试日志。
			skipped++
			continue
		}
		seen[info.IP] = struct{}{}
		if p.cache.Upsert(info) {
			changed = true
		}
	}
	if skipped > 0 {
		p.logger.Debug("对账跳过了无法通过本地校验的内核条目", "count", skipped)
	}

	// 内核列表里没有、又不在等待确认 → 幽灵。
	for _, info := range p.cache.All() {
		if _, ok := seen[info.IP]; ok {
			continue
		}
		if p.cache.IsPending(info.IP, secs) {
			continue
		}
		if p.cache.Remove(info.IP) {
			changed = true
		}
	}

	// 过期兜底：内核到期解封的事件可能在 socket 缓冲溢出时丢失。
	if ips := p.cache.SweepExpired(secs); len(ips) > 0 {
		changed = true
	}

	if pending := p.cache.PendingCount(secs); pending > 0 {
		p.logger.Debug("对账保留了等待确认的封禁", "count", pending)
	}
	if changed {
		p.publishDomain(DomainBans, "对账修正")
	}
	p.store.SetLinkReconciled(now)
	p.syncRouterCounters()
}

// publishDomain 推送一条域通知。
//
// 每个域的载荷来自**它自己**的数据源：bans 读本泵的封禁镜像、whitelist 读本泵的白名单
// 镜像、stats 与 rates 读同一份 telemetry 快照（本函数总在 SetStats/SetRates 之后调用，
// 镜像方取到的就是这一轮的值）。此前 default 分支把 bans 的镜像发给所有未知的域，于是
// `/api/v1/events` 的 stats 与 rates 两帧带的是封禁列表——前端按 StatsResponse 解析，
// 得到的是形状完全不同的对象，仪表盘上的读数与 REST 悄悄分叉。
//
// 载荷的**形状**由 DomainMirror 定（表现层），本函数只定**内容来自哪张表**：把内核内部
// 结构直接发出去等于让 SSE 成为一种独立的数据契约，REST 的字段改名不会同步到它。
//
// 域名在发布点是**逐字面量**：契约声明的每个事件名都要在 Go 侧有一个字面发布点
// （verify_http.py 按 `.Publish("<域名>", …)` 找），把名字塞进变量等于宣布它没有生产者。
func (p *EventPump) publishDomain(domain, why string) {
	if p.publish == nil {
		return
	}
	if p.mirror == nil {
		// 没有镜像就没有可信的载荷：宁可这一帧不发（前端退回 REST 读数），
		// 也不发一份与同域 REST 不同形的帧。
		p.logger.Debug("域载荷镜像未接线，跳过推送", "domain", domain, "reason", why)
		return
	}
	switch domain {
	case DomainBans:
		p.publish.Publish("bans", p.mirror.Bans(p.cache.All()))
	case DomainWhitelist:
		p.publish.Publish("whitelist", p.mirror.Whitelist(p.whitelist.List()))
	case DomainStats:
		p.publish.Publish("stats", p.mirror.Stats())
	case DomainRates:
		p.publish.Publish("rates", p.mirror.Rates())
	default:
		p.logger.Debug("未知域，不推送", "domain", domain, "reason", why)
		return
	}
	p.logger.Debug("推送域通知", "domain", domain, "reason", why)
}

// syncRouterCounters 把接收侧计数并入链路状态。路由器为空时跳过。
func (p *EventPump) syncRouterCounters() {
	if p.router == nil {
		return
	}
	s := p.router.Stats()
	down := p.router.linkDownClosed()
	p.store.SetRouterCounters(telemetry.RouterCounters{
		EventsDropped:    s.EventsDropped,
		DecodeErrors:     s.DecodeErrors,
		Malformed:        s.Malformed,
		UnmatchedReplies: s.UnmatchedReplies,
		ForeignPortIDs:   s.ForeignPortID,
	}, down)
}

// banInfoFromChange 由封禁事件构造镜像条目。
//
// BannedAt 取本地时刻而非事件里的时长：契约的 BanStateChange 没有 banned_at 字段，
// duration_secs 是「这次封禁多久」。
func (p *EventPump) banInfoFromChange(ev *contract.BanStateChange, addr netip.Addr, at time.Time) bans.BanInfo {
	info := bans.BanInfo{
		IP:          addr.String(),
		JailName:    ev.JailName,
		Reason:      ev.Reason,
		BannedAt:    at.Unix(),
		IsPermanent: ev.IsPermanent(),
	}
	if validated, err := bans.ValidateIP(info.IP); err == nil {
		info.Num = validated.Num
	}
	if !info.IsPermanent {
		info.ExpiresAt = at.Unix() + int64(ev.DurationSecs)
	}
	return info
}

// banInfoFromEntry 由内核封禁表条目构造镜像条目。
//
// 条目的 banned_at/duration_secs 都来自内核，因此镜像里的过期时刻与内核一致；地址无法
// 通过守护进程侧校验的条目被跳过（返回 false），这类条目只可能来自 procfs 的手工写入。
func banInfoFromEntry(e *contract.BanEntry, now int64) (bans.BanInfo, bool) {
	addr, err := addrFromWire(e.AF, e.Addr)
	if err != nil {
		return bans.BanInfo{}, false
	}
	validated, err := bans.ValidateIP(addr.String())
	if err != nil {
		return bans.BanInfo{}, false
	}
	bannedAt := int64(e.BannedAt)
	if bannedAt == 0 {
		bannedAt = now
	}
	info := bans.BanInfo{
		IP:          validated.Addr.String(),
		Num:         validated.Num,
		JailName:    e.JailName,
		Reason:      e.Reason,
		BannedAt:    bannedAt,
		IsPermanent: e.IsPermanent || e.DurationSecs == 0,
	}
	if !info.IsPermanent {
		info.ExpiresAt = bannedAt + int64(e.DurationSecs)
	}
	return info, true
}

// addrFromWire 把契约的 (af, addr16) 还原成单播地址，与 client.addrToWire 互逆。
func addrFromWire(af contract.AddrFamily, a contract.Addr16) (netip.Addr, error) {
	switch af {
	case contract.AFInet:
		var v4 [4]byte
		copy(v4[:], a[:4])
		return netip.AddrFrom4(v4), nil
	case contract.AFInet6:
		return netip.AddrFrom16(a), nil
	default:
		return netip.Addr{}, fmt.Errorf("未定义的地址族 %d", uint8(af))
	}
}

// prefixFromAddr 按前缀长度构造前缀；长度未给出时取完整前缀（单机）。
//
// 内核已把地址归一化（主机位清零），这里不再二次掩码；长度越界（IPv4 >32 或 IPv6 >128）
// 同样退回完整前缀，避免把一个非法长度当成有效掩码。
func prefixFromAddr(addr netip.Addr, prefixLen uint8) netip.Prefix {
	full := bans.FullPrefixLen(addr)
	if int(prefixLen) < 0 || uint8(prefixLen) > full {
		return netip.PrefixFrom(addr, int(full))
	}
	return netip.PrefixFrom(addr, int(prefixLen))
}

// orDefault 在零值时退回默认周期。
func orDefault(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}
