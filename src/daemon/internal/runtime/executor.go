// 入站主链路执行体：inotify 监视 → 按源增量读 → 行切分/规则匹配 → 阈值判定 → 封禁下发。
//
// 这是「运行时模型」里 ingest + parse + decision + pipeline 四段在生产路径上的唯一装配点，
// 由单个 goroutine 顺序驱动。四段共用同一份「按源读取偏移 + 按源半行缓冲 + 按 jail 失败
// 窗口」状态，顺序执行即天然串行：段与段之间不需要有界 channel，也就不存在「队列满时丢
// 字节」。
//
// # 一轮迭代的顺序
//
//  1. 跑到期维护（单调时钟定时器，与事件流量解耦）；
//  2. 排空内核→执行体的反向指令（配置采纳、下发抑制），见 directives.go；
//  3. 把 Web UI 改的启用状态桥接进本地配置，有变化则重建监视集合；
//  4. 补挂「轮转后路径暂时不可见」的源；
//  5. poll 同时等 inotify fd 与信号 fd，超时上限取「interval 秒」与「下一个定时器到期点」
//     的较小者；
//  6. 分派：信号（终止 / 重载 / 回滚）与 inotify 事件（读新增字节 → 判定 → 下发）。
//
// # 副作用归属
//
// 判定层只产出 BanIntent（纯内存结论）；下发与本地镜像在本执行体内完成。执行体不直接
// 触碰进程级全局态，而是把「内核下发」「统计计数」「本地封禁镜像」「配置重载」「周期维护」
// 收成窄接口，由组合根注入真实实现——这样主链路可喂字节进去、断言「是否产生封禁意图、
// 副作用是否按序发生」，而不必先把全局态摆好。
package runtime

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/decision"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/ingest"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/jail"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/logparse"
)

// 维护任务周期。都按旧实现的节拍保留，但驱动源从「poll 超时」换成单调时钟定时器：
// 事件洪泛不再推迟维护。
const (
	// cleanupInterval 是失败窗口清理周期。
	cleanupInterval = 60 * time.Second
	// clusterScanInterval 是集群扫描检测周期。
	//
	// 必须显著小于 cluster.Window（默认 60 秒）：检测间隔与窗口同量级时，一批失败会在
	// 下一次检测前滑出窗口，扫描永远凑不够 MinIPs（详见 Pipeline.ScanClusters）。
	clusterScanInterval = 10 * time.Second
	// rescanInterval 是监视集合重扫周期，覆盖「启动时不存在、之后才创建的日志文件」。
	rescanInterval = 60 * time.Second
	// historyInterval 是历史快照周期。
	historyInterval = 300 * time.Second
	// dataCleanupInterval 是数据清理周期。
	dataCleanupInterval = 300 * time.Second
	// pendingReaddRetry 是待重挂源的轮询上限：轮转后新文件出现即挂上，不必等 rescanInterval。
	pendingReaddRetry = 1 * time.Second
	// overflowCatchupBatches 是单次溢出补读对每个源最多连读的批数。
	//
	// 溢出后不再有后续事件唤醒，只读一批会把超过 BatchReadMax 的积压留在文件里；但
	// 持续写入时无上限地追会让单线程执行体被一个源钉住，故给一批上限（64 × 256 KiB
	// ≈ 16 MiB，远超一次溢出能堆出来的常规积压），剩下的等下一个事件接着读。
	overflowCatchupBatches = 64
	// rotationDrainBatches 是轮转摘源前补读旧 fd 尾部的最多批数，防止异常大的
	// 旧文件把单线程主循环钉住。
	rotationDrainBatches = 64
)

// BanSink 是封禁下发的副作用汇聚点。
//
// 执行体按「占位+待确认 → 下发 → 失败回滚」的顺序调用，对应旧实现
// handle_failed_attempt_for_jail 的尾部。把这几步收在一个接口后，测试可注入只记录调用序列
// 的假实现，验证顺序与回滚；生产实现挂在组合根，把内核指令与 Web UI 镜像接起来。
type BanSink interface {
	// InsertPending 在一个原子步骤里为 info 占位并标记「等待内核确认」，返回是否为赢家。
	//
	// 两步不可分开：中间一旦让对账跑进来，刚下发、内核列表里还没出现的条目会被当幽灵
	// 摘掉，而待确认标记随后挂到一个不存在的条目上。同一 IP 已存在时返回 false，不改动
	// 任何状态（并发去重，防止重复封禁与统计双计），调用方据此提前返回。
	InsertPending(info bans.BanInfo) bool
	// Send 向内核下发一次封禁；durationSecs 为 0 表示永久，prefixLen 为前缀长度。
	Send(addr netip.Addr, prefixLen uint8, durationSecs uint32, reason string) error
	// RollbackInsert 回滚一次下发失败：撤销占位与待确认标记，允许下次重试。
	RollbackInsert(ip string)
}

// ClusterBanRecorder 是 BanSink 的可选扩展：集群网段封禁成功下发后的记账入口。
//
// 集群封禁不经过 BanSink.InsertPending：那条路按单 IP 键占位活跃缓存与待确认标记，
// 而网段不是 netip.Addr，内核回显的条目也不是「一个地址」，占位会与事件泵的对账
// 互相误伤。但底账必须与自动单 IP 封禁同一个入口，否则网段封禁在 ban_events /
// ban_history / 信誉表里完全缺失。没实现本接口的 sink 只是少了底账，不影响下发。
type ClusterBanRecorder interface {
	// RecordClusterBan 在网段封禁已成功下发内核之后记录底账。
	RecordClusterBan(info bans.BanInfo)
}

// StatsSink 是统计计数器的写入端。
//
// 计数口径由执行体决定，sink 只负责落数：lines_parsed / lines_skipped / regex_matches 直接
// 搬差值，ips_extracted 与 failed_attempts 同值（每个识别出的 IP 计一次失败）。per-jail 无
// lines_skipped——与旧链路一致。
type StatsSink interface {
	// AddGlobal 累加全局计数（parsed / skipped / regexes / ips）。
	AddGlobal(parsed, skipped, regexes, ips uint64)
	// AddJail 累加某 jail 的计数（parsed / regexes / ips）。
	AddJail(jail string, parsed, regexes, ips uint64)
	// IncInotifyEvents 记一次 inotify 唤醒（不是事件条数）。
	IncInotifyEvents()
	// IncLogRotations 记一次轮转（仅 MOVE_SELF / DELETE_SELF）。
	IncLogRotations()
	// IncBansTriggered 记一次 per-jail 封禁触发（下发成功之后）。
	IncBansTriggered(jail string)
	// IncConfigReloads 记一次成功的配置热重载（SIGHUP 或配置文件自身变化触发）。
	IncConfigReloads()
}

// MaintenanceHooks 承载周期维护的外部副作用。
type MaintenanceHooks interface {
	// RecordHistorySnapshot 记录一次历史快照（每 5 分钟）。
	RecordHistorySnapshot(now int64)
	// PerformDataCleanup 执行一次数据清理（每 5 分钟）。
	PerformDataCleanup()
}

// ConfigReloader 承载配置热重载与回滚。
//
// 两个方法都直接改写传入的 cfg（成功时写入新配置，失败时保持/恢复旧配置）；执行体据返回值
// 记日志，随后一律按当前 cfg 重建规则集。
type ConfigReloader interface {
	// Reload 依据磁盘上的配置文件热重载。
	Reload(cfg *config.Config) error
	// Rollback 回滚到上一份配置。
	Rollback(cfg *config.Config) error
}

// KernelConfigPusher 把当前配置投影下发到内核。
//
// 为什么挂在执行体上：配置的独占所有权在这里（重载 / 回滚 / 内核侧指令都只改这一份 cfg），
// 而「内核应当按哪组阈值跑」必须由配置的属主说了算。HTTP 的 PUT /config 只是同步发一次好把
// 内核的采纳结论带回响应；手工编辑文件、SIGHUP、SIGUSR1 都只经过这里。少这一条，那些路径
// 改完配置后面板显示新值、内核仍按旧值判定。
//
// 与 BanSink 同为可空，nil 时不下发（重载本身照常成功——内核通道坏了不该让配置回滚）。
type KernelConfigPusher interface {
	// ApplyConfig 下发一份配置投影，返回内核未采纳的位图。
	ApplyConfig(change *contract.SetConfig) (rejected contract.ConfigFlags, err error)
}

// JailEnabledSource 提供 Web UI 权威的 jail 启用状态。
//
// 启用状态的权威源由 API 层写入（见 internal/http 的 jail 控制端点），执行体每个 poll
// 周期把它桥接进本地配置。本接口把这份「权威状态」抽象出来，返回 jail 名 → 是否启用。
type JailEnabledSource interface {
	EnabledStates() map[string]bool
	// SetEnabled 设置指定 jail 的启用状态（API 层写入，执行体下一个 poll 周期同步）。
	SetEnabled(jail string, enabled bool)
}

// JailSnapshotListener 在 jail 配置快照换了形状之后收到通知。
//
// 执行体是 jail 配置的唯一属主：初始装配、热重载、回滚、内核侧配置指令、启用状态同步
// 都会让它把新形状发布给读侧（config.SetActiveJails）。发布之后喊这一声是给 SSE 的
// jails 域用的——配置属主才知道什么时候真的变了，表现层只能猜。
//
// 本层不认识表现层：实现由组合根提供，它把这一声接到 http.APIHandlers 的域推送上。
// 同步调用，实现方必须非阻塞（SSE broker 的 Publish 是投队列、队满丢弃，正合此用）。
type JailSnapshotListener interface {
	OnJailSnapshotChanged()
}

// Deps 是执行体的外部依赖集合。nil 的可选依赖按「不动作」处理，便于测试按需注入。
type Deps struct {
	// Logger 是结构化日志器；nil 时静默。
	Logger *slog.Logger
	// Facts 是判定所需的外部事实（信誉分、历史封禁次数）。
	Facts DecisionFacts
	// ThreatIntel 是威胁情报缓存查询口；nil 时不查情报，所有封禁都走失败窗口。
	ThreatIntel ThreatIntel
	// Sink 是封禁下发副作用汇聚点。
	Sink BanSink
	// Stats 是统计计数器写入端。
	Stats StatsSink
	// Hooks 是周期维护副作用；nil 时周期维护只做内部的窗口清理与监视重扫。
	Hooks MaintenanceHooks
	// Reloader 是配置重载器；nil 时 SIGHUP / SIGUSR1 只记日志。
	Reloader ConfigReloader
	// KernelConfig 是配置变更后的内核下发出口；nil 时重载只改本进程配置。
	KernelConfig KernelConfigPusher
	// Enabled 是 Web UI 权威的启用状态源；nil 时跳过启用状态同步。
	Enabled JailEnabledSource
	// JailSnapshot 在 jail 配置快照发布后收到通知（组合根接到 SSE 的 jails 域推送）；
	// nil 时只发布快照、不通知订阅方。
	JailSnapshot JailSnapshotListener
	// KernelCmd 是内核→执行体的反向指令流（见 directives.go）；nil 时不接收。
	//
	// 通道由组合根创建，生产方（事件泵）非阻塞投递，执行体每轮迭代开头排空。关闭该通道
	// 表示生产方不再产生指令，执行体此后停止接收。
	KernelCmd <-chan Directive
}

// ready 是一次 poll 的唤醒来源。
type ready struct {
	// signals 表示信号 fd 可读。
	signals bool
	// inotify 表示 inotify fd 可读。
	inotify bool
}

// timers 是周期任务定时器集合。
type timers struct {
	table       *TimerTable
	cleanup     TimerID
	cluster     TimerID
	rescan      TimerID
	history     TimerID
	dataCleanup TimerID
}

// newTimers 登记五个周期任务。首个到期点都是「当前 + 一个周期」：与旧实现「启动时把
// last_* 置为 now」同义，即启动后不在第 0 秒抢跑一轮维护。
// 登记失败时返回 error，由调用方处理，避免 panic 导致整个守护进程崩溃。
func newTimers(now time.Time) (*timers, error) {
	table := NewTimerTable(5)
	register := func(id TimerID, ok bool) (TimerID, error) {
		if !ok {
			return 0, errors.New("容量 5 的定时器表登记五个周期任务失败")
		}
		return id, nil
	}
	cleanup, err := register(table.Every(cleanupInterval, now.Add(cleanupInterval)))
	if err != nil {
		return nil, fmt.Errorf("timers: 注册 cleanup 周期任务失败: %w", err)
	}
	cluster, err := register(table.Every(clusterScanInterval, now.Add(clusterScanInterval)))
	if err != nil {
		return nil, fmt.Errorf("timers: 注册 cluster 周期任务失败: %w", err)
	}
	rescan, err := register(table.Every(rescanInterval, now.Add(rescanInterval)))
	if err != nil {
		return nil, fmt.Errorf("timers: 注册 rescan 周期任务失败: %w", err)
	}
	history, err := register(table.Every(historyInterval, now.Add(historyInterval)))
	if err != nil {
		return nil, fmt.Errorf("timers: 注册 history 周期任务失败: %w", err)
	}
	dataCleanup, err := register(table.Every(dataCleanupInterval, now.Add(dataCleanupInterval)))
	if err != nil {
		return nil, fmt.Errorf("timers: 注册 dataCleanup 周期任务失败: %w", err)
	}
	return &timers{
		table:       table,
		cleanup:     cleanup,
		cluster:     cluster,
		rescan:      rescan,
		history:     history,
		dataCleanup: dataCleanup,
	}, nil
}

// InboundExecutor 是入站主链路执行体。**由单个 goroutine 独占**，内部状态一律不加锁。
type InboundExecutor struct {
	// cfg 是当前生效的配置。本执行体是唯一的改写者（自动重载 / 回滚 / 启用状态同步）。
	cfg *config.Config
	// logger 是结构化日志器；可能为 nil。
	logger *slog.Logger

	// watcher 是 inotify 实例的唯一所有者。
	watcher *ingest.Watcher
	// registry 是稳定身份 ↔ wd ↔ 路径的登记表。
	registry *ingest.SourceRegistry
	// readers 是各源的读取状态（长驻 fd + 长驻读缓冲）。
	readers map[ingest.SourceID]*ingest.SourceReader
	// pipeline 是判定装配体（规则集 / 失败窗口 / 半行缓冲 / 计数）。
	pipeline *Pipeline
	// signals 是信号 fd（与 inotify fd 并入同一个 poll）。
	signals *SignalSource
	// facts 是判定事实源。
	facts DecisionFacts

	// sink / stats / hooks / reloader / enabled 是注入的副作用汇聚点；
	// jailSnapshot 是 jail 配置快照变化后的通知出口（SSE 的 jails 域）；
	// kernelConfig 把变了形状的配置下发内核。
	sink         BanSink
	stats        StatsSink
	hooks        MaintenanceHooks
	reloader     ConfigReloader
	kernelConfig KernelConfigPusher
	enabled      JailEnabledSource
	jailSnapshot JailSnapshotListener

	// cmd 是反向指令流；生产方关闭后置为 nil（关闭的通道恒可读，留着会让每轮迭代空转）。
	cmd <-chan Directive
	// rejected 是「内核刚拒绝过它的封禁下发」的 IP → 抑制到期时刻。
	rejected map[string]time.Time
	// rejectionTTL 是抑制窗口长度，默认 dispatchRejectionCooldown；测试可缩短。
	rejectionTTL time.Duration

	// intents 是封禁意图复用缓冲，避免每批分配。
	intents []BanIntent
	// timers 是周期任务。
	timers *timers
	// pendingReadd 是轮转后路径暂时不可见、等待重挂的源路径集合。
	pendingReadd map[string]struct{}
	// mainDone 在 Run() 退出时关闭，Close() 据此等待主循环退出后再关闭 watcher，
	// 避免与 poll() 中正在阻塞的 unix.Poll 产生 fd 竞态。
	mainDone chan struct{}
}

// NewInboundExecutor 装配执行体：编译 jail 规则集、挂上初始 watch。
//
// 返回错误表示 inotify 初始化失败，或**一个源都挂不上**（配置错误 / 权限不足 / kmod 未
// 加载）——后者与旧 file_monitor::setup_inotify 的 watched_count == 0 语义一致：装配即
// 失败，由组合根以启动失败处理。
func NewInboundExecutor(cfg *config.Config, signals *SignalSource, deps Deps) (*InboundExecutor, error) {
	if cfg == nil {
		return nil, errors.New("runtime: 配置为空，无法装配入站主链路")
	}
	watcher, err := ingest.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("runtime: 初始化 inotify 失败: %w", err)
	}
	facts := deps.Facts
	if facts == nil {
		facts = NoHistory{}
	}
	e := &InboundExecutor{
		cfg:          cfg,
		logger:       deps.Logger,
		watcher:      watcher,
		registry:     ingest.NewSourceRegistry(),
		readers:      make(map[ingest.SourceID]*ingest.SourceReader),
		pipeline:     NewPipeline(),
		signals:      signals,
		facts:        facts,
		sink:         deps.Sink,
		stats:        deps.Stats,
		hooks:        deps.Hooks,
		reloader:     deps.Reloader,
		kernelConfig: deps.KernelConfig,
		enabled:      deps.Enabled,
		jailSnapshot: deps.JailSnapshot,
		cmd:          deps.KernelCmd,
		rejected:     make(map[string]time.Time),
		rejectionTTL: dispatchRejectionCooldown,
		pendingReadd: make(map[string]struct{}),
		mainDone:     make(chan struct{}),
	}
	t, err := newTimers(time.Now())
	if err != nil {
		_ = watcher.Close()
		return nil, fmt.Errorf("runtime: 初始化周期任务失败: %w", err)
	}
	e.timers = t
	e.refreshJails()
	e.pipeline.intel = deps.ThreatIntel
	e.reconcileWatches()
	if e.registry.IsEmpty() {
		_ = watcher.Close()
		return nil, errors.New("runtime: No log files could be watched（没有任何可监视的日志源）")
	}
	// 装配即下发一次：内核模块的参数是编译/加载期默认值，守护进程的配置要等到第一次
	// 重载才落上去的话，「刚启动的这段时间内核按谁的阈值判」就没有答案。
	e.pushKernelConfig("初始装配")
	e.info("入站主链路已就绪", "sources", e.registry.Len(), "jails", e.pipeline.JailCount())
	return e, nil
}

// Close 释放 inotify fd、信号桥与所有日志文件读取器。
//
// 必须先等 Run() 退出（通过 mainDone）再关闭 watcher，否则 poll() 中正在阻塞的
// unix.Poll 与被关闭的 inotify fd 之间产生竞态：关闭后的 fd 号可能被内核重新分配，
// poll 在新 fd 上继续等待或读到错误，行为不可预测。
func (e *InboundExecutor) Close() {
	<-e.mainDone
	_ = e.watcher.Close()
	if e.signals != nil {
		e.signals.Close()
	}
	// 关闭所有日志文件读取器，释放 fd
	for _, reader := range e.readers {
		_ = reader.Close()
	}
}

// Run 驱动主循环直到 stop 置位。
//
// 循环体只做三件事：算本次等待上限、跑一轮 step、处理 step 的异常退出。step 返回错误
// 意味着 fd 层出现无法恢复的问题（poll 失效等），此时必须自行置位终止令牌——否则组合
// 根会永远阻塞在 join 上，而本协程已经退出。
func (e *InboundExecutor) Run(stop, terminate *Shutdown) {
	defer close(e.mainDone)
	for !stop.IsShutdown() {
		timeout := e.nextPollTimeout(time.Now())
		if err := e.step(timeout, stop, terminate); err != nil {
			e.warn("入站主链路异常退出", "error", err)
			if terminate != nil {
				terminate.Request()
			}
			stop.Request()
			break
		}
	}
	e.info("入站主链路已停止")
}

// Step 执行一轮迭代。导出供测试逐轮驱动断言。
func (e *InboundExecutor) Step(timeout time.Duration, stop, terminate *Shutdown) error {
	return e.step(timeout, stop, terminate)
}

// step 是一轮迭代：跑到期维护 → 排空反向指令 → 桥接启用状态 → 补挂待重挂源 → 等待 → 分派。
func (e *InboundExecutor) step(timeout time.Duration, stop, terminate *Shutdown) error {
	e.runDueMaintenance()
	if stop.IsShutdown() {
		return nil
	}
	e.drainDirectives()
	e.syncJailEnabled()
	e.retryPendingReadd()
	r, err := e.poll(timeout)
	if err != nil {
		return err
	}
	if r.signals {
		e.handleSignals(stop, terminate)
	}
	if r.inotify {
		e.handleInotify()
	}
	return nil
}

// poll 同时等 inotify fd 与信号 fd。信号 fd 未接线时只等 inotify。
func (e *InboundExecutor) poll(timeout time.Duration) (ready, error) {
	fds := []unix.PollFd{{Fd: int32(e.watcher.FD()), Events: unix.POLLIN}}
	signalsIdx := -1
	if e.signals != nil {
		fds = append(fds, unix.PollFd{Fd: int32(e.signals.FD()), Events: unix.POLLIN})
		signalsIdx = len(fds) - 1
	}
	// 毫秒上限：poll 的 timeout 是毫秒整数，钳到 int32 上界避免溢出成负数（负数 = 无限
	// 等待）。interval 由配置校验保证在合理区间内，正常路径远达不到上界。
	millis := timeout.Milliseconds()
	if millis > math.MaxInt32 {
		millis = math.MaxInt32
	}
	n, err := unix.Poll(fds, int(millis))
	if err != nil {
		if errors.Is(err, unix.EINTR) {
			return ready{}, nil
		}
		return ready{}, err
	}
	var r ready
	if n > 0 {
		// 只有 POLLIN 代表「有数据可读」：POLLHUP/POLLERR/POLLNVAL 说明 fd 已关闭或出错，
		// 当成可读会让上层对着坏 fd 反复空转，故走错误路径交给主循环终止。
		if rv := fds[0].Revents; rv&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return ready{}, fmt.Errorf("inotify fd 不可用：revents=%#x", rv)
		} else if rv&unix.POLLIN != 0 {
			r.inotify = true
		}
		if signalsIdx >= 0 {
			if rv := fds[signalsIdx].Revents; rv&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				return ready{}, fmt.Errorf("信号 fd 不可用：revents=%#x", rv)
			} else if rv&unix.POLLIN != 0 {
				r.signals = true
			}
		}
	}
	return r, nil
}

// nextPollTimeout 是下一轮 poll 的超时上限。
func (e *InboundExecutor) nextPollTimeout(now time.Time) time.Duration {
	config.RLockConfig()
	secs := e.cfg.Interval
	config.RUnlockConfig()
	if secs == 0 {
		secs = 1
	}
	cap := time.Duration(secs) * time.Second
	if len(e.pendingReadd) > 0 {
		// 有轮转待重挂的源：以 1 秒为上限轮询，直到路径重新出现。
		if pendingReaddRetry < cap {
			cap = pendingReaddRetry
		}
	}
	if deadline, ok := e.timers.table.NextDeadline(); ok {
		if deadline.Before(now.Add(cap)) {
			d := deadline.Sub(now)
			if d < 0 {
				return 0
			}
			return d
		}
	}
	return cap
}

// handleSignals 取走本轮全部待处理信号并分派。
func (e *InboundExecutor) handleSignals(stop, terminate *Shutdown) {
	if e.signals == nil {
		return
	}
	for {
		kind, ok, err := e.signals.PollRead()
		if err != nil {
			e.warn("读取信号 fd 失败", "error", err)
			return
		}
		if !ok {
			return
		}
		switch kind {
		case SignalTerminate:
			e.info("收到终止信号，停止入站主链路")
			if terminate != nil {
				terminate.Request()
			}
			stop.Request()
			return
		case SignalReload:
			e.reloadConfig()
		case SignalRollback:
			e.rollbackConfig()
		}
	}
}

// handleInotify 读走本轮全部 inotify 事件并逐条处理。
func (e *InboundExecutor) handleInotify() {
	events, err := e.watcher.ReadEvents()
	if err != nil {
		e.warn("读取 inotify 事件失败", "error", err)
		return
	}
	if len(events) == 0 {
		return
	}
	// 与旧实现同口径：一次唤醒计一次（不是事件条数）。
	if e.stats != nil {
		e.stats.IncInotifyEvents()
	}
	e.handleWatchEvents(events)
}

// handleWatchEvents 分派一批 inotify 事件，溢出事件单独走补读路径。
//
// 溢出事件不属于任何 watch，`registry.Resolve(-1)` 必然落空——与「已摘除的旧 watch
// 残留事件」形同，若混在逐条分派里就会被静默丢掉，而它恰恰是唯一能提示「有事件丢了」
// 的信号。这里先于普通事件处理，保证同一批里即便另有正常事件，补读也不会被跳过。
func (e *InboundExecutor) handleWatchEvents(events []ingest.WatchEvent) {
	for _, event := range events {
		if event.IsOverflow() {
			e.drainAfterOverflow()
			continue
		}
		e.handleEvent(event)
	}
}

// drainAfterOverflow 在内核队列溢出后对所有已注册日志源做一次补读，返回尝试补读的
// 源数量（供测试断言「全部源都被覆盖、且每个只走一遍」）。
//
// 单次 drainSource 只交出一批（BatchReadMax），而溢出后没有后续事件唤醒，只读一批会
// 把更大的积压留在文件里、且不会再有第二声提示；因此这里逐源连读到「偏移不再前进」
// 为止，批数上限见 overflowCatchupBatches。
//
// 只做溢出触发的补读、不引入周期全量 drain：溢出之外，读路径本身有重扫与待重挂兜底，
// 而周期 drain 会在完全空闲时也逐源 Lstat/Seek 一遍，把「按事件读」退化成轮询。
// 配置文件源由 drainSource 按 owners 过滤（它只收 Jail 非空的 owner），不会被顺手读。
func (e *InboundExecutor) drainAfterOverflow() int {
	e.warn("inotify 队列溢出，部分事件已丢失，对全部日志源补读一次")
	var ids []ingest.SourceID
	e.registry.Iterate(func(id ingest.SourceID, _ ingest.SourceEntry) {
		ids = append(ids, id)
	})
	for _, id := range ids {
		reader := e.readers[id]
		if reader == nil {
			continue
		}
		for batches := 0; batches < overflowCatchupBatches; batches++ {
			before := reader.Offset()
			e.drainSource(id)
			if reader.Offset() == before {
				break
			}
		}
	}
	return len(ids)
}

// handleEvent 路由单条 inotify 事件：配置文件变更触发重载，日志内容变更触发读取，
// 自身被移走/删除触发轮转处理。
func (e *InboundExecutor) handleEvent(event ingest.WatchEvent) {
	id, ok := e.registry.Resolve(event.WD)
	if !ok {
		// 已被摘除的旧 watch（轮转后残留事件）：无主，丢弃。
		return
	}
	entry, ok := e.registry.Get(id)
	if !ok {
		return
	}

	// 同一路径可能既是配置文件又是日志文件：先按日志 owner 收完本批字节，再处理
	// 配置重载。反过来先 return 的话，日志 owner 虽被保留却永远等不到读取。
	hasConfig := false
	for _, owner := range entry.Owners {
		if owner.IsConfig {
			hasConfig = true
			break
		}
	}

	if event.IsContentChange() {
		// drainSource 只对 Jail owner 生效，纯配置文件源在这里是空操作。
		e.drainSource(id)
	}
	if hasConfig && (event.IsContentChange() || event.IsSelfGone()) {
		e.info("检测到配置文件变化，自动重载", "path", entry.Path)
		e.reloadConfig()
		return
	}
	if event.IsSelfGone() {
		e.handleRotation(id, entry.Path)
	}
}

// drainSource 读出某个源的新增字节并送进判定。
func (e *InboundExecutor) drainSource(id ingest.SourceID) {
	entry, ok := e.registry.Get(id)
	if !ok {
		return
	}
	// 收集所有 jail owners
	var jails []string
	for _, owner := range entry.Owners {
		if owner.Jail != "" {
			jails = append(jails, owner.Jail)
		}
	}
	if len(jails) == 0 {
		return
	}
	reader := e.readers[id]
	if reader == nil {
		return
	}
	chunk, err := reader.ReadNew(entry.Path)
	if err != nil {
		// 持有 fd 意外失效（seek 出错）：重置该源，下一轮重开。
		e.warn("读取日志失败，重置该源", "path", entry.Path, "error", err)
		reader.Reset()
		return
	}
	// 把日志分发给所有共享此文件的 jail。全局计数只取第一个 jail 的差值，按源只累加
	// 一次；jail 级计数各自累加。
	for i, jail := range jails {
		e.feed(jail, id, chunk.Bytes, chunk.Rotated, i == 0)
	}
}

// feed 把一批新增字节喂给判定层，并镜像计数、下发意图。
//
// global 为真表示本批字节的计数差值同时计入全局口径；共享源的同一批字节只在第一个
// jail 上置真，全局行数/正则/IP 计数因此按源各只增一次。
func (e *InboundExecutor) feed(jail string, id ingest.SourceID, bytes []byte, rotated, global bool) {
	if rotated {
		// 轮转 / 截断：旧文件的半行不得与新文件的开头拼接。
		e.pipeline.OnSourceRotated(id)
	}
	if len(bytes) == 0 {
		return
	}
	tick := e.tick()
	before := e.pipeline.Counters()
	e.intents = e.intents[:0]
	out, accepted := e.pipeline.OnChunk(jail, id, bytes, tick, e.facts, e.intents)
	e.intents = out
	after := e.pipeline.Counters()
	if !accepted {
		e.warn("日志源归属的 jail 未注册，本批丢弃", "jail", jail)
		return
	}
	e.mirrorCounters(jail, before, after)
	if global {
		e.mirrorGlobal(before, after)
	}
	for i := range e.intents {
		e.dispatchIntent(&e.intents[i])
	}
	e.intents = e.intents[:0]
}

// flushPendingLine 把某源挂起的半行当作完整行处理（源关闭 / 轮转前调用）。
//
// global 的语义与 feed 相同。
func (e *InboundExecutor) flushPendingLine(jail string, id ingest.SourceID, global bool) {
	tick := e.tick()
	before := e.pipeline.Counters()
	e.intents = e.intents[:0]
	out, accepted := e.pipeline.FlushSource(jail, id, tick, e.facts, e.intents)
	e.intents = out
	after := e.pipeline.Counters()
	if !accepted {
		return
	}
	e.mirrorCounters(jail, before, after)
	if global {
		e.mirrorGlobal(before, after)
	}
	for i := range e.intents {
		e.dispatchIntent(&e.intents[i])
	}
	e.intents = e.intents[:0]
}

// tick 构造判定用时间上下文：真实时钟 + 真实高峰判定。
func (e *InboundExecutor) tick() Tick {
	now := time.Now()
	return NewTick(now.Unix(), decision.IsPeakHours(uint32(now.UTC().Hour())))
}

// info 记一条 info 级日志（logger 为 nil 时静默）。
func (e *InboundExecutor) info(msg string, args ...any) {
	if e.logger == nil {
		return
	}
	e.logger.Info(msg, args...)
}

// warn 记一条 warn 级日志（logger 为 nil 时静默）。
func (e *InboundExecutor) warn(msg string, args ...any) {
	if e.logger == nil {
		return
	}
	e.logger.Warn(msg, args...)
}

// debug 记一条 debug 级日志（logger 为 nil 时静默）。
func (e *InboundExecutor) debug(msg string, args ...any) {
	if e.logger == nil {
		return
	}
	e.logger.Debug(msg, args...)
}

// logSource 是一个被监视的日志来源（jail 名 + 路径）。
type logSource struct {
	jail string
	path string
}

// handleRotation 处理轮转（MOVE_SELF / DELETE_SELF）：补读旧尾 → flush 半行 → 摘旧
// watch → 按当前路径重挂（新 inode）并从文件头读起；路径暂不可见时登记为待重挂。
func (e *InboundExecutor) handleRotation(id ingest.SourceID, path string) {
	entry, ok := e.registry.Get(id)
	if !ok {
		return
	}
	// 收集所有 jail owners
	var jails []string
	for _, owner := range entry.Owners {
		if owner.Jail != "" {
			jails = append(jails, owner.Jail)
		}
	}
	if len(jails) == 0 {
		return
	}
	// 计数口径与旧实现一致：只有 MOVE_SELF / DELETE_SELF 记一次轮转。
	if e.stats != nil {
		e.stats.IncLogRotations()
	}

	// 同一批事件里内容变更可能先于 MOVE_SELF 到达：ReadNew 已把 fd 切到新 inode 并
	// 推进偏移。此时再从头重挂会把同一批行判定两次，故只把 watch 挂到新 inode 上，
	// SourceID 与读取偏移保持不变。
	if reader := e.readers[id]; reader != nil {
		if current := inodeOfPath(path); reader.Inode() != 0 && reader.Inode() == current {
			e.rebindWatch(id, entry, path)
			return
		}
	}

	// 旧文件最后未读的尾部仍是证据：先按 jail 喂入尾部字节，再 flush 半行。
	// 顺序不能反——先 flush 会把旧半行单独成行，尾部随后又与新文件拼在一起或
	// 单独成行，两者都会丢掉或伪造内容。
	if reader := e.readers[id]; reader != nil {
		if tail := reader.DrainTail(rotationDrainBatches); len(tail) > 0 {
			for i, jail := range jails {
				e.feed(jail, id, tail, false, i == 0)
			}
		}
	}
	for i, jail := range jails {
		e.flushPendingLine(jail, id, i == 0)
	}
	e.dropSource(id)

	if _, err := os.Stat(path); err == nil {
		// 轮转重挂会分配新的 SourceID，owner 必须一次性全部迁过去：否则除第一个
		// jail 外，其余 jail 直到下次周期重扫（60 秒）都收不到这个文件的新行。
		// 也要在首轮读取之前登记齐全——新文件在挂 watch 前写入的内容按 owner 表分发。
		if _, added := e.addSharedLogSource(jails, path, true); !added {
			e.pendingReadd[ingest.CleanPath(path)] = struct{}{}
		}
	} else {
		e.debug("日志轮转后文件暂不可见，待重挂", "path", path)
		e.pendingReadd[ingest.CleanPath(path)] = struct{}{}
	}
}

// rebindWatch 把一个源重挂到 path 当前指向的 inode 上，保留 SourceID 与读取偏移。
//
// 用于读取器已由内容变更事件切到新文件的轮转：旧 watch 仍钉在被移走的 inode 上，
// 不重挂的话新文件此后的写入没有事件可唤醒。摘除旧 watch 与登记新 wd 之间没有读取，
// 该源的偏移与半行缓冲不受影响。
func (e *InboundExecutor) rebindWatch(id ingest.SourceID, entry ingest.SourceEntry, path string) {
	wd, err := e.watcher.Add(path, ingest.LogFileWatchMask())
	if err != nil {
		// 重挂失败不能把旧 watch 留在被移走的 inode 上：摘源并登记待重挂，
		// 由 retryPendingReadd 在路径重新可见时按当前 jail 归属挂回。
		e.warn("轮转后重挂 watch 失败", "path", path, "error", err)
		e.dropSource(id)
		e.pendingReadd[ingest.CleanPath(path)] = struct{}{}
		return
	}
	if wd != entry.WD {
		if err := e.watcher.Remove(entry.WD); err != nil {
			e.debug("摘除旧 inode 的 watch 失败", "path", path, "error", err)
		}
	}
	e.registry.Rebind(id, wd, inodeOfPath(path))
}

// retryPendingReadd 重试「轮转后待重挂」的源：路径一出现就挂上（上限 1 秒），失败保持
// 静默，避免路径长期不出现时按秒刷日志。
func (e *InboundExecutor) retryPendingReadd() {
	if len(e.pendingReadd) == 0 {
		return
	}
	candidates := make([]string, 0, len(e.pendingReadd))
	for path := range e.pendingReadd {
		candidates = append(candidates, path)
	}
	for _, path := range candidates {
		if e.registry.ContainsPath(path) {
			delete(e.pendingReadd, path)
			continue
		}
		if _, err := os.Stat(path); err != nil {
			continue
		}
		jails := e.jailsForPath(path)
		if len(jails) == 0 {
			// 配置里已不再监视该文件（或所有相关 jail 被禁用）：交给重扫摘除。
			delete(e.pendingReadd, path)
			continue
		}
		if _, added := e.addSharedLogSource(jails, path, true); added {
			delete(e.pendingReadd, path)
			e.info("轮转后的日志文件已重新挂载", "path", path)
		}
	}
}

// reconcileWatches 按当前配置对齐监视集合：摘掉不再需要的，补挂/更新其余的。
//
// 这是启动、配置重载、jail 启用状态变化与周期重扫共用的唯一路径，只做增量增删，
// SourceID 保持稳定，各源的读取偏移与半行缓冲不受影响。
func (e *InboundExecutor) reconcileWatches() {
	keep := make(map[string]struct{})
	config.RLockConfig()
	configFile := e.cfg.ConfigFile
	config.RUnlockConfig()
	if configFile != "" {
		keep[ingest.CleanPath(configFile)] = struct{}{}
	}
	logs := e.enabledLogSources()
	// 同一路径可能被多个已启用 jail 共享：按路径汇总 owner 集合，后面一次对齐。
	logPaths := make([]string, 0, len(logs))
	logOwners := make(map[string][]string, len(logs))
	for _, ls := range logs {
		clean := ingest.CleanPath(ls.path)
		if _, seen := logOwners[clean]; !seen {
			logPaths = append(logPaths, ls.path)
		}
		logOwners[clean] = append(logOwners[clean], ls.jail)
		keep[clean] = struct{}{}
	}

	var stale []ingest.SourceID
	e.registry.Iterate(func(id ingest.SourceID, entry ingest.SourceEntry) {
		if _, ok := keep[ingest.CleanPath(entry.Path)]; !ok {
			stale = append(stale, id)
		}
	})
	for _, id := range stale {
		e.dropSource(id)
	}

	if configFile != "" && !e.registry.ContainsPath(configFile) {
		e.addConfigWatch(configFile)
	}

	for _, lsPath := range logPaths {
		clean := ingest.CleanPath(lsPath)
		if id, _, _, ok := e.entryForPath(lsPath); ok {
			// 已在监视：把日志 owner 集合精确对齐到当前启用的 jail，保留 SourceID、
			// wd、inode 与读取偏移；禁用但仍留在 owner 表里的 jail 由此被摘掉。
			e.registry.SetLogOwners(clean, logOwners[clean])
			// 同一路径可能先作为配置文件登记（配置文件与日志文件重合）：那时只挂了
			// watch，没有读取器。只对齐 owner 的话日志 owner 永远等不到读行。
			if len(logOwners[clean]) > 0 && e.readers[id] == nil {
				_, fromStart := e.pendingReadd[clean]
				e.readers[id] = e.newSourceReader(lsPath, fromStart)
				if _, statErr := os.Stat(lsPath); statErr == nil {
					delete(e.pendingReadd, clean)
				}
				e.drainSource(id)
			}
			continue
		}
		// 待重挂的源从文件头读；其余（新出现的文件）定位到末尾，不回放历史。
		// 挂失败（Stat / inotify / 权限）时必须保留待重挂项：丢失 fromStart 后下一次
		// 会以 OpenAtEnd 打开轮转后的新文件，整段写入被跳过。
		_, fromStart := e.pendingReadd[clean]
		if _, added := e.addSharedLogSource(logOwners[clean], lsPath, fromStart); added {
			delete(e.pendingReadd, clean)
		}
	}

	// 已不再配置的路径不必再等。
	for path := range e.pendingReadd {
		if _, ok := keep[ingest.CleanPath(path)]; !ok {
			delete(e.pendingReadd, path)
		}
	}
}

// addSharedLogSource 挂一个日志源，并把内容分发给 jails 中的每个 jail。
//
// fromStart=false 时定位到文件末尾（不回放历史）。所有 owner 在首轮读取之前登记：
// 轮转重挂时新文件可能已经写入了内容，首轮读取按 owner 表逐 jail 分发，晚登记的
// jail 会永久错过这段内容。
func (e *InboundExecutor) addSharedLogSource(jails []string, path string, fromStart bool) (ingest.SourceID, bool) {
	if len(jails) == 0 {
		return 0, false
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		e.warn("跳过符号链接日志文件", "path", path)
		return 0, false
	}
	if _, err := os.Stat(path); err != nil {
		e.debug("日志文件不存在，跳过", "path", path)
		return 0, false
	}
	wd, err := e.watcher.Add(path, ingest.LogFileWatchMask())
	if err != nil {
		e.warn("添加 inotify watch 失败", "path", path, "error", err)
		return 0, false
	}
	inode := inodeOfPath(path)
	id := e.registry.Register(ingest.LogOwner(jails[0]), path, wd, inode)
	for _, jail := range jails[1:] {
		e.registry.Register(ingest.LogOwner(jail), path, wd, inode)
	}
	reader := e.newSourceReader(path, fromStart)
	e.readers[id] = reader
	// 立即读一次：覆盖「内容先于 watch 到达」的窗口——轮转后新文件在挂 watch 之前就
	// 被写入时，不会有任何 inotify 事件来触发读取。
	e.drainSource(id)
	return id, true
}

// newSourceReader 按 fromStart 语义建一个读取器：待重挂的源从文件头读，其余定位到
// 末尾，不回放历史。
func (e *InboundExecutor) newSourceReader(path string, fromStart bool) *ingest.SourceReader {
	reader := ingest.NewSourceReader(e.logger)
	if !fromStart {
		reader.OpenAtEnd(path)
	}
	return reader
}

// addConfigWatch 给配置文件挂 watch。
func (e *InboundExecutor) addConfigWatch(path string) bool {
	wd, err := e.watcher.Add(path, ingest.LogFileWatchMask())
	if err != nil {
		e.warn("添加配置文件监控失败", "path", path, "error", err)
		return false
	}
	inode := inodeOfPath(path)
	e.registry.Register(ingest.ConfigOwner(), path, wd, inode)
	e.info("已添加配置文件监控", "path", path)
	return true
}

// dropSource 摘除一个源：watch、读取器、半行缓冲全部回收。
func (e *InboundExecutor) dropSource(id ingest.SourceID) {
	if entry, ok := e.registry.Remove(id); ok {
		// 旧 wd 可能已随轮转失效：摘除失败只记 debug。
		if err := e.watcher.Remove(entry.WD); err != nil {
			e.debug("摘除 inotify watch 失败", "path", entry.Path, "error", err)
		}
	}
	if reader := e.readers[id]; reader != nil {
		reader.Reset()
		delete(e.readers, id)
	}
	e.pipeline.ForgetSource(id)
}

// entryForPath 按路径找登记项（路径数量是个位到百位量级，线性查找即可）。
func (e *InboundExecutor) entryForPath(path string) (ingest.SourceID, int32, uint64, bool) {
	clean := ingest.CleanPath(path)
	var (
		foundID    ingest.SourceID
		foundWD    int32
		foundInode uint64
		found      bool
	)
	e.registry.Iterate(func(id ingest.SourceID, entry ingest.SourceEntry) {
		if !found && ingest.CleanPath(entry.Path) == clean {
			foundID, foundWD, foundInode, found = id, entry.WD, entry.Inode, true
		}
	})
	return foundID, foundWD, foundInode, found
}

// snapshotJails 在读锁内拷一份 jail 列表。
//
// 只拷到元素这一层：LogFiles/Regexes 的底层数组在重载时整份替换，写方（本执行体）是
// 唯一改写者，解锁后继续读这些切片不会与别的 goroutine 冲突；而 HTTP 侧的写方只碰
// cfg.Webui / cfg.Ddos，与 Jails 无关。
func (e *InboundExecutor) snapshotJails() []config.Jail {
	config.RLockConfig()
	defer config.RUnlockConfig()
	jails := make([]config.Jail, len(e.cfg.Jails))
	copy(jails, e.cfg.Jails)
	return jails
}

// enabledLogSources 返回当前配置里启用的日志源。
func (e *InboundExecutor) enabledLogSources() []logSource {
	var out []logSource
	for _, jail := range e.snapshotJails() {
		if !jail.Enabled {
			continue
		}
		for _, file := range jail.LogFiles {
			out = append(out, logSource{jail: jail.Name, path: file})
		}
	}
	return out
}

// jailForPath 找出监视该路径的 jail（按当前配置，取启用的）。
// jailsForPath 返回配置里监视该路径的全部已启用 jail（同一文件可被多个 jail 共享）。
func (e *InboundExecutor) jailsForPath(path string) []string {
	clean := ingest.CleanPath(path)
	var out []string
	for _, jail := range e.snapshotJails() {
		if !jail.Enabled {
			continue
		}
		for _, file := range jail.LogFiles {
			if ingest.CleanPath(file) == clean {
				out = append(out, jail.Name)
				break
			}
		}
	}
	return out
}

// reloadConfig 处理 SIGHUP（或配置文件自身变化）触发的热重载。
func (e *InboundExecutor) reloadConfig() {
	if e.reloader == nil {
		e.info("配置重载器未接线，忽略重载请求")
		return
	}
	loaded := true
	if err := e.reloader.Reload(e.cfg); err != nil {
		loaded = false
		e.warn("配置重载失败", "error", err)
	} else {
		e.info("配置重载成功")
		if e.stats != nil {
			e.stats.IncConfigReloads()
		}
	}
	// 无论成功与否都按当前 cfg 重建：失败时 Reload 已把 cfg 回滚成旧配置，重建即回到
	// 旧集合（重建幂等，重复调用无副作用）。
	e.refreshJails()
	e.reconcileWatches()
	if loaded {
		e.pushKernelConfig("热重载")
	}
}

// rollbackConfig 处理 SIGUSR1 触发的配置回滚。
func (e *InboundExecutor) rollbackConfig() {
	if e.reloader == nil {
		e.info("配置重载器未接线，忽略回滚请求")
		return
	}
	if err := e.reloader.Rollback(e.cfg); err != nil {
		e.warn("配置回滚失败", "error", err)
		return
	}
	e.info("配置回滚成功")
	// 回滚会改 max_retries / findtime / ban_time 与启用状态，判定参数必须跟着走。
	e.refreshJails()
	// 回滚同样会改启用状态与 log_files：监视集合必须按回滚后的配置对齐，否则被回滚
	// 禁用的 jail 会继续收行判定，直到下一轮周期重扫。
	e.reconcileWatches()
	// 回滚掉的那份配置同样要回到内核上，否则「SIGUSR1 之后」= 面板与判定回到旧值、内核
	// 仍停在被回滚掉的新值。
	e.pushKernelConfig("配置回滚")
}

// pushKernelConfig 把当前配置投影下发内核（见 KernelConfigPusher）。
//
// 失败只记日志、不改变重载结论：配置已经落到本进程并生效于判定链，内核那一侧没收到只是
// 阈值暂时滞后，下一次重载或 API 写入会再发一次。把一次 netlink 失败升级成执行体的错误，
// 代价是整条主链路停摆——那比阈值滞后严重得多。
//
// 未被采纳的位按载荷字段名记 warn：这类位说的是「配置里写了一个内核不收的取值」（速率上限
// 为 0、窗口超过 60 秒……），与通道故障是两种修法，前者要改配置文件。
func (e *InboundExecutor) pushKernelConfig(reason string) {
	if e.kernelConfig == nil {
		return
	}
	// 投影只在读锁内算完：它按 Ddos/DefaultBanTime 逐字段取值，与热重载的整份替换并发
	// 会读到混合版本。netlink 下发在锁外，不让内核往返挡住 API 与重载。
	config.RLockConfig()
	change := e.cfg.KernelConfigChange()
	config.RUnlockConfig()
	rejected, err := e.kernelConfig.ApplyConfig(&change)
	if err != nil {
		e.warn("配置下发内核失败", "reason", reason, "error", err)
		return
	}
	if names := rejected.Names(); len(names) > 0 {
		e.warn("配置下发内核：部分位未被采纳", "reason", reason, "rejected", names)
		return
	}
	e.debug("配置已下发内核", "reason", reason, "flags", uint32(change.Flags))
}

// syncJailEnabled 把 Web UI 权威的启用状态桥接进本地配置，有变化才重建监视集合。
//
// 启用状态与补编译都写在共享实例上，必须持写锁。日志与「重建监视集合」放到解锁之后：
// 前者是 I/O，后者要取读锁（RWMutex 不可重入），持写锁调用会自锁。
func (e *InboundExecutor) syncJailEnabled() {
	if e.enabled == nil {
		return
	}
	states := e.enabled.EnabledStates()
	var logs []pendingLog
	changed := false

	config.LockConfig()
	for i := range e.cfg.Jails {
		local := &e.cfg.Jails[i]
		enabled, ok := states[local.Name]
		if !ok || local.Enabled == enabled {
			continue
		}
		logs = append(logs, pendingLog{msg: "Jail 启用状态同步",
			attrs: []any{"jail", local.Name, "enabled", enabled}})
		local.Enabled = enabled
		changed = true
	}
	if changed {
		// 启动/重载只编译 enabled jail 的正则，禁用中的 jail 的 Compiled 全是 nil。
		// 这里启用时补一次编译，否则规则集为空：sshd 只剩关键字回退，nginx/FRP 等
		// 只配正则的 jail 会完全失去防护。
		for i := range e.cfg.Jails {
			local := &e.cfg.Jails[i]
			if !local.Enabled {
				continue
			}
			skipped, err := jail.CompileJailRegexesWithWarnings(local)
			// 被跳过的模式逐条告警：部分成功时 err 为 nil，不写出来就没人知道
			// 这条正则没有生效。全部失败时只报汇总，避免重复。
			if err != nil {
				logs = append(logs, pendingLog{warn: true, msg: "启用 jail 时编译正则失败",
					attrs: []any{"jail", local.Name, "error", err}})
			} else {
				for _, w := range skipped {
					logs = append(logs, pendingLog{warn: true, msg: w})
				}
			}
			if len(local.LogFiles) == 0 {
				logs = append(logs, pendingLog{warn: true,
					msg: "jail 已启用但未配置 log_files，不会监视任何日志文件", attrs: []any{"jail", local.Name}})
			}
		}
	}
	config.UnlockConfig()

	for _, l := range logs {
		if l.warn {
			e.warn(l.msg, l.attrs...)
		} else {
			e.info(l.msg, l.attrs...)
		}
	}
	if changed {
		// refreshJails 重建规则集并发布快照（快照存的是副本，原地改 Enabled 不会自己
		// 浮到读侧），比单独 publishJailSnapshot 更完整。
		e.refreshJails()
		e.reconcileWatches()
	}
}

// pendingLog 是一条等锁外再写的日志。
//
// 持写锁期间不写日志：日志器可能落到文件，一次磁盘抖动会钉住所有读方。
type pendingLog struct {
	warn  bool
	msg   string
	attrs []any
}

// refreshJails 按当前配置重建各 jail 的规则集与判定参数（失败窗口由 RegisterJail 保留）。
//
// 先在读锁内拷一份 jail 列表再动：整份替换（*cfg = newCfg）正并发发生时，直接按下标
// 遍历共享 slice 会读到新旧混杂的元素。拷出来的那份在本执行体内不再变化。
func (e *InboundExecutor) refreshJails() {
	jails := e.snapshotJails()
	// 禁用 jail 不保留编译结果：运行期被停用的 jail 还带着上一次启用时编译的正则，
	// 这些规则不参与判定，也不该留在配置里等下一次误用。
	config.LockConfig()
	for i := range e.cfg.Jails {
		if e.cfg.Jails[i].Enabled {
			continue
		}
		for j := range e.cfg.Jails[i].Regexes {
			e.cfg.Jails[i].Regexes[j].Compiled = nil
		}
	}
	config.UnlockConfig()
	keep := make([]string, 0, len(jails))
	for i := range jails {
		jail := &jails[i]
		// 禁用 jail 不登记任何规则：它的 Regexes 里可能还留着上一次启用时编译的结果，
		// 但禁用状态下的行不该再按这些规则判定。
		rules := logparse.NewRuleSet(jail.Name, nil)
		if jail.Enabled {
			rules = e.ruleSetFor(jail)
		}
		policy := NewJailPolicy(jail.MaxRetries, jail.FindTime, jail.BanTime, jail.Cluster)
		e.pipeline.RegisterJail(rules, policy)
		keep = append(keep, jail.Name)
	}
	// 配置里已消失的 jail 连同其失败窗口一并摘除。
	if removed := e.pipeline.RetainJails(keep); removed > 0 {
		e.debug("已摘除配置中不再存在的 jail", "removed", removed)
	}
	// 把这一份 jail 配置推给表现层（见 publishJailSnapshot）。
	e.publishJailSnapshot(jails)
}

// publishJailSnapshot 把当前生效的 jail 配置发布给表现层，并通知订阅方。
//
// 配置所有权在本执行体（组合根只留一个指向同一份 cfg 的闭包），而 /api/v2/jails、SSE 的
// jails 事件、以及两个调参建议端点都读 config.GetActiveJails() 那一份快照。不在这里发布，
// 那三处就永远读到空表——面板上的 jail 页是空的、调参建议永远「无样本」，而两者看起来
// 都像「暂时还没有数据」。
//
// 每个让配置形状或启用状态变了的时刻都要调用：初始装配、热重载/回滚、内核侧配置变更，
// 以及下面的启用状态同步。
//
// 发布之后的那一声是给 SSE 的 jails 域：订阅者只有靠这一声才知道快照换了，否则
// SIGHUP 或内核侧改完配置，界面继续显示旧形状（契约缺陷 HTTP_SSE_JAILS_NO_PUBLISHER）。
// 载荷取的是刚发布的那份快照，与 GET /api/v2/jails 同一个折表函数。
//
// jails 由调用方给：refreshJails 传它刚从读锁内拷出的那一份，保证「重建规则集」与
// 「发布快照」看到的是同一版本；传 nil 表示本次没有现成副本，自行在读锁内取。
func (e *InboundExecutor) publishJailSnapshot(jails []config.Jail) {
	if jails == nil {
		jails = e.snapshotJails()
	}
	config.SetActiveJails(jails)
	if e.jailSnapshot != nil {
		e.jailSnapshot.OnJailSnapshotChanged()
	}
}

// runDueMaintenance 跑到期维护任务（驱动源是单调时钟定时器，事件洪泛不推迟维护）。
func (e *InboundExecutor) runDueMaintenance() {
	fired := e.timers.table.FireDue(time.Now())
	t := e.timers
	for _, f := range fired {
		// 本执行体只登记周期定时器，一次性不会出现。
		if !f.Repeating {
			continue
		}
		switch f.ID {
		case t.cleanup:
			if removed := e.pipeline.Cleanup(nowSecs()); removed > 0 {
				e.debug("清理过期失败条目", "removed", removed)
			}
			e.purgeRejectedDispatches(time.Now())
		case t.cluster:
			e.pipeline.ScanClusters(nowSecs(), e.dispatchClusterHit)
		case t.rescan:
			e.reconcileWatches()
		case t.history:
			e.recordHistorySnapshot()
		case t.dataCleanup:
			e.performDataCleanup()
		}
	}
}

// dispatchClusterHit 处置一次集群扫描命中：审计模式只记日志，否则把该网段的下发交给内核。
//
// 返回值是「是否已处置」，ScanClusters 只对已处置的命中清失败计数。
func (e *InboundExecutor) dispatchClusterHit(jail string, hit decision.ClusterHit, cfg config.ClusterConfig) bool {
	e.warn("检测到集群扫描",
		"jail", jail,
		"cidr", hit.CIDR.String(),
		"src_ips", len(hit.IPs),
		"peak", hit.Peak,
		"audit_only", cfg.AuditOnly,
		// 人能读懂的一句完整描述留在日志里：线上下发只带得下「jail: cluster scan」，
		// 命中细节在这一行（见 dispatchClusterHit 的注释）。
		"detail", hit.Summary(),
	)
	if cfg.AuditOnly || e.sink == nil {
		// 没有下发就不是处置：这些 IP 的失败计数必须留着，否则审计模式下真实来源的
		// 累计会被周期检测清空，而封禁根本没发生。
		return false
	}
	// 线上原因写 jail 名 + 固定标签：契约的 reason 是 str[32]（含 NUL，实际 31 字节），
	// jail 名超长时截断到 20 字节，留空间给 ": cluster"。CIDR 与命中数放日志。
	reason := fmt.Sprintf("%.20s: cluster", jail)
	// 下发形状与白名单路径一致：裸网络地址 + 前缀长度（CidrKey.Addr() 已归一）。
	if err := e.sink.Send(hit.CIDR.Addr(), uint8(hit.CIDR.PrefixLen()), cfg.BanTime, reason); err != nil {
		e.warn("集群网段封禁下发失败", "jail", jail, "cidr", hit.CIDR.String(), "error", err)
	} else if recorder, ok := e.sink.(ClusterBanRecorder); ok {
		// 网段封禁同样进底账：否则集群封禁在事件表、复发统计与信誉表里完全不可见。
		recorder.RecordClusterBan(clusterBanInfo(jail, hit.CIDR.Prefix(), cfg.BanTime, reason))
	}
	// 下发失败也算处置过：失败已记一行日志，而检测间隔远小于 cluster.Window，
	// 保留计数会让同一网段每个周期都重试并重复告警，把真实原因刷掉。失败后的重试
	// 靠后续失败日志重新累计；内核拒绝（多为封禁表满）也不是本周期内能恢复的。
	return true
}

// clusterBanInfo 把一次集群命中整理成底账条目。
//
// IP 取网段的网络地址（已归一），PrefixLen 保留网段长度；底账表不存前缀，读侧会把
// 这条记录当成那个基地址的单机封禁——这是「至少让网段封禁可见」的取舍，比整段缺失好。
//
// BanCount 固定记 1：网段不是「某地址第几次复发」，按单 IP 的复发计数读它没有意义；
// 底账要的是「这个网段被封过一次、封了多久」。
func clusterBanInfo(jail string, cidr netip.Prefix, banTime uint32, reason string) bans.BanInfo {
	now := nowSecs()
	info := bans.BanInfo{
		IP:        cidr.Addr().String(),
		PrefixLen: uint8(cidr.Bits()),
		JailName:  jail,
		Reason:    reason,
		BannedAt:  now,
		BanCount:  1,
	}
	if banTime == 0 {
		info.IsPermanent = true
	} else {
		info.ExpiresAt = now + int64(banTime)
	}
	return info
}

// dispatchIntent 把一个封禁意图下发内核，并镜像到本地缓存与统计。
//
// 顺序对齐旧实现：单赢家占位并标记待确认 → 下发 → 失败则一并回滚；
// 只有下发成功后才给 per-jail 的 bans_triggered 加 1。
func (e *InboundExecutor) dispatchIntent(intent *BanIntent) {
	jail := intent.Jail
	info, ok := e.banInfoFor(intent)
	if !ok {
		e.warn("IP 验证失败，跳过封禁", "ip", intent.IP.String(), "jail", jail)
		return
	}
	// 缓存键、待确认标记、抑制窗口与内核事件必须用同一个规范形式：LogParse 给出的
	// `::ffff:1.2.3.4` 与内核回显的 `1.2.3.4` 若不归一，同一条封禁会在镜像里分裂成两条。
	ip := info.IP
	plan := intent.Plan
	if e.dispatchSuppressed(ip, time.Now()) {
		// 内核刚刚拒绝过这个 IP 的下发（多半是封禁表满）。条目已被事件泵从镜像里撤掉，
		// 不抑制的话下一条失败日志就会重新占位、再发一次 netlink 往返。判定与计数不受影响，
		// 只是不再重复下发；抑制到期后自然恢复。
		e.debug("该 IP 处于下发抑制窗口内，跳过重复下发", "ip", ip, "jail", jail)
		return
	}
	if e.sink == nil {
		return
	}
	if !e.sink.InsertPending(info) {
		// 同一 IP 已在活跃封禁缓存里：情报命中路径会对每行日志重算一次意图，
		// 这里静默去重，避免「一条攻击日志一条封禁日志」。
		return
	}
	e.info("触发封禁",
		"reason", intent.Reason,
		"ip", ip,
		"jail", jail,
		"duration", plan.Duration,
		"is_permanent", plan.IsPermanent,
		"ban_count", plan.BanCount,
	)

	// 永久封禁 duration 为 0；临时封禁把秒数钳进 uint32。
	durationSecs := uint32(0)
	if !plan.IsPermanent {
		if plan.Duration > math.MaxUint32 {
			durationSecs = math.MaxUint32
		} else {
			durationSecs = uint32(plan.Duration)
		}
	}
	// intent.IP 可能是 mapped IPv4（16 字节形式），统一 unmapped 后再下发，
	// 避免与内核回显的 canonical 形式不一致导致镜像分裂。
	canonicalAddr := intent.IP.Unmap()
	if err := e.sink.Send(canonicalAddr, bans.FullPrefixLen(canonicalAddr), durationSecs, jail); err != nil {
		e.sink.RollbackInsert(ip)
		e.warn("内核封禁失败，已回滚缓存标记", "ip", ip, "jail", jail, "error", err)
		return
	}
	if e.stats != nil {
		e.stats.IncBansTriggered(jail)
	}
}

// banInfoFor 由封禁意图构造本地缓存条目；IP 非法时返回 ok=false。
//
// reason 填 jail 名——与旧实现逐字一致（前端「原因」列显示的就是它）。
func (e *InboundExecutor) banInfoFor(intent *BanIntent) (bans.BanInfo, bool) {
	ip := intent.IP.String()
	validated, err := bans.ValidateIP(ip)
	if err != nil {
		return bans.BanInfo{}, false
	}
	jail := intent.Jail
	return bans.BanInfo{
		IP:          bans.CanonicalIP(validated.Addr),
		Num:         validated.Num,
		JailName:    jail,
		Reason:      jail,
		BannedAt:    nowSecs(),
		ExpiresAt:   intent.Plan.ExpiresAt,
		IsPermanent: intent.Plan.IsPermanent,
		FailCount:   intent.Plan.FailCount,
		BanCount:    intent.Plan.BanCount,
	}, true
}

// mirrorCounters 把一批处理产生的计数差值镜像到 per-jail 计数器。
//
// 全局计数不在这里累加：共享源的一批字节会被依次喂给多个 jail，全局口径按源只算一次，
// 由 feed / flushPendingLine 在第一个 jail 上另走 mirrorGlobal。
func (e *InboundExecutor) mirrorCounters(jail string, before, after Counters) {
	parsed := satSub(after.LinesParsed, before.LinesParsed)
	skipped := satSub(after.LinesSkipped, before.LinesSkipped)
	regexes := satSub(after.RegexMatches, before.RegexMatches)
	ips := satSub(after.IPsExtracted, before.IPsExtracted)
	bans := satSub(after.BansIntent, before.BansIntent)
	if parsed+skipped+regexes+ips == 0 {
		return
	}
	if e.stats != nil {
		e.stats.AddJail(jail, parsed, regexes, ips)
	}
	// 镜像到全局 jail 运行时统计（Web UI 可读）。
	config.UpdateJailStats(jail, parsed, regexes, ips, ips, bans)
}

// mirrorGlobal 把一段处理（可能覆盖同一源的多个 jail）的计数差值镜像到全局计数器。
//
// 每个源的一批字节只调用一次：共享文件的同一行在 jail 级各计一次，在全局只计一次。
func (e *InboundExecutor) mirrorGlobal(before, after Counters) {
	parsed := satSub(after.LinesParsed, before.LinesParsed)
	skipped := satSub(after.LinesSkipped, before.LinesSkipped)
	regexes := satSub(after.RegexMatches, before.RegexMatches)
	ips := satSub(after.IPsExtracted, before.IPsExtracted)
	if parsed+skipped+regexes+ips == 0 {
		return
	}
	if e.stats != nil {
		e.stats.AddGlobal(parsed, skipped, regexes, ips)
	}
}

// ruleSetFor 把配置里的 jail 规则编译结果转成判定层要的 RuleSet。
//
// 只搬 Compiled != nil 的条目：正则的安全校验发生在编译阶段，未通过的条目若在这里按
// 模式串重新编译就会被「救活」，等于绕过安全闸门。已编译的条目再走一次 NewRule（重载是
// 低频操作），换来「规则集不可变、热路径零加锁」。
func (e *InboundExecutor) ruleSetFor(jail *config.Jail) *logparse.RuleSet {
	rules := make([]*logparse.Rule, 0, len(jail.Regexes))
	for i := range jail.Regexes {
		info := &jail.Regexes[i]
		if info.Compiled == nil {
			continue
		}
		rule, err := logparse.NewRule(info.Name, info.Pattern)
		if err != nil {
			e.warn("跳过无法编译的规则", "jail", jail.Name, "rule", info.Name, "error", err)
			continue
		}
		rules = append(rules, rule)
	}
	return logparse.NewRuleSet(jail.Name, rules)
}

// recordHistorySnapshot 记录一次历史快照（每 5 分钟）。
func (e *InboundExecutor) recordHistorySnapshot() {
	if e.hooks != nil {
		e.hooks.RecordHistorySnapshot(nowSecs())
	}
}

// performDataCleanup 执行一次数据清理（每 5 分钟）。
func (e *InboundExecutor) performDataCleanup() {
	if e.hooks != nil {
		e.hooks.PerformDataCleanup()
	}
}

// nowSecs 返回当前 Unix 秒。
func nowSecs() int64 { return time.Now().Unix() }

// satSub 返回 a - b，a < b 时返回 0（无符号相减的饱和语义）。
func satSub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

// inodeOfPath 取路径的 inode 号（仅用于登记项诊断日志）。取不到时返回 0。
func inodeOfPath(path string) uint64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}
