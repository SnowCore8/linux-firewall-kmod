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
//  2. 把 Web UI 改的启用状态桥接进本地配置，有变化则重建监视集合；
//  3. 补挂「轮转后路径暂时不可见」的源；
//  4. poll 同时等 inotify fd 与信号 fd，超时上限取「interval 秒」与「下一个定时器到期点」
//     的较小者；
//  5. 分派：信号（终止 / 重载 / 回滚）与 inotify 事件（读新增字节 → 判定 → 下发）。
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
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/decision"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/ingest"
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
)

// BanSink 是封禁下发的副作用汇聚点。
//
// 执行体按「占位 → 待确认 → 下发 → 失败回滚」的顺序调用，对应旧实现
// handle_failed_attempt_for_jail 的尾部。把这几步收在一个接口后，测试可注入只记录调用序列
// 的假实现，验证顺序与回滚；生产实现挂在组合根，把内核指令与 Web UI 镜像接起来。
type BanSink interface {
	// TryInsert 原子地在活跃封禁缓存里为 info 占位并更新反向索引，返回「本调用是否为赢家」。
	//
	// 同一 IP 已存在则返回 false（并发去重，防止重复封禁与统计双计），调用方据此提前返回。
	TryInsert(info bans.BanInfo) bool
	// MarkPendingAck 标记该 IP 的封禁等待内核确认。
	MarkPendingAck(ip string)
	// Send 向内核下发一次封禁；durationSecs 为 0 表示永久，prefixLen 为前缀长度。
	Send(addr netip.Addr, prefixLen uint8, durationSecs uint32, reason string) error
	// RollbackInsert 回滚一次下发失败：撤销占位与待确认标记，允许下次重试。
	RollbackInsert(ip string)
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

// JailEnabledSource 提供 Web UI 权威的 jail 启用状态。
//
// 旧实现的启用状态权威源是 http_exporter 的全局表，只改它再持久化到 YAML；执行体每个 poll
// 周期把它桥接进本地配置。本接口把这份「权威状态」抽象出来，返回 jail 名 → 是否启用。
type JailEnabledSource interface {
	EnabledStates() map[string]bool
	// SetEnabled 设置指定 jail 的启用状态（API 层写入，执行体下一个 poll 周期同步）。
	SetEnabled(jail string, enabled bool)
}

// Deps 是执行体的外部依赖集合。nil 的可选依赖按「不动作」处理，便于测试按需注入。
type Deps struct {
	// Logger 是结构化日志器；nil 时静默。
	Logger *slog.Logger
	// Facts 是判定所需的外部事实（信誉分、历史封禁次数）。
	Facts DecisionFacts
	// Sink 是封禁下发副作用汇聚点。
	Sink BanSink
	// Stats 是统计计数器写入端。
	Stats StatsSink
	// Hooks 是周期维护副作用；nil 时周期维护只做内部的窗口清理与监视重扫。
	Hooks MaintenanceHooks
	// Reloader 是配置重载器；nil 时 SIGHUP / SIGUSR1 只记日志。
	Reloader ConfigReloader
	// Enabled 是 Web UI 权威的启用状态源；nil 时跳过启用状态同步。
	Enabled JailEnabledSource
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
func newTimers(now time.Time) *timers {
	table := NewTimerTable(5)
	must := func(id TimerID, ok bool) TimerID {
		if !ok {
			// 容量 5 的表登记五个周期任务不应失败，是编码错误。
			panic("timers: 容量 5 的定时器表登记五个周期任务失败")
		}
		return id
	}
	return &timers{
		table:       table,
		cleanup:     must(table.Every(cleanupInterval, now.Add(cleanupInterval))),
		cluster:     must(table.Every(clusterScanInterval, now.Add(clusterScanInterval))),
		rescan:      must(table.Every(rescanInterval, now.Add(rescanInterval))),
		history:     must(table.Every(historyInterval, now.Add(historyInterval))),
		dataCleanup: must(table.Every(dataCleanupInterval, now.Add(dataCleanupInterval))),
	}
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

	// sink / stats / hooks / reloader / enabled 是注入的副作用汇聚点。
	sink     BanSink
	stats    StatsSink
	hooks    MaintenanceHooks
	reloader ConfigReloader
	enabled  JailEnabledSource

	// intents 是封禁意图复用缓冲，避免每批分配。
	intents []BanIntent
	// timers 是周期任务。
	timers *timers
	// pendingReadd 是轮转后路径暂时不可见、等待重挂的源路径集合。
	pendingReadd map[string]struct{}
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
		enabled:      deps.Enabled,
		timers:       newTimers(time.Now()),
		pendingReadd: make(map[string]struct{}),
	}
	e.refreshJails()
	e.reconcileWatches()
	if e.registry.IsEmpty() {
		_ = watcher.Close()
		return nil, errors.New("runtime: No log files could be watched（没有任何可监视的日志源）")
	}
	e.info("入站主链路已就绪", "sources", e.registry.Len(), "jails", e.pipeline.JailCount())
	return e, nil
}

// Config 返回当前生效的配置（组合根读 HTTP 端口、Web UI、jail 列表等装配参数）。
//
// 配置所有权在执行体，是因为只有本执行体改配置（自动重载 / 回滚 / 启用状态同步）；组合根
// 若留一份副本，重载后就会与本执行体分叉。
func (e *InboundExecutor) Config() *config.Config { return e.cfg }

// Close 释放 inotify fd 与信号桥。
func (e *InboundExecutor) Close() {
	_ = e.watcher.Close()
	if e.signals != nil {
		e.signals.Close()
	}
}

// Run 驱动主循环直到 stop 置位。
//
// 循环体只做三件事：算本次等待上限、跑一轮 step、处理 step 的异常退出。step 返回错误
// 意味着 fd 层出现无法恢复的问题（poll 失效等），此时必须自行置位终止令牌——否则组合
// 根会永远阻塞在 join 上，而本协程已经退出。
func (e *InboundExecutor) Run(stop, terminate *Shutdown) {
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

// step 是一轮迭代：跑到期维护 → 桥接启用状态 → 补挂待重挂源 → 等待 → 分派。
func (e *InboundExecutor) step(timeout time.Duration, stop, terminate *Shutdown) error {
	e.runDueMaintenance()
	if stop.IsShutdown() {
		return nil
	}
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
		r.inotify = fds[0].Revents != 0
		if signalsIdx >= 0 {
			r.signals = fds[signalsIdx].Revents != 0
		}
	}
	return r, nil
}

// nextPollTimeout 是下一轮 poll 的超时上限。
func (e *InboundExecutor) nextPollTimeout(now time.Time) time.Duration {
	secs := e.cfg.Interval
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
	for _, event := range events {
		e.handleEvent(event)
	}
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

	if entry.Owner.IsConfig {
		if event.IsContentChange() || event.IsSelfGone() {
			e.info("检测到配置文件变化，自动重载", "path", entry.Path)
			e.reloadConfig()
		}
		return
	}

	if event.IsContentChange() {
		e.drainSource(id)
	}
	if event.IsSelfGone() {
		e.handleRotation(id, entry.Path)
	}
}

// drainSource 读出某个源的新增字节并送进判定。
func (e *InboundExecutor) drainSource(id ingest.SourceID) {
	entry, ok := e.registry.Get(id)
	if !ok || entry.Owner.Jail == "" {
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
	e.feed(entry.Owner.Jail, id, chunk.Bytes, chunk.Rotated)
}

// feed 把一批新增字节喂给判定层，并镜像计数、下发意图。
func (e *InboundExecutor) feed(jail string, id ingest.SourceID, bytes []byte, rotated bool) {
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
	for i := range e.intents {
		e.dispatchIntent(&e.intents[i])
	}
	e.intents = e.intents[:0]
}

// flushPendingLine 把某源挂起的半行当作完整行处理（源关闭 / 轮转前调用）。
func (e *InboundExecutor) flushPendingLine(jail string, id ingest.SourceID) {
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

// handleRotation 处理轮转（MOVE_SELF / DELETE_SELF）：flush 半行 → 摘旧 watch → 按
// 当前路径重挂（新 inode）并从文件头读起；路径暂不可见时登记为待重挂。
func (e *InboundExecutor) handleRotation(id ingest.SourceID, path string) {
	entry, ok := e.registry.Get(id)
	if !ok || entry.Owner.Jail == "" {
		return
	}
	jail := entry.Owner.Jail
	// 计数口径与旧实现一致：只有 MOVE_SELF / DELETE_SELF 记一次轮转。
	if e.stats != nil {
		e.stats.IncLogRotations()
	}

	// 旧文件最后那半行仍是证据：先 flush 再摘。
	e.flushPendingLine(jail, id)
	e.dropSource(id)

	if _, err := os.Stat(path); err == nil {
		if _, added := e.addLogSource(jail, path, true); !added {
			e.pendingReadd[ingest.CleanPath(path)] = struct{}{}
		}
	} else {
		e.debug("日志轮转后文件暂不可见，待重挂", "path", path)
		e.pendingReadd[ingest.CleanPath(path)] = struct{}{}
	}
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
		jail, ok := e.jailForPath(path)
		if !ok {
			// 配置里已不再监视该文件（或该 jail 被禁用）：交给重扫摘除。
			delete(e.pendingReadd, path)
			continue
		}
		if _, added := e.addLogSource(jail, path, true); added {
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
	if e.cfg.ConfigFile != "" {
		keep[ingest.CleanPath(e.cfg.ConfigFile)] = struct{}{}
	}
	logs := e.enabledLogSources()
	for _, ls := range logs {
		keep[ingest.CleanPath(ls.path)] = struct{}{}
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

	if e.cfg.ConfigFile != "" && !e.registry.ContainsPath(e.cfg.ConfigFile) {
		e.addConfigWatch(e.cfg.ConfigFile)
	}

	for _, ls := range logs {
		if _, wd, inode, ok := e.entryForPath(ls.path); ok {
			// 已在监视：只更新归属（同一路径可能被改挂到别的 jail）。
			e.registry.Register(ingest.LogOwner(ls.jail), ls.path, wd, inode)
			continue
		}
		// 待重挂的源从文件头读；其余（新出现的文件）定位到末尾，不回放历史。
		key := ingest.CleanPath(ls.path)
		_, fromStart := e.pendingReadd[key]
		delete(e.pendingReadd, key)
		e.addLogSource(ls.jail, ls.path, fromStart)
	}

	// 已不再配置的路径不必再等。
	for path := range e.pendingReadd {
		if _, ok := keep[ingest.CleanPath(path)]; !ok {
			delete(e.pendingReadd, path)
		}
	}
}

// addLogSource 给一个日志文件挂 watch、登记身份、建读取器，并立即读一次。
//
// fromStart=false 时定位到文件末尾（不回放历史）。返回值 added=false 表示路径当前不可
// 挂（符号链接 / 不存在 / watch 失败），由调用方决定是否登记为待重挂。
func (e *InboundExecutor) addLogSource(jail, path string, fromStart bool) (ingest.SourceID, bool) {
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
	id := e.registry.Register(ingest.LogOwner(jail), path, wd, inode)
	reader := ingest.NewSourceReader(e.logger)
	if !fromStart {
		reader.OpenAtEnd(path)
	}
	e.readers[id] = reader
	// 立即读一次：覆盖「内容先于 watch 到达」的窗口——轮转后新文件在挂 watch 之前就
	// 被写入时，不会有任何 inotify 事件来触发读取。
	e.drainSource(id)
	return id, true
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

// enabledLogSources 返回当前配置里启用的日志源。
func (e *InboundExecutor) enabledLogSources() []logSource {
	var out []logSource
	for i := range e.cfg.Jails {
		jail := &e.cfg.Jails[i]
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
func (e *InboundExecutor) jailForPath(path string) (string, bool) {
	clean := ingest.CleanPath(path)
	for i := range e.cfg.Jails {
		jail := &e.cfg.Jails[i]
		if !jail.Enabled {
			continue
		}
		for _, file := range jail.LogFiles {
			if ingest.CleanPath(file) == clean {
				return jail.Name, true
			}
		}
	}
	return "", false
}

// reloadConfig 处理 SIGHUP（或配置文件自身变化）触发的热重载。
func (e *InboundExecutor) reloadConfig() {
	if e.reloader == nil {
		e.info("配置重载器未接线，忽略重载请求")
		return
	}
	if err := e.reloader.Reload(e.cfg); err != nil {
		e.warn("配置重载失败", "error", err)
	} else {
		e.info("配置重载成功")
	}
	// 无论成功与否都按当前 cfg 重建：失败时 Reload 已把 cfg 回滚成旧配置，重建即回到
	// 旧集合（重建幂等，重复调用无副作用）。
	e.refreshJails()
	e.reconcileWatches()
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
}

// syncJailEnabled 把 Web UI 权威的启用状态桥接进本地配置，有变化才重建监视集合。
func (e *InboundExecutor) syncJailEnabled() {
	if e.enabled == nil {
		return
	}
	states := e.enabled.EnabledStates()
	changed := false
	for i := range e.cfg.Jails {
		local := &e.cfg.Jails[i]
		enabled, ok := states[local.Name]
		if !ok || local.Enabled == enabled {
			continue
		}
		e.info("Jail 启用状态同步", "jail", local.Name, "enabled", enabled)
		local.Enabled = enabled
		changed = true
	}
	if changed {
		e.reconcileWatches()
	}
}

// refreshJails 按当前配置重建各 jail 的规则集与判定参数（失败窗口由 RegisterJail 保留）。
func (e *InboundExecutor) refreshJails() {
	keep := make([]string, 0, len(e.cfg.Jails))
	for i := range e.cfg.Jails {
		jail := &e.cfg.Jails[i]
		rules := e.ruleSetFor(jail)
		policy := NewJailPolicy(jail.MaxRetries, jail.FindTime, jail.BanTime, jail.Cluster)
		e.pipeline.RegisterJail(rules, policy)
		keep = append(keep, jail.Name)
	}
	// 配置里已消失的 jail 连同其失败窗口一并摘除。
	if removed := e.pipeline.RetainJails(keep); removed > 0 {
		e.debug("已摘除配置中不再存在的 jail", "removed", removed)
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
func (e *InboundExecutor) dispatchClusterHit(jail string, hit decision.ClusterHit, cfg config.ClusterConfig) {
	e.warn("检测到集群扫描",
		"jail", jail,
		"cidr", hit.CIDR.String(),
		"src_ips", len(hit.IPs),
		"peak", hit.Peak,
		"audit_only", cfg.AuditOnly,
	)
	if cfg.AuditOnly || e.sink == nil {
		return
	}
	// 下发的形状与白名单路径一致：裸网络地址 + 前缀长度（CidrKey.Addr() 已归一）。
	reason := fmt.Sprintf("%s: %s", jail, hit.Summary())
	if err := e.sink.Send(hit.CIDR.Addr(), uint8(hit.CIDR.PrefixLen()), cfg.BanTime, reason); err != nil {
		e.warn("集群网段封禁下发失败", "jail", jail, "cidr", hit.CIDR.String(), "error", err)
	}
}

// dispatchIntent 把一个封禁意图下发内核，并镜像到本地缓存与统计。
//
// 顺序对齐旧实现：try_insert 单赢家 → 镜像 → 标记待确认 → 下发 → 失败则三者回滚；
// 只有下发成功后才给 per-jail 的 bans_triggered 加 1。
func (e *InboundExecutor) dispatchIntent(intent *BanIntent) {
	ip := intent.IP.String()
	jail := intent.Jail
	info, ok := e.banInfoFor(intent)
	if !ok {
		e.warn("IP 验证失败，跳过封禁", "ip", ip, "jail", jail)
		return
	}
	plan := intent.Plan
	e.info("触发封禁",
		"reason", intent.Reason,
		"ip", ip,
		"jail", jail,
		"duration", plan.Duration,
		"is_permanent", plan.IsPermanent,
		"ban_count", plan.BanCount,
	)

	if e.sink == nil {
		return
	}
	if !e.sink.TryInsert(info) {
		return
	}
	e.sink.MarkPendingAck(ip)

	// 永久封禁 duration 为 0；临时封禁把秒数钳进 uint32。
	durationSecs := uint32(0)
	if !plan.IsPermanent {
		if plan.Duration > math.MaxUint32 {
			durationSecs = math.MaxUint32
		} else {
			durationSecs = uint32(plan.Duration)
		}
	}
	if err := e.sink.Send(intent.IP, bans.FullPrefixLen(intent.IP), durationSecs, jail); err != nil {
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
		IP:          ip,
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

// mirrorCounters 把一批处理产生的计数差值镜像到全局与 per-jail 计数器。
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
		e.stats.AddGlobal(parsed, skipped, regexes, ips)
		e.stats.AddJail(jail, parsed, regexes, ips)
	}
	// 镜像到全局 jail 运行时统计（Web UI 可读）。
	config.UpdateJailStats(jail, parsed, regexes, ips, ips, bans)
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
