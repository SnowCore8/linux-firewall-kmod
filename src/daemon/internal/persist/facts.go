// 判定事实源：把「每行日志一次信誉分扣减」折叠成按 IP 的批量落盘。
//
// 为什么不能直接查库：判定层对每一行识别出合法 IP 的日志都要先记一次失败、紧接着取
// 信誉分算阈值（顺序是契约的一部分，见 runtime.DecisionFacts）。高流量 jail 下这就是
// 每行两次 SQLite 往返，入站主链路会被磁盘钉死——而这条链路的等待上限本该由日志事件
// 决定。本缓存把同一 IP 的连续失败折叠成一条 UPDATE，按周期或按容量落盘。
//
// 折叠的代价：库里的分数落后于内存，最长落后一个刷盘周期；进程被杀时未落盘的部分丢失。
// 信誉分只是渐进式阈值的一个加法调整量（ReputationAdjustment），不是封禁事实本身，可接受。
//
// 反方向的落差同样存在：库侧还有恢复调度器（RecoverReputation）与封禁写库两条改分路径，
// 它们不经过本缓存。若只在首次访问时读一次库，判定层会永远按进程启动时的旧分算阈值，
// 故 StartFlusher 同时按 reloadEvery 把内存分重新对齐到库（见 reloadScores）。
//
// 并发：读写由入站执行体的单个 goroutine 发起，刷盘与重载由 StartFlusher 起的另一个
// goroutine 发起，故共用一把锁。批量刷盘把 SQLite 放在锁外（锁内只摘脏项、清零）；唯一的
// 例外是容量满时的逐出落盘——那是一行 UPDATE，且只在 4096 个不同 IP 同时活跃时才走到。
// 逐出落盘与重载还要串行化（dbMu）：见 writeAll 与 reloadScores 的注释。
package persist

import (
	"container/list"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/risk"
)

const (
	// DefaultFailurePenalty 是一次失败尝试扣掉的信誉分，与旧实现逐字一致。
	DefaultFailurePenalty = 10
	// DefaultBanPenalty 是一次封禁扣掉的信誉分（banSink 落库时用同一常量，两侧不得分叉）。
	DefaultBanPenalty = 10
	// defaultFactsCapacity 是缓存容量：超出即刷掉最久未用的一条并逐出。
	//
	// 4096 是「一个刷盘周期内可能同时活跃的 attacker IP 数」的宽裕上界：按 5 秒周期、
	// 每 IP 每秒 100 行失败日志算，也远不到这里；到了就说明在被灌日志，逐出时顺手落盘。
	defaultFactsCapacity = 4096
	// defaultFactsFlushEvery 是脏条目的最长驻留时间。
	defaultFactsFlushEvery = 5 * time.Second
	// defaultScoreReloadEvery 是内存分数与库重新对齐的间隔。库侧的恢复与封禁写库都不经过
	// 本缓存，不重载就会让判定阈值一直按进程启动时的旧分算；5 分钟是「恢复是每小时一次的
	// 慢变量、而重载不能让每个活跃 IP 每拍都读一次库」的折中。
	defaultScoreReloadEvery = 5 * time.Minute
	// eventDropWarnInterval 是风险事件队列丢弃告警的最小间隔：队列满说明在灌流量，
	// 每条丢弃都打日志会把日志本身变成放大源。
	eventDropWarnInterval = 30 * time.Second
	// fullReputation 是未知 IP 的起始信誉分（库里没有该行时按满分算）。
	fullReputation = 100
)

// FactsOptions 是缓存的调参项，零值取各默认。
type FactsOptions struct {
	// FailurePenalty 是每次失败的扣分，<=0 取 DefaultFailurePenalty。
	FailurePenalty int
	// Capacity 是缓存条目上限，<=0 取 defaultFactsCapacity。
	Capacity int
	// FlushEvery 是脏条目的最长驻留时间，<=0 取 defaultFactsFlushEvery。
	FlushEvery time.Duration
	// ScoreReloadEvery 是内存分数从库重载的间隔，<=0 取 defaultScoreReloadEvery。
	ScoreReloadEvery time.Duration
	// Logger 为 nil 时用 slog.Default()。
	Logger *slog.Logger
	// RiskEngineEnabled 启用多维风险向量记录（feature flag）。
	// 为 false 时不构建风险引擎，阈值计算不受影响。
	RiskEngineEnabled bool
	// RiskWeights 覆盖各维度默认权重；零值或未给出的维度保持 1.0。
	RiskWeights map[string]float64
	// RiskHalfLifeDays 是向量衰减半衰期（天），<=0 用默认 7 天。
	RiskHalfLifeDays float64
}

// factsEntry 是一个 IP 的缓存项。
//
// score 是「内存里现在应该是多少分」，pending 是其中尚未落盘的扣分量：落库走
// RecordFailure(ip, pending)，即 SQL 侧 MAX(0, score - pending)，与内存的钳位同式。
type factsEntry struct {
	ip          string
	score       uint32
	scoreLoaded bool
	// scoreLoadedAt 是上次从库对齐分数的时间；重载按 reloadEvery 判断是否过期。
	scoreLoadedAt time.Time
	pending       uint32

	bans       uint32
	bansLoaded bool
}

// Facts 是 runtime.DecisionFacts 的生产实现。
type Facts struct {
	db       *DB
	penalty  uint32
	capacity int

	logger *slog.Logger

	mu       sync.Mutex
	lru      *list.List
	index    map[string]*list.Element
	flushGap time.Duration
	// reloadEvery 是内存分与库对齐的间隔（StartFlusher 按此节拍调 reloadScores）。
	reloadEvery time.Duration
	// dbMu 串行化「读库后应用」与「摘 pending 后写库」两条路径。
	//
	// 重载的公式是「库中分 - 尚未落盘的 pending」，而 flush 摘走 pending 与写库之间存在
	// 窗口：若重载恰在此窗口读到库，扣分既不在读数里也不在 pending 里，分数会短暂回弹。
	// 两个临界区都退化成「不再有别的数据库写者插入」，窗口就消失了。
	// 锁序固定为 dbMu -> mu；不得在持 mu 时取 dbMu。
	dbMu sync.Mutex

	// riskEngine 是多维风险向量引擎（Phase 4 新增）。
	// 为 nil 时退化为旧单维度模型（向后兼容）。
	riskEngine *risk.Engine

	// eventCh 是风险事件异步持久化的有界工作队列。
	// 容量 1024 是「高流量攻击下几秒内可能堆积的事件数」的宽裕上界；
	// 满时丢弃新事件而非阻塞主链路或创建无界 goroutine。
	eventCh chan riskEvent
	// eventWorkers 是持久化 worker 数量，与 CPU 数解耦（SQLite 单写连接，多 worker 无益）。
	eventWorkers  int
	eventWG       sync.WaitGroup
	eventStopOnce sync.Once
	// stopped 在 mu 下读写：关停时同一个临界区内「置位 + 关闭 eventCh」，
	// 生产方的非阻塞发送也持同一把锁，故不会向已关闭的 channel 发送。
	stopped bool
	// eventDrops 是队列满时累计丢弃的事件数；lastEventDropWarn 是上次告警时间。
	// 两者在 mu 下读写。丢弃本身不可恢复（内存里的向量已经记上），累计值让
	// 「到底丢了多少」可查，限流告警避免每条丢弃都写一行日志。
	eventDrops        uint64
	lastEventDropWarn time.Time
}

// riskEvent 是异步持久化的风险事件。
type riskEvent struct {
	ip        string
	eventType risk.EventType
	increment float64
}

// NewFacts 装配缓存。db 为 nil 时退化为纯内存实现（不落盘，读侧永远满分起算）。
func NewFacts(db *DB, opts FactsOptions) *Facts {
	penalty := opts.FailurePenalty
	if penalty <= 0 {
		penalty = DefaultFailurePenalty
	}
	capacity := opts.Capacity
	if capacity <= 0 {
		capacity = defaultFactsCapacity
	}
	gap := opts.FlushEvery
	if gap <= 0 {
		gap = defaultFactsFlushEvery
	}
	reloadGap := opts.ScoreReloadEvery
	if reloadGap <= 0 {
		reloadGap = defaultScoreReloadEvery
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	var riskEngine *risk.Engine
	if opts.RiskEngineEnabled {
		weights := risk.DefaultDimensionWeights()
		setWeight := func(name string, dst *float64) {
			if v, ok := opts.RiskWeights[name]; ok && v > 0 {
				*dst = v
			}
		}
		setWeight("failure", &weights.Failure)
		setWeight("ban", &weights.Ban)
		setWeight("scan", &weights.Scan)
		setWeight("bruteforce", &weights.Bruteforce)
		setWeight("ddos", &weights.DDoS)
		setWeight("geo", &weights.Geo)
		setWeight("cluster", &weights.Cluster)
		riskEngine = risk.NewEngineWithHalfLife(weights, opts.RiskHalfLifeDays)
		if db != nil {
			// 后台衰减与「近零记录删除」用引擎同一份权重，避免两套默认值各说各话。
			db.SetRiskVectorWeights(weights)
		}
		logger.Info("multi-dimensional risk engine enabled")
	}

	f := &Facts{
		db:           db,
		penalty:      uint32(penalty),
		capacity:     capacity,
		logger:       logger,
		lru:          list.New(),
		index:        make(map[string]*list.Element, capacity),
		flushGap:     gap,
		reloadEvery:  reloadGap,
		riskEngine:   riskEngine,
		eventCh:      make(chan riskEvent, 1024),
		eventWorkers: 1, // SQLite 单写连接，多 worker 无益
	}

	// 启动异步持久化 worker（仅在 db 和 riskEngine 都存在时）
	if db != nil && riskEngine != nil {
		f.startEventWorkers()
	}

	return f
}

// startEventWorkers 启动风险事件持久化 worker。
func (f *Facts) startEventWorkers() {
	for i := 0; i < f.eventWorkers; i++ {
		f.eventWG.Add(1)
		go f.eventWorker()
	}
}

// Stop 停止风险事件持久化：关闭工作队列，等 worker 把已入队事件写完。
//
// 不先排空就退出进程会丢掉 channel 里最多 1024 条事件及其向量快照——这些正是
// `risk_engine.enabled` 打开时 API 要读的读数。幂等，且必须在关库之前调用。
func (f *Facts) Stop() {
	f.eventStopOnce.Do(func() {
		f.mu.Lock()
		f.stopped = true
		close(f.eventCh)
		f.mu.Unlock()
		f.eventWG.Wait()
	})
}

// eventWorker 从 eventCh 读取事件并持久化到数据库。
func (f *Facts) eventWorker() {
	defer f.eventWG.Done()
	for ev := range f.eventCh {
		if err := f.db.InsertEvent(ev.ip, ev.eventType, ev.increment, 0); err != nil {
			f.logger.Warn("risk event persist failed", "ip", ev.ip, "error", err)
		}
		// 向量快照与事件同批落库：查询接口读的是 ip_risk_vectors，只写事件表
		// 会让 API 永远回零向量。
		if vec, ok := f.riskEngine.GetVector(ev.ip); ok {
			if err := f.db.UpsertRiskVector(ev.ip, vec, time.Now().Unix()); err != nil {
				f.logger.Warn("risk vector persist failed", "ip", ev.ip, "error", err)
			}
		}
	}
}

// key 把地址归一成缓存键：IPv4 映射地址（::ffff:1.2.3.4）与其点分十进制写法必须落进
// 同一条目，否则同一主机会有两份互不相见的信誉分。
func key(addr netip.Addr) string {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return addr.String()
}

// touchLocked 取（或建）缓存项并标为最近使用。容量满时逐出最久未用的一条并先落其脏账。
// 返回 (entry, evicted)：evicted 非 nil 时调用方需在锁外执行 writeBack，避免持锁期间做 DB I/O。
func (f *Facts) touchLocked(ip string) (*factsEntry, *factsEntry) {
	if el, ok := f.index[ip]; ok {
		f.lru.MoveToFront(el)
		return el.Value.(*factsEntry), nil
	}
	var evicted *factsEntry
	if f.lru.Len() >= f.capacity {
		if back := f.lru.Back(); back != nil {
			f.lru.Remove(back)
			evicted = back.Value.(*factsEntry)
			delete(f.index, evicted.ip)
		}
	}
	e := &factsEntry{ip: ip}
	f.index[ip] = f.lru.PushFront(e)
	return e, evicted
}

// loadScoreLocked 把内存分对齐到库里的值（未知 IP 按满分起算）。
func (f *Facts) loadScoreLocked(e *factsEntry) {
	if e.scoreLoaded {
		return
	}
	e.scoreLoaded = true
	e.scoreLoadedAt = time.Now()
	e.score = fullReputation
	if f.db == nil {
		return
	}
	rep, err := f.db.GetIPReputation(e.ip)
	if err != nil {
		f.logger.Warn("读取信誉分失败，按满分处理", "ip", e.ip, "error", err)
		return
	}
	if rep != nil {
		e.score = clampScore(rep.Score)
	}
}

// loadBansLocked 读入历史封禁次数。
func (f *Facts) loadBansLocked(e *factsEntry) {
	if e.bansLoaded {
		return
	}
	e.bansLoaded = true
	if f.db == nil {
		return
	}
	h, err := f.db.GetBanHistory(e.ip)
	if err != nil {
		f.logger.Warn("读取封禁历史失败，按零次处理", "ip", e.ip, "error", err)
		return
	}
	if h != nil && h.BanCount > 0 {
		e.bans = uint32(h.BanCount)
	}
}

// reloadScores 把超过 reloadEvery 未对齐的条目重新对齐到库里的分数。
//
// 为什么需要：库侧的恢复调度器与封禁写库都不经过本缓存，只加载一次会让判定阈值永远按
// 进程启动时的旧分算（恢复再多也看不见）。
//
// 有效分 = clamp(库中分) - 尚未落盘的 pending：pending 是库里还没有的失败扣分，重载不能
// 把它抹掉，否则这批失败要等下次落盘才重新计入。
//
// 已读条目快照在锁外，读库与写回都持 dbMu（理由见 dbMu 字段注释），逐条应用时用指针
// 校验条目没被逐出后重建，避免把过期的库读数套到新条目上。
//
// 已知边界（不为此加状态机）：NoteBan 的封禁扣分由 banSink 的 RecordBan 同步写库、不进
// pending。若那笔写库失败（已进重试队列），重载会按库中尚未扣的分数把内存分抬回，直到
// 重试队列补写成功；这期间分数偏高，只影响阈值的一个加法调整量，不影响封禁事实。
func (f *Facts) reloadScores() {
	if f.db == nil {
		return
	}
	now := time.Now()
	type staleEntry struct {
		ip string
		e  *factsEntry
	}
	f.mu.Lock()
	var stale []staleEntry
	for el := f.lru.Front(); el != nil; el = el.Next() {
		e := el.Value.(*factsEntry)
		if e.scoreLoaded && now.Sub(e.scoreLoadedAt) >= f.reloadEvery {
			stale = append(stale, staleEntry{ip: e.ip, e: e})
		}
	}
	f.mu.Unlock()
	if len(stale) == 0 {
		return
	}

	f.dbMu.Lock()
	defer f.dbMu.Unlock()
	for _, s := range stale {
		rep, err := f.db.GetIPReputation(s.ip)
		if err != nil {
			f.logger.Warn("重载信誉分失败，保留内存分数", "ip", s.ip, "error", err)
			continue
		}
		dbScore := uint32(fullReputation)
		if rep != nil {
			dbScore = clampScore(rep.Score)
		}
		f.mu.Lock()
		cur, ok := f.index[s.ip]
		if !ok || cur.Value.(*factsEntry) != s.e {
			// 条目已被逐出或换成了替代条目：它的分数由它自己的加载路径负责。
			f.mu.Unlock()
			continue
		}
		if s.e.pending > dbScore {
			s.e.score = 0
		} else {
			s.e.score = dbScore - s.e.pending
		}
		s.e.scoreLoadedAt = time.Now()
		f.mu.Unlock()
	}
}

// RecordFailure 记一次失败尝试：内存扣分并记入待落盘量。
func (f *Facts) RecordFailure(addr netip.Addr) {
	f.mu.Lock()
	e, evicted := f.touchLocked(key(addr))
	f.loadScoreLocked(e)
	if e.score > f.penalty {
		e.score -= f.penalty
	} else {
		e.score = 0
	}
	e.pending += f.penalty

	// 多维风险引擎：记录失败事件（feature flag 控制）
	drops, dropIP, warnDrop := uint64(0), "", false
	if f.riskEngine != nil && !f.stopped {
		ip := key(addr)
		f.riskEngine.RecordEvent(ip, risk.EventFailure, 1.0)
		// 异步持久化到数据库（不阻塞主链路）
		// 使用有界 channel 而非无界 goroutine，防止高流量下内存耗尽
		drops, dropIP, warnDrop = f.enqueueRiskLocked(riskEvent{ip: ip, eventType: risk.EventFailure, increment: 1.0})
	}
	f.mu.Unlock()
	// 日志在锁外写：告警要落到文件，持缓存锁做 I/O 会钉住所有判定。
	if warnDrop {
		f.warnEventDrop(dropIP, drops)
	}
	// 逐出落盘在锁外执行，避免持锁期间做 DB I/O 阻塞其他缓存操作
	if evicted != nil {
		f.writeBack(evicted)
	}
}

// enqueueRiskLocked 非阻塞入队一条风险事件。
//
// 队列满时累加丢弃计数并按 eventDropWarnInterval 限流告警，返回本次是否该写日志
// 及累计丢弃数。调用方必须持有 f.mu，且在释放后再调用 warnEventDrop。
func (f *Facts) enqueueRiskLocked(ev riskEvent) (drops uint64, ip string, warn bool) {
	select {
	case f.eventCh <- ev:
		return 0, "", false
	default:
		f.eventDrops++
		if now := time.Now(); f.lastEventDropWarn.IsZero() ||
			now.Sub(f.lastEventDropWarn) >= eventDropWarnInterval {
			f.lastEventDropWarn = now
			return f.eventDrops, ev.ip, true
		}
		return f.eventDrops, "", false
	}
}

// warnEventDrop 写一条丢弃告警；必须在释放 f.mu 之后调用。
func (f *Facts) warnEventDrop(ip string, drops uint64) {
	f.logger.Warn("risk event queue full, dropping events",
		"last_ip", ip, "dropped_total", drops, "capacity", cap(f.eventCh))
}

// RecordRiskEvent 记录自定义风险事件到多维引擎。
//
// 仅在 riskEngine != nil 时生效（feature flag 控制）。
// eventType 和 increment 由调用方决定（如 ClassifyFailure 的返回值）。
func (f *Facts) RecordRiskEvent(addr netip.Addr, eventType risk.EventType, increment float64) {
	if f.riskEngine == nil {
		return
	}
	ip := key(addr)
	f.riskEngine.RecordEvent(ip, eventType, increment)
	// 发送与 Stop 的关闭共用 f.mu：否则 Stop 关掉 channel 后仍可能有一条事件发进来。
	f.mu.Lock()
	if f.stopped {
		f.mu.Unlock()
		return
	}
	// 异步持久化，使用有界 channel 防止高流量下内存耗尽
	drops, dropIP, warnDrop := f.enqueueRiskLocked(riskEvent{ip: ip, eventType: eventType, increment: increment})
	f.mu.Unlock()
	if warnDrop {
		f.warnEventDrop(dropIP, drops)
	}
}

// RiskVector 返回指定 IP 的当前风险向量（多维引擎启用时）。
//
// 返回 (零向量, false) 表示引擎未启用或该 IP 无记录。
func (f *Facts) RiskVector(addr netip.Addr) (risk.RiskVector, bool) {
	if f.riskEngine == nil {
		return risk.RiskVector{}, false
	}
	return f.riskEngine.GetVector(key(addr))
}

// RiskEngineEnabled 报告多维风险引擎是否启用。
func (f *Facts) RiskEngineEnabled() bool {
	return f.riskEngine != nil
}

// ReputationScore 返回该 IP 当前的信誉分（含本次失败，见调用契约的顺序要求）。
func (f *Facts) ReputationScore(addr netip.Addr) uint32 {
	f.mu.Lock()
	e, evicted := f.touchLocked(key(addr))
	f.loadScoreLocked(e)
	score := e.score
	f.mu.Unlock()
	if evicted != nil {
		f.writeBack(evicted)
	}
	return score
}

// PriorBanCount 返回该 IP 此前已封禁次数。
func (f *Facts) PriorBanCount(addr netip.Addr) uint32 {
	f.mu.Lock()
	e, evicted := f.touchLocked(key(addr))
	f.loadBansLocked(e)
	bans := e.bans
	f.mu.Unlock()
	if evicted != nil {
		f.writeBack(evicted)
	}
	return bans
}

// NoteBan 把「刚刚发生了一次封禁」同步进缓存。
//
// 为什么需要它：banSink 落库时既写 ban_history（次数 +1）又写 ip_reputation（扣分），
// 这两笔都在缓存之外。不同步进来，缓存会继续报告封禁前的次数与分数，而渐进式时长恰好
// 读的就是这个次数。扣分量不进 pending——库里那笔已经由 RecordBan 落好了。
func (f *Facts) NoteBan(addr netip.Addr) {
	f.mu.Lock()
	e, evicted := f.touchLocked(key(addr))
	// 库侧的这次封禁已经由 RecordBanHistory/RecordBan 落好了，因此「本次封禁前是否
	// 已经有内存读数」决定了要不要自增：
	//   - 已加载的条目记的是封禁前的值，落库后库值比内存新一次，必须增量；
	//   - 新建或尚未加载的条目读到的就是**封禁后**的库值，再自增会把同一次封禁记两遍
	//     （条目在落库与 NoteBan 之间被 LRU 逐出，就是这个形状）。
	// 无库时没有那笔落库，始终按内存增量。
	hadScore := e.scoreLoaded
	hadBans := e.bansLoaded
	f.loadScoreLocked(e)
	f.loadBansLocked(e)
	if hadBans || f.db == nil {
		e.bans++
	}
	if hadScore || f.db == nil {
		if pen := uint32(DefaultBanPenalty); e.score > pen {
			e.score -= pen
		} else {
			e.score = 0
		}
	}
	f.mu.Unlock()
	if evicted != nil {
		f.writeBack(evicted)
	}
	// 封禁也是风险维度之一；引擎未启用时 RecordRiskEvent 是空操作。
	f.RecordRiskEvent(addr, risk.EventBan, 1.0)
}

// Flush 把所有脏账落盘，返回最后一个失败（其余失败逐条记日志，不让一次 IO 抖动挡住关停）。
func (f *Facts) Flush() error {
	f.mu.Lock()
	dirty := f.takeDirtyLocked()
	f.mu.Unlock()
	return f.writeAll(dirty)
}

// takeDirtyLocked 摘出全部脏项并把待写量清零：SQLite 往返在锁外做。
func (f *Facts) takeDirtyLocked() []*factsEntry {
	var dirty []*factsEntry
	for el := f.lru.Front(); el != nil; el = el.Next() {
		e := el.Value.(*factsEntry)
		if e.pending > 0 {
			dirty = append(dirty, e)
		}
	}
	return dirty
}

// writeAll 逐条落盘并清零。条目被摘出后仍可能并发地再产生新的 pending，故这里只清
// 「本次写掉的量」，不能整格清零。
//
// 摘 pending 与写库都持 dbMu：重载要在「读库 + 应用」之间看不到被摘走却尚未写成的账
// （见 dbMu 字段注释）。锁序 dbMu -> mu。
func (f *Facts) writeAll(dirty []*factsEntry) error {
	var last error
	for _, e := range dirty {
		f.dbMu.Lock()
		f.mu.Lock()
		n := e.pending
		e.pending = 0
		f.mu.Unlock()
		if n == 0 {
			f.dbMu.Unlock()
			continue
		}
		if err := f.writeN(e.ip, n); err != nil {
			f.logger.Warn("信誉分落盘失败", "ip", e.ip, "error", err)
			last = err
			// 写失败就把量还回去，下一拍重试：宁可分数暂时不一致，也不要丢掉扣分记录。
			// 还账必须认索引里的现存条目：写库在锁外，期间本条可能已被逐出、同 IP 又
			// 建了新条目，直接还给 e 会把扣分挂到一条不再被索引的孤儿上。
			f.mu.Lock()
			f.requeueLostLocked(e, n)
			f.mu.Unlock()
		}
		f.dbMu.Unlock()
	}
	return last
}

// requeueLostLocked 把一笔未能落盘的扣分记回索引中的条目；调用方必须持有写锁。
//
// e 可能已被逐出：writeAll 写库期间逐出路径取走 pending 并将条目移出索引，随后同一
// IP 的新日志又建了一条替代条目。把量还给 e 就是还给孤儿——它不在 lru/index 里，
// 后续 Flush 永远摘不到它，这部分扣分再也不会落盘。三种情况分别处理：
//   - 索引里还是 e：直接追加 pending；
//   - 换成了替代条目：按 writeBack 同一口径把欠账并入（库里尚未包含这笔扣分，故重载
//     库值后先减分再追加 pending，保持「内存分 = 库分 - 待落盘量」）；
//   - 索引里没有：把 e 重新挂回，下一拍继续重试。
func (f *Facts) requeueLostLocked(e *factsEntry, n uint32) {
	if cur, exists := f.index[e.ip]; exists {
		ce := cur.Value.(*factsEntry)
		if ce == e {
			e.pending += n
			return
		}
		f.loadScoreLocked(ce)
		ce.pending += n
		if ce.score > n {
			ce.score -= n
		} else {
			ce.score = 0
		}
		f.lru.MoveToFront(cur)
		return
	}
	e.pending += n
	f.index[e.ip] = f.lru.PushFront(e)
}

// writeBack 是逐出路径上的同步落盘（容量已满时才走到，摊薄后仍是一次/条）。
// 写失败时把条目重新放回缓存，让后续周期 flush 重试，避免丢待落盘数据。
//
// pending 的读写都在锁内：被逐出的条目可能已被刷盘协程摘进脏表，也可能在落盘期间
// 因同一个 IP 再次出现而被新建条目接管——两条路径都会碰同一份 pending。
func (f *Facts) writeBack(e *factsEntry) {
	f.dbMu.Lock()
	f.mu.Lock()
	n := e.pending
	e.pending = 0
	f.mu.Unlock()
	if n == 0 {
		f.dbMu.Unlock()
		return
	}
	if err := f.writeN(e.ip, n); err != nil {
		f.logger.Warn("逐出时信誉分落盘失败，重新入队等待重试", "ip", e.ip, "error", err)
		f.mu.Lock()
		// 该 IP 可能已被其他路径重新创建：欠账并入现存条目，而不是挂在一条已不在索引
		// 里的对象上——后者会让这部分扣分永远不再落盘（同 writeAll 失败路径）。
		f.requeueLostLocked(e, n)
		f.mu.Unlock()
	}
	f.dbMu.Unlock()
}

// writeN 把 delta 分的扣分落库；调用方必须持有 dbMu（锁序见该字段注释）。
//
// total_failures 的语义是「失败条数」而不是「落盘批次数」：delta 是折叠的扣分总量，
// 除以单次扣分就还原出这批里有多少条失败。
func (f *Facts) writeN(ip string, delta uint32) error {
	if f.db == nil || delta == 0 {
		return nil
	}
	count := int(delta / f.penalty)
	if count <= 0 {
		count = 1
	}
	return f.db.RecordFailure(ip, int(delta), count)
}

// StartFlusher 起一个后台 goroutine，按 opts.FlushEvery 的节拍把脏账落盘，按
// opts.ScoreReloadEvery 的节拍把陈旧的内存分对齐到库，stopCh 关闭时做最后一次刷盘再退出
// （与 DB 自带的两个周期调度器同一关停口径，可复用同一条 stop 通道）。
// 返回的通道在最终刷盘结束后关闭；调用方必须先等它关闭再关数据库，否则最后一批
// 信誉分可能写到已经关闭的连接上。
//
// 刷盘与重载放同一个 goroutine：两者都改内存分，串行后重载不需要与 flush 竞争同一笔账。
func (f *Facts) StartFlusher(stopCh <-chan struct{}) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(f.flushGap)
		defer ticker.Stop()
		reloadTicker := time.NewTicker(f.reloadEvery)
		defer reloadTicker.Stop()
		for {
			select {
			case <-stopCh:
				if err := f.Flush(); err != nil {
					f.logger.Warn("关停时信誉分刷盘失败", "error", err)
				}
				return
			case <-ticker.C:
				f.mu.Lock()
				dirty := f.takeDirtyLocked()
				f.mu.Unlock()
				if err := f.writeAll(dirty); err != nil {
					f.logger.Warn("周期刷盘失败", "error", err)
				}
			case <-reloadTicker.C:
				f.reloadScores()
			}
		}
	}()
	return done
}

// Stats 返回缓存条目数与待落盘条目数，供调试与测试观察。
func (f *Facts) Stats() (entries, pending int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for el := f.lru.Front(); el != nil; el = el.Next() {
		entry, ok := el.Value.(*factsEntry)
		if !ok {
			continue
		}
		if entry.pending > 0 {
			pending++
		}
	}
	return f.lru.Len(), pending
}

func clampScore(v int) uint32 {
	if v < 0 {
		return 0
	}
	if v > fullReputation {
		return fullReputation
	}
	return uint32(v)
}
