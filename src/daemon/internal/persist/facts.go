// 判定事实源：把「每行日志一次信誉分扣减」折叠成按 IP 的批量落盘。
//
// 为什么不能直接查库：判定层对每一行识别出合法 IP 的日志都要先记一次失败、紧接着取
// 信誉分算阈值（顺序是契约的一部分，见 runtime.DecisionFacts）。高流量 jail 下这就是
// 每行两次 SQLite 往返，入站主链路会被磁盘钉死——而这条链路的等待上限本该由日志事件
// 决定。本缓存把同一 IP 的连续失败折叠成一条 UPDATE，按周期或按容量落盘。
//
// 折叠的代价：库里的分数落后于内存，最长落后一个刷盘周期；进程被杀时未落盘的部分丢失。
// 信誉分只是渐进式阈值的一个乘数（ReputationMultiplier），不是封禁事实本身，可接受。
//
// 并发：读写由入站执行体的单个 goroutine 发起，刷盘由 StartFlusher 起的另一个 goroutine
// 发起，故共用一把锁。批量刷盘把 SQLite 放在锁外（锁内只摘脏项、清零）；唯一的例外是
// 容量满时的逐出落盘——那是一行 UPDATE，且只在 4096 个不同 IP 同时活跃时才走到。
package persist

import (
	"container/list"
	"log/slog"
	"net/netip"
	"sync"
	"time"
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
	// Logger 为 nil 时用 slog.Default()。
	Logger *slog.Logger
}

// factsEntry 是一个 IP 的缓存项。
//
// score 是「内存里现在应该是多少分」，pending 是其中尚未落盘的扣分量：落库走
// RecordFailure(ip, pending)，即 SQL 侧 MAX(0, score - pending)，与内存的钳位同式。
type factsEntry struct {
	ip          string
	score       uint32
	scoreLoaded bool
	pending     uint32

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
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Facts{
		db:       db,
		penalty:  uint32(penalty),
		capacity: capacity,
		logger:   logger,
		lru:      list.New(),
		index:    make(map[string]*list.Element, capacity),
		flushGap: gap,
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
func (f *Facts) touchLocked(ip string) *factsEntry {
	if el, ok := f.index[ip]; ok {
		f.lru.MoveToFront(el)
		return el.Value.(*factsEntry)
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
	if evicted != nil && evicted.pending > 0 {
		// 逐出即落盘，否则这条 IP 的扣分就只剩内存里那一份、重启后凭空消失。
		f.writeBack(evicted)
	}
	return e
}

// loadScoreLocked 把内存分对齐到库里的值（未知 IP 按满分起算）。
func (f *Facts) loadScoreLocked(e *factsEntry) {
	if e.scoreLoaded {
		return
	}
	e.scoreLoaded = true
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

// RecordFailure 记一次失败尝试：内存扣分并记入待落盘量。
func (f *Facts) RecordFailure(addr netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.touchLocked(key(addr))
	f.loadScoreLocked(e)
	if e.score > f.penalty {
		e.score -= f.penalty
	} else {
		e.score = 0
	}
	e.pending += f.penalty
}

// ReputationScore 返回该 IP 当前的信誉分（含本次失败，见调用契约的顺序要求）。
func (f *Facts) ReputationScore(addr netip.Addr) uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.touchLocked(key(addr))
	f.loadScoreLocked(e)
	return e.score
}

// PriorBanCount 返回该 IP 此前已封禁次数。
func (f *Facts) PriorBanCount(addr netip.Addr) uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.touchLocked(key(addr))
	f.loadBansLocked(e)
	return e.bans
}

// NoteBan 把「刚刚发生了一次封禁」同步进缓存。
//
// 为什么需要它：banSink 落库时既写 ban_history（次数 +1）又写 ip_reputation（扣分），
// 这两笔都在缓存之外。不同步进来，缓存会继续报告封禁前的次数与分数，而渐进式时长恰好
// 读的就是这个次数。扣分量不进 pending——库里那笔已经由 RecordBan 落好了。
func (f *Facts) NoteBan(addr netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.touchLocked(key(addr))
	f.loadScoreLocked(e)
	f.loadBansLocked(e)
	e.bans++
	if pen := uint32(DefaultBanPenalty); e.score > pen {
		e.score -= pen
	} else {
		e.score = 0
	}
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
func (f *Facts) writeAll(dirty []*factsEntry) error {
	var last error
	for _, e := range dirty {
		f.mu.Lock()
		n := e.pending
		e.pending = 0
		f.mu.Unlock()
		if n == 0 {
			continue
		}
		if err := f.writeN(e.ip, n); err != nil {
			f.logger.Warn("信誉分落盘失败", "ip", e.ip, "error", err)
			last = err
			// 写失败就把量还回去，下一拍重试：宁可分数暂时不一致，也不要丢掉扣分记录。
			f.mu.Lock()
			e.pending += n
			f.mu.Unlock()
		}
	}
	return last
}

// writeBack 是逐出路径上的同步落盘（容量已满时才走到，摊薄后仍是一次/条）。
func (f *Facts) writeBack(e *factsEntry) {
	n := e.pending
	e.pending = 0
	if err := f.writeN(e.ip, n); err != nil {
		f.logger.Warn("逐出时信誉分落盘失败", "ip", e.ip, "error", err)
	}
}

func (f *Facts) writeN(ip string, delta uint32) error {
	if f.db == nil || delta == 0 {
		return nil
	}
	return f.db.RecordFailure(ip, int(delta))
}

// StartFlusher 起一个后台 goroutine，按 opts.FlushEvery 的节拍把脏账落盘，stopCh 关闭
// 时做最后一次刷盘再退出（与 DB 自带的两个周期调度器同一关停口径，可复用同一条 stop 通道）。
func (f *Facts) StartFlusher(stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(f.flushGap)
		defer ticker.Stop()
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
			}
		}
	}()
}

// Stats 返回缓存条目数与待落盘条目数，供调试与测试观察。
func (f *Facts) Stats() (entries, pending int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for el := f.lru.Front(); el != nil; el = el.Next() {
		if el.Value.(*factsEntry).pending > 0 {
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
