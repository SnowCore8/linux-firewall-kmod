package decision

import (
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

// StaleTrackerWindow 是「长时间未活动」的判定窗口：超过它的每 IP 跟踪条目会被
// CleanupStale 回收。5 分钟足以覆盖一次连续攻击的间隔，也避免条目无限增长。
const StaleTrackerWindow = 5 * time.Minute

// ipTracker 是单个 IP 的违规跟踪条目（IP 本身作为 map 键，故不重复存字段）。
type ipTracker struct {
	// violationCount 是累计违规次数。
	violationCount atomic.Uint32
	// lastViolation 是最后一次违规时间（Unix 秒）。
	lastViolation atomic.Int64
}

func (t *ipTracker) increment(now int64) uint32 {
	t.lastViolation.Store(now)
	return t.violationCount.Add(1)
}

// DdosStats 是 DDoS 事件的累计计数（只增，可并发读）。
type DdosStats struct {
	// EventsDetected 是收到的 DDoS 事件总数。
	EventsDetected atomic.Uint64
	// AutoBansTriggered 是内核据此触发的自动封禁数。
	AutoBansTriggered atomic.Uint64
	// TrackedIPs 是当前被跟踪的 IP 数（由引擎维护）。
	TrackedIPs atomic.Uint64
}

// Snapshot 是 DdosStats 的只读快照。
type DdosStatsSnapshot struct {
	EventsDetected    uint64
	AutoBansTriggered uint64
	TrackedIPs        uint64
}

// Snapshot 读取当前计数。
func (s *DdosStats) Snapshot() DdosStatsSnapshot {
	return DdosStatsSnapshot{
		EventsDetected:    s.EventsDetected.Load(),
		AutoBansTriggered: s.AutoBansTriggered.Load(),
		TrackedIPs:        s.TrackedIPs.Load(),
	}
}

// DdosEngine 接收内核推送的 DDoS 事件并记账。
//
// 内核已经完成封禁，守护进程**不重复封禁**，这里只把「发生了什么」记进统计与日志。
// 事件与封禁都不经过本引擎下发，因此它不持有任何发送通道。
type DdosEngine struct {
	logger *slog.Logger
	stats  *DdosStats

	mu       sync.Mutex
	cfg      config.DdosConfig
	trackers map[netip.Addr]*ipTracker
}

// NewDdosEngine 创建决策引擎。logger 为 nil 时静默。
func NewDdosEngine(cfg config.DdosConfig, logger *slog.Logger) *DdosEngine {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &DdosEngine{
		logger:   logger,
		stats:    &DdosStats{},
		cfg:      cfg,
		trackers: make(map[netip.Addr]*ipTracker),
	}
}

// Stats 返回累计计数的可读句柄。
func (e *DdosEngine) Stats() *DdosStats { return e.stats }

// Config 返回当前配置快照（供 API 层同步 webui 与 ddos 字段）。
func (e *DdosEngine) Config() config.DdosConfig {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

// UpdateConfig 替换配置。
func (e *DdosEngine) UpdateConfig(cfg config.DdosConfig) {
	e.mu.Lock()
	e.cfg = cfg
	e.mu.Unlock()
	e.logger.Info("DDoS 决策引擎配置更新",
		"auto_ban_threshold", cfg.AutoBanThreshold,
		"auto_ban_duration", cfg.AutoBanDuration)
}

// HandleEvent 处理一次 DDoS 事件。now 由调用方注入（Unix 秒），便于测试。
func (e *DdosEngine) HandleEvent(ip netip.Addr, reason string, ratePPS uint32, now int64) {
	e.stats.EventsDetected.Add(1)

	e.mu.Lock()
	tracker, ok := e.trackers[ip]
	if !ok {
		tracker = &ipTracker{}
		tracker.lastViolation.Store(now)
		tracker.violationCount.Store(1)
		e.trackers[ip] = tracker
		e.stats.TrackedIPs.Store(uint64(len(e.trackers)))
		// 新条目已把本次计入，故只有已存在的条目才需要自增。
		e.mu.Unlock()
		e.logger.Info("DDoS 事件：内核已封禁",
			"ip", ip.String(), "reason", reason, "rate_pps", ratePPS,
			"violation_count", uint32(1), "threshold", e.threshold())
		return
	}
	count := tracker.increment(now)
	threshold := e.cfg.AutoBanThreshold
	e.mu.Unlock()

	e.logger.Info("DDoS 事件：内核已封禁",
		"ip", ip.String(), "reason", reason, "rate_pps", ratePPS,
		"violation_count", count, "threshold", threshold)
}

// threshold 返回当前的自动封禁阈值（加锁读）。
func (e *DdosEngine) threshold() uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg.AutoBanThreshold
}

// CleanupStale 回收长时间未活动的每 IP 跟踪条目，避免内存无限增长。
func (e *DdosEngine) CleanupStale(now int64) int {
	cutoff := now - int64(StaleTrackerWindow/time.Second)

	e.mu.Lock()
	defer e.mu.Unlock()

	removed := 0
	for ip, tracker := range e.trackers {
		if tracker.lastViolation.Load() < cutoff {
			delete(e.trackers, ip)
			removed++
		}
	}
	if removed > 0 {
		e.stats.TrackedIPs.Store(uint64(len(e.trackers)))
	}
	return removed
}

// TrackedIPs 返回当前跟踪的 IP 数量。
func (e *DdosEngine) TrackedIPs() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.trackers)
}
