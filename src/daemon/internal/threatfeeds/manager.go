package threatfeeds

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/threatfeeds/sources"
)

// FeedEntry 是情报条目（从 sources 包别名导入以避免循环）。
type FeedEntry = sources.FeedEntry

// FeedSource 定义情报源接口。
type FeedSource = sources.FeedSource

// FeedManager 管理所有情报源的拉取、解析、聚合与缓存。
//
// 设计目标：
//   - 并发拉取：多个源并行刷新，总耗时取最慢源
//   - 错误隔离：单个源失败不影响其他源
//   - 性能隔离：刷新在后台 goroutine，不阻塞主判定链路
//   - 可观测：每个源的状态、错误、条目数可查询
//   - 熔断器：连续失败超过阈值的源自动暂停刷新，冷却期后恢复
type FeedManager struct {
	cfg       Config
	sources   []FeedSource
	cache     *FeedCache
	scheduler *Scheduler
	http      *HTTPClient

	mu         sync.RWMutex
	lastUpdate time.Time
	stats      map[string]*SourceStats

	ctx    context.Context
	cancel context.CancelFunc
}

// SourceStats 是单个源的统计信息。
type SourceStats struct {
	Name                string
	Enabled             bool
	LastUpdate          time.Time
	EntryCount          int
	Error               error
	RefreshCount        uint64
	ErrorCount          uint64
	ConsecutiveFailures int
	CircuitBrokenUntil  time.Time
}

// NewFeedManager 创建新的情报管理器。
func NewFeedManager(cfg Config) (*FeedManager, error) {
	if !cfg.Enabled {
		return nil, nil // 未启用时返回 nil
	}

	// 熔断器默认值兜底：配置未给出时使用合理默认
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 3
	}
	if cfg.CooldownDuration <= 0 {
		cfg.CooldownDuration = 1 * time.Hour
	}

	ctx, cancel := context.WithCancel(context.Background())

	mgr := &FeedManager{
		cfg:       cfg,
		cache:     NewFeedCache(),
		http:      NewHTTPClient(cfg.HTTPTimeout, cfg.MaxRetries),
		stats:     make(map[string]*SourceStats),
		ctx:       ctx,
		cancel:    cancel,
		scheduler: NewScheduler(cfg.RefreshInterval, 30*time.Minute), // 30 分钟抖动
	}

	// 构建源适配器
	for _, srcCfg := range cfg.Sources {
		if !srcCfg.Enabled {
			continue
		}
		src, err := mgr.buildSource(srcCfg)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("构建源 %s 失败: %w", srcCfg.Name, err)
		}
		mgr.sources = append(mgr.sources, src)
		mgr.stats[srcCfg.Name] = &SourceStats{
			Name:    srcCfg.Name,
			Enabled: true,
		}
	}

	return mgr, nil
}

// buildSource 根据配置构建源适配器。
func (m *FeedManager) buildSource(cfg SourceConfig) (FeedSource, error) {
	switch cfg.Name {
	case "ipsum":
		return sources.NewIpsumSource(cfg.URL, cfg.Category, cfg.Confidence), nil
	case "firehol_level1", "firehol":
		return sources.NewFireHOLSource(cfg.Name, cfg.URL, cfg.Category, cfg.Confidence), nil
	case "dshield":
		return sources.NewDShieldSource(cfg.URL, cfg.Category, cfg.Confidence), nil
	case "blocklist_de":
		return sources.NewBlocklistSource(cfg.URL, cfg.Category, cfg.Confidence), nil
	case "feodo":
		return sources.NewFeodoSource(cfg.URL, cfg.Category, cfg.Confidence), nil
	default:
		return nil, fmt.Errorf("未知的情报源: %s", cfg.Name)
	}
}

// isCircuitBroken 检查指定源是否处于熔断冷却期。
// 调用方必须持有 m.mu 的读锁或写锁。
func (m *FeedManager) isCircuitBroken(name string) bool {
	stats, ok := m.stats[name]
	if !ok {
		return false
	}
	if stats.CircuitBrokenUntil.IsZero() {
		return false
	}
	return time.Now().Before(stats.CircuitBrokenUntil)
}

// resetExpiredCircuitBreakers 清除已过冷却期的源熔断状态，使其可重新触发。
// 调用方必须持有写锁。
func (m *FeedManager) resetExpiredCircuitBreakers() {
	now := time.Now()
	for _, stats := range m.stats {
		if !stats.CircuitBrokenUntil.IsZero() && !now.Before(stats.CircuitBrokenUntil) {
			stats.CircuitBrokenUntil = time.Time{}
			stats.ConsecutiveFailures = 0
		}
	}
}

// RefreshAll 并发刷新所有源。
//
// 熔断器：调度前检查每个源的熔断状态，处于冷却期内的源跳过本轮刷新，
// 冷却期过后自动恢复尝试。
func (m *FeedManager) RefreshAll(ctx context.Context) error {
	if len(m.sources) == 0 {
		return nil
	}

	// 清除已过冷却期的熔断状态，使持续失败的源可重新触发熔断
	m.mu.Lock()
	m.resetExpiredCircuitBreakers()
	m.mu.Unlock()

	var wg sync.WaitGroup
	results := make(chan RefreshResult, len(m.sources))

	for _, src := range m.sources {
		// 熔断检查：冷却期内的源跳过刷新
		m.mu.RLock()
		broken := m.isCircuitBroken(src.Name())
		m.mu.RUnlock()

		if broken {
			slog.Debug("情报源处于熔断冷却期，跳过本轮刷新",
				"source", src.Name())
			continue
		}

		wg.Add(1)
		go func(s FeedSource) {
			defer wg.Done()
			result := m.refreshOne(ctx, s)
			results <- result
		}(src)
	}

	// 等待所有 goroutine 完成后关闭 channel
	go func() {
		wg.Wait()
		close(results)
	}()

	// 聚合结果
	var firstErr error
	hasSuccess := false
	for result := range results {
		m.updateSourceStats(result)
		if result.Err != nil {
			slog.Warn("情报源刷新失败", "source", result.Source, "error", result.Err)
			if firstErr == nil {
				firstErr = result.Err
			}
			continue
		}
		hasSuccess = true
		m.cache.Merge(result.Entries)
		slog.Info("情报源刷新成功", "source", result.Source, "entries", len(result.Entries), "duration", result.Duration)
	}

	// 仅在有源刷新成功时更新 lastUpdate，避免全失败时误导 API 消费者
	if hasSuccess {
		m.mu.Lock()
		m.lastUpdate = time.Now()
		m.mu.Unlock()
	}

	return firstErr
}

// refreshOne 刷新单个源。
func (m *FeedManager) refreshOne(ctx context.Context, src FeedSource) RefreshResult {
	start := time.Now()

	data, err := m.http.Fetch(ctx, src.URL())
	if err != nil {
		return RefreshResult{
			Source:   src.Name(),
			Err:      err,
			Duration: time.Since(start),
		}
	}

	entries, err := src.Parse(data)
	if err != nil {
		return RefreshResult{
			Source:   src.Name(),
			Err:      err,
			Duration: time.Since(start),
		}
	}

	return RefreshResult{
		Source:   src.Name(),
		Entries:  entries,
		Duration: time.Since(start),
	}
}

// updateSourceStats 更新源统计信息，包含熔断器逻辑。
//
// 成功时：ConsecutiveFailures 归零，清除冷却时间。
// 失败时：ConsecutiveFailures 累加；达到阈值时设置冷却截止时间并记录告警。
func (m *FeedManager) updateSourceStats(result RefreshResult) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats, ok := m.stats[result.Source]
	if !ok {
		return
	}

	stats.RefreshCount++
	if result.Err != nil {
		stats.Error = result.Err
		stats.ErrorCount++
		stats.ConsecutiveFailures++

		// 达到熔断阈值：设置冷却截止时间
		if stats.ConsecutiveFailures >= m.cfg.FailureThreshold && stats.CircuitBrokenUntil.IsZero() {
			stats.CircuitBrokenUntil = time.Now().Add(m.cfg.CooldownDuration)
			slog.Warn("情报源连续失败达到阈值，进入熔断冷却期",
				"source", result.Source,
				"consecutive_failures", stats.ConsecutiveFailures,
				"cooldown_until", stats.CircuitBrokenUntil,
				"cooldown_duration", m.cfg.CooldownDuration)
		}
	} else {
		stats.Error = nil
		stats.LastUpdate = time.Now()
		stats.EntryCount = len(result.Entries)
		// 成功：连续失败计数归零，清除冷却时间
		stats.ConsecutiveFailures = 0
		stats.CircuitBrokenUntil = time.Time{}
	}
}

// Lookup 查询 IP 是否在情报缓存中。
func (m *FeedManager) Lookup(ip netip.Addr) (*FeedEntry, bool) {
	return m.cache.Lookup(ip)
}

// StartScheduler 启动定时调度器。
func (m *FeedManager) StartScheduler() {
	go m.scheduler.Run(m.ctx, func() {
		if err := m.RefreshAll(m.ctx); err != nil {
			slog.Warn("定时刷新情报失败", "error", err)
		}
		// 每次刷新后清理过期缓存条目，防止源停止刷新时条目持续累积
		m.cache.Cleanup()
	})
}

// Stop 停止调度器并清理资源。
func (m *FeedManager) Stop() {
	m.scheduler.Stop()
	m.cancel()
}

// Stats 返回所有源的统计信息。
func (m *FeedManager) Stats() []SourceStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]SourceStats, 0, len(m.stats))
	for _, s := range m.stats {
		result = append(result, *s)
	}
	return result
}

// SourceConfigs 返回配置的源列表副本（API 读侧用来补 URL/分类/置信度等静态字段）。
func (m *FeedManager) SourceConfigs() []SourceConfig {
	out := make([]SourceConfig, len(m.cfg.Sources))
	copy(out, m.cfg.Sources)
	return out
}

// BackgroundContext 返回管理器的生命周期上下文：Stop 时被取消。
// 手动触发的后台刷新挂在它上面，进程关停时刷新随之收敛，而不是绑在某个请求上。
func (m *FeedManager) BackgroundContext() context.Context {
	return m.ctx
}

// CacheStats 返回缓存统计信息。
func (m *FeedManager) CacheStats() CacheStats {
	return m.cache.Stats()
}

// LastUpdate 返回上次成功更新时间。
func (m *FeedManager) LastUpdate() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastUpdate
}

// SourceCount 返回启用的源数量。
func (m *FeedManager) SourceCount() int {
	return len(m.sources)
}
