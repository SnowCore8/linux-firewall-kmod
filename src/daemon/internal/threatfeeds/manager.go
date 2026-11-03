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
type FeedManager struct {
	cfg       Config
	sources   []FeedSource
	cache     *FeedCache
	scheduler *Scheduler
	http      *HTTPClient

	mu         sync.RWMutex
	lastUpdate time.Time
	errors     map[string]error // 每个源的最新错误
	stats      map[string]*SourceStats

	ctx    context.Context
	cancel context.CancelFunc
}

// SourceStats 是单个源的统计信息。
type SourceStats struct {
	Name         string
	Enabled      bool
	LastUpdate   time.Time
	EntryCount   int
	Error        error
	RefreshCount uint64
	ErrorCount   uint64
}

// NewFeedManager 创建新的情报管理器。
func NewFeedManager(cfg Config) (*FeedManager, error) {
	if !cfg.Enabled {
		return nil, nil // 未启用时返回 nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	mgr := &FeedManager{
		cfg:       cfg,
		cache:     NewFeedCache(),
		http:      NewHTTPClient(cfg.HTTPTimeout, cfg.MaxRetries),
		errors:    make(map[string]error),
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
		return sources.NewFireHOLSource(cfg.URL, cfg.Category, cfg.Confidence), nil
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

// RefreshAll 并发刷新所有源。
func (m *FeedManager) RefreshAll(ctx context.Context) error {
	if len(m.sources) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	results := make(chan RefreshResult, len(m.sources))

	for _, src := range m.sources {
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
	for result := range results {
		m.updateSourceStats(result)
		if result.Err != nil {
			slog.Warn("情报源刷新失败", "source", result.Source, "error", result.Err)
			if firstErr == nil {
				firstErr = result.Err
			}
			continue
		}
		m.cache.Merge(result.Entries)
		slog.Info("情报源刷新成功", "source", result.Source, "entries", len(result.Entries), "duration", result.Duration)
	}

	m.mu.Lock()
	m.lastUpdate = time.Now()
	m.mu.Unlock()

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

// updateSourceStats 更新源统计信息。
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
	} else {
		stats.Error = nil
		stats.LastUpdate = time.Now()
		stats.EntryCount = len(result.Entries)
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
