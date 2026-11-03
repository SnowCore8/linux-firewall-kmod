// Package threatfeeds 实现威胁情报源的自动拉取、解析、聚合与缓存。
//
// 设计目标：
//   - 性能隔离：情报更新不阻塞主判定链路
//   - 错误容忍：单个源失败不影响其他源
//   - 热重载：SIGHUP 触发配置重载时同步刷新情报
//   - 可观测：每个源的状态、错误、条目数可查询
package threatfeeds

import (
	"time"
)

// RefreshResult 是单个源刷新的结果。
type RefreshResult struct {
	// Source 是源名称。
	Source string
	// Entries 是解析后的情报条目。
	Entries []FeedEntry
	// Err 是刷新过程中的错误（网络、解析等）。
	Err error
	// Duration 是刷新耗时。
	Duration time.Duration
}

// FeedStats 是情报源的统计信息。
type FeedStats struct {
	// Source 是源名称。
	Source string
	// LastUpdate 是上次成功更新时间。
	LastUpdate time.Time
	// EntryCount 是当前有效条目数。
	EntryCount int
	// Error 是最新错误（nil 表示无错误）。
	Error error
	// Enabled 是该源是否启用。
	Enabled bool
}
