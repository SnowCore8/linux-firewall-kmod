package http

import (
	"net/http"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/threatfeeds"
)

// ThreatFeedResponse 是单个威胁情报源的读侧视图（契约 type ThreatFeedResponse）。
//
// 静态字段（URL/分类/置信度）来自配置，动态字段（同步时刻/条目数/错误）来自 FeedManager
// 的源统计——两边按源名对齐，配置里有而统计缺席的源按「从未同步」给出。
type ThreatFeedResponse struct {
	ID                  string  `json:"id"`
	Name                string  `json:"name"`
	SourceURL           string  `json:"source_url"`
	Enabled             bool    `json:"enabled"`
	Category            string  `json:"category"`
	Confidence          float64 `json:"confidence"`
	LastSyncedAt        *int64  `json:"last_synced_at"`
	EntryCount          uint32  `json:"entry_count"`
	SyncStatus          string  `json:"sync_status"`
	LastError           *string `json:"last_error"`
	ConsecutiveFailures uint32  `json:"consecutive_failures"`
	CircuitBrokenUntil  *int64  `json:"circuit_broken_until"`
}

// ThreatFeedListResponse 是情报源列表载荷（GET /api/v2/threat-feeds）。
type ThreatFeedListResponse struct {
	Feeds []ThreatFeedResponse `json:"feeds"`
	Total uint32               `json:"total"`
}

// ThreatFeedSyncResult 是手动同步的应答（POST /api/v2/threat-feeds/sync）。
//
// 同步在后台执行，应答时计数尚不可知：new_entries/updated_entries 如实给 0，
// feed_id 用 "all" 表示这次触发覆盖全部启用源——不拿旧读数冒充本次结果。
type ThreatFeedSyncResult struct {
	FeedID         string `json:"feed_id"`
	NewEntries     uint32 `json:"new_entries"`
	UpdatedEntries uint32 `json:"updated_entries"`
	SyncedAt       int64  `json:"synced_at"`
}

// ListThreatFeeds 处理 GET /api/v2/threat-feeds
// 返回所有威胁情报源的列表及其同步状态。
func (h *APIHandlers) ListThreatFeeds(w http.ResponseWriter, r *http.Request) {
	if h.threatFeeds == nil {
		WriteServiceUnavailable(w, "threat feed subsystem not initialized")
		return
	}

	feeds := h.threatFeedViews()
	WriteSuccess(w, ThreatFeedListResponse{Feeds: feeds, Total: uint32(len(feeds))})
}

// SyncThreatFeed 处理 POST /api/v2/threat-feeds/sync
// 手动触发一次威胁情报同步。
func (h *APIHandlers) SyncThreatFeed(w http.ResponseWriter, r *http.Request) {
	if h.threatFeeds == nil {
		WriteServiceUnavailable(w, "threat feed subsystem not initialized")
		return
	}

	// 触发同步（异步执行）。RefreshAll 自带每源错误隔离，失败落在源统计里由读侧报出。
	go func() {
		_ = h.threatFeeds.RefreshAll(h.threatFeeds.BackgroundContext())
	}()

	WriteSuccess(w, ThreatFeedSyncResult{
		FeedID:   "all",
		SyncedAt: time.Now().Unix(),
	})
}

// GetThreatFeed 处理 GET /api/v2/threat-feeds/{id}
// 返回单个威胁情报源的详情。
func (h *APIHandlers) GetThreatFeed(w http.ResponseWriter, r *http.Request) {
	if h.threatFeeds == nil {
		WriteServiceUnavailable(w, "threat feed subsystem not initialized")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		WriteCode(w, httpcontract.Code40006, "missing feed id")
		return
	}

	for _, feed := range h.threatFeedViews() {
		if feed.ID == id {
			WriteSuccess(w, feed)
			return
		}
	}

	WriteCode(w, httpcontract.Code404, "feed not found")
}

// threatFeedViews 把配置里的源与运行时统计对齐成契约载荷。
func (h *APIHandlers) threatFeedViews() []ThreatFeedResponse {
	statsByName := map[string]threatfeeds.SourceStats{}
	for _, s := range h.threatFeeds.Stats() {
		statsByName[s.Name] = s
	}

	feeds := make([]ThreatFeedResponse, 0, len(h.threatFeeds.SourceConfigs()))
	for _, src := range h.threatFeeds.SourceConfigs() {
		view := ThreatFeedResponse{
			ID:         src.Name,
			Name:       src.Name,
			SourceURL:  src.URL,
			Enabled:    src.Enabled,
			Category:   src.Category,
			Confidence: src.Confidence,
			SyncStatus: "never",
		}
		if stats, ok := statsByName[src.Name]; ok {
			if !stats.LastUpdate.IsZero() {
				synced := stats.LastUpdate.Unix()
				view.LastSyncedAt = &synced
				view.SyncStatus = "ok"
			}
			if stats.EntryCount > 0 {
				view.EntryCount = uint32(stats.EntryCount)
			}
			if stats.Error != nil {
				msg := stats.Error.Error()
				view.LastError = &msg
				view.SyncStatus = "error"
			}
			view.ConsecutiveFailures = uint32(stats.ConsecutiveFailures)
			if !stats.CircuitBrokenUntil.IsZero() {
				until := stats.CircuitBrokenUntil.Unix()
				view.CircuitBrokenUntil = &until
			}
		}
		feeds = append(feeds, view)
	}
	return feeds
}
