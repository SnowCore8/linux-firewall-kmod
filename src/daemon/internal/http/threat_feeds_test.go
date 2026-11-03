// 威胁情报源三个端点的行为核对（GET /api/v2/threat-feeds、POST …/sync、GET …/:id）。
//
// 这一面钉住三件容易走样事：
//   - 管理器缺席（threat_feeds.enabled=false 或装配失败）时如实报 503/50003，
//     不回一个「看起来正常」的空列表——空列表会让面板显示「情报系统正常，0 个源」；
//   - 载荷字段与契约 ThreatFeedResponse 对齐：静态字段来自配置、动态字段来自源统计，
//     从未同步过的源 last_synced_at 是 null 而不是 0；
//   - 同步是异步触发：应答给触发时刻与全量 feed_id，不拿旧读数冒充本次结果。
package http

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/threatfeeds"
)

// newTestFeedManager 建一个不触网的情报管理器：两个源都指向 .invalid（DNS 必败），
// 构造与 Stats 不需要网络，测试里也从不等待刷新完成。
func newTestFeedManager(t *testing.T) *threatfeeds.FeedManager {
	t.Helper()
	mgr, err := threatfeeds.NewFeedManager(threatfeeds.Config{
		Enabled:         true,
		RefreshInterval: time.Hour,
		HTTPTimeout:     50 * time.Millisecond,
		MaxRetries:      1,
		Sources: []threatfeeds.SourceConfig{
			{Name: "ipsum", URL: "https://fw-test.invalid/ipsum.txt", Enabled: true, Category: "abuse", Confidence: 0.8},
			{Name: "firehol_level1", URL: "https://fw-test.invalid/firehol.netset", Enabled: false, Category: "abuse", Confidence: 0.85},
		},
	})
	if err != nil {
		t.Fatalf("建测试情报管理器失败: %v", err)
	}
	if mgr == nil {
		t.Fatal("Enabled=true 时 NewFeedManager 返回 nil")
	}
	t.Cleanup(mgr.Stop)
	return mgr
}

func feedServer(t *testing.T, mgr *threatfeeds.FeedManager) *Server {
	t.Helper()
	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.ThreatFeeds = mgr })
	return s
}

// TestThreatFeedsUnavailableWithoutManager 核对管理器缺席时三个端点都报 503/50003。
func TestThreatFeedsUnavailableWithoutManager(t *testing.T) {
	s, _ := newTestServer(t, nil) // cfg.ThreatFeeds 为 nil

	w := authedGet(t, s, analysisPath(httpcontract.RouteGetApiV2ThreatFeeds))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("列表状态码 %d，期望 503（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}
	if got := envelopeCode(t, decodeEnvelope(t, w.Body.Bytes())); got != httpcontract.Code50003 {
		t.Errorf("列表信封 code = %d，期望 %d", got, httpcontract.Code50003)
	}

	w = authedSend(t, s, http.MethodPost,
		strings.TrimPrefix(httpcontract.RoutePostApiV2ThreatFeedsSync, "POST "), "", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("同步状态码 %d，期望 503（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}

	w = authedGet(t, s, "/api/v2/threat-feeds/ipsum")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("详情状态码 %d，期望 503（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}
}

// TestThreatFeedsListMatchesConfig 核对列表载荷：静态字段抄配置、动态字段报「从未同步」。
func TestThreatFeedsListMatchesConfig(t *testing.T) {
	s := feedServer(t, newTestFeedManager(t))

	w := authedGet(t, s, analysisPath(httpcontract.RouteGetApiV2ThreatFeeds))
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}
	var list ThreatFeedListResponse
	if err := json.Unmarshal(unwrapData(t, w.Body.Bytes()), &list); err != nil {
		t.Fatalf("载荷解码失败: %v（body=%s）", err, w.Body)
	}
	if list.Total != 2 || len(list.Feeds) != 2 {
		t.Fatalf("列表 = %d 条 / total %d，期望配置里的 2 个源", len(list.Feeds), list.Total)
	}

	byID := map[string]ThreatFeedResponse{}
	for _, f := range list.Feeds {
		byID[f.ID] = f
	}
	ipsum, ok := byID["ipsum"]
	if !ok {
		t.Fatalf("列表里没有 ipsum: %v", list.Feeds)
	}
	if ipsum.Name != "ipsum" || ipsum.SourceURL != "https://fw-test.invalid/ipsum.txt" ||
		ipsum.Category != "abuse" || ipsum.Confidence != 0.8 || !ipsum.Enabled {
		t.Errorf("ipsum 静态字段 = %+v，期望与配置一致", ipsum)
	}
	// 从未同步：last_synced_at 是 null（Option 缺席），不是 0 时刻。
	raw := decodeEnvelope(t, w.Body.Bytes())["data"]
	if !strings.Contains(string(raw), `"last_synced_at":null`) {
		t.Errorf("从未同步的源 last_synced_at 不是 null: %s", truncate(raw))
	}
	if ipsum.SyncStatus != "never" || ipsum.EntryCount != 0 || ipsum.LastError != nil {
		t.Errorf("ipsum 动态字段 = status %q / entries %d / err %v，期望 never/0/null",
			ipsum.SyncStatus, ipsum.EntryCount, ipsum.LastError)
	}
	// 禁用的源也在列表里（enabled=false），面板要能显示「配了但没开」。
	if firehol, ok := byID["firehol_level1"]; !ok || firehol.Enabled {
		t.Errorf("firehol_level1 = %+v（在场=%v），期望在场且 enabled=false", firehol, ok)
	}
}

// TestThreatFeedByID 核对详情端点：按 id 命中给单个对象，未命中给 404。
func TestThreatFeedByID(t *testing.T) {
	s := feedServer(t, newTestFeedManager(t))

	feed := get[ThreatFeedResponse](t, s, "/api/v2/threat-feeds/ipsum")
	if feed.ID != "ipsum" || feed.SourceURL != "https://fw-test.invalid/ipsum.txt" {
		t.Errorf("详情 = %+v，期望 ipsum 那条配置", feed)
	}

	w := authedGet(t, s, "/api/v2/threat-feeds/nonexistent")
	if w.Code != http.StatusNotFound {
		t.Errorf("未命中状态码 %d，期望 404（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}
	if got := envelopeCode(t, decodeEnvelope(t, w.Body.Bytes())); got != httpcontract.Code404 {
		t.Errorf("未命中信封 code = %d，期望 %d", got, httpcontract.Code404)
	}
}

// TestThreatFeedsSyncTrigger 核对同步端点：应答即触发结论，计数如实为 0。
func TestThreatFeedsSyncTrigger(t *testing.T) {
	s := feedServer(t, newTestFeedManager(t))

	before := time.Now().Unix()
	w := authedSend(t, s, http.MethodPost,
		strings.TrimPrefix(httpcontract.RoutePostApiV2ThreatFeedsSync, "POST "), "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}
	if got := envelopeCode(t, decodeEnvelope(t, w.Body.Bytes())); got != 0 {
		t.Fatalf("信封 code = %d，期望 0", got)
	}
	var result ThreatFeedSyncResult
	if err := json.Unmarshal(unwrapData(t, w.Body.Bytes()), &result); err != nil {
		t.Fatalf("载荷解码失败: %v（body=%s）", err, w.Body)
	}
	// 全量触发：feed_id 报 "all"；后台刷新还没跑完，计数不拿旧读数冒充。
	if result.FeedID != "all" {
		t.Errorf("feed_id = %q，期望 all（这条路由触发的是全部启用源）", result.FeedID)
	}
	if result.NewEntries != 0 || result.UpdatedEntries != 0 {
		t.Errorf("计数 = %d/%d，异步触发时期望 0/0", result.NewEntries, result.UpdatedEntries)
	}
	if result.SyncedAt < before || result.SyncedAt > time.Now().Unix() {
		t.Errorf("synced_at = %d，期望落在请求时刻附近", result.SyncedAt)
	}
}
