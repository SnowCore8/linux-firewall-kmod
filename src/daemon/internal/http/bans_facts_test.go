// 手工/批量封禁要同步判定层缓存，写库瞬时失败要进重试队列。
//
// 这两条路径不经过 runtime 的 banSink：写库和 Facts.NoteBan 都得自己做。漏掉 Facts 那段，
// 下一次自动判定仍按封禁前的次数与信誉算渐进时长；漏掉重试队列，封禁底账会在一次瞬时
// 写失败后永久缺失（封禁本身不回滚）。
package http

import (
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

// TestCreateBanSyncsFactsCache 核对单条手工封禁后判定层缓存的次数与信誉分都变了。
func TestCreateBanSyncsFactsCache(t *testing.T) {
	const ip = "203.0.113.71"
	db := newAnalysisDB(t, "bans-facts-create.db")
	facts := persist.NewFacts(db, persist.FactsOptions{Logger: discardLogger()})
	t.Cleanup(facts.Stop)

	s, _ := newTestServer(t, func(cfg *APIConfig) {
		cfg.DB = db
		cfg.Facts = facts
	})
	t.Cleanup(func() { removeBanForTest(ip) })

	addr := netip.MustParseAddr(ip)
	if got := facts.PriorBanCount(addr); got != 0 {
		t.Fatalf("封禁前 PriorBanCount = %d，期望 0", got)
	}
	if got := facts.ReputationScore(addr); got != 100 {
		t.Fatalf("封禁前信誉分 = %d，期望 100", got)
	}

	w := authedSend(t, s, http.MethodPost, "/api/v2/bans", "application/json", `{"ip":"`+ip+`"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /bans 状态码 %d，期望 201（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}

	if got := facts.PriorBanCount(addr); got != 1 {
		t.Errorf("封禁后 PriorBanCount = %d，期望 1（手工封禁没有同步缓存）", got)
	}
	if got, want := facts.ReputationScore(addr), uint32(100-persist.DefaultBanPenalty); got != want {
		t.Errorf("封禁后信誉分 = %d，期望 %d（手工封禁没有同步扣分）", got, want)
	}
}

// TestBatchBanSyncsFactsCache 核对批量路径的每一条成功下发也同步判定层缓存。
func TestBatchBanSyncsFactsCache(t *testing.T) {
	const ip = "203.0.113.72"
	db := newAnalysisDB(t, "bans-facts-batch.db")
	facts := persist.NewFacts(db, persist.FactsOptions{Logger: discardLogger()})
	t.Cleanup(facts.Stop)

	s, _ := newTestServer(t, func(cfg *APIConfig) {
		cfg.DB = db
		cfg.Facts = facts
	})
	t.Cleanup(func() { removeBanForTest(ip) })

	addr := netip.MustParseAddr(ip)
	if got := facts.PriorBanCount(addr); got != 0 {
		t.Fatalf("封禁前 PriorBanCount = %d，期望 0", got)
	}

	w := authedSend(t, s, http.MethodPost, "/api/v2/bans/batch", "application/json",
		`{"ips":["`+ip+`"],"duration":600}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /bans/batch 状态码 %d，期望 201（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}

	if got := facts.PriorBanCount(addr); got != 1 {
		t.Errorf("批量封禁后 PriorBanCount = %d，期望 1（批量路径没有同步缓存）", got)
	}
	if got, want := facts.ReputationScore(addr), uint32(100-persist.DefaultBanPenalty); got != want {
		t.Errorf("批量封禁后信誉分 = %d，期望 %d（批量路径没有同步扣分）", got, want)
	}
}

// TestCreateBanEnqueuesFailedLedgerWrites 核对写库失败时三步底账都进了重试队列。
//
// 关掉真库来制造瞬时失败，队列也是真的：Enqueue 是同步的，Len 在 POST 返回时就能读到
// 三条任务（history/event/reputation）。封禁应仍然落成 201，不因底账写失败回滚。
func TestCreateBanEnqueuesFailedLedgerWrites(t *testing.T) {
	const ip = "203.0.113.73"
	db := newAnalysisDB(t, "bans-retry.db")
	queue := persist.NewRetryQueue(db, persist.RetryQueueConfig{
		MaxSize:          10,
		Logger:           discardLogger(),
		RetryInterval:    time.Hour,
		MaxRetryInterval: time.Hour,
	})
	t.Cleanup(queue.Stop)
	if err := db.Close(); err != nil {
		t.Fatalf("关闭测试库失败: %v", err)
	}

	s, _ := newTestServer(t, func(cfg *APIConfig) {
		cfg.DB = db
		cfg.RetryQueue = queue
	})
	t.Cleanup(func() { removeBanForTest(ip) })

	w := authedSend(t, s, http.MethodPost, "/api/v2/bans", "application/json", `{"ip":"`+ip+`"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /bans 状态码 %d，期望 201（底账写失败不该回滚封禁，body=%s）", w.Code, truncate(w.Body.Bytes()))
	}
	if got := queue.Len(); got != 3 {
		t.Errorf("重试队列任务数 = %d，期望 3（history/event/reputation 各一条）", got)
	}
}
