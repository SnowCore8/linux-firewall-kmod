// 手工与批量封禁的 DB 记账：两条路径都要扣信誉分（与自动路径同一个常量）。
//
// 漏掉这一步的地址在 ip_reputation 里没有 last_ban、total_bans 停在 0、分数居高不下，
// 下一次自动判定读到的就是「这个 IP 从没被封过、信誉很好」，渐进时长与低信誉阈值都会算错。
package http

import (
	"net/http"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

// TestCreateBanRecordsReputationPenalty 用真实临时 SQLite 核对单条封禁确实扣分。
//
// 预置一个已知分数（80）而不是查「新建条目的默认分」，是为了分辨「扣了分」与「只是建了
// 一条记录」——后者同样能让 GetIPReputation 返回非空。
func TestCreateBanRecordsReputationPenalty(t *testing.T) {
	const ip = "203.0.113.61"
	db := newAnalysisDB(t, "bans-create.db")
	if err := db.SetIPReputation(ip, 80); err != nil {
		t.Fatalf("预置信誉分失败: %v", err)
	}

	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.DB = db })
	t.Cleanup(func() { removeBanForTest(ip) })

	w := authedSend(t, s, http.MethodPost, "/api/v2/bans", "application/json", `{"ip":"`+ip+`"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /bans 状态码 %d，期望 201（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}

	rep, err := db.GetIPReputation(ip)
	if err != nil {
		t.Fatalf("读取信誉分失败: %v", err)
	}
	if rep == nil {
		t.Fatalf("手工封禁后 %s 在 ip_reputation 里没有记录", ip)
	}
	if want := 80 - persist.DefaultBanPenalty; rep.Score != want {
		t.Errorf("score = %d，期望 %d（预置 80 扣掉一次 ban 扣分）", rep.Score, want)
	}
	if rep.TotalBans != 1 {
		t.Errorf("total_bans = %d，期望 1", rep.TotalBans)
	}
	if rep.LastBan == nil {
		t.Error("last_ban 为空，手工封禁没有写进信誉表")
	}
}

// TestBatchBanRecordsReputationPenalty 核对批量路径逐条扣分：失败的那几条（这里没有）
// 不该扣分，成功下发的每一条都要有记录。
func TestBatchBanRecordsReputationPenalty(t *testing.T) {
	ips := []string{"203.0.113.62", "203.0.113.63"}
	db := newAnalysisDB(t, "bans-batch.db")

	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.DB = db })
	t.Cleanup(func() {
		for _, ip := range ips {
			removeBanForTest(ip)
		}
	})

	w := authedSend(t, s, http.MethodPost, "/api/v2/bans/batch", "application/json",
		`{"ips":["203.0.113.62","203.0.113.63"],"duration":600}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /bans/batch 状态码 %d，期望 201（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}

	for _, ip := range ips {
		rep, err := db.GetIPReputation(ip)
		if err != nil {
			t.Fatalf("读取 %s 的信誉分失败: %v", ip, err)
		}
		if rep == nil {
			t.Fatalf("批量封禁后 %s 在 ip_reputation 里没有记录", ip)
		}
		if want := 100 - persist.DefaultBanPenalty; rep.Score != want {
			t.Errorf("%s score = %d，期望 %d（新建 100 扣一次 ban 扣分）", ip, rep.Score, want)
		}
		if rep.TotalBans != 1 {
			t.Errorf("%s total_bans = %d，期望 1", ip, rep.TotalBans)
		}
	}
}
