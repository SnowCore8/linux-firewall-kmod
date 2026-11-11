// 白名单推荐的阈值口径：min_bans 判的是**网段合计**，不是单个地址。
//
// 这个区别在旧实现里看不出来：先按 IP 次数过滤再聚合，聚合结果里永远只有「本身
// 就高频」的地址所在的网段，而按网段加白的意义恰恰在于「单个地址都不算高频，合起来
// 才高频」。所以这里的用例特意让每个 IP 都不达标、合计却达标。
package http

import (
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// TestWhitelistRecommendationsThresholdAppliesAfterSubnetAggregation 是 M-33 的行为断言。
func TestWhitelistRecommendationsThresholdAppliesAfterSubnetAggregation(t *testing.T) {
	db := newAnalysisDB(t, "recommend-aggregate.db")
	record := func(ip string, n int) {
		for i := 0; i < n; i++ {
			if _, err := db.RecordBanHistory(ip, false); err != nil {
				t.Fatalf("写封禁历史失败: %v", err)
			}
		}
	}
	// 同一 /24 里 4 个地址各 2 次：单 IP 都够不到默认阈值 5，合计 8 次。
	record("198.51.100.11", 2)
	record("198.51.100.12", 2)
	record("198.51.100.13", 2)
	record("198.51.100.14", 2)
	// 同一 /48 里 2 个地址各 3 次：同样单 IP 不达标，合计 6 次。
	record("2001:db8:2::11", 3)
	record("2001:db8:2::12", 3)
	// 对照：单地址 4 次，落在阈值之下，不该单独成为推荐。
	record("192.0.2.50", 4)

	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.DB = db })

	recs := get[[]WhitelistRecommendation](t,
		s, analysisPath(httpcontract.RouteGetApiV2WhitelistRecommendations))
	if len(recs) != 2 {
		t.Fatalf("推荐 %d 条，期望 2 条（/24 合计 8 次、/48 合计 6 次）: %+v", len(recs), recs)
	}
	if recs[0].CIDR != "198.51.100.0/24" || recs[0].TotalBans != 8 || recs[0].AffectedIPs != 4 {
		t.Errorf("第一条 = %+v，期望 198.51.100.0/24 / 8 次 / 4 个地址", recs[0])
	}
	if recs[1].CIDR != "2001:db8:2::/48" || recs[1].TotalBans != 6 || recs[1].AffectedIPs != 2 {
		t.Errorf("第二条 = %+v，期望 2001:db8:2::/48 / 6 次 / 2 个地址", recs[1])
	}

	// 阈值抬到网段合计之上：聚合结果照样被滤掉，而不是被 IP 级过滤顺手放大。
	strict := get[[]WhitelistRecommendation](t,
		s, analysisPath(httpcontract.RouteGetApiV2WhitelistRecommendations)+"?min_bans=7")
	if len(strict) != 1 || strict[0].CIDR != "198.51.100.0/24" {
		t.Errorf("min_bans=7 的推荐 = %+v，期望只剩合计 8 次的那条", strict)
	}
}
