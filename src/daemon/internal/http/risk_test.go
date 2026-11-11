// 风险事件接口的分页口径：limit/offset 下推到 SQL，total 是过滤后的全集。
//
// 旧实现把该 IP 的全部事件读进内存再截断，且 total 记的是截断后的条数——大表下
// 内存与延迟无界，面板上的「共 N 条」也永远不超过 100。这里同时钉住三件事：
// 分页真的生效、total 不随 limit/offset 变、越界参数有确定的回落行为。
package http

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/risk"
)

// riskEventsPath 从契约的注册串拼出可请求路径，避免测试里复制第二份路径。
func riskEventsPath(ip string) string {
	pattern := strings.TrimPrefix(httpcontract.RouteGetApiV2RiskEventsIp, "GET ")
	return strings.Replace(pattern, "{ip}", ip, 1)
}

// seedRiskEvents 写入 count 条事件，occurred_at 递增，id 与写入顺序一致。
func seedRiskEvents(t *testing.T, db *persist.DB, ip string, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		if err := db.InsertEvent(ip, risk.EventFailure, 1, 1000+int64(i)); err != nil {
			t.Fatalf("写事件失败: %v", err)
		}
	}
}

// TestRiskEventsPaginatesAndReportsFullTotal 是 M-34 的行为断言。
func TestRiskEventsPaginatesAndReportsFullTotal(t *testing.T) {
	db := newAnalysisDB(t, "risk-events.db")
	const ip = "203.0.113.30"
	seedRiskEvents(t, db, ip, 130)
	// 另一个 IP 的事件不能混进过滤后的总数。
	seedRiskEvents(t, db, "203.0.113.31", 3)

	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.DB = db })
	base := riskEventsPath(ip)

	// 默认页：最多 100 条，按时间降序（最新的是 id=130）。
	first := get[RiskEventResponse](t, s, base)
	if first.Total != 130 {
		t.Errorf("默认页 total = %d，期望该 IP 的全部 130 条", first.Total)
	}
	if len(first.Events) != 100 {
		t.Fatalf("默认页返回 %d 条，期望上限 100 条", len(first.Events))
	}
	if first.Events[0].ID != 130 || first.Events[99].ID != 31 {
		t.Errorf("默认页首尾 id = %d/%d，期望 130/31（按时间降序）",
			first.Events[0].ID, first.Events[99].ID)
	}

	// limit 超上限回落默认值：不能把 131 条一次性拉出来。
	capped := get[RiskEventResponse](t, s, base+"?limit=100000")
	if capped.Total != 130 || len(capped.Events) != 100 {
		t.Errorf("limit=100000 的 total/条数 = %d/%d，期望 130/100（上限校验）",
			capped.Total, len(capped.Events))
	}

	// offset 真正跳过前面的条数，且 total 不随分页变化。
	tail := get[RiskEventResponse](t, s, base+"?limit=10&offset=125")
	if tail.Total != 130 {
		t.Errorf("offset=125 的 total = %d，期望仍是全集 130", tail.Total)
	}
	if len(tail.Events) != 5 || tail.Events[0].ID != 5 || tail.Events[4].ID != 1 {
		t.Errorf("offset=125 的页 = %d 条，首尾 %d/%d，期望 5 条、首尾 5/1",
			len(tail.Events), tail.Events[0].ID, tail.Events[len(tail.Events)-1].ID)
	}

	// offset 超界：空页、total 仍是全集，且 events 是 [] 而不是 null。
	beyond := authedGet(t, s, base+"?offset=999")
	if !bytes.Contains(beyond.Body.Bytes(), []byte(`"events":[]`)) {
		t.Errorf("offset=999 的 events 不是空数组: %s", beyond.Body)
	}
	if got := get[RiskEventResponse](t, s, base+"?offset=999"); got.Total != 130 || len(got.Events) != 0 {
		t.Errorf("offset=999 的 total/条数 = %d/%d，期望 130/0", got.Total, len(got.Events))
	}

	// 负 offset 与垃圾 offset 按 0 处理：契约没有参数非法的失败码，只能读第一页。
	negative := get[RiskEventResponse](t, s, base+"?offset=-5")
	if len(negative.Events) != 100 || negative.Events[0].ID != 130 {
		t.Errorf("offset=-5 的页 = %d 条，首条 id=%d，期望按第一页读", len(negative.Events), negative.Events[0].ID)
	}
	if junk := get[RiskEventResponse](t, s, base+"?offset=abc"); len(junk.Events) != 100 {
		t.Errorf("offset=abc 的页 = %d 条，期望按第一页读", len(junk.Events))
	}
}

// 列表的 total 是表内全集条数，不是本页条数：面板上「共 N 个地址」必须与库一致，
// 不能恒等于 100。limit 仍按契约的固定上限返回 100 条（契约没有 limit/offset 参数）。
func TestListRiskVectorsReportsFullTotal(t *testing.T) {
	db := newAnalysisDB(t, "risk-vectors-list.db")
	const total = 130
	for i := 0; i < total; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		if err := db.UpsertRiskVector(ip, risk.RiskVector{Failure: float64(i + 1)}, 1000+int64(i)); err != nil {
			t.Fatalf("写向量 %s 失败: %v", ip, err)
		}
	}

	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.DB = db })
	path := strings.TrimPrefix(httpcontract.RouteGetApiV2RiskVectors, "GET ")
	got := get[RiskVectorListResponse](t, s, path)

	if got.Total != total {
		t.Errorf("total = %d，期望表内全集 %d", got.Total, total)
	}
	if len(got.Vectors) != 100 {
		t.Errorf("返回 %d 条，期望上限 100 条", len(got.Vectors))
	}
}
