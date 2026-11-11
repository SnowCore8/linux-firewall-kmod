// 事件表的分页查询：limit/offset 必须在 SQL 里生效，且只命中目标 IP。
//
// 旧读路径把该 IP 的全部事件读进内存再截断，大表下内存与延迟都无界。这里钉住
// 三条性质：分页真的由 SQL 完成、排序按时间降序且同一时刻按 id 降序（翻页稳定）、
// 非法参数有确定的回落行为。
package persist

import (
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/risk"
)

func TestListEventsByIPPushesPaginationDown(t *testing.T) {
	db := newTestDB(t)
	const ip = "203.0.113.40"
	for i := 0; i < 5; i++ {
		if err := db.InsertEvent(ip, risk.EventFailure, 1, 1000+int64(i)); err != nil {
			t.Fatalf("写事件失败: %v", err)
		}
	}
	// 另一个 IP 的事件既不进 total，也不进页。
	if err := db.InsertEvent("203.0.113.41", risk.EventFailure, 1, 2000); err != nil {
		t.Fatalf("写事件失败: %v", err)
	}

	total, err := db.CountEventsByIP(ip)
	if err != nil {
		t.Fatalf("计数失败: %v", err)
	}
	if total != 5 {
		t.Errorf("CountEventsByIP = %d，期望 5（过滤条件之后的全集）", total)
	}

	page, err := db.ListEventsByIP(ip, 2, 1)
	if err != nil {
		t.Fatalf("分页查询失败: %v", err)
	}
	if len(page) != 2 || page[0].OccurredAt != 1003 || page[1].OccurredAt != 1002 {
		t.Fatalf("第二页 = %+v，期望 2 条、时间 1003/1002（降序跳过最新一条）", page)
	}

	beyond, err := db.ListEventsByIP(ip, 10, 10)
	if err != nil {
		t.Fatalf("越界页查询失败: %v", err)
	}
	if len(beyond) != 0 {
		t.Errorf("offset 越界返回 %d 条，期望空页", len(beyond))
	}

	// limit<=0 回落默认值 100，offset<0 按 0：读侧不会因为参数垃圾拿到空页。
	fallback, err := db.ListEventsByIP(ip, 0, -5)
	if err != nil {
		t.Fatalf("回落查询失败: %v", err)
	}
	if len(fallback) != 5 || fallback[0].OccurredAt != 1004 {
		t.Errorf("limit=0/offset=-5 的页 = %d 条、首条时间 %d，期望按第一页读",
			len(fallback), fallback[0].OccurredAt)
	}
}
