// 趋势口径的行为锁定：契约 JailAttackTrend.trend 写的是「按近 24h 与前一日的量比较；
// 无样本记 stable」。这里刻意造出「24h 对前一日」与「24h 对 7 天日均」给出相反结论的
// 样本，防止实现再滑回后者——两种算法都能产出合法的 rising/falling/stable 字符串，
// 面板上看不出差别，只有算式本身知道答的是哪个问题。
package analysis

import (
	"testing"
	"time"
)

func TestJailTrendComparesWithPreviousDay(t *testing.T) {
	now := time.Now().Unix()
	// 两个取样点：近 24h 内（1 小时前）与前一日（30 小时前）。
	const (
		lastDay = int64(3600)
		prevDay = int64(30 * 3600)
	)

	var rows []seedRow
	seed := func(jail string, base int, offsets []int64) {
		for i, off := range offsets {
			rows = append(rows, seedRow{ip: ipAt(203, 0, base, i+1), jail: jail, at: now - off, count: 1})
		}
	}

	// 3 对 3：日环比 1.0 → stable；按 7 天日均（6/7 ≈ 0.857）算则是 3.5 → rising。
	seed("dod-stable", 60, []int64{prevDay, prevDay, prevDay, lastDay, lastDay, lastDay})
	// 4 → 1：日环比 0.25 → falling；按 7 天日均（5/7 ≈ 0.714）算则是 1.4 → stable。
	seed("dod-falling", 70, []int64{prevDay, prevDay, prevDay, prevDay, lastDay})
	// 2 → 4：日环比 2.0 → rising。
	seed("dod-rising", 80, []int64{prevDay, prevDay, lastDay, lastDay, lastDay, lastDay})
	// 前一日无样本：没有基数可比，只能记 stable。
	seed("dod-no-baseline", 90, []int64{lastDay, lastDay})

	summary, err := PredictAttacks(newSeededDB(t, rows), 15)
	if err != nil {
		t.Fatalf("预测失败: %v", err)
	}

	want := map[string]struct {
		trend   string
		bans24h int
		bans7d  int
	}{
		"dod-stable":      {"stable", 3, 6},
		"dod-falling":     {"falling", 1, 5},
		"dod-rising":      {"rising", 4, 6},
		"dod-no-baseline": {"stable", 2, 2},
	}
	if len(summary.JailTrends) != len(want) {
		t.Fatalf("趋势 %d 条，期望 %d 条: %+v", len(summary.JailTrends), len(want), summary.JailTrends)
	}
	for _, got := range summary.JailTrends {
		w, ok := want[got.JailName]
		if !ok {
			t.Errorf("出现未预期的 jail %q: %+v", got.JailName, got)
			continue
		}
		if got.Trend != w.trend || got.Bans24h != w.bans24h || got.Bans7d != w.bans7d {
			t.Errorf("%s = %q（24h %d / 7d %d），期望 %q（24h %d / 7d %d）",
				got.JailName, got.Trend, got.Bans24h, got.Bans7d,
				w.trend, w.bans24h, w.bans7d)
		}
	}
}
