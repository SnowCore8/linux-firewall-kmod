// 分析窗口的截断口径：时间条件必须进 SQL，不能「先取最近 1 万条、再在内存里按时间筛」。
//
// 事件总量超过 1 万后，旧形状只能看到最近 1 万条——7/30 天窗口的统计因此系统性偏低，
// 而且没有任何截断标记。这里直插 1 万条以上的窗口内样本与窗口外的老样本，钉住两件事：
// 窗口内的样本一条都不能少，窗口外的老数据一条都不能进来。
package analysis

import (
	"testing"
	"time"
)

func TestAnalysisWindowsExceedEventLimitAndExcludeOldRows(t *testing.T) {
	now := time.Now().Unix()

	const (
		inWindowBans = 10050 // 超过旧实现的 10000 条截断线
		ancientBans  = 8000  // 落在 7/30 天窗口之外
	)
	rows := make([]seedRow, 0, inWindowBans+ancientBans+5)

	// 窗口内：sshd 每个地址封一次，全部发生在 1 小时前。
	for i := 0; i < inWindowBans; i++ {
		rows = append(rows, seedRow{
			ip:    ipAt(10, 0, i/256, i%256),
			jail:  "sshd",
			at:    now - 3600,
			count: 1,
		})
	}

	// 预测样本：同一地址三次等间隔封禁（1 小时一次），用于确认按地址聚合仍完整。
	for i := 0; i < 3; i++ {
		rows = append(rows, seedRow{
			ip:    ipAt(10, 200, 0, 1),
			jail:  "cron",
			at:    now - int64(3-i)*3600,
			count: 1,
		})
	}

	// 窗口外：40 天前的老封禁，若被并进 7/30 天窗口会改变总数与复发读数。
	for i := 0; i < ancientBans; i++ {
		rows = append(rows, seedRow{
			ip:    ipAt(172, 16, i/256, i%256),
			jail:  "ancient",
			at:    now - 40*86400,
			count: 1,
		})
	}
	// 窗口外的复发样本：若窗口条件失效，ancient 会作为复发 jail 出现在时长建议里。
	rows = append(rows,
		seedRow{ip: ipAt(172, 16, 9, 9), jail: "ancient", at: now - 41*86400, count: 1},
		seedRow{ip: ipAt(172, 16, 9, 9), jail: "ancient", at: now - 40*86400, count: 2},
	)

	db := newSeededDB(t, rows)

	// 阈值建议：近 7 天的封禁数必须是完整的 10050，而不是被截成 10000。
	thresholds, err := RecommendThresholds(db, map[string]int{"sshd": 5})
	if err != nil {
		t.Fatalf("阈值建议失败: %v", err)
	}
	var sshd *ThresholdFinding
	for i := range thresholds {
		if thresholds[i].JailName == "sshd" {
			sshd = &thresholds[i]
		}
		if thresholds[i].JailName == "ancient" {
			t.Errorf("40 天前的 ancient 事件进入了 7 天阈值窗口: %+v", thresholds[i])
		}
	}
	if sshd == nil {
		t.Fatalf("阈值建议里没有 sshd: %+v", thresholds)
	}
	if sshd.TotalBans != inWindowBans || sshd.UniqueIPs != inWindowBans {
		t.Errorf("sshd 近 7 天 = %d 条 / %d 个地址，期望 %d/%d（窗口内样本不得被截断）",
			sshd.TotalBans, sshd.UniqueIPs, inWindowBans, inWindowBans)
	}

	// 时长建议：30 天窗口，窗口外的 ancient 不得出现。
	durations, err := RecommendBanDurations(db, map[string]int64{"sshd": 3600})
	if err != nil {
		t.Fatalf("时长建议失败: %v", err)
	}
	for _, d := range durations {
		if d.JailName == "ancient" {
			t.Errorf("40 天前的 ancient 复发样本进入了 30 天时长窗口: %+v", d)
		}
	}

	// 网络分布：7 天窗口的总封禁数 = 10050 + 3，且窗口外的 172.16.0.0/24 不出现。
	dist, err := AnalyzeNetworkDistribution(db, 7, 500)
	if err != nil {
		t.Fatalf("网络分布失败: %v", err)
	}
	var total int
	for _, d := range dist {
		total += d.TotalBans
		if d.Subnet == "172.16.0.0/24" {
			t.Errorf("窗口外的网段进入了 7 天网络分布: %+v", d)
		}
	}
	if want := inWindowBans + 3; total != want {
		t.Errorf("7 天网络分布总封禁 = %d，期望 %d（窗口内样本不得被截断）", total, want)
	}

	// 预测：按地址聚合，等间隔地址仍应得到 3 次事件的完整样本。
	summary, err := PredictAttacks(db, 15)
	if err != nil {
		t.Fatalf("预测失败: %v", err)
	}
	found := false
	for _, p := range summary.Predictions {
		if p.IP == ipAt(10, 200, 0, 1) {
			found = true
			if p.EventCount != 3 {
				t.Errorf("等间隔地址事件数 = %d，期望 3", p.EventCount)
			}
			if p.MedianPeriod != 3600 {
				t.Errorf("等间隔地址中位间隔 = %v，期望 3600", p.MedianPeriod)
			}
		}
	}
	if !found {
		t.Errorf("预测结果里没有 %s: %+v", ipAt(10, 200, 0, 1), summary.Predictions)
	}
	// 7 天窗口只会留下 sshd 与 cron；ancient 不在窗口内。
	for _, tr := range summary.JailTrends {
		if tr.JailName == "ancient" {
			t.Errorf("40 天前的 ancient 进入了 7 天趋势: %+v", tr)
		}
	}
}
