// 分析层三条判据的行为核对：复发按**本 jail 内的地址**算、jail 归属取最近一次封禁、
// 配置级永久封禁的 jail 不进时长建议。
//
// 这三条都不是「算子写错了」那种一眼能看见的缺陷，而是**口径**：它们各自都能产出一个
// 数值合理、形状合规的读数，但回答的是不同的问题。契约与载荷注释已经把口径写死了，
// 这里把算式钉住——否则下次改动会把口径悄悄换回去，而面板上看不出来。
package analysis

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

type seedRow struct {
	ip    string
	jail  string
	at    int64
	count int
	perm  bool
}

// newSeededDB 建一份**时刻可控**的封禁底账。
//
// persist.RecordBanEvent 把 banned_at 钉在 time.Now()，而本层的判据是「近 7 天的样本」与
// 「复发间隔的中位数」——全部落在同一秒的样本区分不了这两件事，所以这里另开一条连接
// 直插 SQL（写完即关，读侧是新连接的同一份文件）。
func newSeededDB(t *testing.T, rows []seedRow) *persist.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "analysis.db")

	db, err := persist.NewDB(persist.Config{Path: path})
	if err != nil {
		t.Fatalf("建分析测试库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("打开底账写入通道失败: %v", err)
	}
	defer raw.Close()
	for _, r := range rows {
		perm := 0
		if r.perm {
			perm = 1
		}
		if _, err := raw.Exec(
			`INSERT INTO ban_events (ip, jail_name, banned_at, ban_count, is_permanent, created_at, duration_secs)
			 VALUES (?, ?, ?, ?, ?, ?, NULL)`,
			r.ip, r.jail, r.at, r.count, perm, r.at,
		); err != nil {
			t.Fatalf("写底账 %s@%s 失败: %v", r.ip, r.jail, err)
		}
	}
	return db
}

// TestThresholdRecidivismIsPerJailAndPerIP 核对复发率的分子分母都是**本 jail 内**的地址。
//
// 旧实现拿事件的 ban_count>1 当复发，那个数是跨 jail 的全局累计次数，于是「被 sshd 封过的
// 地址这次被 mysql 封」会被记进 mysql 的复发——阈值建议要回答「这个 jail 拦得住吗」，
// 借全局次数回答会串味。本用例把 mysql 的每条事件都写成 ban_count=2（旧口径会读成
// 100% 复发、建议降阈值），新口径必须读成 0%。
func TestThresholdRecidivismIsPerJailAndPerIP(t *testing.T) {
	now := time.Now().Unix()
	var rows []seedRow

	// sshd：4 个地址各被封 2 次 + 2 个地址各 1 次 = 10 条事件，唯一地址 6，复发地址 4 → 66.7%。
	for i := 1; i <= 4; i++ {
		ip := ipAt(203, 0, 10, i)
		rows = append(rows,
			seedRow{ip: ip, jail: "sshd", at: now - 600, count: 1},
			seedRow{ip: ip, jail: "sshd", at: now - 300, count: 2},
		)
	}
	for i := 5; i <= 6; i++ {
		rows = append(rows, seedRow{ip: ipAt(203, 0, 10, i), jail: "sshd", at: now - 200, count: 1})
	}

	// mysql：10 个**各不相同**的地址，每条都带着「这个地址历史上被封过 2 次」的 ban_count。
	// 在 mysql 这一侧它们都只出现一次 → 本 jail 内没有复发。
	for i := 1; i <= 10; i++ {
		rows = append(rows, seedRow{ip: ipAt(198, 51, 100, i), jail: "mysql", at: now - 100, count: 2})
	}

	db := newSeededDB(t, rows)
	findings, err := RecommendThresholds(db, map[string]int{"sshd": 5, "mysql": 10})
	if err != nil {
		t.Fatalf("阈值建议失败: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("读数 %d 条，期望 2 个 jail: %+v", len(findings), findings)
	}

	// 按复发率降序：sshd（66.7%）在前。
	sshd, mysql := findings[0], findings[1]
	if sshd.JailName != "sshd" || mysql.JailName != "mysql" {
		t.Fatalf("排序 = %q,%q，期望复发率高的 sshd 在前", sshd.JailName, mysql.JailName)
	}
	if sshd.TotalBans != 10 || sshd.UniqueIPs != 6 || sshd.RecidivistIPs != 4 {
		t.Errorf("sshd 计数 = 事件 %d / 地址 %d / 复发 %d，期望 10 / 6 / 4",
			sshd.TotalBans, sshd.UniqueIPs, sshd.RecidivistIPs)
	}
	if want := 100 * float64(4) / float64(6); sshd.RecidivismRate < want-0.01 || sshd.RecidivismRate > want+0.01 {
		t.Errorf("sshd 复发率 = %v，期望 %.4f（百分数、按地址）", sshd.RecidivismRate, want)
	}
	if sshd.Direction != "decrease" || sshd.RecommendedVal != 3 {
		t.Errorf("sshd 建议 = %q → %d，期望 decrease 到 3（5×0.7 取整）", sshd.Direction, sshd.RecommendedVal)
	}

	// mysql：跨 jail 的 ban_count 不算这里的复发。
	if mysql.UniqueIPs != 10 || mysql.RecidivistIPs != 0 || mysql.RecidivismRate != 0 {
		t.Errorf("mysql 计数 = 地址 %d / 复发 %d / 率 %v，期望 10 / 0 / 0（旧口径会读成 100%%）",
			mysql.UniqueIPs, mysql.RecidivistIPs, mysql.RecidivismRate)
	}
	if mysql.Direction != "maintain" || mysql.RecommendedVal != mysql.CurrentValue || mysql.CurrentValue != 10 {
		t.Errorf("mysql 建议 = %q，当前 %d → 建议 %d，期望维持配置里的 10",
			mysql.Direction, mysql.CurrentValue, mysql.RecommendedVal)
	}
}

// TestThresholdFallsBackToDefaultForUnknownJail 核对配置里查不到的 jail 拿到的是**兜底值**。
//
// 这条存在的原因不是兜底值本身，而是载荷读不出「5 是配置的」还是「查不到才给的」——
// internal/http 因此把这类 jail 从建议里滤掉（见 mapThresholdRecommendations 的 known 过滤）。
func TestThresholdFallsBackToDefaultForUnknownJail(t *testing.T) {
	now := time.Now().Unix()
	rows := make([]seedRow, 0, MinThresholdSampleEvents)
	for i := 0; i < MinThresholdSampleEvents; i++ {
		rows = append(rows, seedRow{ip: ipAt(203, 0, 20, i+1), jail: "orphan", at: now - int64(i+1)*60, count: 1})
	}
	findings, err := RecommendThresholds(newSeededDB(t, rows), map[string]int{})
	if err != nil {
		t.Fatalf("阈值建议失败: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("读数 %d 条: %+v", len(findings), findings)
	}
	if findings[0].CurrentValue != DefaultThresholdForRecommendation {
		t.Errorf("current = %d，期望兜底值 %d", findings[0].CurrentValue, DefaultThresholdForRecommendation)
	}
	if findings[0].Direction != "maintain" || findings[0].RecommendedVal != findings[0].CurrentValue {
		t.Errorf("建议 = %q → %d，期望维持兜底值（样本薄且复发率 0，不该给出改动）",
			findings[0].Direction, findings[0].RecommendedVal)
	}
}

// TestThresholdIgnoresSamplesOutsideWindow 核对近 7 天之外的封禁不参与样本。
func TestThresholdIgnoresSamplesOutsideWindow(t *testing.T) {
	old := time.Now().AddDate(0, 0, -30).Unix()
	rows := make([]seedRow, 0, MinThresholdSampleEvents)
	for i := 0; i < MinThresholdSampleEvents; i++ {
		rows = append(rows, seedRow{ip: ipAt(203, 0, 30, i+1), jail: "ancient", at: old, count: 1})
	}
	findings, err := RecommendThresholds(newSeededDB(t, rows), map[string]int{"ancient": 5})
	if err != nil {
		t.Fatalf("阈值建议失败: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("30 天前的样本读出了 %d 条建议，期望 0（样本窗口是近 7 天）", len(findings))
	}
}

// TestBanDurationSkipsPermanentJail 核对配置级永久封禁的 jail 不进时长建议，
// 而临时封禁的 jail 按复发间隔中位数给出延长值。
func TestBanDurationSkipsPermanentJail(t *testing.T) {
	now := time.Now().Unix()
	db := newSeededDB(t, []seedRow{
		// perm：同一地址被封两次（间隔 1 小时），但配置里它的 ban_time 是 -1（永久）。
		{ip: "203.0.40.1", jail: "perm", at: now - 7200, count: 1},
		{ip: "203.0.40.1", jail: "perm", at: now - 3600, count: 2},
		// temp：同样两次，配置里 600 秒 → 中位间隔 3600 > 600，该延长。
		{ip: "203.0.40.2", jail: "temp", at: now - 7200, count: 1},
		{ip: "203.0.40.2", jail: "temp", at: now - 3600, count: 2},
		// singles：每个地址只被封一次 → 没有间隔样本，整 jail 不产出条目。
		{ip: "203.0.40.3", jail: "singles", at: now - 60, count: 1},
		{ip: "203.0.40.4", jail: "singles", at: now - 30, count: 1},
	})

	findings, err := RecommendBanDurations(db, map[string]int64{"perm": -1, "temp": 600, "singles": 600})
	if err != nil {
		t.Fatalf("时长建议失败: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("读数 %d 条，期望只有 temp: %+v", len(findings), findings)
	}
	got := findings[0]
	if got.JailName != "temp" || got.CurrentDuration != 600 {
		t.Errorf("条目 = %q（当前 %d 秒），期望 temp 且当前 600", got.JailName, got.CurrentDuration)
	}
	// median(3600) > current(600) → recommended = max(3600×1.5, 600×2) = 5400。
	if got.MedianInterval != 3600 || got.RecommendedDuration != 5400 {
		t.Errorf("中位间隔 %v，建议 %d 秒，期望 3600 / 5400", got.MedianInterval, got.RecommendedDuration)
	}
	if got.IsSufficient {
		t.Error("is_sufficient = true，复发比封禁时长还早就不该报「够用」")
	}
	if got.RecidivistCount != 1 {
		t.Errorf("recidivist_count = %d，期望 1（本 jail 内被封 ≥2 次的地址数）", got.RecidivistCount)
	}
}

// TestPeriodicAttackerReportsNewestJail 核对 jail 归属取该地址**最近一次**封禁的 jail。
//
// 事件按 banned_at 降序读入，直接覆盖会停在最早那条的归属上：一个地址从 sshd 迁到 nginx
// 之后，面板上还把它算成 sshd 的周期性攻击者，那条 jail 的调参建议就跟着被同一个数喂。
// 种子里故意把最新那条**先**写进去，这样「第一条赢」的实现会读成 nginx 之外的错值。
func TestPeriodicAttackerReportsNewestJail(t *testing.T) {
	now := time.Now().Unix()
	db := newSeededDB(t, []seedRow{
		{ip: "203.0.50.1", jail: "nginx", at: now - 600, count: 4}, // 最新
		{ip: "203.0.50.1", jail: "sshd", at: now - 1200, count: 3},
		{ip: "203.0.50.1", jail: "sshd", at: now - 1800, count: 2},
		{ip: "203.0.50.1", jail: "sshd", at: now - 2400, count: 1},
	})

	findings, err := DetectPeriodicAttackers(db, 3, 20, 10000)
	if err != nil {
		t.Fatalf("周期检测失败: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("读数 %d 条: %+v", len(findings), findings)
	}
	got := findings[0]
	if got.JailName != "nginx" {
		t.Errorf("jail_name = %q，期望最近一次封禁所属的 nginx", got.JailName)
	}
	if got.EventCount != 4 {
		t.Errorf("event_count = %d，期望 4", got.EventCount)
	}
	if got.AvgInterval != 600 {
		t.Errorf("avg_interval = %v，期望 600", got.AvgInterval)
	}
	// 严格等间隔 → 变异系数 0 → 规则度满分。
	if got.Regularity != 100 || got.Jitter != 0 {
		t.Errorf("规则度 %v（jitter %v），期望 100 / 0", got.Regularity, got.Jitter)
	}
	for i := 1; i < len(got.Timestamps); i++ {
		if got.Timestamps[i] <= got.Timestamps[i-1] {
			t.Errorf("时刻没有升序: %v", got.Timestamps)
			break
		}
	}
}

// ipAt 造一个确定性的文档用途地址段（203.0.113.0/24 之外也一律走 TEST-NET 风格），
// 避免每个用例手写一遍四段字符串。
func ipAt(a, b, c, d int) string {
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
}
