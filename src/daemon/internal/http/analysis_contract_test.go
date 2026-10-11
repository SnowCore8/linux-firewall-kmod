// 历史库分析面的行为核对：映射后的载荷真的来自库里那份底账，而不是形状正确的常数。
//
// 契约门禁能核对 struct 与 type 块逐字对齐，但它不知道 `ban_count` 该是活跃封禁还是
// 历史累计、`recidivism_rate` 该是 0-1 还是百分数、旧行没有时长的该不该进直方图。这些
// **口径**只能把一份手工底账喂进映射函数、或打一次请求看结果——本文件就是这一层。
//
// 与 payload_contract_test.go 的分工：那边管「载荷有没有这些 key」，这边管「key 后面的
// 数是怎么算出来的」。
package http

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/analysis"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

// analysisPath 把生成物里的注册串（"GET /api/v1/…"）换成可请求路径。
//
// 测试里不复制第二份路径字符串：改了契约而用例仍绿，等于测试在给旧形状背书。
func analysisPath(pattern string) string { return strings.TrimPrefix(pattern, "GET ") }

// dataOf 取一次 GET 的 data 并解成对象（复用 stats_test.go 的泛型 get，它已经核对过 200）。
func dataOf(t *testing.T, s *Server, pattern string) map[string]any {
	t.Helper()
	return get[map[string]any](t, s, analysisPath(pattern))
}

// newAnalysisDB 建一个独立的历史库（每个用例一份，互不污染）。
func newAnalysisDB(t *testing.T, name string) *persist.DB {
	t.Helper()
	db, err := persist.NewDB(persist.Config{Path: filepath.Join(t.TempDir(), name), Logger: discardLogger()})
	if err != nil {
		t.Fatalf("建分析测试库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func secs(v int64) *int64 { return &v }

// TestBanEffectivenessFunnel 核对分级成效的漏斗读法。
//
// 「到达第 L 级 = 到过 ≥L，复发 = 又升到 L+1」只有拿一份手工底账才分得清：把 movedUp
// 写成本级地址数、或把 total 写成事件数，都能产出一个看着合理的百分数，但只有这份手算的
// 数能证明它按**地址**在走。
func TestBanEffectivenessFunnel(t *testing.T) {
	rows := []persist.BanLevelRow{
		// A 到过第 2 级。
		{IP: "203.0.113.1", BanCount: 1},
		{IP: "203.0.113.1", BanCount: 2},
		// B 到过第 3 级，且第 3 次是永久。
		{IP: "203.0.113.2", BanCount: 1},
		{IP: "203.0.113.2", BanCount: 3, IsPermanent: true},
		// C 只到过第 1 级。
		{IP: "203.0.113.3", BanCount: 1},
		// D 顶格之后又被封过一次（永久解封后再犯）——第 4 级唯一的复发信号。
		{IP: "203.0.113.4", BanCount: 4, IsPermanent: true},
		{IP: "203.0.113.4", BanCount: 5, IsPermanent: true},
	}
	resp := mapBanEffectiveness(rows)

	if len(resp.Levels) != EffectivenessLevelCount {
		t.Fatalf("级数 = %d，期望 %d", len(resp.Levels), EffectivenessLevelCount)
	}
	want := []struct {
		level     uint8
		total     uint32
		recid     uint32
		rate      float64
		permanent uint32
	}{
		{1, 4, 3, 75, 0},
		{2, 3, 2, 200.0 / 3, 0},
		{3, 2, 1, 50, 1},
		{4, 1, 1, 100, 1},
	}
	for i, w := range want {
		got := resp.Levels[i]
		if got.Level != w.level || got.TotalIPs != w.total || got.RecidivistIPs != w.recid ||
			math.Abs(got.RecidivismRate-w.rate) > 1e-9 || got.PermanentBans != w.permanent {
			t.Errorf("第 %d 级 = %+v，期望 到达 %d / 复发 %d / 率 %.4f / 永久 %d",
				got.Level, got, w.total, w.recid, w.rate, w.permanent)
		}
		if got.Label == "" {
			t.Errorf("第 %d 级没有标签", w.level)
		}
	}

	// 顶格不走「复发率低所以有效」那套措辞：它的分母是已到永久的地址。
	if verdict := resp.Levels[3].Verdict; verdict != "已到顶格（永久），其中 1 个解封后再次被封禁" {
		t.Errorf("第 4 级 verdict = %q，期望报出顶格后再犯的那个地址", verdict)
	}
	if resp.Levels[0].Verdict != "复发率偏高，这一级没拦住" {
		t.Errorf("第 1 级 verdict = %q，75%% 的复发率该报「没拦住」", resp.Levels[0].Verdict)
	}

	// 整体复发率：4 个地址里 3 个升到第 2 级及以上 → 75（百分数，不是 0.75）。
	if resp.TotalUniqueIPs != 4 || math.Abs(resp.OverallRecidivismRate-75) > 1e-9 {
		t.Errorf("整体读数 = %d 个地址 / %.4f%%，期望 4 / 75", resp.TotalUniqueIPs, resp.OverallRecidivismRate)
	}
	if resp.Summary == "" {
		t.Error("summary 为空")
	}

	// 空底账：每一级都写「无样本」而不是「这一级很有效」，面板不能把「没人到达」读成「拦住了」。
	empty := mapBanEffectiveness(nil)
	if len(empty.Levels) != EffectivenessLevelCount {
		t.Fatalf("空底账的级数 = %d，期望 %d", len(empty.Levels), EffectivenessLevelCount)
	}
	for _, l := range empty.Levels {
		if l.TotalIPs != 0 || l.Verdict != "无样本" {
			t.Errorf("空底账的第 %d 级 = %+v，期望 0 个地址且 verdict「无样本」", l.Level, l)
		}
	}
	if empty.TotalUniqueIPs != 0 || empty.OverallRecidivismRate != 0 {
		t.Errorf("空底账的整体读数 = %d / %v", empty.TotalUniqueIPs, empty.OverallRecidivismRate)
	}
}

// TestBanDurationHistogramBuckets 核对时长直方图的边界与「不知道」的排除。
func TestBanDurationHistogramBuckets(t *testing.T) {
	samples := []persist.BanEvent{
		{IP: "203.0.113.31", IsPermanent: true},         // 永久：按标记入最后一桶
		{IP: "203.0.113.32"},                            // 旧行无时长：不进任何桶
		{IP: "203.0.113.33", DurationSecs: secs(60)},    // ≤5 分钟
		{IP: "203.0.113.34", DurationSecs: secs(300)},   // 边界：300 不在 [0,300) → 5–30 分钟
		{IP: "203.0.113.35", DurationSecs: secs(1800)},  // 30 分钟–2 小时
		{IP: "203.0.113.36", DurationSecs: secs(7200)},  // 2–24 小时
		{IP: "203.0.113.37", DurationSecs: secs(86400)}, // >24 小时
		{IP: "203.0.113.38", DurationSecs: secs(-5)},    // 被写坏的负数：收进 0，落第一桶
	}
	resp := mapBanDurationHistogram(samples)

	if len(resp.Labels) != len(resp.Counts) {
		t.Fatalf("labels/counts 长度不等: %d vs %d", len(resp.Labels), len(resp.Counts))
	}
	wantCounts := []uint64{2, 1, 1, 1, 1, 1}
	for i, want := range wantCounts {
		if resp.Counts[i] != want {
			t.Errorf("桶 %q = %d 条，期望 %d（全部读数 %v）", resp.Labels[i], resp.Counts[i], want, resp.Counts)
		}
	}
	// 8 条样本里有 1 条没有时长读数 → total 只算能归桶的 7 条。
	if resp.Total != 7 {
		t.Errorf("total = %d，期望 7（无时长读数的旧行不计入，画成 0 秒是凭空造柱子）", resp.Total)
	}
}

// TestBanEffectivenessAndHistogramReadHistory 核对两条统计端点把库里的底账读了进来。
//
// 只核对 key 会放过「handler 返回硬编码空载荷」这一类缺陷——形状对，数全是 0。
func TestBanEffectivenessAndHistogramReadHistory(t *testing.T) {
	db := newAnalysisDB(t, "effectiveness.db")
	const ip = "203.0.113.20"
	for _, n := range []int{1, 2, 3} {
		if err := db.RecordBanEvent(ip, "sshd", n, n == 3, secs(1800)); err != nil {
			t.Fatalf("写封禁事件失败: %v", err)
		}
	}
	if err := db.RecordBanEvent("203.0.113.21", "sshd", 1, false, secs(60)); err != nil {
		t.Fatalf("写封禁事件失败: %v", err)
	}
	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.DB = db })

	data := dataOf(t, s, httpcontract.RouteGetApiV1StatsBanEffectiveness)
	requireKeys(t, data, "levels", "total_unique_ips", "overall_recidivism_rate", "summary")
	if data["total_unique_ips"] != float64(2) {
		t.Errorf("total_unique_ips = %v，期望 2（库里两个地址）", data["total_unique_ips"])
	}
	levels, ok := data["levels"].([]any)
	if !ok || len(levels) != EffectivenessLevelCount {
		t.Fatalf("levels = %v，期望 %d 档", data["levels"], EffectivenessLevelCount)
	}
	first := levels[0].(map[string]any)
	requireKeys(t, first, "level", "label", "total_ips", "recidivist_ips", "recidivism_rate",
		"permanent_bans", "verdict")
	if first["total_ips"] != float64(2) || first["recidivist_ips"] != float64(1) {
		t.Errorf("第 1 级读数 = %v/%v，期望 2 个地址到达、1 个升到第 2 级",
			first["total_ips"], first["recidivist_ips"])
	}
	// 第 3 次封禁是永久：permanent_bans 按**该级本身**计。
	third := levels[2].(map[string]any)
	if third["permanent_bans"] != float64(1) {
		t.Errorf("第 3 级 permanent_bans = %v，期望 1", third["permanent_bans"])
	}
	// 整体复发率按地址：2 个地址里 1 个复发 → 50（百分数刻度）。
	if math.Abs(data["overall_recidivism_rate"].(float64)-50) > 1e-9 {
		t.Errorf("overall_recidivism_rate = %v，期望 50", data["overall_recidivism_rate"])
	}

	hist := dataOf(t, s, httpcontract.RouteGetApiV1StatsBanDurationHistogram)
	requireKeys(t, hist, "labels", "counts", "total")
	counts, ok := hist["counts"].([]any)
	if !ok || len(counts) != 6 {
		t.Fatalf("counts = %v，期望 6 桶", hist["counts"])
	}
	// 两次 1800 秒 → 「30 分钟–2 小时」桶（下标 2）；一次 60 秒 → 第一桶；第三次封禁是永久，
	// is_permanent 优先于时长，所以它落最后一桶而不是第三桶。
	if counts[2] != float64(2) || counts[0] != float64(1) || counts[5] != float64(1) {
		t.Errorf("直方图 = %v，期望 60 秒 1 条、1800 秒 2 条、永久 1 条", counts)
	}
	if hist["total"] != float64(4) {
		t.Errorf("total = %v，期望 4（库里四条事件全都有可归桶的读数）", hist["total"])
	}
}

// TestAnalysisRoutesDegradeInsideEnvelope 核对契约**没编 codes** 的三条路由不报业务错误。
//
// 库缺失时它们回 200 + 空读数 + 一句 summary；把「读不到」回成 50002/50003 会让面板整块
// 变成错误提示，而契约在这些路由上根本没留业务码可用。
func TestAnalysisRoutesDegradeInsideEnvelope(t *testing.T) {
	s, _ := newTestServer(t, nil) // cfg.DB 为 nil

	for _, pattern := range []string{
		httpcontract.RouteGetApiV1StatsBanEffectiveness,
		httpcontract.RouteGetApiV1StatsBanDurationHistogram,
		httpcontract.RouteGetApiV1StatsAttackGeo,
	} {
		w := authedGet(t, s, analysisPath(pattern))
		if w.Code != http.StatusOK {
			t.Errorf("%s 状态码 %d，契约没给这条路由编码，期望 200（body=%s）",
				pattern, w.Code, truncate(w.Body.Bytes()))
			continue
		}
		env := decodeEnvelope(t, w.Body.Bytes())
		if got := envelopeCode(t, env); got != 0 {
			t.Errorf("%s 信封 code = %d，期望 0", pattern, got)
		}
	}

	// 空读数仍要给全形状：levels 是空数组（不是 null），summary 要说清原因。
	data := dataOf(t, s, httpcontract.RouteGetApiV1StatsBanEffectiveness)
	if arr, ok := data["levels"].([]any); !ok || len(arr) != 0 {
		t.Errorf("库缺失时 levels = %v，期望空数组", data["levels"])
	}
	if sum, _ := data["summary"].(string); sum == "" {
		t.Error("库缺失时 summary 为空，面板读不出是「没有底账」还是「查不动」")
	}

	// 对照组：契约给 recidivism 编了业务码，库缺失时那条必须如实报缺，不能伪装成空读数。
	w := authedGet(t, s, analysisPath(httpcontract.RouteGetApiV1StatsRecidivism))
	if w.Code == http.StatusOK {
		t.Errorf("recidivism 在库缺失时回 200，契约给它编了 50003（body=%s）", truncate(w.Body.Bytes()))
	}
	env := decodeEnvelope(t, w.Body.Bytes())
	if got := envelopeCode(t, env); got != httpcontract.Code50003 {
		t.Errorf("code = %d，期望契约的 %d（依赖未就绪）", got, httpcontract.Code50003)
	}
	if want := httpcontract.CodeHTTPStatus[httpcontract.Code50003]; w.Code != want {
		t.Errorf("状态码 %d，契约 50003 编的是 %d", w.Code, want)
	}
}

// TestAttackGeoReportsRealCoords 核对地理端点在 GeoIP 缺席时只说「没有定位」，
// 本机坐标仍按配置给出。
func TestAttackGeoReportsRealCoords(t *testing.T) {
	const lat, lon = 31.23, 121.47

	withCoords := dataOf(t, geoServer(t, &config.Config{
		ServerLatitude: lat, ServerLongitude: lon, ServerCoordsSet: true,
	}), httpcontract.RouteGetApiV1StatsAttackGeo)
	requireKeys(t, withCoords, "geoip_enabled", "points", "total_ips", "located_ips",
		"server_latitude", "server_longitude", "server_location_source")
	if withCoords["geoip_enabled"] != false {
		t.Errorf("geoip_enabled = %v，本实现没有 GeoIP 读库，期望恒为 false", withCoords["geoip_enabled"])
	}
	if pts, ok := withCoords["points"].([]any); !ok || len(pts) != 0 {
		t.Errorf("points = %v，期望空数组（没有定位结果可给）", withCoords["points"])
	}
	if withCoords["located_ips"] != float64(0) || withCoords["total_ips"] != float64(0) {
		t.Errorf("地理计数 = %v/%v，没有 GeoIP 时期望 0/0", withCoords["located_ips"], withCoords["total_ips"])
	}
	if withCoords["server_location_source"] != "config" {
		t.Errorf("server_location_source = %v，配置给了经纬度时期望 config", withCoords["server_location_source"])
	}
	if withCoords["server_latitude"] != lat || withCoords["server_longitude"] != lon {
		t.Errorf("本机坐标 = %v/%v，期望 %v/%v（前端靠它画本机标记与弧线）",
			withCoords["server_latitude"], withCoords["server_longitude"], lat, lon)
	}

	without := dataOf(t, geoServer(t, &config.Config{}), httpcontract.RouteGetApiV1StatsAttackGeo)
	if without["server_location_source"] != "none" {
		t.Errorf("server_location_source = %v，配置没给经纬度时期望 none", without["server_location_source"])
	}
	if without["server_latitude"] != nil {
		t.Errorf("server_latitude = %v，期望 null（不是猜一个坐标冒充探测结果）", without["server_latitude"])
	}
}

func geoServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	s, _ := newTestServer(t, func(c *APIConfig) {
		c.GetCurrentConfig = func() *config.Config { return cfg }
	})
	return s
}

// TestJailsPayloadIsRealData 核对 /api/v1/jails 的三组数各自来自正确的源。
//
// 配置（enabled/max_retries/findtime/ban_time）、活跃封禁镜像（ban_count）、判定层的常量
// 与时刻（两个乘数、is_peak_hours、effective_max_retries）。最容易错的两件：
//   - ban_count 写成 ban_events 的历史累计（那是 ban-effectiveness 那一面的口径）；
//   - effective_max_retries 把内网/信誉系数也乘进去（那两个按**来源地址**生效，
//     jail 级不存在「对所有地址的阈值」这个数）。
//
// 同时钉住「配置里不存在的 jail 不进载荷」：镜像与库里的孤儿条目不能变成一个新的 jail。
func TestJailsPayloadIsRealData(t *testing.T) {
	const (
		jailPayloadName = "jail-payload-sshd"
		otherJail       = "jail-payload-mysql"
		goneJail        = "jail-payload-gone"
		maxRetries      = uint32(5)
		findTime        = uint32(600)
		banTime         = int32(1800)
		otherMaxRetries = uint32(4)
	)

	db := newAnalysisDB(t, "jails.db")
	// 历史里 5 条本 jail 的封禁事件——载荷的 ban_count **不该**读它。
	for i := 1; i <= 5; i++ {
		ip := fmt.Sprintf("203.0.120.%d", i)
		if err := db.RecordBanEvent(ip, jailPayloadName, 1, false, secs(60)); err != nil {
			t.Fatalf("写封禁事件失败: %v", err)
		}
	}

	restoreJails := config.GetActiveJails()
	t.Cleanup(func() { config.SetActiveJails(restoreJails) })
	config.SetActiveJails([]config.Jail{
		{Name: jailPayloadName, Enabled: true, MaxRetries: maxRetries, FindTime: findTime, BanTime: banTime},
		{Name: otherJail, Enabled: false, MaxRetries: otherMaxRetries, FindTime: findTime, BanTime: -1},
	})

	// 活跃封禁：2 条属于本 jail、1 条属于另一个、1 条属于**配置里已消失**的 jail。
	seed := []bans.BanInfo{
		{IP: "203.0.121.1", JailName: jailPayloadName, BannedAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + 60},
		{IP: "203.0.121.2", JailName: jailPayloadName, BannedAt: time.Now().Unix(), IsPermanent: true},
		{IP: "203.0.121.3", JailName: otherJail, BannedAt: time.Now().Unix(), IsPermanent: true},
		{IP: "203.0.121.4", JailName: goneJail, BannedAt: time.Now().Unix(), IsPermanent: true},
	}
	for _, info := range seed {
		if !bans.GlobalCache().TryInsert(info) {
			t.Fatalf("测试种子 %s 已在镜像里", info.IP)
		}
	}
	t.Cleanup(func() {
		for _, info := range seed {
			_ = removeBanForTest(info.IP)
		}
	})
	config.UpdateJailStats(jailPayloadName, 100, 20, 15, 12, 3)

	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.DB = db })
	w := authedGet(t, s, analysisPath(httpcontract.RouteGetApiV1Jails))
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}
	var jails []map[string]any
	if err := json.Unmarshal(decodeEnvelope(t, w.Body.Bytes())["data"], &jails); err != nil {
		t.Fatalf("/api/v1/jails 载荷不是对象数组: %v（data=%s）", err, truncate(w.Body.Bytes()))
	}
	byName := map[string]map[string]any{}
	for _, j := range jails {
		byName[j["name"].(string)] = j
	}
	got, ok := byName[jailPayloadName]
	if !ok {
		t.Fatalf("载荷里没有 %s（读到 %d 个 jail: %v）", jailPayloadName, len(jails), jails)
	}
	requireKeys(t, got, "name", "enabled", "ban_count", "max_retries", "effective_max_retries",
		"findtime", "ban_time", "is_peak_hours", "peak_hours_multiplier", "internal_ip_multiplier",
		"lines_parsed", "regex_matches", "ips_extracted", "failed_attempts", "bans_triggered")

	if got["enabled"] != true || got["max_retries"] != float64(maxRetries) ||
		got["findtime"] != float64(findTime) || got["ban_time"] != float64(banTime) {
		t.Errorf("配置读数 = %v，期望 enabled=true max_retries=%d findtime=%d ban_time=%d",
			got, maxRetries, findTime, banTime)
	}
	// 活跃口径：2 条，不是库里的 5 条历史事件。
	if got["ban_count"] != float64(2) {
		t.Errorf("ban_count = %v，期望 2（当前活跃封禁；历史累计归 ban-effectiveness）", got["ban_count"])
	}
	if got["peak_hours_multiplier"] != 1.5 || got["internal_ip_multiplier"] != 2.0 {
		t.Errorf("乘数读数 = %v/%v，期望判定层的 1.5 / 2.0",
			got["peak_hours_multiplier"], got["internal_ip_multiplier"])
	}

	// is_peak_hours 与 effective_max_retries：按测试此刻的 UTC 小时独立算一遍。
	hour := uint32(time.Now().UTC().Hour())
	wantPeak := hour >= 9 && hour < 18
	if got["is_peak_hours"] != wantPeak {
		t.Errorf("is_peak_hours = %v，UTC %d 时期望 %v", got["is_peak_hours"], hour, wantPeak)
	}
	wantEffective := float64(maxRetries)
	if wantPeak {
		wantEffective = math.Ceil(wantEffective * 1.5)
	}
	if got["effective_max_retries"] != wantEffective {
		t.Errorf("effective_max_retries = %v，期望 %v（只乘高峰期系数：内网与信誉按来源地址生效）",
			got["effective_max_retries"], wantEffective)
	}

	// 运行时计数器与 config.GetJailStats 同源（本进程累计，重启归零）。
	stats, ok := config.GetJailStats(jailPayloadName)
	if !ok {
		t.Fatalf("测试种下的 jail 计数器读不到")
	}
	if got["lines_parsed"] != float64(stats.LinesParsed) || got["bans_triggered"] != float64(stats.BansTriggered) {
		t.Errorf("计数器 = %v/%v，期望与 config.GetJailStats 一致（%d/%d）",
			got["lines_parsed"], got["bans_triggered"], stats.LinesParsed, stats.BansTriggered)
	}

	// 禁用与永久时长照配置给；没有活跃封禁以外的数目混进来。
	mysql, ok := byName[otherJail]
	if !ok {
		t.Fatalf("载荷里没有 %s", otherJail)
	}
	if mysql["ban_count"] != float64(1) || mysql["enabled"] != false || mysql["ban_time"] != float64(-1) {
		t.Errorf("%s 读数 = ban_count %v / enabled %v / ban_time %v，期望 1 / false / -1（永久）",
			otherJail, mysql["ban_count"], mysql["enabled"], mysql["ban_time"])
	}

	// 配置里已消失的 jail 不进载荷：镜像里那条孤儿封禁不该变成一个新的 jail。
	if len(jails) != 2 {
		t.Errorf("载荷有 %d 个 jail，期望 2（配置里现存的两个）: %v", len(jails), jails)
	}
	if _, leaked := byName[goneJail]; leaked {
		t.Errorf("载荷里有配置中不存在的 %s", goneJail)
	}
}

// TestWhitelistRecommendationsAggregatesBySubnet 核对白名单推荐按网段聚合、载荷是数组。
func TestWhitelistRecommendationsAggregatesBySubnet(t *testing.T) {
	db := newAnalysisDB(t, "recommend.db")
	// 同一 /24 里两个地址，累计 11 封（6+5）。只报次数的话，「1 台机器抽风」与
	// 「20 台正常用户被误伤」在面板上长得一样，所以 affected_ips 要单独给。
	for i := 0; i < 6; i++ {
		if _, err := db.RecordBanHistory("203.0.130.11", false); err != nil {
			t.Fatalf("写封禁历史失败: %v", err)
		}
	}
	for i := 0; i < 5; i++ {
		if _, err := db.RecordBanHistory("203.0.130.12", false); err != nil {
			t.Fatalf("写封禁历史失败: %v", err)
		}
	}
	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.DB = db })

	raw := decodeEnvelope(t, authedGet(t, s, analysisPath(httpcontract.RouteGetApiV1WhitelistRecommendations)).Body.Bytes())["data"]
	var recs []map[string]any
	if err := json.Unmarshal(raw, &recs); err != nil {
		t.Fatalf("推荐载荷不是对象数组: %v（data=%s）", err, raw)
	}
	if len(recs) != 1 {
		t.Fatalf("推荐条目 %d 条，期望按 /24 聚合成 1 条: %v", len(recs), recs)
	}
	rec := recs[0]
	requireKeys(t, rec, "rec_type", "cidr", "reason", "affected_ips", "total_bans", "confidence")
	if rec["cidr"] != "203.0.130.0/24" || rec["affected_ips"] != float64(2) || rec["total_bans"] != float64(11) {
		t.Errorf("聚合读数 = %v，期望 203.0.130.0/24 / 2 个地址 / 11 次", rec)
	}
	if rec["rec_type"] != "subnet" {
		t.Errorf("rec_type = %v，本实现只产网段级推荐，期望 subnet", rec["rec_type"])
	}
	// 置信度阶梯与 analysis.RecommendThresholds 同刻度：11 次落 ≥10 那一档 → 50。
	if rec["confidence"] != float64(50) {
		t.Errorf("confidence = %v，期望 50（11 次封禁落 ≥10 那一档）", rec["confidence"])
	}

	// 阈值抬到样本够不到的地方：仍是空数组而不是 null（前端对载荷直接 .map()）。
	strict := decodeEnvelope(t,
		authedGet(t, s, "/api/v1/whitelist/recommendations?min_bans=999").Body.Bytes())["data"]
	if trimmed := strings.TrimSpace(string(strict)); trimmed != "[]" {
		t.Errorf("无推荐时 data = %s，期望空数组而不是 null", trimmed)
	}
}

// TestRecommendationPayloadsDropUnknownJails 核对两个建议载荷把「配置里已不存在的 jail」
// 滤掉，且 needs_adjustment 就是分析层 is_sufficient 取反。
func TestRecommendationPayloadsDropUnknownJails(t *testing.T) {
	known := func(jail string) bool { return jail == "sshd" }

	thresholds := mapThresholdRecommendations([]analysis.ThresholdFinding{
		{JailName: "sshd", Direction: "decrease", CurrentValue: 5, RecommendedVal: 3,
			TotalBans: 40, UniqueIPs: 20, RecidivistIPs: 9, RecidivismRate: 45,
			AvgBansPerIP: 2, Confidence: 0.9, Explanation: "复发率过高"},
		// 手工封禁路径固定写 "api"，它不是有阈值可调的 jail。
		{JailName: "api", Direction: "decrease", CurrentValue: 5, RecommendedVal: 1,
			TotalBans: 30, UniqueIPs: 30, Confidence: 0.7, Explanation: "兜底阈值"},
	}, known)

	if len(thresholds.Recommendations) != 1 {
		t.Fatalf("阈值建议 = %+v，期望只留配置里现存的 sshd（兜底阈值不能冒充读数）", thresholds.Recommendations)
	}
	got := thresholds.Recommendations[0]
	if got.Direction != "decrease" || got.CurrentThreshold != 5 || got.RecommendedThreshold != 3 {
		t.Errorf("阈值条目 = %+v，期望 current 5 → recommended 3、direction decrease", got)
	}
	// 置信度：分析层给 0-1，载荷给 u8 百分数。
	if got.Confidence != 90 {
		t.Errorf("confidence = %d，期望 0.9 换算成 90", got.Confidence)
	}
	if got.RecidivismRate < 30 {
		t.Errorf("recidivism_rate = %v，期望百分数刻度（>30 才建议降阈值）", got.RecidivismRate)
	}
	if thresholds.Summary == "" {
		t.Error("summary 为空")
	}

	durations := mapBanDurationRecommendations([]analysis.BanDurationFinding{
		{JailName: "sshd", CurrentDuration: 600, RecommendedDuration: 2700, RecidivistCount: 4,
			MedianInterval: 1800.4, Explanation: "复发间隔中位数超过当前封禁时长", IsSufficient: false},
		{JailName: "api", CurrentDuration: 600, RecommendedDuration: 600, RecidivistCount: 1,
			MedianInterval: 30, IsSufficient: true},
	}, known)

	if len(durations.Recommendations) != 1 {
		t.Fatalf("时长建议 = %+v，期望过滤掉 \"api\" 那一条", durations.Recommendations)
	}
	d := durations.Recommendations[0]
	if d.JailName != "sshd" || d.CurrentBanTime != 600 || d.RecommendedBanTime != 2700 ||
		d.MedianReturnSecs != 1800 {
		t.Errorf("时长条目 = %+v，期望 sshd / current 600 / recommended 2700 / 中位间隔 1800（四舍五入）", d)
	}
	if d.NeedsAdjustment != true {
		t.Errorf("needs_adjustment = %v，is_sufficient=false 的那条该报需要调整", d.NeedsAdjustment)
	}
	if durations.Summary == "" {
		t.Error("summary 为空")
	}
}

// TestRecidivismAndReputationReadPercentScale 核对两个统计面把库里的百分数与判定层的
// 系数原样给出（缺陷 HTTP_RECIDIVISM_RATE_UNIT 的行为断言）。
func TestRecidivismAndReputationReadPercentScale(t *testing.T) {
	db := newAnalysisDB(t, "recidivism.db")
	// 三个地址：两个复发（ban_count>1）、一个只封过一次 → 复发率 2/3×100 ≈ 66.7。
	for _, e := range []struct {
		ip    string
		count int
	}{{"203.0.140.1", 2}, {"203.0.140.2", 3}, {"203.0.140.3", 1}} {
		if err := db.RecordBanEvent(e.ip, "sshd", e.count, e.count == 3, secs(3600)); err != nil {
			t.Fatalf("写封禁事件失败: %v", err)
		}
	}
	if _, err := db.RecordBanHistory("203.0.140.2", true); err != nil {
		t.Fatalf("写封禁历史失败: %v", err)
	}
	if err := db.SetIPReputation("203.0.140.9", 60); err != nil {
		t.Fatalf("写信誉分失败: %v", err)
	}
	if err := db.RecordFailure("203.0.140.9", 10); err != nil {
		t.Fatalf("记失败失败: %v", err)
	}
	if err := db.RecordBan("203.0.140.9", 10); err != nil {
		t.Fatalf("记封禁失败: %v", err)
	}
	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.DB = db })

	data := dataOf(t, s, httpcontract.RouteGetApiV1StatsRecidivism)
	requireKeys(t, data, "total_ips", "recidivist_ips", "recidivism_rate", "permanent_bans", "top_recidivists")
	if data["total_ips"] != float64(3) || data["recidivist_ips"] != float64(2) {
		t.Errorf("复发计数 = %v/%v，期望 3/2", data["total_ips"], data["recidivist_ips"])
	}
	rate, _ := data["recidivism_rate"].(float64)
	if rate < 66 || rate > 67 {
		t.Errorf("recidivism_rate = %v，期望 66~67 的百分数刻度（0-1 的 0.667 正是缺陷 HTTP_RECIDIVISM_RATE_UNIT）", rate)
	}
	// permanent_bans 取自 ban_history 的**当前**永久标记，与前三项取自 ban_events 不同源。
	if data["permanent_bans"] != float64(1) {
		t.Errorf("permanent_bans = %v，期望 1", data["permanent_bans"])
	}
	top, ok := data["top_recidivists"].([]any)
	if !ok || len(top) != 2 {
		t.Fatalf("top_recidivists = %v，期望 2 条（ban_count>1 的地址）", data["top_recidivists"])
	}
	requireKeys(t, top[0].(map[string]any), "ip", "ban_count", "last_banned_at", "was_permanent")

	var list []map[string]any
	raw := decodeEnvelope(t, authedGet(t, s, analysisPath(httpcontract.RouteGetApiV1StatsReputation)).Body.Bytes())["data"]
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("信誉载荷不是对象数组: %v（data=%s）", err, raw)
	}
	if len(list) != 1 {
		t.Fatalf("低信誉清单 %d 条，期望 1 条: %v", len(list), list)
	}
	entry := list[0]
	requireKeys(t, entry, "ip", "score", "last_failure_at", "total_failures", "total_bans",
		"threshold_multiplier")
	if entry["ip"] != "203.0.140.9" {
		t.Fatalf("清单里是 %v，期望刚写的那条", entry["ip"])
	}
	// 60 分被 RecordFailure(10) 与 RecordBan(10) 各扣 10 → 40，落判定层第三档系数 0.5：
	// 载荷与真正生效的阈值同源，不能另抄一份分段表。
	if entry["score"] != float64(40) || entry["threshold_multiplier"] != 0.5 {
		t.Errorf("信誉条目 = score %v / multiplier %v，期望 40 与 0.5（判定层 <50 那一档）",
			entry["score"], entry["threshold_multiplier"])
	}
	if entry["total_failures"] != float64(1) || entry["total_bans"] != float64(1) {
		t.Errorf("累计计数 = %v/%v，期望 1/1", entry["total_failures"], entry["total_bans"])
	}
	if entry["last_failure_at"] == float64(0) {
		t.Errorf("last_failure_at = 0，记过一次失败时期望非零时刻")
	}
}
