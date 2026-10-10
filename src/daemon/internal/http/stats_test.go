// 统计与内核快照读数面的行为核对。
//
// 每条断言都针对一个「看起来正常但可能是假的」的形状：today_bans 与 total_bans 是不是
// 同一个数、速率数组有没有真的排序、分位数护栏没过时到底是「全零」还是「没有读数」、
// 定长热力图会不会因为缺数据而缩短。这些都不是编译期能发现的，只能真发一次请求。
package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/analysis"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/telemetry"
)

// v4 造一个 IPv4 的 addr16（内核把前 4 字节用作 v4）。
func v4(a, b, c, d byte) contract.Addr16 {
	return contract.Addr16{a, b, c, d}
}

// snapshotProvider 装一份固定快照，测完即弃。
func snapshotProvider(snap telemetry.Snapshot) func(*APIConfig) {
	return func(cfg *APIConfig) {
		cfg.GetKernelSnapshot = func() telemetry.Snapshot { return snap }
	}
}

// get 发一次带认证的 GET 并按契约载荷解码。
func get[T any](t *testing.T, s *Server, path string) T {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", authHeader())
	s.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s 状态码 %d，期望 200（body=%s）", path, w.Code, w.Body)
	}
	var out T
	if err := json.Unmarshal(unwrapData(t, w.Body.Bytes()), &out); err != nil {
		t.Fatalf("GET %s 载荷解码失败: %v（body=%s）", path, err, w.Body)
	}
	return out
}

// TestStatsTodayBansIsNotTotalBans 是缺陷 HTTP_TODAY_BANS_EQUALS_TOTAL 的行为断言。
//
// 两个量必须各走各的路：total_bans 是内核自加载起的累计计数器，today_bans 是历史库里
// 本地自然日窗口内的行数。历史库缺席时 today_bans 是 0 而不是抄内核的累计值——抄过来的
// 话面板上「今日封禁」会在模块重载时归零、在长跑后变成一个从不由天数决定的数。
func TestStatsTodayBansIsNotTotalBans(t *testing.T) {
	s, _ := newTestServer(t, snapshotProvider(telemetry.Snapshot{
		Stats: contract.StatsResponse{TotalBans: 7, CurrentBans: 2},
		Link:  telemetry.Link{Lease: telemetry.LeaseHeld},
	}))

	stats := get[StatsResponse](t, s, "/api/v1/stats")
	if stats.TotalBans != 7 {
		t.Errorf("total_bans = %d，期望透传内核的 7", stats.TotalBans)
	}
	if stats.TodayBans != 0 {
		t.Errorf("today_bans = %d，历史库缺席时应为 0 而不是抄 total_bans", stats.TodayBans)
	}
	if stats.TodayBans == stats.TotalBans && stats.TotalBans != 0 {
		t.Errorf("today_bans 与 total_bans 同为 %d，两者同源的旧缺陷复发", stats.TotalBans)
	}
	// 定长 24 项的热力图字段与四个图都在载荷里；缺任何一条前端都要写分支。
	if len(stats.BanTrend.Labels) != 7 {
		t.Errorf("ban_trend 标签 %d 个，期望 %d 天", len(stats.BanTrend.Labels), 7)
	}
	if stats.ThreatLevel.Level != threatLevels[0] {
		t.Errorf("threat_level.level = %q，无异常读数时期望 %q",
			stats.ThreatLevel.Level, threatLevels[0])
	}
	if len(stats.ThreatLevel.Factors) == 0 {
		t.Error("threat_level.factors 为空数组，面板那一栏会没有文字")
	}
}

// TestStatsUptimeUsesConfiguredStart 核对运行时长的起点来自组合根而不是 handler 构造时刻。
func TestStatsUptimeUsesConfiguredStart(t *testing.T) {
	start := time.Now().Add(-90 * time.Second)
	s, _ := newTestServer(t, func(cfg *APIConfig) {
		cfg.StartedAt = start
		cfg.GetKernelSnapshot = func() telemetry.Snapshot {
			return telemetry.Snapshot{Link: telemetry.Link{Lease: telemetry.LeaseHeld}}
		}
	})

	stats := get[StatsResponse](t, s, "/api/v1/stats")
	if stats.UptimeSeconds < 89 || stats.UptimeSeconds > 92 {
		t.Errorf("uptime_seconds = %d，起点在 90 秒前时应约为 90", stats.UptimeSeconds)
	}
}

// TestRatesCurrentSortsByPps 核对速率数组按 pps 降序，且地址是点分文本。
func TestRatesCurrentSortsByPps(t *testing.T) {
	snap := telemetry.Snapshot{
		Rates: telemetry.Rates{Entries: []contract.RateEntry{
			{AF: contract.AFInet, Addr: v4(10, 0, 0, 1), Packets: 5, Bytes: 500},
			{AF: contract.AFInet, Addr: v4(10, 0, 0, 2), Packets: 50, Bytes: 5000},
			{AF: contract.AFInet, Addr: v4(10, 0, 0, 3), Packets: 20, Bytes: 2000},
		}},
		Link: telemetry.Link{Lease: telemetry.LeaseHeld},
	}
	s, _ := newTestServer(t, snapshotProvider(snap))

	rows := get[[]RateResponse](t, s, "/api/v1/rates/current")
	if len(rows) != 3 {
		t.Fatalf("取回 %d 行，期望 3 行", len(rows))
	}
	want := []struct {
		ip  string
		pps uint64
	}{{"10.0.0.2", 50}, {"10.0.0.3", 20}, {"10.0.0.1", 5}}
	for i, w := range want {
		if rows[i].IP != w.ip || rows[i].PacketsPerSec != w.pps {
			t.Errorf("第 %d 行 = %s/%d，期望 %s/%d（按 pps 降序）",
				i, rows[i].IP, rows[i].PacketsPerSec, w.ip, w.pps)
		}
	}
}

// TestRatesWindowsRoundsInsteadOfTruncating 核对 0.6 pps 报成 1 而不是 0。
func TestRatesWindowsRoundsInsteadOfTruncating(t *testing.T) {
	snap := telemetry.Snapshot{
		Windows: telemetry.Windows{
			PPS: analysis.EWMASnapshot{Short: 0.6, Medium: 12.4, Long: 300.5},
			BPS: analysis.EWMASnapshot{Short: 0.4},
		},
		Link: telemetry.Link{Lease: telemetry.LeaseHeld},
	}
	s, _ := newTestServer(t, snapshotProvider(snap))

	w := get[RateWindowSnapshot](t, s, "/api/v1/rates/windows")
	if w.PpsShort != 1 {
		t.Errorf("pps_short = %d，0.6 应四舍五入成 1 而不是截成 0", w.PpsShort)
	}
	if w.PpsMid != 12 || w.PpsLong != 301 {
		t.Errorf("pps_mid/long = %d/%d，期望 12/301", w.PpsMid, w.PpsLong)
	}
	if w.BpsShort != 0 {
		t.Errorf("bps_short = %d，0.4 应舍成 0", w.BpsShort)
	}
}

// TestRatesHistoryIsAscendingAndLimited 核对历史序列的形状：升序、limit 取最近 n 条。
func TestRatesHistoryIsAscendingAndLimited(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	samples := []telemetry.RateSample{
		{At: now, TotalPPS: 10, TotalBPS: 1000},
		{At: now.Add(5 * time.Second), TotalPPS: 20, TotalBPS: 2000, TrackedIPs: 3},
		{At: now.Add(10 * time.Second), TotalPPS: 30, TotalBPS: 3000},
	}
	// 注入的 provider 按请求条数取**最近** n 点，与 telemetry.RateHistory.Samples 同语义。
	recent := func(n int) []telemetry.RateSample {
		if n <= 0 || n > len(samples) {
			return samples
		}
		return samples[len(samples)-n:]
	}
	s, _ := newTestServer(t, func(cfg *APIConfig) {
		cfg.GetRateSamples = recent
	})

	all := get[[]RateHistoryResponse](t, s, "/api/v1/rates/history")
	if len(all) != 3 {
		t.Fatalf("取回 %d 点，期望 3 点", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i].Timestamp <= all[i-1].Timestamp {
			t.Errorf("第 %d 点时间戳 %d 不晚于前一点 %d，序列不是升序",
				i, all[i].Timestamp, all[i-1].Timestamp)
		}
	}
	if all[1].TrackedIps != 3 {
		t.Errorf("第 2 点 tracked_ips = %d，期望 3", all[1].TrackedIps)
	}

	limited := get[[]RateHistoryResponse](t, s, "/api/v1/rates/history?limit=2")
	if len(limited) != 2 {
		t.Fatalf("limit=2 取回 %d 点，期望 2 点", len(limited))
	}
	if limited[1].TotalPps != 30 || limited[0].TotalPps != 20 {
		t.Errorf("limit=2 取到的是 %+v，期望最近两点（20pps, 30pps）", limited)
	}
}

// TestPacketSizesAndTtlCarryLabelsAndPercentages 核对直方图的三件套形状。
//
// 标签长度必须恒等于分桶数：内核一个桶都没命中时也要把 5 个桶名画出来，否则面板的横轴
// 在空表上会整个消失，「没有流量」看起来像「图坏了」。
func TestPacketSizesAndTtlCarryLabelsAndPercentages(t *testing.T) {
	snap := telemetry.Snapshot{
		Analysis: contract.AnalysisResponse{
			PktSizes: [contract.AnalysisPktSizeBins]uint64{1, 1, 0, 0, 0},
			TTLDist:  [contract.AnalysisTTLBins]uint64{0, 0, 0, 0, 0, 0},
		},
		Link: telemetry.Link{Lease: telemetry.LeaseHeld},
	}
	s, _ := newTestServer(t, snapshotProvider(snap))

	pkts := get[PacketSizeDistributionResponse](t, s, "/api/v1/stats/packet-sizes")
	if len(pkts.Labels) != contract.AnalysisPktSizeBins {
		t.Fatalf("包长标签 %d 个，期望 %d 个", len(pkts.Labels), contract.AnalysisPktSizeBins)
	}
	if pkts.Total != 2 {
		t.Errorf("total = %d，期望两桶之和 2", pkts.Total)
	}
	if len(pkts.Percentages) != len(pkts.Counts) {
		t.Fatalf("percentages 与 counts 长度不等：%d vs %d", len(pkts.Percentages), len(pkts.Counts))
	}
	if pkts.Percentages[0] != 50 || pkts.Percentages[2] != 0 {
		t.Errorf("percentages[0]/[2] = %v/%v，期望 50/0（占总数百分比）",
			pkts.Percentages[0], pkts.Percentages[2])
	}

	ttl := get[TtlDistributionResponse](t, s, "/api/v1/stats/ttl-distribution")
	if len(ttl.Labels) != contract.AnalysisTTLBins {
		t.Errorf("TTL 标签 %d 个，期望 %d 个", len(ttl.Labels), contract.AnalysisTTLBins)
	}
	if ttl.Total != 0 || ttl.Percentages[0] != 0 {
		t.Errorf("空直方图 total=%d pct[0]=%v，期望两者 0（不是 NaN）", ttl.Total, ttl.Percentages[0])
	}
}

// TestIpFragmentsRatioIsPercent 核对分片占比的单位是 0-100 且总数为 0 时不除零。
func TestIpFragmentsRatioIsPercent(t *testing.T) {
	s, _ := newTestServer(t, snapshotProvider(telemetry.Snapshot{
		Analysis: contract.AnalysisResponse{IPFragTotal: 400, IPFragCount: 4},
	}))
	got := get[IpFragmentStatsResponse](t, s, "/api/v1/stats/ip-fragments")
	if got.FragmentRatio != 1.0 {
		t.Errorf("fragment_ratio = %v，4/400 应为 1.0（百分数，不是 0-1 比例）", got.FragmentRatio)
	}

	empty, _ := newTestServer(t, snapshotProvider(telemetry.Snapshot{}))
	zero := get[IpFragmentStatsResponse](t, empty, "/api/v1/stats/ip-fragments")
	if zero.FragmentRatio != 0 {
		t.Errorf("无流量时 fragment_ratio = %v，期望 0 而不是 NaN", zero.FragmentRatio)
	}
}

// TestUdpPortsClampsKernelCount 核对「内核报的行数」不会越过定长数组的容量。
//
// 这条不只是为了不 panic：载荷里 total_entries 原样透传内核给的数（哪怕是 9999），
// ports 只截到容量，读侧因此看得见截断而不是被一个自洽的假数字骗过去。
func TestUdpPortsClampsKernelCount(t *testing.T) {
	var a contract.AnalysisResponse
	a.UDPPortCount = 9_999
	a.UDPPortCapacity = 512
	for i := range a.UDPPorts {
		a.UDPPorts[i] = contract.UdpPortItem{Port: uint16(5000 + i), Packets: uint64(i)}
	}
	s, _ := newTestServer(t, snapshotProvider(telemetry.Snapshot{Analysis: a}))

	got := get[UdpPortDistributionResponse](t, s, "/api/v1/stats/udp-ports")
	if len(got.Ports) != contract.AnalysisUDPPortCap {
		t.Errorf("ports = %d 行，期望夹到容量 %d", len(got.Ports), contract.AnalysisUDPPortCap)
	}
	if got.TotalEntries != 9_999 || got.MaxEntries != 512 {
		t.Errorf("total/max = %d/%d，期望原样透传 9999/512", got.TotalEntries, got.MaxEntries)
	}
}

// TestScannersReportThresholdAndRows 核对两路 Top-N 都带阈值与行，且行里是点分 IP。
func TestScannersReportThresholdAndRows(t *testing.T) {
	var a contract.AnalysisResponse
	a.PortScanCount = 4_096 // 内核的累计检出事件计数，与下面 1 行不成比例
	a.PortScanThreshold = 5
	a.PortScanners[0] = contract.ScannerItem{
		AF: contract.AFInet, Addr: v4(198, 51, 100, 9), Metric: 12, Packets: 340,
	}
	a.ServiceProbeCount = 1
	a.ServiceProbeThreshold = 3
	a.ServiceProbes[0] = contract.ScannerItem{
		AF: contract.AFInet, Addr: v4(192, 0, 2, 7), Metric: 4, Packets: 88,
	}
	s, _ := newTestServer(t, snapshotProvider(telemetry.Snapshot{Analysis: a}))

	scanners := get[PortScanResponse](t, s, "/api/v1/stats/port-scanners")
	if scanners.Threshold != 5 || scanners.TotalDetected != 4_096 {
		t.Errorf("port-scanners threshold/total = %d/%d，期望 5/4096",
			scanners.Threshold, scanners.TotalDetected)
	}
	if len(scanners.Scanners) != 1 || scanners.Scanners[0].IP != "198.51.100.9" {
		t.Errorf("scanners = %+v，期望 1 行且 IP 为点分文本", scanners.Scanners)
	}
	if scanners.Scanners[0].UniquePorts != 12 {
		t.Errorf("unique_ports = %d，期望内核的 metric 12", scanners.Scanners[0].UniquePorts)
	}

	probes := get[ServiceProbeResponse](t, s, "/api/v1/stats/service-probes")
	if probes.TotalDetected == 0 {
		t.Error("service-probes 缺 total_detected（缺陷 HTTP_SERVICE_PROBE_NO_TOTAL 复发）")
	}
	if len(probes.Probes) != 1 || probes.Probes[0].ProtocolCount != 4 {
		t.Errorf("probes = %+v，期望 1 行且 protocol_count=4", probes.Probes)
	}
}

// TestHeatmapAlwaysHasTwentyFourBuckets 核对热力图恒长 24。
//
// 历史库缺席时每个桶都是 0，但槽位必须都在：前端按下标读小时，压缩数组等于把 04 点画到
// 03 点上。
func TestHeatmapAlwaysHasTwentyFourBuckets(t *testing.T) {
	s, _ := newTestServer(t, nil)

	h := get[HourlyHeatmap](t, s, "/api/v1/stats/heatmap")
	if len(h.Hours) != 24 {
		t.Fatalf("hours = %d 项，期望定长 24", len(h.Hours))
	}
	for i, b := range h.Hours {
		if b.Hour != uint32(i) {
			t.Errorf("第 %d 项 hour = %d，期望下标即小时", i, b.Hour)
		}
		if b.Bans != 0 || b.FailedAttempts != 0 || b.DdosEvents != 0 {
			t.Errorf("第 %d 项 = %+v，历史库缺席时三列都应为 0", i, b)
		}
	}
}

// TestAnomaliesGuardKeepsNullVsZero 核对样本不足时给「没有基线」而不是「基线为 0」。
//
// 0 基线会让任何非零当前值都算成无穷偏离，图上是一片红；null 才说的是「这一轮没有可读的
// 分位数」。护栏之上必须反过来：global_features 有值、两条基线各 9 个特征。
func TestAnomaliesGuardKeepsNullVsZero(t *testing.T) {
	short, _ := newTestServer(t, func(cfg *APIConfig) {
		cfg.GetRateSamples = func(int) []telemetry.RateSample {
			return []telemetry.RateSample{{TotalPPS: 1}, {TotalPPS: 2}}
		}
	})
	guarded := get[AnomalyResponse](t, short, "/api/v1/stats/anomalies")
	if guarded.GlobalFeatures != nil {
		t.Errorf("样本仅 2 点时 global_features = %v，期望 null", guarded.GlobalFeatures)
	}
	if guarded.GlobalSampleCount != 2 {
		t.Errorf("global_sample_count = %d，期望如实报 2", guarded.GlobalSampleCount)
	}
	if guarded.GlobalScore != 0 || len(guarded.IpAnomalies) != 0 {
		t.Errorf("护栏未过时 score=%v anomalies=%d，期望 0 与空", guarded.GlobalScore, len(guarded.IpAnomalies))
	}
	// 两条基线与维度表是空数组（不是 null）：前端对它们做 .map()。
	raw := getRaw(t, short, "/api/v1/stats/anomalies")
	if _, ok := raw["global_baseline_p50"].(string); ok {
		t.Error("global_baseline_p50 不是数组")
	}
	if v, ok := raw["global_baseline_p50"].([]any); !ok || len(v) != 0 {
		t.Errorf("global_baseline_p50 = %v，期望空数组", raw["global_baseline_p50"])
	}
	if v, ok := raw["global_features"]; !ok || v != nil {
		t.Errorf("global_features = %v，期望 null", v)
	}

	full, _ := newTestServer(t, func(cfg *APIConfig) {
		samples := make([]telemetry.RateSample, 0, analysis.MinGlobalSamples)
		for i := 0; i < analysis.MinGlobalSamples; i++ {
			samples = append(samples, telemetry.RateSample{
				At:       time.Now().Add(time.Duration(i) * 5 * time.Second),
				TotalPPS: uint64(100 + i*10),
			})
		}
		cfg.GetRateSamples = func(int) []telemetry.RateSample { return samples }
		cfg.GetKernelSnapshot = func() telemetry.Snapshot {
			return telemetry.Snapshot{
				Rates: telemetry.Rates{Entries: []contract.RateEntry{
					{AF: contract.AFInet, Addr: v4(10, 0, 0, 1), Packets: 10},
					{AF: contract.AFInet, Addr: v4(10, 0, 0, 2), Packets: 11},
					{AF: contract.AFInet, Addr: v4(10, 0, 0, 3), Packets: 12, SynPackets: 9},
					{AF: contract.AFInet, Addr: v4(10, 0, 0, 4), Packets: 13, Bytes: 600},
					// 恰好 analysis.MinIPSamples 个地址，最后一个比同伴高两个量级。
					{AF: contract.AFInet, Addr: v4(10, 0, 0, 5), Packets: 900, Bytes: 90_000,
						SynPackets: 800, UniquePorts: 30},
				}},
			}
		}
	})
	out := get[AnomalyResponse](t, full, "/api/v1/stats/anomalies")
	if out.GlobalFeatures == nil {
		t.Fatal("样本达护栏后 global_features 仍是 null")
	}
	if len(out.GlobalBaselineP50) != len(analysis.GlobalAnomalyFeatures) {
		t.Errorf("基线 %d 项，期望 %d 个特征", len(out.GlobalBaselineP50), len(analysis.GlobalAnomalyFeatures))
	}
	if len(out.IpAnomalies) == 0 {
		t.Error("5 个地址里那个速率高两个量级的地址没进离群列表")
	}
	if top := out.IpAnomalies[0]; top.IP != "10.0.0.5" {
		t.Errorf("离群榜首 = %q，期望明显离群的 10.0.0.5", top.IP)
	}
}

// getRaw 取回信封里的 data 作为通用 JSON，用于核对 null 与空数组这类形状差异。
func getRaw(t *testing.T, s *Server, path string) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", authHeader())
	s.mux.ServeHTTP(w, req)
	var out map[string]any
	if err := json.Unmarshal(unwrapData(t, w.Body.Bytes()), &out); err != nil {
		t.Fatalf("GET %s 解码失败: %v（body=%s）", path, err, w.Body)
	}
	return out
}

// TestGlobalFeatureMatrixColumnsMatchNames 逐列核对 globalFeatureMatrix 的取值顺序与
// analysis.GlobalAnomalyFeatures 的名字表一致。
//
// 错位是这里最贵的一种 bug：编译与形状核对全都过，面板把 bps 当成 pps 比分位，数值全对
// 而结论全错。每个字段给一个互不相同的值，任何一格挪动都会被名字逮住。
func TestGlobalFeatureMatrixColumnsMatchNames(t *testing.T) {
	sample := telemetry.RateSample{
		TotalPPS: 1, TotalBPS: 2,
		SynPPS: 3, UdpPPS: 4, IcmpPPS: 5, AckPPS: 6, RstPPS: 7, FinPPS: 8,
		TrackedIPs: 9,
	}
	want := map[string]float64{
		"total_pps": 1, "total_bps": 2,
		"syn_pps": 3, "udp_pps": 4, "icmp_pps": 5, "ack_pps": 6,
		"rst_pps": 7, "fin_pps": 8, "tracked_ips": 9,
	}
	m := globalFeatureMatrix([]telemetry.RateSample{sample})
	if len(m.Names) != len(analysis.GlobalAnomalyFeatures) || len(m.Rows[0]) != len(want) {
		t.Fatalf("名字表 %d 列 / 行 %d 格，期望各 %d",
			len(m.Names), len(m.Rows[0]), len(want))
	}
	for i, name := range m.Names {
		if name != analysis.GlobalAnomalyFeatures[i] {
			t.Fatalf("第 %d 列名字 = %q，与 analysis 的名字表不符", i, name)
		}
		if got := m.Rows[0][i]; got != want[name] {
			t.Errorf("第 %d 列（%s）= %v，期望 %v", i, name, got, want[name])
		}
	}
}

// TestIPFeatureRowColumnsMatchNames 同样逐列核对 per-IP 那张矩阵：三个 ratio 是「该地址
// 自己流量里的占比」，把它们当成绝对速率会让一个纯 UDP 反射源读成低速率。
func TestIPFeatureRowColumnsMatchNames(t *testing.T) {
	entry := contract.RateEntry{
		Packets: 1000, Bytes: 7,
		SynPackets: 500, UDPPackets: 250, ICMPPackets: 100,
		UniquePorts: 3,
	}
	want := map[string]float64{
		"packets_per_sec": 1000, "bytes_per_sec": 7,
		"syn_ratio": 0.5, "udp_ratio": 0.25, "icmp_ratio": 0.1,
		"unique_ports": 3,
	}
	m := ipFeatureMatrix([]contract.RateEntry{entry})
	if len(m.Rows[0]) != len(analysis.IPAnomalyFeatures) {
		t.Fatalf("行数 %d 与名字表 %d 不等长", len(m.Rows[0]), len(analysis.IPAnomalyFeatures))
	}
	for i, name := range analysis.IPAnomalyFeatures {
		if got := m.Rows[0][i]; got != want[name] {
			t.Errorf("第 %d 列（%s）= %v，期望 %v", i, name, got, want[name])
		}
	}

	// 速率为 0 时占比取 0 而不是除零：内核会给刚建条目、还没计数的地址一个 0。
	zero := ipFeatureRow(contract.RateEntry{})
	for i, got := range zero {
		if got != 0 {
			t.Errorf("零流量地址的第 %d 列 = %v，期望 0", i, got)
		}
	}
}
