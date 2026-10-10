// 内核快照读数面：GET /api/v1/rates/{current,windows} 与
// GET /api/v1/stats/{packet-sizes,ttl-distribution,ip-fragments,udp-ports,icmp-types,
// port-scanners,service-probes,anomalies}。
//
// 这一组端点只有一个数据源：事件泵发布的 telemetry 快照（内核最近一次回答的形状）。
// 于是同一轮刷新里的速率、协议分布与 Top-N 出自同一次采样，而不是各问一次内核。
//
// 两条共同的口径约束：
//   - 链路未注册或采样失败时，快照里就是**上一次成功的读数**（零值表示从未采到）。
//     契约给这些路由只编了 code 0，没有为「读数陈旧」另造错误码——新鲜度的判据在
//     /health 的链路字段，不在这里；
//   - 内核的直方图是**自模块加载起的累计计数**（fw_stats.c 的 per-CPU 数组只在 init/
//     unload 归零，flush 只搬运 accept/drop 那组），所以这些图的横轴不是时间窗口。
//     面板把它们当「本机见过的流量长什么样」读，不是「最近 5 秒长什么样」。
package http

import (
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/analysis"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/telemetry"
)

// RatesCurrent 返回每个被跟踪源地址的当前速率（GET /api/v1/rates/current）。
//
// 载荷是数组而不是分页：内核速率表的容量上限（FW_RATE_CPU_SLOTS=512 个在跟踪的源地址）
// 本来就在一次响应能带出的量级内，事件泵也是整表取回的。分页在这里只会多一次往返。
func (h *APIHandlers) RatesCurrent(w http.ResponseWriter, r *http.Request) {
	WriteSuccess(w, h.ratesCurrent(h.kernelSnapshot()))
}

// ratesCurrent 把速率表条目折成载荷并按 pps 降序。
//
// 排序在守护进程侧做：内核按哈希序回表，两次刷新之间同一个地址会跳到图的另一端，
// 前端按「前 N 个」画条形图时看到的就是一排随机地址。
func (h *APIHandlers) ratesCurrent(snap telemetry.Snapshot) []RateResponse {
	out := make([]RateResponse, 0, len(snap.Rates.Entries))
	skipped := 0
	for _, e := range snap.Rates.Entries {
		ip, err := e.Addr.IP(e.AF)
		if err != nil {
			// 地址族不在契约定义内：这一行没有可展示的地址。丢掉它并记数，而不是把
			// 空串当 IP 写出去——前端会把空串当成一个可点、可复制的「地址」。
			skipped++
			continue
		}
		out = append(out, RateResponse{
			IP:                ip.String(),
			PacketsPerSec:     e.Packets,
			BytesPerSec:       e.Bytes,
			SynPacketsPerSec:  e.SynPackets,
			UdpPacketsPerSec:  e.UDPPackets,
			IcmpPacketsPerSec: e.ICMPPackets,
			AckPacketsPerSec:  e.ACKPackets,
			RstPacketsPerSec:  e.RSTPackets,
			FinPacketsPerSec:  e.FINPackets,
		})
	}
	if skipped > 0 {
		h.server.logger.Warn("速率表有条目地址族无法识别，已跳过", "count", skipped)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PacketsPerSec != out[j].PacketsPerSec {
			return out[i].PacketsPerSec > out[j].PacketsPerSec
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// RatesWindows 返回全局速率的多窗口 EWMA（GET /api/v1/rates/windows）。
//
// 三档窗口（5 秒 / 60 秒 / 300 秒）是守护进程侧的派生量：内核只回答「自上次查询以来的
// 平均速率」，没有窗口概念，所以这条路由的数据源是快照的 Windows 字段而不是内核。
// 取整到整数 pps/bps 是契约给的 u64 形状决定的——平滑值本身是浮点。
func (h *APIHandlers) RatesWindows(w http.ResponseWriter, r *http.Request) {
	WriteSuccess(w, rateWindows(h.kernelSnapshot()))
}

// rateWindows 把浮点 EWMA 折成契约的整数载荷。
//
// 四舍五入而不是截断：截断会让 0.6 pps 报成 0，图上读成「完全没有流量」，而它恰恰是
// 判定突发的短期窗口里最不该被吃掉的那点余量。
func rateWindows(snap telemetry.Snapshot) RateWindowSnapshot {
	return RateWindowSnapshot{
		PpsShort: uint64(math.Round(snap.Windows.PPS.Short)),
		PpsMid:   uint64(math.Round(snap.Windows.PPS.Medium)),
		PpsLong:  uint64(math.Round(snap.Windows.PPS.Long)),
		BpsShort: uint64(math.Round(snap.Windows.BPS.Short)),
		BpsMid:   uint64(math.Round(snap.Windows.BPS.Medium)),
		BpsLong:  uint64(math.Round(snap.Windows.BPS.Long)),
	}
}

// PacketSizes 返回包长分桶直方图（GET /api/v1/stats/packet-sizes）。
func (h *APIHandlers) PacketSizes(w http.ResponseWriter, r *http.Request) {
	a := h.kernelSnapshot().Analysis
	counts := uint64Slice(a.PktSizes[:])
	total := sumCounts(counts)
	WriteSuccess(w, PacketSizeDistributionResponse{
		Labels:      labelsOf(contract.AnalysisPktSizeLabels[:]),
		Counts:      counts,
		Total:       total,
		Percentages: percentages(counts, total),
	})
}

// TtlDistribution 返回 TTL 分桶直方图（GET /api/v1/stats/ttl-distribution）。
func (h *APIHandlers) TtlDistribution(w http.ResponseWriter, r *http.Request) {
	a := h.kernelSnapshot().Analysis
	counts := uint64Slice(a.TTLDist[:])
	total := sumCounts(counts)
	WriteSuccess(w, TtlDistributionResponse{
		Labels:      labelsOf(contract.AnalysisTTLLabels[:]),
		Counts:      counts,
		Total:       total,
		Percentages: percentages(counts, total),
	})
}

// IpFragments 返回分片流量占比（GET /api/v1/stats/ip-fragments）。
//
// total_packets 是**所有**被记账的 IP 包（内核在 fw_stat_account 里对每个包都加 total，
// 只在 is_fragment 时加 count），故 ratio 是「分片包占全部流量的百分比」。
func (h *APIHandlers) IpFragments(w http.ResponseWriter, r *http.Request) {
	a := h.kernelSnapshot().Analysis
	ratio := 0.0
	if a.IPFragTotal > 0 {
		ratio = float64(a.IPFragCount) / float64(a.IPFragTotal) * 100
	}
	WriteSuccess(w, IpFragmentStatsResponse{
		TotalPackets:    a.IPFragTotal,
		FragmentPackets: a.IPFragCount,
		FragmentRatio:   ratio,
	})
}

// UdpPorts 返回 UDP 端口分布（GET /api/v1/stats/udp-ports）。
//
// 截断在这里是看得见的：ports 最多 FW_ANALYSIS_UDP_PACK_MAX=64 行，而内核的跟踪容量是
// MAX_UDP_PORT_ENTRIES=512。内核在打包满 64 行时就停止遍历（哈希序），并在同一个字段
// 里给出**本次带出的行数**而不是表内总数，所以读侧无法从这份载荷判断表是否已经装满
// （契约 defect HTTP_UDP_PORT_TOTAL_IS_PACKED_COUNT）。行的顺序按端口升序，两次刷新可比。
func (h *APIHandlers) UdpPorts(w http.ResponseWriter, r *http.Request) {
	a := h.kernelSnapshot().Analysis
	n := packedRows(a.UDPPortCount, len(a.UDPPorts))
	ports := make([]UdpPortEntry, 0, n)
	for _, e := range a.UDPPorts[:n] {
		ports = append(ports, UdpPortEntry{
			Port:         e.Port,
			Packets:      e.Packets,
			Bytes:        e.Bytes,
			LastSeenSecs: e.LastSeenSecs,
		})
	}
	WriteSuccess(w, UdpPortDistributionResponse{
		Ports:        ports,
		TotalEntries: uint64(a.UDPPortCount),
		MaxEntries:   uint64(a.UDPPortCapacity),
	})
}

// IcmpTypes 返回 ICMP 类型分布（GET /api/v1/stats/icmp-types）。截断口径同 UDP。
func (h *APIHandlers) IcmpTypes(w http.ResponseWriter, r *http.Request) {
	a := h.kernelSnapshot().Analysis
	n := packedRows(a.ICMPTypeCount, len(a.ICMPTypes))
	types := make([]IcmpTypeEntry, 0, n)
	for _, e := range a.ICMPTypes[:n] {
		types = append(types, IcmpTypeEntry{
			Type:         e.Type,
			Code:         e.Code,
			Packets:      e.Packets,
			Bytes:        e.Bytes,
			LastSeenSecs: e.LastSeenSecs,
		})
	}
	WriteSuccess(w, IcmpTypeDistributionResponse{
		Types:        types,
		TotalEntries: uint64(a.ICMPTypeCount),
		MaxEntries:   uint64(a.ICMPTypeCapacity),
	})
}

// PortScanners 返回疑似端口扫描者（GET /api/v1/stats/port-scanners）。
func (h *APIHandlers) PortScanners(w http.ResponseWriter, r *http.Request) {
	a := h.kernelSnapshot().Analysis
	n := packedRows(a.PortScanCount, len(a.PortScanners))
	scanners := h.scannerRows(a.PortScanners[:n])
	WriteSuccess(w, PortScanResponse{
		Threshold: a.PortScanThreshold,
		// total_detected 是内核的**累计检出事件计数**（fw_info.port_scan_detected，
		// 每次判定 +1），与 scanners 的行数不是同一个量：后者只带最近活跃的前 20 个
		// 地址。两者的差异写进契约 defect HTTP_SCANNER_TOTAL_COUNT_ASYMMETRY。
		TotalDetected: a.PortScanCount,
		Scanners:      scanners,
	})
}

// ServiceProbes 返回多协议探测者（GET /api/v1/stats/service-probes）。
func (h *APIHandlers) ServiceProbes(w http.ResponseWriter, r *http.Request) {
	a := h.kernelSnapshot().Analysis
	n := packedRows(a.ServiceProbeCount, len(a.ServiceProbes))
	WriteSuccess(w, ServiceProbeResponse{
		Threshold: a.ServiceProbeThreshold,
		// 这一侧的 total_detected 是**本次快照带出的行数**（内核把 packed 计数放在同一个
		// 字段名下），与 PortScanners 的累计口径不同。字段按同名对齐是缺陷
		// HTTP_SERVICE_PROBE_NO_TOTAL 闭合时的形状，口径差异由
		// HTTP_SCANNER_TOTAL_COUNT_ASYMMETRY 记录，不在这里把两个量伪造成相等。
		TotalDetected: a.ServiceProbeCount,
		Probes:        h.probeRows(a.ServiceProbes[:n]),
	})
}

// Anomalies 返回全局流量偏离与 per-IP 行为离群（GET /api/v1/stats/anomalies）。
//
// 两路的基线各自来自一路真源，都不含任何猜测值：
//   - 全局用速率历史环（每问一次内核一个点，容量 ≈ 1 小时），当前值 = 最新一个点；
//     行数未达 analysis.MinGlobalSamples 时整段基线不给出，global_features 写成 null；
//   - per-IP 用**同一份快照**里的速率表做横向比较（当前这一批被跟踪地址之间的离群），
//     地址数未达 analysis.MinIPSamples 时列表为空。
//
// 这里没有任何判定会触发封禁：契约把这条路由定为只观测，封禁判据在 detect 与 decision
// 各自的阈值里，两者口径不同。
func (h *APIHandlers) Anomalies(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	out := AnomalyResponse{Timestamp: now.Unix()}

	// 全局：环内全部采样点（0 = 不限条数，取环里实际有的）。
	report := analysis.Deviate(globalFeatureMatrix(h.rateSamples(0)), analysis.MinGlobalSamples)
	out.GlobalSampleCount = uint64(report.Samples)
	if report.Ok {
		out.GlobalScore = report.Score
		out.GlobalDimensions = dimensionsToResponse(report.Dimensions)
		out.GlobalFeatures = featuresToResponse(report.Current)
		out.GlobalBaselineP50 = featuresToResponse(report.BaselineP50)
		out.GlobalBaselineP95 = featuresToResponse(report.BaselineP95)
	} else {
		// 样本不足时按契约的三种形状给：global_features 保持 nil（编码成 null，「本轮
		// 没有当前值」），两条基线与维度表是**空数组**而不是 null——前端对它们做
		// .map()，null 会让整页崩，而空数组只是少几根柱子。
		out.GlobalDimensions = []DimensionScore{}
		out.GlobalBaselineP50 = []FeatureValue{}
		out.GlobalBaselineP95 = []FeatureValue{}
	}

	out.IpAnomalies = ipAnomalies(h.kernelSnapshot())
	WriteSuccess(w, out)
}

// globalFeatureMatrix 把速率历史采样点摊成「9 个特征 × n 行」，最后一行是最新采样。
//
// 特征顺序必须与 analysis.GlobalAnomalyFeatures 逐字对应，偏移一格就会把 bps 当成 pps
// 比分位；本包 stats_test.go 的列序用例按名字表逐列核对，analysis/anomaly_test.go 核对
// Deviate 的维度名与列下标同序。
func globalFeatureMatrix(samples []telemetry.RateSample) analysis.FeatureMatrix {
	rows := make([][]float64, 0, len(samples))
	for _, s := range samples {
		rows = append(rows, []float64{
			float64(s.TotalPPS), float64(s.TotalBPS),
			float64(s.SynPPS), float64(s.UdpPPS), float64(s.IcmpPPS),
			float64(s.AckPPS), float64(s.RstPPS), float64(s.FinPPS),
			float64(s.TrackedIPs),
		})
	}
	return analysis.FeatureMatrix{Names: analysis.GlobalAnomalyFeatures, Rows: rows}
}

// ipFeatureMatrix 把一份速率表摊成横向可比对的特征矩阵。
func ipFeatureMatrix(entries []contract.RateEntry) analysis.FeatureMatrix {
	rows := make([][]float64, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, ipFeatureRow(e))
	}
	return analysis.FeatureMatrix{Names: analysis.IPAnomalyFeatures, Rows: rows}
}

// ipFeatureRow 取单个地址的当前行为特征。
//
// 三个 ratio 是「该地址自己流量里的占比」（0-1），不是绝对速率：绝对值已经由
// packets_per_sec 与 bytes_per_sec 两列表达，占比列要回答的是「它在做什么协议」，
// 一个纯 UDP 反射源与一个纯 SYN 扫描源的速率可以相同而意图相反。
// 速率为 0 时占比取 0 而不是除零。
func ipFeatureRow(e contract.RateEntry) []float64 {
	return []float64{
		float64(e.Packets), float64(e.Bytes),
		ratio(e.SynPackets, e.Packets),
		ratio(e.UDPPackets, e.Packets),
		ratio(e.ICMPPackets, e.Packets),
		float64(e.UniquePorts),
	}
}

func ratio(part, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total)
}

// ipAnomalies 给出同一批被跟踪地址之间的离群排名（分数降序，最多 MaxIPAnomalies 条）。
//
// 排在最前面的是「与同伴比最不像」的地址，而不是「流量最大」的地址：一个大流量正常源
// 在每一维上都被同批的多数地址比着，偏离分自然低。
func ipAnomalies(snap telemetry.Snapshot) []IpAnomalyEntry {
	entries := snap.Rates.Entries
	report := analysis.Deviate(ipFeatureMatrix(entries), analysis.MinIPSamples)
	if !report.Ok {
		return []IpAnomalyEntry{}
	}
	out := make([]IpAnomalyEntry, 0, len(report.RowScores))
	for i, score := range report.RowScores {
		if score < analysis.IPAnomalyMinScore || i >= len(entries) {
			continue
		}
		ip, err := entries[i].Addr.IP(entries[i].AF)
		if err != nil {
			continue
		}
		out = append(out, IpAnomalyEntry{
			IP:         ip.String(),
			Score:      score,
			Dimensions: dimensionsToResponse(report.Rows[i].Dimensions),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > analysis.MaxIPAnomalies {
		out = out[:analysis.MaxIPAnomalies]
	}
	return out
}

// packedRows 把内核给出的行数夹进定长数组的边界内。
//
// count 来自内核，理论上不会超过数组容量（两者由同一份契约生成），但读侧不能把「上游
// 没越界」当成前提：越界就是 slice panic，而这只影响一个统计面板。
func packedRows(count uint32, capacity int) int {
	if n := int(count); n < capacity {
		return n
	}
	return capacity
}

// scannerRows 把端口扫描者条目折成载荷；认不出的地址族同 ratesCurrent 一起跳过。
func (h *APIHandlers) scannerRows(items []contract.ScannerItem) []PortScannerEntry {
	out := make([]PortScannerEntry, 0, len(items))
	skipped := 0
	for _, s := range items {
		ip, err := s.Addr.IP(s.AF)
		if err != nil {
			skipped++
			continue
		}
		out = append(out, PortScannerEntry{
			IP:          ip.String(),
			UniquePorts: s.Metric,
			Packets:     s.Packets,
		})
	}
	if skipped > 0 {
		h.server.logger.Warn("端口扫描者条目地址族无法识别，已跳过", "count", skipped)
	}
	return out
}

func (h *APIHandlers) probeRows(items []contract.ScannerItem) []ServiceProbeEntry {
	out := make([]ServiceProbeEntry, 0, len(items))
	skipped := 0
	for _, s := range items {
		ip, err := s.Addr.IP(s.AF)
		if err != nil {
			skipped++
			continue
		}
		out = append(out, ServiceProbeEntry{
			IP:            ip.String(),
			ProtocolCount: s.Metric,
			Packets:       s.Packets,
		})
	}
	if skipped > 0 {
		h.server.logger.Warn("服务探测者条目地址族无法识别，已跳过", "count", skipped)
	}
	return out
}

func dimensionsToResponse(dims []analysis.Dimension) []DimensionScore {
	out := make([]DimensionScore, 0, len(dims))
	for _, d := range dims {
		out = append(out, DimensionScore{Name: d.Name, Score: d.Score})
	}
	return out
}

func featuresToResponse(feats []analysis.Feature) []FeatureValue {
	out := make([]FeatureValue, 0, len(feats))
	for _, f := range feats {
		out = append(out, FeatureValue{Name: f.Name, Value: f.Value})
	}
	return out
}

// uint64Slice 复制一段计数，让载荷里的切片不与快照数组共享底层内存。
func uint64Slice(src []uint64) []uint64 {
	out := make([]uint64, len(src))
	copy(out, src)
	return out
}

func sumCounts(counts []uint64) uint64 {
	var total uint64
	for _, c := range counts {
		total += c
	}
	return total
}

// labelsOf 复制标签表：内核的标签是 Go 包级变量，直接交给编码器等于把可写的表暴露给
// 包外——改一格就会在所有后续响应里生效。
func labelsOf(src []string) []string {
	out := make([]string, len(src))
	copy(out, src)
	return out
}
