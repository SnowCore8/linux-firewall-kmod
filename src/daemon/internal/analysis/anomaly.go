// 异常检测：把「一批同尺度的观测行」和它们自己的分位基线相比，给出逐维偏差分。
//
// 只观测、不判定封禁：这里的输出全部进面板，没有任何一条路径会因为它而封 IP（封禁判定
// 在 decision 与 detect 里，各自的阈值口径不同）。
//
// 基线用 p50/p95 而不是均值/标准差：速率类特征都是重尾分布（一次突发能把均值抬高一个
// 量级），均值±σ 在真实流量下几乎永远不会触发，而分位数对离群值天然稳健。spread = p95-p50
// 为 0（同分布的一列全等值）时不除零：值不超过 p95 记 0 分，超过记满 1 分——恒定流量突然
// 出现任何非零偏离本来就是最强的信号。
package analysis

import (
	"math"
	"sort"
)

// 两套维度名表：全局按速率样本的列，per-IP 按速率表的单条目。
//
// 名字会原样进契约载荷的 DimensionScore.name 与 FeatureValue.name，因此这里是**唯一**
// 一份定义；面板按名字对齐标签，改名要同步 frontend。
var (
	// GlobalAnomalyFeatures 是全局流量的维度名，与 GlobalFeatureRow 的取值顺序一一对应。
	GlobalAnomalyFeatures = []string{
		"total_pps", "total_bps",
		"syn_pps", "udp_pps", "icmp_pps", "ack_pps", "rst_pps", "fin_pps",
		"tracked_ips",
	}

	// IPAnomalyFeatures 是单个源地址的维度名，与 IPFeatureRow 的取值顺序一一对应。
	IPAnomalyFeatures = []string{
		"packets_per_sec", "bytes_per_sec",
		"syn_ratio", "udp_ratio", "icmp_ratio",
		"unique_ports",
	}
)

// 样本护栏与输出上限。
const (
	// MinGlobalSamples 是全局基线可用的最小样本数。低于它时**不给出**任何基线，
	// 而不是给一份半截基线：刚启动的守护进程只有三五个点，p95 就等于最大值本身，
	// 任何一点噪声都会被读成满格偏离。
	MinGlobalSamples = 10
	// MinIPSamples 是 per-IP 群体基线的最小地址数。少于它时没有「同批可比」的对象。
	MinIPSamples = 5
	// MaxIPAnomalies 是 per-IP 列表的长度上限（契约 AnomalyResponse.ip_anomalies 注释）。
	MaxIPAnomalies = 20
	// IPAnomalyMinScore 是进入 per-IP 列表的最低综合分（0-100）。
	//
	// 有下限才不会把整张速率表都倒进面板：p50 之上的那一半地址按定义多少都有正偏离，
	// 全列出来等于没有信息。
	IPAnomalyMinScore = 20
)

// Feature 是一个命名特征值。
type Feature struct {
	Name  string
	Value float64
}

// Dimension 是一个维度的偏差分（0-1）。
type Dimension struct {
	Name  string
	Score float64
}

// FeatureMatrix 是「一组命名特征 × 若干观测行」。
//
// Rows 的**最后一行**被视为当前值，其余各行（含它自己）一起参与分位基线计算——基线与
// 当前值同源才可比，用「历史算基线、当前值另取一路」会引入两套采样时刻。
type FeatureMatrix struct {
	Names []string
	Rows  [][]float64
}

// RowDeviation 是一行的逐维偏差。
type RowDeviation struct {
	Dimensions []Dimension
}

// DeviationReport 是一次偏离计算的结果。
//
// Ok=false 表示行数未达护栏：此时基线与维度表都是空的，调用方必须把「没有基线」原样
// 传给读侧（契约里 global_features 为 null 就是这个意思），而不是把零当成读数。
type DeviationReport struct {
	Ok          bool
	Samples     int
	BaselineP50 []Feature
	BaselineP95 []Feature
	// Current 是最后一行（当前值）的命名特征，与两条基线同一个名字表：读侧把三列并排
	// 画出来才能看出「现在这一格相对基线偏了多少」。
	Current []Feature
	// Dimensions 与 Score 属于最后一行（当前值）。
	Dimensions []Dimension
	Score      float64
	// Rows 与 RowScores 与入参 Rows 一一对齐。
	Rows      []RowDeviation
	RowScores []float64
}

// Deviate 按列取 p50/p95 基线，给出每一行相对基线的偏差分。
//
// minSamples 是行数护栏（< minSamples 时 Ok=false）。
//
// 同一个函数服务两路读法：全局把「时间序列」当行（最后一行 = 当前时刻），per-IP 把
// 「同一批地址」当行（Rows/RowScores 逐行对齐入参，调用方按行号回填地址）。
func Deviate(m FeatureMatrix, minSamples int) DeviationReport {
	n := len(m.Rows)
	if minSamples < 1 {
		minSamples = 1
	}
	if n < minSamples || len(m.Names) == 0 {
		return DeviationReport{Samples: n}
	}

	p50 := make([]float64, len(m.Names))
	p95 := make([]float64, len(m.Names))
	for col := range m.Names {
		column := make([]float64, 0, n)
		for _, row := range m.Rows {
			column = append(column, valueAt(row, col))
		}
		p50[col] = percentile(column, 0.50)
		p95[col] = percentile(column, 0.95)
	}

	out := DeviationReport{
		Ok:          true,
		Samples:     n,
		BaselineP50: nameValues(m.Names, p50),
		BaselineP95: nameValues(m.Names, p95),
		Current:     nameValues(m.Names, m.Rows[n-1]),
		Rows:        make([]RowDeviation, n),
		RowScores:   make([]float64, n),
	}
	for i, row := range m.Rows {
		dims := make([]Dimension, len(m.Names))
		sum := 0.0
		for col, name := range m.Names {
			s := deviation(valueAt(row, col), p50[col], p95[col])
			dims[col] = Dimension{Name: name, Score: s}
			sum += s
		}
		out.Rows[i] = RowDeviation{Dimensions: dims}
		out.RowScores[i] = sum / float64(len(dims)) * 100
	}
	out.Dimensions = out.Rows[n-1].Dimensions
	out.Score = out.RowScores[n-1]
	return out
}

// deviation 把当前值折成 0-1 的偏差分：p50 及以下为 0，p95 及以上为 1。
func deviation(v, p50, p95 float64) float64 {
	spread := p95 - p50
	if spread <= 0 || math.IsNaN(spread) {
		if v > p95 {
			return 1
		}
		return 0
	}
	ratio := (v - p50) / spread
	switch {
	case ratio <= 0:
		return 0
	case ratio >= 1:
		return 1
	default:
		return ratio
	}
}

// percentile 取最近秩分位数（对已拷贝的切片排序，不碰调用方的行）。
//
// 用最近秩而不是插值：这里的答案只服务于「偏离了多少」这一视觉判断，插值带来的那点
// 平滑不会改变结论，而它会让 p50 落在两个真实样本之间，图上读不出对应时刻。
func percentile(values []float64, q float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	idx := int(math.Round(q * float64(len(sorted)-1)))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// valueAt 越界取 0：某一行短于特征名表说明产出方漏了维度，缺的那一列按「没有观测」记，
// 而不是让整个报告失败——一列缺失只影响那一维的分。
func valueAt(row []float64, col int) float64 {
	if col < 0 || col >= len(row) {
		return 0
	}
	return row[col]
}

func nameValues(names []string, values []float64) []Feature {
	out := make([]Feature, 0, len(names))
	for i, name := range names {
		out = append(out, Feature{Name: name, Value: valueAt(values, i)})
	}
	return out
}
