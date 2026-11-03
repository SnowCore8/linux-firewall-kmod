// Package risk 实现多维风险向量引擎：事件分类、向量衰减、阈值判定。
//
// 设计目标：
//   - 纯函数可测试：DecayFactor、ClassifyFailure 不依赖任何状态
//   - 事件溯源：每次攻击事件持久化，向量可重算
//   - 加法阈值模型：修复旧乘法模型的系数抵消 Bug
package risk

// EventType 枚举攻击事件类型。
//
// 每种类型对应 RiskVector 的一个维度，独立衰减、独立权重。
type EventType string

const (
	// EventFailure 认证失败（SSH 密码错误、HTTP 401 等）。
	EventFailure EventType = "failure"
	// EventBan 被封禁历史（每次封禁记录一次）。
	EventBan EventType = "ban"
	// EventScan 扫描行为（端口扫描、目录遍历等）。
	EventScan EventType = "scan"
	// EventBruteforce 爆破行为（高频认证失败）。
	EventBruteforce EventType = "bruteforce"
	// EventDDoS DDoS 行为（流量型攻击）。
	EventDDoS EventType = "ddos"
	// EventGeo 异常地域（境外访问、非常用 IP 段）。
	EventGeo EventType = "geo"
	// EventCluster 关联集群（与已知恶意 IP 关联）。
	EventCluster EventType = "cluster"
)

// AllEventTypes 返回所有事件类型（用于校验、遍历）。
func AllEventTypes() []EventType {
	return []EventType{
		EventFailure,
		EventBan,
		EventScan,
		EventBruteforce,
		EventDDoS,
		EventGeo,
		EventCluster,
	}
}

// RiskVector 是多维风险向量，每个维度独立衰减。
//
// 向量值范围 [0, +∞)，典型值 [0, 100]。衰减后半衰期 7 天。
type RiskVector struct {
	Failure    float64 `json:"failure"`
	Ban        float64 `json:"ban"`
	Scan       float64 `json:"scan"`
	Bruteforce float64 `json:"bruteforce"`
	DDoS       float64 `json:"ddos"`
	Geo        float64 `json:"geo"`
	Cluster    float64 `json:"cluster"`
}

// Add 累加另一个向量（事件增量）。
func (v *RiskVector) Add(other RiskVector) {
	v.Failure += other.Failure
	v.Ban += other.Ban
	v.Scan += other.Scan
	v.Bruteforce += other.Bruteforce
	v.DDoS += other.DDoS
	v.Geo += other.Geo
	v.Cluster += other.Cluster
}

// Decay 对向量施加衰减（半衰期 7 天）。
//
// days 是自上次事件以来的天数。衰减后每个维度独立乘以 DecayFactor(days)。
func (v *RiskVector) Decay(days float64) {
	factor := DecayFactor(days)
	v.Failure *= factor
	v.Ban *= factor
	v.Scan *= factor
	v.Bruteforce *= factor
	v.DDoS *= factor
	v.Geo *= factor
	v.Cluster *= factor
}

// Total 返回向量各维度的加权和（用于阈值判定）。
//
// 权重由 DimensionWeights 配置，默认均为 1.0。
func (v *RiskVector) Total(weights DimensionWeights) float64 {
	return v.Failure*weights.Failure +
		v.Ban*weights.Ban +
		v.Scan*weights.Scan +
		v.Bruteforce*weights.Bruteforce +
		v.DDoS*weights.DDoS +
		v.Geo*weights.Geo +
		v.Cluster*weights.Cluster
}

// IsZero 报告向量是否全为 0（无风险）。
func (v *RiskVector) IsZero() bool {
	return v.Failure == 0 &&
		v.Ban == 0 &&
		v.Scan == 0 &&
		v.Bruteforce == 0 &&
		v.DDoS == 0 &&
		v.Geo == 0 &&
		v.Cluster == 0
}

// DimensionWeights 配置各维度权重（用于计算加权和）。
//
// 默认值均为 1.0，可通过配置文件调整。权重越大，该维度对总风险的贡献越大。
type DimensionWeights struct {
	Failure    float64 `json:"failure" yaml:"failure"`
	Ban        float64 `json:"ban" yaml:"ban"`
	Scan       float64 `json:"scan" yaml:"scan"`
	Bruteforce float64 `json:"bruteforce" yaml:"bruteforce"`
	DDoS       float64 `json:"ddos" yaml:"ddos"`
	Geo        float64 `json:"geo" yaml:"geo"`
	Cluster    float64 `json:"cluster" yaml:"cluster"`
}

// DefaultDimensionWeights 返回默认权重（均为 1.0）。
func DefaultDimensionWeights() DimensionWeights {
	return DimensionWeights{
		Failure:    1.0,
		Ban:        1.0,
		Scan:       1.0,
		Bruteforce: 1.0,
		DDoS:       1.0,
		Geo:        1.0,
		Cluster:    1.0,
	}
}
