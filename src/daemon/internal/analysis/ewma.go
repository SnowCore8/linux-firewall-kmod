// Package analysis 的 EWMA 子模块：多窗口指数加权移动平均平滑器，用于从内核 procfs
// 读取的速率数据中检测异常流量趋势。
//
// 设计目标：
//   - 短期窗口（5s）捕捉突发流量尖峰
//   - 中期窗口（60s）识别持续性攻击趋势
//   - 长期窗口（300s）建立正常流量基线
//   - 动态基线学习（α=0.01）适应流量模式缓慢变化
//   - 业务高峰期（9-18 UTC）基线上调 50% 避免误报
//   - 异常基线检测：流量 > 基线×3 时冻结 EWMA 更新 5 分钟，防止异常值污染基线
package analysis

import (
	"sync"
	"time"
)

// 窗口常量。
const (
	// ShortWindow 短期窗口秒数：捕捉突发。
	ShortWindow = 5
	// MediumWindow 中期窗口秒数：识别趋势。
	MediumWindow = 60
	// LongWindow 长期窗口秒数：建立基线。
	LongWindow = 300

	// BaselineAlpha 基线学习系数：越小越平滑，抗噪声越强。
	BaselineAlpha = 0.01
	// PeakMultiplier 高峰期基线上调系数。
	PeakMultiplier = 1.5
	// AnomalyMultiplier 异常判定倍数：流量超过基线此倍数时冻结更新。
	AnomalyMultiplier = 3.0
	// FreezeDurationSecs 异常冻结时长（秒）。
	FreezeDurationSecs = 300
)

// EWMASmoother 是多窗口 EWMA 平滑器。
//
// 每个窗口独立维护一个 EWMA 值，输入为每秒采样速率。短期窗口对突发敏感，长期窗口
// 提供稳定基线。三者联合判定异常：短期远超长期时触发告警。
type EWMASmoother struct {
	mu sync.Mutex

	// 各窗口 EWMA 值。
	shortVal  float64
	mediumVal float64
	longVal   float64

	// 各窗口平滑系数（α = 2/(N+1)，N 为窗口秒数）。
	shortAlpha  float64
	mediumAlpha float64
	longAlpha   float64

	// 是否已收到首个样本（首样本直接赋值，不做平滑）。
	initialized bool

	// 动态基线：长期 EWMA 的慢速跟踪值。
	baseline float64
	// 基线是否处于冻结状态（异常值污染防护）。
	frozen      bool
	frozenUntil time.Time

	// 最近一次采样时间戳（用于判断采样间隔）。
	lastSampleAt time.Time
}

// NewEWMASmoother 创建多窗口 EWMA 平滑器。
func NewEWMASmoother() *EWMASmoother {
	return &EWMASmoother{
		shortAlpha:  2.0 / (float64(ShortWindow) + 1),
		mediumAlpha: 2.0 / (float64(MediumWindow) + 1),
		longAlpha:   2.0 / (float64(LongWindow) + 1),
	}
}

// Sample 喂入一个速率样本（每秒事件数）。
//
// 首样本直接初始化所有窗口；后续样本按各窗口 α 做指数加权平滑。
// 当样本值超过基线×AnomalyMultiplier 时，冻结基线更新 FreezeDurationSecs 秒，
// 防止异常值污染长期基线。
func (s *EWMASmoother) Sample(rate float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	if !s.initialized {
		s.shortVal = rate
		s.mediumVal = rate
		s.longVal = rate
		s.baseline = rate
		s.initialized = true
		s.lastSampleAt = now
		return
	}

	// 检查是否解除冻结。
	if s.frozen && now.After(s.frozenUntil) {
		s.frozen = false
	}

	// 标准 EWMA 更新：new = α × input + (1-α) × old。
	s.shortVal = s.shortAlpha*rate + (1-s.shortAlpha)*s.shortVal
	s.mediumVal = s.mediumAlpha*rate + (1-s.mediumAlpha)*s.mediumVal
	s.longVal = s.longAlpha*rate + (1-s.longAlpha)*s.longVal

	// 基线更新：仅在未冻结且样本未超过异常阈值时执行。
	effectiveBaseline := s.baseline
	if isPeakHours(now) {
		effectiveBaseline *= PeakMultiplier
	}

	if !s.frozen && rate <= effectiveBaseline*AnomalyMultiplier {
		s.baseline = BaselineAlpha*rate + (1-BaselineAlpha)*s.baseline
	} else if !s.frozen && rate > effectiveBaseline*AnomalyMultiplier {
		// 异常值：冻结基线更新。
		s.frozen = true
		s.frozenUntil = now.Add(FreezeDurationSecs * time.Second)
	}

	s.lastSampleAt = now
}

// Snapshot 返回当前各窗口 EWMA 值与基线的快照。
func (s *EWMASmoother) Snapshot() EWMASnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	effectiveBaseline := s.baseline
	if isPeakHours(time.Now()) {
		effectiveBaseline *= PeakMultiplier
	}

	return EWMASnapshot{
		Short:             s.shortVal,
		Medium:            s.mediumVal,
		Long:              s.longVal,
		Baseline:          s.baseline,
		EffectiveBaseline: effectiveBaseline,
		Frozen:            s.frozen,
		Initialized:       s.initialized,
	}
}

// IsAnomalous 判断当前短期速率是否异常（短期 > 基线×倍数）。
//
// multiplier 为判定倍数，传 0 时使用默认 AnomalyMultiplier。
// 未初始化时返回 false。
func (s *EWMASmoother) IsAnomalous(multiplier float64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized {
		return false
	}
	if multiplier <= 0 {
		multiplier = AnomalyMultiplier
	}

	effectiveBaseline := s.baseline
	if isPeakHours(time.Now()) {
		effectiveBaseline *= PeakMultiplier
	}

	return s.shortVal > effectiveBaseline*multiplier
}

// AnomalyLevel 返回异常严重程度：0=正常，1=轻度（>2×），2=中度（>3×），3=严重（>5×）。
func (s *EWMASmoother) AnomalyLevel() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized || s.baseline <= 0 {
		return 0
	}

	effectiveBaseline := s.baseline
	if isPeakHours(time.Now()) {
		effectiveBaseline *= PeakMultiplier
	}
	if effectiveBaseline <= 0 {
		return 0
	}

	ratio := s.shortVal / effectiveBaseline
	switch {
	case ratio > 5:
		return 3
	case ratio > 3:
		return 2
	case ratio > 2:
		return 1
	default:
		return 0
	}
}

// EWMASnapshot 是平滑器的只读快照。
type EWMASnapshot struct {
	// Short 短期窗口 EWMA（5s）。
	Short float64 `json:"short_ewma"`
	// Medium 中期窗口 EWMA（60s）。
	Medium float64 `json:"medium_ewma"`
	// Long 长期窗口 EWMA（300s）。
	Long float64 `json:"long_ewma"`
	// Baseline 原始基线值。
	Baseline float64 `json:"baseline"`
	// EffectiveBaseline 考虑高峰期上调后的有效基线。
	EffectiveBaseline float64 `json:"effective_baseline"`
	// Frozen 基线是否处于冻结状态。
	Frozen bool `json:"frozen"`
	// Initialized 是否已收到首个样本。
	Initialized bool `json:"initialized"`
}

// TrendDirection 返回中期窗口相对长期窗口的趋势方向。
func (snap EWMASnapshot) TrendDirection() string {
	if !snap.Initialized {
		return "unknown"
	}
	if snap.Long <= 0 {
		return "stable"
	}
	ratio := snap.Medium / snap.Long
	switch {
	case ratio > 1.5:
		return "rising"
	case ratio < 0.5:
		return "falling"
	default:
		return "stable"
	}
}

// ShortBurstRatio 返回短期窗口相对有效基线的倍数。
func (snap EWMASnapshot) ShortBurstRatio() float64 {
	if snap.EffectiveBaseline <= 0 {
		return 0
	}
	return snap.Short / snap.EffectiveBaseline
}

// isPeakHours 判断给定时间是否处于业务高峰期（9-18 UTC）。
func isPeakHours(t time.Time) bool {
	hour := t.UTC().Hour()
	return hour >= 9 && hour < 18
}

// RateSampler 从外部数据源按固定间隔采样速率并喂给 EWMA 平滑器。
//
// 典型用法：每秒从 procfs 读取累计计数，计算差值作为速率，喂给 Sample。
type RateSampler struct {
	smoother  *EWMASmoother
	lastCount uint64
	lastTime  time.Time
}

// NewRateSampler 创建速率采样器，绑定到指定的 EWMA 平滑器。
func NewRateSampler(smoother *EWMASmoother) *RateSampler {
	return &RateSampler{smoother: smoother}
}

// Observe 喂入一个累计计数样本，自动计算速率并更新平滑器。
//
// 首样本只记录基准，不产生速率；后续样本按时间差计算每秒速率。
func (r *RateSampler) Observe(count uint64) {
	now := time.Now()
	if r.lastTime.IsZero() {
		r.lastCount = count
		r.lastTime = now
		return
	}

	elapsed := now.Sub(r.lastTime).Seconds()
	if elapsed <= 0 {
		return
	}

	delta := float64(count - r.lastCount)
	if count < r.lastCount {
		// 计数器回绕（重启/溢出）：重置基准。
		delta = 0
	}
	rate := delta / elapsed

	r.smoother.Sample(rate)
	r.lastCount = count
	r.lastTime = now
}

// MultiJailEWMA 为多个 jail 各自维护独立的 EWMA 平滑器。
type MultiJailEWMA struct {
	mu       sync.RWMutex
	smothers map[string]*EWMASmoother
}

// NewMultiJailEWMA 创建多 jail EWMA 管理器。
func NewMultiJailEWMA() *MultiJailEWMA {
	return &MultiJailEWMA{
		smothers: make(map[string]*EWMASmoother),
	}
}

// GetOrCreate 获取或创建指定 jail 的 EWMA 平滑器。
func (m *MultiJailEWMA) GetOrCreate(jail string) *EWMASmoother {
	m.mu.RLock()
	s, ok := m.smothers[jail]
	m.mu.RUnlock()
	if ok {
		return s
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// double-check：避免并发创建。
	if s, ok = m.smothers[jail]; ok {
		return s
	}
	s = NewEWMASmoother()
	m.smothers[jail] = s
	return s
}

// AllSnapshots 返回所有 jail 的 EWMA 快照。
func (m *MultiJailEWMA) AllSnapshots() map[string]EWMASnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]EWMASnapshot, len(m.smothers))
	for jail, s := range m.smothers {
		result[jail] = s.Snapshot()
	}
	return result
}

// AnomalousJails 返回当前处于异常状态的 jail 列表。
func (m *MultiJailEWMA) AnomalousJails() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var anomalous []string
	for jail, s := range m.smothers {
		if s.IsAnomalous(0) {
			anomalous = append(anomalous, jail)
		}
	}
	return anomalous
}
