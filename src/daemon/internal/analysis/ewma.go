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
	"math"
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

	// 是否已收到首个样本（首样本直接赋值，不做平滑）。
	initialized bool

	// 动态基线：长期 EWMA 的慢速跟踪值。
	baseline float64
	// 基线是否处于冻结状态（异常值污染防护）。
	frozen      bool
	frozenUntil time.Time

	// 最近一次与首次采样时间戳：前者换算采样间隔，后者判断基线是否已预热。
	lastSampleAt  time.Time
	firstSampleAt time.Time
}

// warmupDuration 是基线预热期：这段时间内不报异常，冻结机制也不生效。
//
// 首样本到长期基线收敛之间，short 已经跟上真实流量而 baseline 还停在初始值，
// 比值天然很大；此时若按「超过基线×3」冻结，基线会被钉在初始值附近，解冻后又
// 立刻重新触发，守卫能持续很久。预热期取长期窗口长度，期间无条件学习基线。
const warmupDuration = LongWindow * time.Second

// NewEWMASmoother 创建多窗口 EWMA 平滑器。
func NewEWMASmoother() *EWMASmoother {
	return &EWMASmoother{}
}

// decayAlpha 返回采样间隔 dt 秒的等效 EWMA 系数。
//
// 窗口 N 秒的 1 Hz 系数是 α=2/(N+1)，跨 dt 秒的等效系数是 1-(1-α)^dt。
// 写死 1 Hz 系数、却按 5 秒喂样本，会把 5s/60s/300s 三个窗口分别放大成
// 约 25s/5min/25min。
func decayAlpha(dt float64, windowSecs int) float64 {
	if dt <= 0 {
		dt = 1
	}
	alpha1 := 2 / (float64(windowSecs) + 1)
	return 1 - math.Pow(1-alpha1, dt)
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
		s.firstSampleAt = now
		s.lastSampleAt = now
		return
	}

	// 检查是否解除冻结。
	if s.frozen && now.After(s.frozenUntil) {
		s.frozen = false
	}

	// 标准 EWMA 更新：new = α(dt) × input + (1-α(dt)) × old。
	dt := now.Sub(s.lastSampleAt).Seconds()
	shortA := decayAlpha(dt, ShortWindow)
	mediumA := decayAlpha(dt, MediumWindow)
	longA := decayAlpha(dt, LongWindow)
	s.shortVal = shortA*rate + (1-shortA)*s.shortVal
	s.mediumVal = mediumA*rate + (1-mediumA)*s.mediumVal
	s.longVal = longA*rate + (1-longA)*s.longVal

	// 基线更新：仅在未冻结且样本未超过异常阈值时执行。
	//
	// 冻结判据的参照取 baseline 与 longVal 的较大者：baseline 以 α=0.01 学习，
	// 启动/长时间空闲后仍在 0 附近，此时任何非零流量都会「超过基线×3」并把基线
	// 钉死在初始值。longVal 在一个长期窗口内就完成收敛，用它兜住收敛期。
	reference := s.baseline
	if s.longVal > reference {
		reference = s.longVal
	}
	if PeakHours(now) {
		reference *= PeakMultiplier
	}

	baselineAlpha := 1 - math.Pow(1-BaselineAlpha, dt) // 与 1 Hz 的 BaselineAlpha 同源
	warming := now.Sub(s.firstSampleAt) < warmupDuration
	if !s.frozen && (warming || reference <= 0 || rate <= reference*AnomalyMultiplier) {
		s.baseline = baselineAlpha*rate + (1-baselineAlpha)*s.baseline
	} else if !s.frozen {
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

	now := time.Now()
	effectiveBaseline := s.baseline
	if PeakHours(now) {
		effectiveBaseline *= PeakMultiplier
	}

	return EWMASnapshot{
		Short:             s.shortVal,
		Medium:            s.mediumVal,
		Long:              s.longVal,
		Baseline:          s.baseline,
		EffectiveBaseline: effectiveBaseline,
		// 冻结的解除只在 Sample 里发生；采样停止（链路断开）时不能一直报 frozen。
		Frozen:      s.frozen && now.Before(s.frozenUntil),
		Initialized: s.initialized,
	}
}

// AnomalyLevel 返回异常严重程度：0=正常，1=轻度（>2×），2=中度（>3×），3=严重（>5×）。
func (s *EWMASmoother) AnomalyLevel() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized || s.baseline <= 0 {
		return 0
	}
	// 预热期内基线还没收敛，short/baseline 的比值没有意义。
	if time.Since(s.firstSampleAt) < warmupDuration {
		return 0
	}

	effectiveBaseline := s.baseline
	if PeakHours(time.Now()) {
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

// PeakHours 判断给定时间是否处于业务高峰期（9-18 UTC）。
//
// 这条判据同时决定 EWMA 基线是否上调 50% 和威胁评估载荷的 peak_hours 字段，所以只有
// 一个函数：留一份未导出的副本，两处「高峰期」的口径就会各自漂移，而它直接改变告警数量。
func PeakHours(t time.Time) bool {
	hour := t.UTC().Hour()
	return hour >= 9 && hour < 18
}
