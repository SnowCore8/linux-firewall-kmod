package risk

import "math"

// HalfLifeDays 是向量衰减的半衰期（天）。
//
// 7 天后风险值减半，30 天后降至约 6.25%（0.5^(30/7)）。
const HalfLifeDays = 7.0

// DecayFactor 计算指数衰减因子。
//
// 公式：0.5^(days/HalfLifeDays)
//
//	days == 0 → 1.0（无衰减）
//	days == 7 → 0.5（半衰期）
//	days == 30 → ~0.0625（30 天后降至 6.25%）
//
// 纯函数，不依赖任何状态，便于测试。
func DecayFactor(days float64) float64 {
	if days <= 0 {
		return 1.0
	}
	return math.Pow(0.5, days/HalfLifeDays)
}

// DaysSince 计算自 lastEventAt（Unix 秒）至 now（Unix 秒）的天数。
//
// 用于 DecayFactor 的输入。now < lastEventAt 时返回 0（不衰减）。
func DaysSince(now, lastEventAt int64) float64 {
	if now <= lastEventAt {
		return 0
	}
	return float64(now-lastEventAt) / 86400.0
}
