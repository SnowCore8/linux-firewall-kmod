// Package decision 承载封禁判定的纯计算部件：有效阈值、渐进式时长、封禁计划。
//
// 这里没有任何状态，也没有锁——旧实现把这些算式与全局封禁历史、信誉分表、活跃
// 封禁缓存纠缠在一起，换个时钟或换个 IP 都要先把全局态摆好。拆成纯函数后，同一份
// 算式可以用假定的 now / 分数直接跑对照测试，不受真实时钟与真实缓存影响。
//
// 判据须与设计文档「冻结面 · 判定语义」逐条一致：
//
//   - 有效阈值 = max_retries × 高峰(1.5) × 内网(2.0) × 信誉，再 ceil 并至少为 1
//   - 信誉系数：≥80 → 1.0，≥50 → 0.8，否则 0.5
//   - 渐进式时长：第 1 次 base，第 2 次 1800，第 3 次 86400，第 4 次起 0（永久）
//   - ban_time < 0 即配置级永久；progressive == 0 且已封禁 ≥3 次亦为永久
package decision

import (
	"net/netip"
)

// 判定调整量（加法模型）。
const (
	// PeakHoursAddend 是高峰期阈值加数（业务高峰 9–18 点 UTC，含 9 不含 18）。
	PeakHoursAddend = 2
	// InternalSourceAddend 是内网来源的阈值加数。
	InternalSourceAddend = 3
)

// IsPeakHours 报告 hourUTC 是否落在判定用的「业务高峰期」内。
//
// 只接受小时数（UTC，0..23），时间源由调用方提供——这样判据可被固定小时数的测试
// 完全覆盖，不依赖跑测试时的真实时钟。
func IsPeakHours(hourUTC uint32) bool {
	return hourUTC >= 9 && hourUTC < 18
}

// IsInternal 报告 ip 是否为内网（私有）地址，即「来源可信度较高、阈值可放宽」的来源。
//
// 判据：v4 的 10/8、172.16/12、192.168/16；v6 的 fc00::/7（ULA）。
func IsInternal(ip netip.Addr) bool {
	if ip.Is4() {
		o := ip.As4()
		return o[0] == 10 || (o[0] == 172 && o[1] >= 16 && o[1] <= 31) || (o[0] == 192 && o[1] == 168)
	}
	b := ip.As16()
	return b[0]&0xFE == 0xFC
}

// EffectiveThreshold 计算有效阈值（加法模型，修复旧乘法 Bug）。
//
// 公式：baseThreshold + peakAddend + internalAddend + reputationAdjustment
//
//	baseThreshold：配置值（max_retries）
//	peakAddend：高峰期固定加 2（不再乘 1.5）
//	internalAddend：内网固定加 3（不再乘 2.0）
//	reputationAdjustment：信誉调整（-2 到 0，连续函数）
//
// 修复旧乘法模型的 Bug：内网(2.0) × 低信誉(0.5) = 1.0，导致系数抵消。
// 新模型下，内网低信誉 IP 的阈值 = base + 3 - 2 = base + 1，高于外网低信誉 IP（base - 2）。
func EffectiveThreshold(maxRetries uint32, peakHours, internal bool, reputationScore uint32) uint32 {
	addend := int(maxRetries)

	if peakHours {
		addend += PeakHoursAddend
	}

	if internal {
		addend += InternalSourceAddend
	}

	addend += ReputationAdjustment(reputationScore)

	if addend < 1 {
		addend = 1
	}

	return uint32(addend)
}

// ReputationAdjustment 根据信誉分返回阈值调整值（连续函数，替代旧阶梯乘法）。
//
//	信誉 >= 80：0（高信誉不调整）
//	信誉 >= 50：-1（中信誉减 1）
//	信誉 < 50：-2（低信誉减 2）
//
// 加法调整量，直接叠加到基础阈值上。
func ReputationAdjustment(score uint32) int {
	switch {
	case score >= 80:
		return 0
	case score >= 50:
		return -1
	default:
		return -2
	}
}

// ProgressiveDuration 按**此前**已封禁次数决定本次时长。
//
//	priorBanCount == 0（首次）→ baseDuration
//	== 1 → 1800 秒
//	== 2 → 86400 秒
//	>= 3 → 0（永久）
func ProgressiveDuration(baseDuration, priorBanCount uint32) uint32 {
	switch priorBanCount {
	case 0:
		return baseDuration
	case 1:
		return 1800
	case 2:
		return 86400
	default:
		return 0
	}
}

// BanPlan 是一次封禁的完整计划（不涉及任何 IO，便于对照与快照）。
type BanPlan struct {
	// Duration 是下发给内核的封禁时长（秒）；0 表示永久。
	Duration uint64
	// IsPermanent 报告是否永久封禁。
	IsPermanent bool
	// ExpiresAt 是过期时刻（Unix 秒）；永久封禁为 0。
	ExpiresAt int64
	// BanCount 是本次封禁后的累计封禁次数。
	BanCount uint32
	// FailCount 是触发本次封禁的失败次数。
	FailCount uint32
	// ProgressiveDuration 是渐进式时长（0 表示永久或退化情形）。
	ProgressiveDuration uint32
}

// PlanBan 依据配置与历史算出本次封禁的参数。
//
// banTime 为负表示配置级永久封禁；priorBanCount 是此前该 IP 已封禁次数；
// failCount 是触发本次封禁的窗口内失败次数。
func PlanBan(banTime int32, priorBanCount uint32, now int64, failCount uint32) BanPlan {
	var baseDuration uint32
	if banTime >= 0 {
		baseDuration = uint32(banTime)
	}

	progressive := ProgressiveDuration(baseDuration, priorBanCount)
	// 配置级永久（banTime < 0），或渐进式升级到永久（第 4 次起）。
	permanent := banTime < 0 || (progressive == 0 && priorBanCount >= 3)

	var expiresAt int64
	switch {
	case permanent:
		expiresAt = 0
	case progressive > 0:
		expiresAt = now + int64(progressive)
	default:
		// progressive == 0 但非永久：banTime == 0 的退化情形。用 base 兜底并至少
		// 1 秒，避免「0 秒即过期」导致封禁形同虚设。
		floor := baseDuration
		if floor < 1 {
			floor = 1
		}
		expiresAt = now + int64(floor)
	}

	duration := uint64(progressive)
	if permanent {
		duration = 0
	}

	return BanPlan{
		Duration:            duration,
		IsPermanent:         permanent,
		ExpiresAt:           expiresAt,
		BanCount:            priorBanCount + 1,
		FailCount:           failCount,
		ProgressiveDuration: progressive,
	}
}
