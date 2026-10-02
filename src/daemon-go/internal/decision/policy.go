// Package decision 承载封禁判定的纯计算部件：有效阈值、渐进式时长、封禁计划。
//
// 这里没有任何状态，也没有锁——旧实现把这些算式与全局封禁历史、信誉分表、活跃
// 封禁缓存纠缠在一起，换个时钟或换个 IP 都要先把全局态摆好。拆成纯函数后，同一份
// 算式可以用假定的 now / 分数直接跑对照测试，不受真实时钟与真实缓存影响。
//
// 判据必须与 Rust 版逐条一致（设计文档「冻结面 · 判定语义」）：
//
//   - 有效阈值 = max_retries × 高峰(1.5) × 内网(2.0) × 信誉，再 ceil 并至少为 1
//   - 信誉系数：≥80 → 1.0，≥50 → 0.8，否则 0.5
//   - 渐进式时长：第 1 次 base，第 2 次 1800，第 3 次 86400，第 4 次起 0（永久）
//   - ban_time < 0 即配置级永久；progressive == 0 且已封禁 ≥3 次亦为永久
package decision

import (
	"math"
	"net/netip"
)

// 判定系数。
const (
	// PeakHoursMultiplier 是高峰期阈值系数（业务高峰 9–18 点 UTC，含 9 不含 18）。
	PeakHoursMultiplier = 1.5
	// InternalSourceMultiplier 是内网来源的阈值系数。
	InternalSourceMultiplier = 2.0
)

// IsPeakHours 报告 hourUTC 是否落在判定用的「业务高峰期」内。
//
// 只接受小时数（UTC，0..23），时间源由调用方提供——这样判据可被固定小时数的测试
// 完全覆盖，不依赖跑测试时的真实时钟。
func IsPeakHours(hourUTC uint32) bool {
	return hourUTC >= 9 && hourUTC < 18
}

// ReputationMultiplier 把信誉分映射为阈值系数：分越高越宽松。
func ReputationMultiplier(score uint32) float64 {
	switch {
	case score >= 80:
		return 1.0
	case score >= 50:
		return 0.8
	default:
		return 0.5
	}
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

// EffectiveThreshold 计算有效失败阈值（达到即触发封禁）。
//
// 三项系数相乘后向上取整，并至少为 1——保证任何配置下都存在触发点，不会出现
// 「阈值 0 导致永不封禁」或「阈值 0 导致每次失败都封禁」的歧义。
func EffectiveThreshold(maxRetries uint32, peakHours, internal bool, reputationScore uint32) uint32 {
	peak := 1.0
	if peakHours {
		peak = PeakHoursMultiplier
	}
	source := 1.0
	if internal {
		source = InternalSourceMultiplier
	}
	value := math.Ceil(float64(maxRetries) * peak * source * ReputationMultiplier(reputationScore))
	if value < 1 {
		value = 1
	}
	return uint32(value)
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
