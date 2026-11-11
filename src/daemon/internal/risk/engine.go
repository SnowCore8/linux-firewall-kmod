package risk

import (
	"math"
	"sort"
	"sync"
	"time"
)

// Engine 是多维风险向量引擎的状态管理器。
//
// 职责：
//   - 维护内存缓存（带 TTL 过期与容量上限，避免每次查询都读数据库）
//   - 记录事件并更新向量
//   - 计算有效阈值（加法模型，修复旧乘法 Bug）
//
// 线程安全：所有公开方法都可并发调用。
type Engine struct {
	mu       sync.RWMutex
	vectors  map[string]*cachedVector
	weights  DimensionWeights
	maxSize  int
}

const defaultMaxSize = 100000

// cachedVector 是内存缓存的向量（带过期时间）。
type cachedVector struct {
	vector    RiskVector
	lastEvent int64
	expiresAt time.Time
}

// NewEngine 创建风险向量引擎。
//
// weights 是各维度权重（默认均为 1.0）。
func NewEngine(weights DimensionWeights) *Engine {
	return &Engine{
		vectors: make(map[string]*cachedVector),
		weights: weights,
		maxSize: defaultMaxSize,
	}
}

// RecordEvent 记录一次攻击事件并更新向量。
//
// ip 是来源 IP，eventType 是事件类型，increment 是向量增量。
// 返回更新后的向量（已衰减）。
func (e *Engine) RecordEvent(ip string, eventType EventType, increment float64) RiskVector {
	// 验证增量：负值/NaN/Inf 会破坏风险计算，直接忽略
	if increment < 0 || math.IsNaN(increment) || math.IsInf(increment, 0) {
		e.mu.Lock()
		defer e.mu.Unlock()
		if cached, ok := e.vectors[ip]; ok {
			return cached.vector
		}
		return RiskVector{}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now().Unix()
	cached, ok := e.vectors[ip]
	if !ok {
		// 容量检查：超过上限时先清理过期条目，仍超则按 expiresAt 淘汰最旧的
		if len(e.vectors) >= e.maxSize {
			e.evictLocked()
		}
		cached = &cachedVector{
			vector:    RiskVector{},
			lastEvent: now,
		}
		e.vectors[ip] = cached
	} else {
		// 先对旧向量施加衰减
		days := DaysSince(now, cached.lastEvent)
		cached.vector.Decay(days)
		cached.lastEvent = now
	}

	// 累加增量
	switch eventType {
	case EventFailure:
		cached.vector.Failure += increment
	case EventBan:
		cached.vector.Ban += increment
	case EventScan:
		cached.vector.Scan += increment
	case EventBruteforce:
		cached.vector.Bruteforce += increment
	case EventDDoS:
		cached.vector.DDoS += increment
	case EventGeo:
		cached.vector.Geo += increment
	case EventCluster:
		cached.vector.Cluster += increment
	}

	cached.expiresAt = time.Now().Add(5 * time.Minute)
	return cached.vector
}

// GetVector 查询指定 IP 的当前风险向量（带缓存）。
//
// 缓存命中时直接返回；缓存未命中或过期时返回零向量（调用方应从数据库加载）。
func (e *Engine) GetVector(ip string) (RiskVector, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	cached, ok := e.vectors[ip]
	if !ok || time.Now().After(cached.expiresAt) {
		return RiskVector{}, false
	}

	// 返回前施加衰减（基于当前时间）
	now := time.Now().Unix()
	days := DaysSince(now, cached.lastEvent)
	vec := cached.vector
	vec.Decay(days)
	return vec, true
}

// SetVector 直接设置指定 IP 的向量（用于从数据库加载）。
// 插入前检查容量，超限时触发淘汰，防止缓存无限增长。
func (e *Engine) SetVector(ip string, vec RiskVector, lastEvent int64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 若已存在则直接覆盖，不触发淘汰
	if _, exists := e.vectors[ip]; !exists {
		e.evictLocked()
	}
	e.vectors[ip] = &cachedVector{
		vector:    vec,
		lastEvent: lastEvent,
		expiresAt: time.Now().Add(5 * time.Minute),
	}
}

// ComputeEffectiveThreshold 计算有效阈值（加法模型）。
//
// 公式：baseThreshold + peakAddend + internalAddend + reputationAdjustment
//
//	baseThreshold：配置值（max_retries）
//	peakAddend：高峰期固定加 2（不再乘 1.5）
//	internalAddend：内网固定加 3（不再乘 2.0）
//	reputationAdjustment：信誉调整（-2 到 0）
//
// 修复旧乘法模型的 Bug：内网(2.0) × 低信誉(0.5) = 1.0，导致系数抵消。
func (e *Engine) ComputeEffectiveThreshold(
	ip string,
	baseThreshold uint32,
	peakHours bool,
	internal bool,
	reputationScore uint32,
) uint32 {
	addend := int(baseThreshold)

	if peakHours {
		addend += 2
	}

	if internal {
		addend += 3
	}

	addend += ReputationAdjustment(reputationScore)

	if addend < 1 {
		addend = 1
	}

	return uint32(addend)
}

// ReputationAdjustment 根据信誉分返回阈值调整值（连续函数，非阶梯）。
//
//	信誉 >= 80：0（高信誉不调整）
//	信誉 >= 50：-1（中信誉减 1）
//	信誉 < 50：-2（低信誉减 2）
//
// 加法模型：信誉分映射为阈值调整量。
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

// ShouldBan 判定指定 IP 是否应被封禁。
//
// 条件：向量加权和 >= 有效阈值。
func (e *Engine) ShouldBan(
	ip string,
	baseThreshold uint32,
	peakHours bool,
	internal bool,
	reputationScore uint32,
) bool {
	vec, ok := e.GetVector(ip)
	if !ok {
		return false
	}

	total := vec.Total(e.weights)
	threshold := e.ComputeEffectiveThreshold(ip, baseThreshold, peakHours, internal, reputationScore)

	return total >= float64(threshold)
}

// Cleanup 清理过期缓存（定期调用，如每 10 分钟一次）。
func (e *Engine) Cleanup() {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	for ip, cached := range e.vectors {
		if now.After(cached.expiresAt) {
			delete(e.vectors, ip)
		}
	}
}

// evictLocked 在持锁期间清理过期条目，若仍超容量则按 expiresAt 升序淘汰最旧的 10%。
// 调用方必须已持有 e.mu。
func (e *Engine) evictLocked() {
	now := time.Now()
	// 先清理过期条目
	for ip, cached := range e.vectors {
		if now.After(cached.expiresAt) {
			delete(e.vectors, ip)
		}
	}
	if len(e.vectors) < e.maxSize {
		return
	}
	// 仍超容量：淘汰 expiresAt 最旧的 10%（按 maxSize 计算）
	target := e.maxSize / 10
	if target <= 0 {
		target = 1
	}
	type entry struct {
		ip        string
		expiresAt time.Time
	}
	entries := make([]entry, 0, len(e.vectors))
	for ip, cached := range e.vectors {
		entries = append(entries, entry{ip: ip, expiresAt: cached.expiresAt})
	}
	// 按 expiresAt 升序排序，取前 target 个淘汰
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].expiresAt.Before(entries[j].expiresAt)
	})
	for i := 0; i < target && i < len(entries); i++ {
		delete(e.vectors, entries[i].ip)
	}
}

// Size 返回缓存中的 IP 数量（用于监控、调试）。
func (e *Engine) Size() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.vectors)
}
