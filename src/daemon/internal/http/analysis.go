package http

import (
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/analysis"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

// AnalysisSummaryResponse 是综合分析摘要载荷（GET /api/v2/analysis/summary，契约同名 type）。
//
// threat_level 与 /api/v2/stats 的 threat_level 同源同口径（buildThreatLevel）。三路计数各
// 复用一条已有检测子系统，与对应的 stats 端点同源同口径，不另起判据：
//   - active_attacks    ← 内核扫描/探测检出的当前活跃源行数（同 /stats/port-scanners、/stats/service-probes）
//   - anomalies_count   ← per-IP 行为离群数（同 /stats/anomalies 的 ip_anomalies）
//   - collaborative_count ← 协同攻击窗口数（同 /stats/collaborative-attacks）
//
// top_risk_ips 复用风险引擎的 ip_risk_vectors（同 /risk/vectors）；引擎未产生读数时为空数组。
type AnalysisSummaryResponse struct {
	ThreatLevel        ThreatLevel          `json:"threat_level"`
	TopRiskIPs         []RiskVectorResponse `json:"top_risk_ips"`
	ActiveAttacks      uint32               `json:"active_attacks"`
	AnomaliesCount     uint32               `json:"anomalies_count"`
	CollaborativeCount uint32               `json:"collaborative_count"`
	Summary            string               `json:"summary"`
	Timestamp          int64                `json:"timestamp"`
}

// AnalysisIpResponse 是单 IP 综合分析载荷（GET /api/v2/analysis/ip/:ip，契约同名 type）。
//
// risk/reputation/prediction 是契约的 Option：子系统缺席或未接线时给字面 null，
// 面板据此显示「无读数」而不是「读数为零」。ban_history 是 Vec，缺席时空数组。
type AnalysisIpResponse struct {
	IP            string                   `json:"ip"`
	Risk          *RiskVectorResponse      `json:"risk"`
	BanHistory    []BanResponse            `json:"ban_history"`
	Reputation    *ReputationEntryResponse `json:"reputation"`
	Prediction    *AttackPrediction        `json:"prediction"`
	IsWhitelisted bool                     `json:"is_whitelisted"`
}

// AnalysisSummary 处理 GET /api/v2/analysis/summary
// 返回综合分析摘要：威胁等级复用 stats 面的读数，其余维度在接线前降级为零值。
func (h *APIHandlers) AnalysisSummary(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		WriteServiceUnavailable(w, "历史数据库未初始化")
		return
	}

	now := time.Now()
	snap := h.kernelSnapshot()
	_, recentBans := h.banWindows(now)

	activeAttacks := h.getActiveAttackCount()
	anomalies := h.getAnomalyCount()
	collaborative := h.getCollaborativeAttackCount()

	WriteSuccess(w, AnalysisSummaryResponse{
		ThreatLevel:        h.buildThreatLevel(snap, now, recentBans),
		TopRiskIPs:         h.getTopRiskIPs(10),
		ActiveAttacks:      activeAttacks,
		AnomaliesCount:     anomalies,
		CollaborativeCount: collaborative,
		Summary:            h.generateAnalysisSummary(activeAttacks, anomalies, collaborative),
		Timestamp:          now.Unix(),
	})
}

// AnalysisIp 处理 GET /api/v2/analysis/ip/{ip}
// 返回单个 IP 的综合分析（风险向量 + 封禁历史 + 信誉 + 预测 + 白名单在场）。
func (h *APIHandlers) AnalysisIp(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		WriteServiceUnavailable(w, "历史数据库未初始化")
		return
	}

	ipStr := r.PathValue("ip")
	if ipStr == "" {
		WriteCode(w, httpcontract.Code40006, "缺少 IP 地址")
		return
	}

	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		WriteCode(w, httpcontract.Code40006, "IP 地址非法: "+err.Error())
		return
	}

	WriteSuccess(w, AnalysisIpResponse{
		IP:            ip.String(),
		Risk:          h.getRiskVector(ip),
		BanHistory:    h.getBanHistory(ip),
		Reputation:    h.getReputation(ip),
		Prediction:    h.getAttackPrediction(ip),
		IsWhitelisted: h.isWhitelisted(ip),
	})
}

// analysisBanHistoryLimit 是单 IP 综合分析一次取多少条封禁事件（与 /risk/events 的量级一致）。
const analysisBanHistoryLimit = 100

// analysisPredictionLimit 是 per-IP 预测查询的候选上限：取满 /stats/attack-predictions
// 允许的最大条数，尽量保证目标 IP 落在返回集合里（预测只对「有周期性证据」的地址产出）。
const analysisPredictionLimit = 100

// analysisCollaborativeLimit 与 /stats/collaborative-attacks 的默认上限对齐；这里只要计数，
// 取满窗口即可。窗口 300s、最小 3 源、事件上限 10000 与兄弟端点逐字一致，避免两处口径分叉。
const analysisCollaborativeLimit = 1000

// riskVectorResponse 把一行风险向量折成契约载荷。total_risk 是七维之和（与 /risk/vectors
// 同口径：加法模型，不做归一化）。
func riskVectorResponse(vec persist.RiskVectorRow) RiskVectorResponse {
	v := vec.Vector
	return RiskVectorResponse{
		IP:          vec.IP,
		Failure:     v.Failure,
		Ban:         v.Ban,
		Scan:        v.Scan,
		Bruteforce:  v.Bruteforce,
		DDoS:        v.DDoS,
		Geo:         v.Geo,
		Cluster:     v.Cluster,
		TotalRisk:   v.Failure + v.Ban + v.Scan + v.Bruteforce + v.DDoS + v.Geo + v.Cluster,
		LastEventAt: vec.LastEventAt,
		UpdatedAt:   vec.UpdatedAt,
	}
}

// getTopRiskIPs 取总风险最高的前 limit 个 IP（复用风险引擎的 ip_risk_vectors）。
//
// GetAllRiskVectors 的顺序不保证，这里按 total_risk 显式降序排一遍再截断，确保「top」名副
// 其实。引擎未启用 / 无读数 / 查询失败都降级为空数组（契约是 Vec，不是 null）。
func (h *APIHandlers) getTopRiskIPs(limit int) []RiskVectorResponse {
	if h.db == nil || limit <= 0 {
		return []RiskVectorResponse{}
	}
	vectors, err := h.db.GetAllRiskVectors()
	if err != nil {
		h.server.logger.Error("analysis: query risk vectors", "error", err)
		return []RiskVectorResponse{}
	}
	sort.SliceStable(vectors, func(i, j int) bool {
		return totalRisk(vectors[i]) > totalRisk(vectors[j])
	})
	if len(vectors) > limit {
		vectors = vectors[:limit]
	}
	out := make([]RiskVectorResponse, 0, len(vectors))
	for _, vec := range vectors {
		out = append(out, riskVectorResponse(vec))
	}
	return out
}

// totalRisk 是七维之和，与 riskVectorResponse 的 TotalRisk 同一算式（排序用）。
func totalRisk(vec persist.RiskVectorRow) float64 {
	v := vec.Vector
	return v.Failure + v.Ban + v.Scan + v.Bruteforce + v.DDoS + v.Geo + v.Cluster
}

// getActiveAttackCount 取当前活跃攻击源数：内核扫描/探测检测列出的有效源行数之和
// （端口扫描行 + 服务探测行）。与 /stats/port-scanners、/stats/service-probes 同源于
// 内核快照的 Analysis 聚合；packedRows 只数数组里真正被填充的行，不含累计事件计数。
func (h *APIHandlers) getActiveAttackCount() uint32 {
	a := h.kernelSnapshot().Analysis
	scanners := packedRows(a.PortScanCount, len(a.PortScanners))
	probes := packedRows(a.ServiceProbeCount, len(a.ServiceProbes))
	return uint32(scanners + probes)
}

// getAnomalyCount 取 per-IP 行为离群数，直接复用 /stats/anomalies 的 ipAnomalies（同一份
// 内核快照、同一离群判据），保证两条路由对「有多少异常地址」永远给同一个数。
func (h *APIHandlers) getAnomalyCount() uint32 {
	return uint32(len(ipAnomalies(h.kernelSnapshot())))
}

// getCollaborativeAttackCount 取协同攻击窗口数，复用 /stats/collaborative-attacks 的检测
// （同窗口/同最小源数/同事件上限）。历史库缺席或查询失败降级为 0（如实报「无协同攻击」）。
func (h *APIHandlers) getCollaborativeAttackCount() uint32 {
	if h.db == nil {
		return 0
	}
	findings, err := analysis.DetectCollaborativeAttacks(h.db, 300, 3, analysisCollaborativeLimit, 10000)
	if err != nil {
		h.server.logger.Error("analysis: detect collaborative attacks", "error", err)
		return 0
	}
	return uint32(len(findings))
}

// generateAnalysisSummary 把三路计数折成一句面板可读的结论。计数为真时逐项点名，避免
// 「检测到潜在威胁」这种没有信息量的话；全零时明确报无活跃威胁。
func (h *APIHandlers) generateAnalysisSummary(attacks, anomalies, collaborative uint32) string {
	if attacks == 0 && anomalies == 0 && collaborative == 0 {
		return "当前无活跃攻击或异常行为"
	}
	parts := make([]string, 0, 3)
	if attacks > 0 {
		parts = append(parts, fmt.Sprintf("%d 个活跃扫描/探测源", attacks))
	}
	if anomalies > 0 {
		parts = append(parts, fmt.Sprintf("%d 个行为离群地址", anomalies))
	}
	if collaborative > 0 {
		parts = append(parts, fmt.Sprintf("%d 起协同攻击窗口", collaborative))
	}
	return "检测到潜在威胁：" + strings.Join(parts, "、") + "，建议关注"
}

// getRiskVector 取单个 IP 的风险向量（复用风险引擎 ip_risk_vectors）。
// 无记录 / 引擎未启用 / 查询失败都返回 nil（契约 Option → null，面板显示「无读数」）。
func (h *APIHandlers) getRiskVector(ip netip.Addr) *RiskVectorResponse {
	if h.db == nil {
		return nil
	}
	vec, err := h.db.GetRiskVector(ip.String())
	if err != nil {
		h.server.logger.Error("analysis: query risk vector", "ip", ip.String(), "error", err)
		return nil
	}
	if vec == nil {
		return nil
	}
	resp := riskVectorResponse(*vec)
	return &resp
}

// getBanHistory 取单个 IP 的封禁历史（复用 ban_events 底账）。
//
// ban_events 不存 reason 列，故 Reason 如实留空——不拿 jail 名或猜测文案冒充。
// remaining_seconds 按「下发时刻 + 计划时长 - 现在」折算；永久封禁或无时长读数（旧行）
// 给 0，与 banToResponse 对活跃表的口径一致（前端凭 is_permanent 显示「永久」）。
func (h *APIHandlers) getBanHistory(ip netip.Addr) []BanResponse {
	if h.db == nil {
		return []BanResponse{}
	}
	events, err := h.db.GetBanEventsByIP(ip.String(), analysisBanHistoryLimit)
	if err != nil {
		h.server.logger.Error("analysis: query ban events", "ip", ip.String(), "error", err)
		return []BanResponse{}
	}
	now := time.Now().Unix()
	out := make([]BanResponse, 0, len(events))
	for _, e := range events {
		remaining := int64(0)
		if !e.IsPermanent && e.DurationSecs != nil {
			if end := e.BannedAt + *e.DurationSecs; end > now {
				remaining = end - now
			}
		}
		out = append(out, BanResponse{
			IP:               e.IP,
			Jail:             e.JailName,
			BannedAt:         e.BannedAt,
			RemainingSeconds: remaining,
			Reason:           "",
			BanCount:         uint32(clampInt(e.BanCount)),
			IsPermanent:      e.IsPermanent,
		})
	}
	return out
}

// getReputation 取单个 IP 的信誉条目（复用 ip_reputation + 与 /stats/reputation 同一个
// mapReputationEntries 映射）。无记录 / 查询失败返回 nil（契约 Option → null）。
func (h *APIHandlers) getReputation(ip netip.Addr) *ReputationEntryResponse {
	if h.db == nil {
		return nil
	}
	rep, err := h.db.GetIPReputation(ip.String())
	if err != nil {
		h.server.logger.Error("analysis: query ip reputation", "ip", ip.String(), "error", err)
		return nil
	}
	if rep == nil {
		return nil
	}
	entries := mapReputationEntries([]persist.IPReputation{*rep})
	if len(entries) == 0 {
		return nil
	}
	return &entries[0]
}

// getAttackPrediction 取单个 IP 的攻击预测：跑一遍 /stats/attack-predictions 的检测
// （同 analysis.PredictAttacks + 同 mapPredictions 映射），从结果里挑出目标 IP。
// 预测只对「有周期性证据」的地址产出，命中不到就返回 nil（契约 Option → null）。
func (h *APIHandlers) getAttackPrediction(ip netip.Addr) *AttackPrediction {
	if h.db == nil {
		return nil
	}
	summary, err := analysis.PredictAttacks(h.db, analysisPredictionLimit)
	if err != nil {
		h.server.logger.Error("analysis: predict attacks", "ip", ip.String(), "error", err)
		return nil
	}
	mapped := mapPredictions(summary, time.Now())
	target := ip.String()
	for i := range mapped.Predictions {
		if mapped.Predictions[i].IP == target {
			prediction := mapped.Predictions[i]
			return &prediction
		}
	}
	return nil
}

// isWhitelisted 报告 IP 是否被白名单覆盖（复用内核下发同源的白名单镜像 bans.GlobalWhitelist）。
func (h *APIHandlers) isWhitelisted(ip netip.Addr) bool {
	return bans.GlobalWhitelist().Contains(ip)
}
