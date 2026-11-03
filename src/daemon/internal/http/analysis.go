package http

import (
	"net/http"
	"net/netip"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// AnalysisSummaryResponse 是综合分析摘要载荷（GET /api/v2/analysis/summary，契约同名 type）。
//
// threat_level 与 /api/v2/stats 的 threat_level 同源同口径（buildThreatLevel）；
// 三路计数（active_attacks/anomalies_count/collaborative_count）在对应检测子系统
// 接线前如实给 0，summary 文本随之报「无活跃攻击」。
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

// getTopRiskIPs 取风险最高的前 limit 个 IP。
// TODO(风险引擎接线): 从 ip_risk_vectors 查询；接线前返回空数组（契约是 Vec，不是 null）。
func (h *APIHandlers) getTopRiskIPs(limit int) []RiskVectorResponse {
	return []RiskVectorResponse{}
}

// getActiveAttackCount 取活跃攻击数。
// TODO(集群扫描检测接线): 从检测子系统读取；接线前如实返回 0。
func (h *APIHandlers) getActiveAttackCount() uint32 {
	return 0
}

// getAnomalyCount 取异常检测命中数。
// TODO(异常检测接线): 从检测子系统读取；接线前如实返回 0。
func (h *APIHandlers) getAnomalyCount() uint32 {
	return 0
}

// getCollaborativeAttackCount 取协同攻击数。
// TODO(协同攻击检测接线): 从检测子系统读取；接线前如实返回 0。
func (h *APIHandlers) getCollaborativeAttackCount() uint32 {
	return 0
}

// generateAnalysisSummary 把三路计数折成一句面板可读的结论。
func (h *APIHandlers) generateAnalysisSummary(attacks, anomalies, collaborative uint32) string {
	if attacks == 0 && anomalies == 0 && collaborative == 0 {
		return "当前无活跃攻击或异常行为"
	}
	return "检测到潜在威胁，建议关注"
}

// getRiskVector 取单个 IP 的风险向量。
// TODO(风险引擎接线): 查 ip_risk_vectors；接线前返回 nil（契约 Option → null）。
func (h *APIHandlers) getRiskVector(ip netip.Addr) *RiskVectorResponse {
	return nil
}

// getBanHistory 取单个 IP 的封禁历史。
// TODO(历史库接线): 查 ban_events；接线前返回空数组（契约是 Vec，不是 null）。
func (h *APIHandlers) getBanHistory(ip netip.Addr) []BanResponse {
	return []BanResponse{}
}

// getReputation 取单个 IP 的信誉条目。
// TODO(信誉系统接线): 查 ip_reputation；接线前返回 nil（契约 Option → null）。
func (h *APIHandlers) getReputation(ip netip.Addr) *ReputationEntryResponse {
	return nil
}

// getAttackPrediction 取单个 IP 的攻击预测。
// TODO(预测模型接线): 从周期性攻击检测读取；接线前返回 nil（契约 Option → null）。
func (h *APIHandlers) getAttackPrediction(ip netip.Addr) *AttackPrediction {
	return nil
}

// isWhitelisted 报告 IP 是否在白名单。
// TODO(白名单镜像接线): 查 bans 白名单缓存；接线前如实返回 false。
func (h *APIHandlers) isWhitelisted(ip netip.Addr) bool {
	return false
}
