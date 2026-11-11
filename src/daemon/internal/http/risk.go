package http

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

// RiskVectors 处理 GET /api/v2/risk/vectors/:ip
//
// 返回指定 IP 的多维风险向量。仅在 risk_engine.enabled=true 时可用。
func (h *APIHandlers) RiskVectors(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		WriteServiceUnavailable(w, "risk engine not initialized")
		return
	}

	ipStr := r.PathValue("ip")
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		WriteCode(w, httpcontract.Code40006, "invalid IP address: "+ipStr)
		return
	}

	vec, err := h.db.GetRiskVector(addr.String())
	if err != nil {
		h.server.logger.Error("query risk vector failed", "ip", addr.String(), "error", err)
		WriteInternalError(w, "查询风险向量失败")
		return
	}

	if vec == nil {
		// IP 无记录，返回零向量
		vec = &persist.RiskVectorRow{
			IP: addr.String(),
		}
	}

	response := RiskVectorResponse{
		IP:          vec.IP,
		Failure:     vec.Vector.Failure,
		Ban:         vec.Vector.Ban,
		Scan:        vec.Vector.Scan,
		Bruteforce:  vec.Vector.Bruteforce,
		DDoS:        vec.Vector.DDoS,
		Geo:         vec.Vector.Geo,
		Cluster:     vec.Vector.Cluster,
		TotalRisk:   vec.Vector.Failure + vec.Vector.Ban + vec.Vector.Scan + vec.Vector.Bruteforce + vec.Vector.DDoS + vec.Vector.Geo + vec.Vector.Cluster,
		LastEventAt: vec.LastEventAt,
		UpdatedAt:   vec.UpdatedAt,
	}

	WriteSuccess(w, response)
}

// ListRiskVectors 处理 GET /api/v2/risk/vectors
//
// 返回所有 IP 的风险向量列表（按总风险降序，最多 100 条）。
func (h *APIHandlers) ListRiskVectors(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		WriteServiceUnavailable(w, "risk engine not initialized")
		return
	}

	// 限制返回数量，避免无界查询导致内存耗尽
	vectors, err := h.db.GetAllRiskVectors(100)
	if err != nil {
		h.server.logger.Error("query risk vectors failed", "error", err)
		WriteInternalError(w, "查询风险向量列表失败")
		return
	}

	response := RiskVectorListResponse{
		Total: uint32(len(vectors)),
	}

	for _, vec := range vectors {
		response.Vectors = append(response.Vectors, RiskVectorResponse{
			IP:          vec.IP,
			Failure:     vec.Vector.Failure,
			Ban:         vec.Vector.Ban,
			Scan:        vec.Vector.Scan,
			Bruteforce:  vec.Vector.Bruteforce,
			DDoS:        vec.Vector.DDoS,
			Geo:         vec.Vector.Geo,
			Cluster:     vec.Vector.Cluster,
			TotalRisk:   vec.Vector.Failure + vec.Vector.Ban + vec.Vector.Scan + vec.Vector.Bruteforce + vec.Vector.DDoS + vec.Vector.Geo + vec.Vector.Cluster,
			LastEventAt: vec.LastEventAt,
			UpdatedAt:   vec.UpdatedAt,
		})
	}

	WriteSuccess(w, response)
}

// RiskEvents 处理 GET /api/v2/risk/events/:ip
//
// 返回指定 IP 的攻击事件历史（按时间降序，默认最近 100 条）。
//
// 分页查询参数（都可选）：
//   - limit: 本次返回条数上限（默认 100，上限 100，超限回落默认值）
//   - offset: 跳过的条数（默认 0，负数按 0 处理）
//
// 分页下推到 SQL：读侧只取一页，不再把该 IP 的整段历史读进内存再截断。total 是
// 该 IP 的全部事件数（过滤条件之后的全集），不是本次返回的条数。
func (h *APIHandlers) RiskEvents(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		WriteServiceUnavailable(w, "risk engine not initialized")
		return
	}

	ipStr := r.PathValue("ip")
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		WriteCode(w, httpcontract.Code40006, "invalid IP address: "+ipStr)
		return
	}

	limit := parseLimit(r, 100, 100)
	offset := parseEventOffset(r)

	// total 先取：COUNT 与分页查询分开走，避免在打开 rows 的连接上再发一条查询
	//（库只配了 1 个连接，嵌套查询会自己等自己）。
	total, err := h.db.CountEventsByIP(addr.String())
	if err != nil {
		h.server.logger.Error("count events failed", "ip", addr.String(), "error", err)
		WriteInternalError(w, "查询攻击事件失败")
		return
	}

	events, err := h.db.ListEventsByIP(addr.String(), limit, offset)
	if err != nil {
		h.server.logger.Error("query events failed", "ip", addr.String(), "error", err)
		WriteInternalError(w, "查询攻击事件失败")
		return
	}

	response := RiskEventResponse{
		IP:     addr.String(),
		Events: make([]RiskEventEntry, 0, len(events)),
		Total:  uint32(total),
	}

	for _, e := range events {
		response.Events = append(response.Events, RiskEventEntry{
			ID:         e.ID,
			IP:         e.IP,
			EventType:  string(e.EventType),
			Increment:  e.Increment,
			OccurredAt: e.OccurredAt,
		})
	}

	WriteSuccess(w, response)
}

// parseEventOffset 读 offset 查询参数：缺省、读不懂、负数一律当 0。
//
// 与 page_size 的宽容处理同一口径：这条路由契约里只编了 40006（IP 非法），
// 参数读不懂没有对应的失败码，只能按第一页读。
func parseEventOffset(r *http.Request) int {
	raw := strings.TrimSpace(r.URL.Query().Get("offset"))
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// RiskVectorResponse 是单个 IP 的多维风险向量响应。
type RiskVectorResponse struct {
	IP          string  `json:"ip"`
	Failure     float64 `json:"failure"`
	Ban         float64 `json:"ban"`
	Scan        float64 `json:"scan"`
	Bruteforce  float64 `json:"bruteforce"`
	DDoS        float64 `json:"ddos"`
	Geo         float64 `json:"geo"`
	Cluster     float64 `json:"cluster"`
	TotalRisk   float64 `json:"total_risk"`
	LastEventAt int64   `json:"last_event_at"`
	UpdatedAt   int64   `json:"updated_at"`
}

// RiskVectorListResponse 是风险向量列表响应。
type RiskVectorListResponse struct {
	Vectors []RiskVectorResponse `json:"vectors"`
	Total   uint32               `json:"total"`
}

// RiskEventEntry 是攻击事件记录。
type RiskEventEntry struct {
	ID         int64   `json:"id"`
	IP         string  `json:"ip"`
	EventType  string  `json:"event_type"`
	Increment  float64 `json:"increment"`
	OccurredAt int64   `json:"occurred_at"`
}

// RiskEventResponse 是攻击事件历史响应。
type RiskEventResponse struct {
	IP     string           `json:"ip"`
	Events []RiskEventEntry `json:"events"`
	Total  uint32           `json:"total"`
}
