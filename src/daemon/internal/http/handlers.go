package http

import (
	"net/http"
	"strconv"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/analysis"
)

func parseLimit(r *http.Request, defaultLimit, maxLimit int) int {
	limit := defaultLimit
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= maxLimit {
			limit = n
		}
	}
	return limit
}

func (h *APIHandlers) BanEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	limit := parseLimit(r, 100, 10000)
	events, err := h.db.GetBanEvents(limit)
	if err != nil {
		h.server.logger.Error("query ban events", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	WriteSuccess(w, events)
}

func (h *APIHandlers) Recidivism(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	totalIPs, recidivistIPs, rate, err := h.db.GetRecidivismStats()
	if err != nil {
		h.server.logger.Error("query recidivism stats", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	topRecidivists, err := h.db.GetTopRecidivists(10)
	if err != nil {
		h.server.logger.Error("query top recidivists", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	WriteSuccess(w, map[string]any{
		"total_ips":       totalIPs,
		"recidivist_ips":  recidivistIPs,
		"recidivism_rate": rate,
		"top_recidivists": topRecidivists,
	})
}

func (h *APIHandlers) Reputation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	limit := parseLimit(r, 20, 1000)
	reps, err := h.db.GetLowReputationIPs(80, limit)
	if err != nil {
		h.server.logger.Error("query low reputation IPs", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	WriteSuccess(w, reps)
}

func (h *APIHandlers) PeriodicAttackers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	limit := parseLimit(r, 20, 1000)
	attackers, err := analysis.DetectPeriodicAttackers(h.db, 3, limit, 10000)
	if err != nil {
		h.server.logger.Error("detect periodic attackers", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	WriteSuccess(w, attackers)
}

func (h *APIHandlers) CollaborativeAttacks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	limit := parseLimit(r, 20, 1000)
	attacks, err := analysis.DetectCollaborativeAttacks(h.db, 300, 3, limit, 10000)
	if err != nil {
		h.server.logger.Error("detect collaborative attacks", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	WriteSuccess(w, attacks)
}

func (h *APIHandlers) NetworkDistribution(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	limit := parseLimit(r, 50, 1000)
	distributions, err := analysis.AnalyzeNetworkDistribution(h.db, 7, limit)
	if err != nil {
		h.server.logger.Error("analyze network distribution", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	WriteSuccess(w, distributions)
}

func (h *APIHandlers) AttackPredictions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	limit := parseLimit(r, 15, 100)
	summary, err := analysis.PredictAttacks(h.db, limit)
	if err != nil {
		h.server.logger.Error("predict attacks", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	WriteSuccess(w, summary)
}

func (h *APIHandlers) BanDurationRecommendations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	recommendations, err := analysis.RecommendBanDurations(h.db, nil)
	if err != nil {
		h.server.logger.Error("recommend ban durations", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	WriteSuccess(w, recommendations)
}

func (h *APIHandlers) ThresholdRecommendations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	recommendations, err := analysis.RecommendThresholds(h.db, nil)
	if err != nil {
		h.server.logger.Error("recommend thresholds", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	WriteSuccess(w, recommendations)
}
