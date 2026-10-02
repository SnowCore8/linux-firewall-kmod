package http

import (
	"net/http"
	"strconv"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/analysis"
)

func (h *APIHandlers) BanEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	events, err := h.db.GetBanEvents(limit)
	if err != nil {
		WriteInternalError(w, err.Error())
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
		WriteInternalError(w, err.Error())
		return
	}
	topRecidivists, err := h.db.GetTopRecidivists(10)
	if err != nil {
		WriteInternalError(w, err.Error())
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
	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	reps, err := h.db.GetLowReputationIPs(80, limit)
	if err != nil {
		WriteInternalError(w, err.Error())
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
	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	attackers, err := analysis.DetectPeriodicAttackers(h.db, 3, limit)
	if err != nil {
		WriteInternalError(w, err.Error())
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
	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	attacks, err := analysis.DetectCollaborativeAttacks(h.db, 300, 3, limit)
	if err != nil {
		WriteInternalError(w, err.Error())
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
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	distributions, err := analysis.AnalyzeNetworkDistribution(h.db, 7, limit)
	if err != nil {
		WriteInternalError(w, err.Error())
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
	limit := 15
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	summary, err := analysis.PredictAttacks(h.db, limit)
	if err != nil {
		WriteInternalError(w, err.Error())
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
		WriteInternalError(w, err.Error())
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
		WriteInternalError(w, err.Error())
		return
	}
	WriteSuccess(w, recommendations)
}
