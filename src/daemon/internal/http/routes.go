package http

import (
	"net/http"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

func (s *Server) RegisterRoutes(api *APIHandlers) {
	s.HandleFunc("/api/v1/health", api.Health)
	s.HandleFunc("/api/v1/stats/summary", api.StatsSummary)
	s.HandleFunc("/api/v1/stats/sse-status", api.SSEStatus)
	s.HandleFunc("/api/v1/stats/ban-events", api.BanEvents)
	s.HandleFunc("/api/v1/stats/recidivism", api.Recidivism)
	s.HandleFunc("/api/v1/stats/reputation", api.Reputation)
	s.HandleFunc("/api/v1/stats/periodic-attackers", api.PeriodicAttackers)
	s.HandleFunc("/api/v1/stats/collaborative-attacks", api.CollaborativeAttacks)
	s.HandleFunc("/api/v1/stats/network-distribution", api.NetworkDistribution)
	s.HandleFunc("/api/v1/stats/attack-predictions", api.AttackPredictions)
	s.HandleFunc("/api/v1/stats/ban-duration-recommendations", api.BanDurationRecommendations)
	s.HandleFunc("/api/v1/stats/threshold-recommendations", api.ThresholdRecommendations)
}

type APIHandlers struct {
	server  *Server
	db      *persist.DB
	sse     *SSEBroker
	metrics *Metrics
}

func NewAPIHandlers(server *Server, db *persist.DB, sse *SSEBroker, metrics *Metrics) *APIHandlers {
	return &APIHandlers{
		server:  server,
		db:      db,
		sse:     sse,
		metrics: metrics,
	}
}

func (h *APIHandlers) Health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	WriteSuccess(w, map[string]any{
		"status": "healthy",
	})
}

func (h *APIHandlers) StatsSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	WriteSuccess(w, map[string]any{
		"active_connections": h.server.ActiveConnections(),
		"max_connections":    h.server.MaxConnections(),
	})
}

func (h *APIHandlers) SSEStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	WriteSuccess(w, map[string]any{
		"active_connections": h.server.ActiveConnections(),
		"max_connections":    h.server.MaxConnections(),
		"at_limit":           h.server.ActiveConnections() >= h.server.MaxConnections(),
	})
}
