package http

import (
	"net/http"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

// JailController 是 jail 启用/禁用的写入端接口。
//
// 由组合根注入 runtime.jailEnabledSource 实现；API 层通过此接口修改 jail 启用状态，
// InboundExecutor 在下一个 poll 周期自动同步。
type JailController interface {
	SetEnabled(jail string, enabled bool)
}

// APIConfig 是 APIHandlers 的构造参数。
//
// 把零散的依赖收拢到一个结构体，避免 NewAPIHandlers 参数列表随功能增长无限膨胀。
type APIConfig struct {
	Server    *Server
	DB        *persist.DB
	SSE       *SSEBroker
	Metrics   *Metrics
	KernelBan KernelBan

	// 认证凭据（来自 config.MetricsUsername / MetricsPassword）
	Username string
	Password string

	// 配置访问
	GetCurrentConfig func() *config.Config
	GetConfigPath    func() string

	// Jail 控制
	JailController JailController

	// 日志
	LogFilePath    func() string
	LogBroadcaster *SSEBroker
}

func (s *Server) RegisterRoutes(api *APIHandlers) {
	// 只读端点：可选认证
	s.HandleFunc("/api/v1/health", api.Health)
	s.HandleFunc("/api/v1/stats/summary", api.StatsSummary)
	s.HandleFunc("/api/v1/stats/sse-status", api.SSEStatus)
	s.HandleFunc("GET /api/v1/bans", OptionalAuth(api.username, api.password, api.ListBans))
	s.HandleFunc("GET /api/v1/bans/stats", OptionalAuth(api.username, api.password, api.BanStats))
	s.HandleFunc("GET /api/v1/bans/detail", OptionalAuth(api.username, api.password, api.BanDetail))
	s.HandleFunc("GET /api/v1/whitelist", OptionalAuth(api.username, api.password, api.ListWhitelist))
	s.HandleFunc("GET /api/v1/whitelist/stats", OptionalAuth(api.username, api.password, api.WhitelistStats))
	s.HandleFunc("GET /api/v1/jails", OptionalAuth(api.username, api.password, api.ListJails))
	s.HandleFunc("GET /api/v1/jail", OptionalAuth(api.username, api.password, api.GetJail))
	s.HandleFunc("GET /api/v1/jail/stats", OptionalAuth(api.username, api.password, api.JailStats))

	// 状态修改端点：强制认证
	s.HandleFunc("POST /api/v1/bans", RequireAuth(api.username, api.password, api.CreateBan))
	s.HandleFunc("DELETE /api/v1/bans", RequireAuth(api.username, api.password, api.DeleteBan))
	s.HandleFunc("POST /api/v1/bans/unban-temporary", RequireAuth(api.username, api.password, api.UnbanAllTemporary))
	s.HandleFunc("POST /api/v1/bans/batch", RequireAuth(api.username, api.password, api.BatchBan))
	s.HandleFunc("POST /api/v1/whitelist", RequireAuth(api.username, api.password, api.AddWhitelist))
	s.HandleFunc("DELETE /api/v1/whitelist", RequireAuth(api.username, api.password, api.RemoveWhitelist))

	// 统计端点：可选认证
	s.HandleFunc("/api/v1/stats/ban-events", OptionalAuth(api.username, api.password, api.BanEvents))
	s.HandleFunc("/api/v1/stats/recidivism", OptionalAuth(api.username, api.password, api.Recidivism))
	s.HandleFunc("/api/v1/stats/reputation", OptionalAuth(api.username, api.password, api.Reputation))
	s.HandleFunc("/api/v1/stats/periodic-attackers", OptionalAuth(api.username, api.password, api.PeriodicAttackers))
	s.HandleFunc("/api/v1/stats/collaborative-attacks", OptionalAuth(api.username, api.password, api.CollaborativeAttacks))
	s.HandleFunc("/api/v1/stats/network-distribution", OptionalAuth(api.username, api.password, api.NetworkDistribution))
	s.HandleFunc("/api/v1/stats/attack-predictions", OptionalAuth(api.username, api.password, api.AttackPredictions))
	s.HandleFunc("/api/v1/stats/ban-duration-recommendations", OptionalAuth(api.username, api.password, api.BanDurationRecommendations))
	s.HandleFunc("/api/v1/stats/threshold-recommendations", OptionalAuth(api.username, api.password, api.ThresholdRecommendations))

	// 配置 API
	s.HandleFunc("GET /api/v1/config", OptionalAuth(api.username, api.password, api.GetConfig))
	s.HandleFunc("PUT /api/v1/config", RequireAuth(api.username, api.password, api.UpdateConfig))

	// 日志 API
	s.HandleFunc("GET /api/v1/logs", OptionalAuth(api.username, api.password, api.GetLogs))
	s.HandleFunc("GET /api/v1/logs/stream", OptionalAuth(api.username, api.password, api.StreamLogs))

	// Jail 启用/禁用
	s.HandleFunc("PUT /api/v1/jails/", RequireAuth(api.username, api.password, api.UpdateJail))

	// 白名单推荐
	s.HandleFunc("GET /api/v1/whitelist/recommendations", OptionalAuth(api.username, api.password, api.GetWhitelistRecommendations))

	// DDoS 速率历史
	s.HandleFunc("GET /api/v1/rates/history", OptionalAuth(api.username, api.password, api.GetRatesHistory))
}

type APIHandlers struct {
	server    *Server
	db        *persist.DB
	sse       *SSEBroker
	metrics   *Metrics
	kernelBan KernelBan

	// 认证凭据
	username string
	password string

	// 配置访问
	getCurrentConfig func() *config.Config
	getConfigPath    func() string

	// Jail 控制
	jailController JailController

	// 日志
	logFilePath    func() string
	logBroadcaster *SSEBroker
}

func NewAPIHandlers(cfg APIConfig) *APIHandlers {
	return &APIHandlers{
		server:           cfg.Server,
		db:               cfg.DB,
		sse:              cfg.SSE,
		metrics:          cfg.Metrics,
		kernelBan:        cfg.KernelBan,
		username:         cfg.Username,
		password:         cfg.Password,
		getCurrentConfig: cfg.GetCurrentConfig,
		getConfigPath:    cfg.GetConfigPath,
		jailController:   cfg.JailController,
		logFilePath:      cfg.LogFilePath,
		logBroadcaster:   cfg.LogBroadcaster,
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
