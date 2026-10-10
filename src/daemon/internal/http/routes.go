package http

import (
	"net/http"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/telemetry"
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
	LogStream *SSEStream
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
	LogFilePath func() string

	// 探针读数来源（GET /health 与 /healthz）
	GetKernelSnapshot func() telemetry.Snapshot
	KmodPresent       func() bool
}

func (s *Server) RegisterRoutes(api *APIHandlers) {
	// ---- 无认证：就绪探针 -----------------------------------------------------
	//
	// 两条路由同一个 handler：契约让 /healthz 成为 /health 的别名，供 k8s/负载均衡用。
	s.HandleFunc(httpcontract.RouteGetHealth, api.Health)
	s.HandleFunc(httpcontract.RouteGetHealthz, api.Health)

	// ---- 需认证：指标与 SSE ---------------------------------------------------
	//
	// /metrics 也在认证组内（契约把它和 REST 放在同一组）：它输出的计数器名与 jail 名
	// 本身就是拓扑信息，未配置的匿名抓取不该拿到。
	//
	// 注册一律写成 `httpcontract.Route*` 常量 + RequireAuth 包裹：
	//   - 注册串本身是核对锚点，逐字面量/常量之外的写法（例如遍历 Routes 表用 r.Pattern）
	//     在 verify_http.py 的扫描器眼里等于「一条路由都没注册」；
	//   - 带着方法前缀的模式让未声明的动词由 ServeMux 直接回 405，这正是契约
	//     errmodel FRAMEWORK_DEFAULT 声明的形状——handler 里不需要再自查 r.Method。
	if api.metrics != nil {
		s.HandleFunc(httpcontract.RouteGetMetrics,
			RequireAuth(api.username, api.password, api.metrics.ServeHTTP))
	}
	if api.sse != nil {
		s.HandleFunc(httpcontract.RouteGetApiV1Events,
			RequireAuth(api.username, api.password, api.sse.ServeHTTP))
	}

	// ---- 需认证：封禁管理 -----------------------------------------------------
	s.HandleFunc(httpcontract.RouteGetApiV1Bans,
		RequireAuth(api.username, api.password, api.ListBans))
	s.HandleFunc(httpcontract.RoutePostApiV1Bans,
		RequireAuth(api.username, api.password, api.CreateBan))
	s.HandleFunc(httpcontract.RouteDeleteApiV1BansIp,
		RequireAuth(api.username, api.password, api.DeleteBan))
	s.HandleFunc(httpcontract.RouteGetApiV1BansIpDetail,
		RequireAuth(api.username, api.password, api.BanDetail))
	s.HandleFunc(httpcontract.RoutePostApiV1BansUnbanTemporary,
		RequireAuth(api.username, api.password, api.UnbanAllTemporary))
	s.HandleFunc(httpcontract.RoutePostApiV1BansBatch,
		RequireAuth(api.username, api.password, api.BatchBan))

	// ---- 需认证：Jail ---------------------------------------------------------
	s.HandleFunc(httpcontract.RouteGetApiV1Jails,
		RequireAuth(api.username, api.password, api.ListJails))
	s.HandleFunc(httpcontract.RoutePutApiV1JailsName,
		RequireAuth(api.username, api.password, api.UpdateJail))

	// ---- 需认证：配置 ---------------------------------------------------------
	s.HandleFunc(httpcontract.RouteGetApiV1Config,
		RequireAuth(api.username, api.password, api.GetConfig))
	s.HandleFunc(httpcontract.RoutePutApiV1Config,
		RequireAuth(api.username, api.password, api.UpdateConfig))

	// ---- 需认证：白名单 -------------------------------------------------------
	s.HandleFunc(httpcontract.RouteGetApiV1Whitelist,
		RequireAuth(api.username, api.password, api.ListWhitelist))
	s.HandleFunc(httpcontract.RoutePostApiV1Whitelist,
		RequireAuth(api.username, api.password, api.AddWhitelist))
	s.HandleFunc(httpcontract.RouteDeleteApiV1WhitelistCidr,
		RequireAuth(api.username, api.password, api.RemoveWhitelist))
	s.HandleFunc(httpcontract.RouteGetApiV1WhitelistRecommendations,
		RequireAuth(api.username, api.password, api.GetWhitelistRecommendations))

	// ---- 需认证：速率 ---------------------------------------------------------
	s.HandleFunc(httpcontract.RouteGetApiV1RatesHistory,
		RequireAuth(api.username, api.password, api.GetRatesHistory))

	// ---- 需认证：统计子路由 ---------------------------------------------------
	//
	// 契约还声明了 /api/v1/stats 与 rates/current、rates/windows、stats/{heatmap,
	// ban-effectiveness,udp-ports,icmp-types,ban-duration-histogram,packet-sizes,
	// ttl-distribution,ip-fragments,port-scanners,service-probes,anomalies,attack-geo}；
	// 它们要接真实数据才有意义，尚未注册，逐条记在 contract/http_gap_baseline.txt 里
	// （见计划 P5）。空壳注册会让面板拿到一份看起来正常、实际恒零的载荷。
	s.HandleFunc(httpcontract.RouteGetApiV1StatsRecidivism,
		RequireAuth(api.username, api.password, api.Recidivism))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsReputation,
		RequireAuth(api.username, api.password, api.Reputation))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsPeriodicAttackers,
		RequireAuth(api.username, api.password, api.PeriodicAttackers))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsCollaborativeAttacks,
		RequireAuth(api.username, api.password, api.CollaborativeAttacks))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsNetworkDistribution,
		RequireAuth(api.username, api.password, api.NetworkDistribution))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsAttackPredictions,
		RequireAuth(api.username, api.password, api.AttackPredictions))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsBanDurationRecommendations,
		RequireAuth(api.username, api.password, api.BanDurationRecommendations))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsThresholdRecommendations,
		RequireAuth(api.username, api.password, api.ThresholdRecommendations))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsSseStatus,
		RequireAuth(api.username, api.password, api.SSEStatus))

	// ---- 需认证：日志 ---------------------------------------------------------
	s.HandleFunc(httpcontract.RouteGetApiV1Logs,
		RequireAuth(api.username, api.password, api.GetLogs))
	if api.logStream != nil {
		s.HandleFunc(httpcontract.RouteGetApiV1LogsStream,
			RequireAuth(api.username, api.password, api.StreamLogs))
	}
}

type APIHandlers struct {
	server    *Server
	db        *persist.DB
	sse       *SSEBroker
	logStream *SSEStream
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
	logFilePath func() string

	// 探针读数来源
	getKernelSnapshot func() telemetry.Snapshot
	kmodPresent       func() bool
}

func NewAPIHandlers(cfg APIConfig) *APIHandlers {
	return &APIHandlers{
		server:            cfg.Server,
		db:                cfg.DB,
		sse:               cfg.SSE,
		logStream:         cfg.LogStream,
		metrics:           cfg.Metrics,
		kernelBan:         cfg.KernelBan,
		username:          cfg.Username,
		password:          cfg.Password,
		getCurrentConfig:  cfg.GetCurrentConfig,
		getConfigPath:     cfg.GetConfigPath,
		jailController:    cfg.JailController,
		logFilePath:       cfg.LogFilePath,
		getKernelSnapshot: cfg.GetKernelSnapshot,
		kmodPresent:       cfg.KmodPresent,
	}
}

// SSEStatus 报两条 SSE 流各自的连接诊断（GET /api/v1/stats/sse-status）。
//
// 必须**按流**报：契约给 events 定 10、给 logs 定 5，前端拿 `events.limit_reached` 决定
// 要不要停止重连。用 HTTP 服务器级的单一 active/max 推断，日志流被拒时前端会判成「还没
// 满」，于是把 503 当网络故障无限重连。两条流的读数各自来自它的 SSEStream 名额账本，
// 不在这里复算上限。
func (h *APIHandlers) SSEStatus(w http.ResponseWriter, r *http.Request) {
	WriteSuccess(w, map[string]any{
		"events": streamStatus(h.eventsStream()),
		"logs":   streamStatus(h.logStream),
	})
}

// eventsStream 返回事件流的名额账本；broker 缺席时为 nil。
func (h *APIHandlers) eventsStream() *SSEStream {
	if h.sse == nil {
		return nil
	}
	return h.sse.SSEStream
}

// streamStatus 把一条流的可观测语义摊成契约载荷 SseStreamStatus 的三个 key。
//
// 流为 nil 表示这条流没接线（未配置凭据或组合根没建）：报 current=0、max=0，
// `limit_reached` 因此为 false，前端照常尝试连接并由 503/失败自己收敛。
func streamStatus(s *SSEStream) map[string]any {
	if s == nil {
		return map[string]any{
			"current_connections": 0,
			"max_connections":     0,
			"limit_reached":       false,
		}
	}
	return map[string]any{
		"current_connections": s.Active(),
		"max_connections":     s.Max(),
		"limit_reached":       s.AtLimit(),
	}
}
