package http

import (
	"net/http"
	"time"

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

	// Lockout 是认证失败计数与锁定窗口（契约 auth 段）。为 nil 时不计数——只可能在
	// 用例里出现，组合根永远建一份。
	Lockout *AuthLockout

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

	// StartedAt 是进程开始装配的时刻（GET /stats 的 uptime_seconds 起点）。
	StartedAt time.Time

	// GetRateSamples 取回速率历史的最近 n 个采样点，供 /api/v1/rates/history 与异常
	// 检测的分位基线共用。来源是事件泵每成功查询一次速率表落的一个点。
	GetRateSamples func(n int) []telemetry.RateSample

	// KernelVersion 读内核模块自报的版本号（/sys/module/firewall/version）。
	// 模块未加载时返回空串——面板上就是「内核 」，不拿守护进程版本顶上去。
	KernelVersion func() string
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
			RequireAuth(api.username, api.password, api.lockout, api.metrics.ServeHTTP))
	}
	if api.sse != nil {
		s.HandleFunc(httpcontract.RouteGetApiV1Events,
			RequireAuth(api.username, api.password, api.lockout, api.sse.ServeHTTP))
	}

	// ---- 需认证：封禁管理 -----------------------------------------------------
	s.HandleFunc(httpcontract.RouteGetApiV1Bans,
		RequireAuth(api.username, api.password, api.lockout, api.ListBans))
	s.HandleFunc(httpcontract.RoutePostApiV1Bans,
		RequireAuth(api.username, api.password, api.lockout, api.CreateBan))
	s.HandleFunc(httpcontract.RouteDeleteApiV1BansIp,
		RequireAuth(api.username, api.password, api.lockout, api.DeleteBan))
	s.HandleFunc(httpcontract.RouteGetApiV1BansIpDetail,
		RequireAuth(api.username, api.password, api.lockout, api.BanDetail))
	s.HandleFunc(httpcontract.RoutePostApiV1BansUnbanTemporary,
		RequireAuth(api.username, api.password, api.lockout, api.UnbanAllTemporary))
	s.HandleFunc(httpcontract.RoutePostApiV1BansBatch,
		RequireAuth(api.username, api.password, api.lockout, api.BatchBan))

	// ---- 需认证：Jail ---------------------------------------------------------
	s.HandleFunc(httpcontract.RouteGetApiV1Jails,
		RequireAuth(api.username, api.password, api.lockout, api.ListJails))
	s.HandleFunc(httpcontract.RoutePutApiV1JailsName,
		RequireAuth(api.username, api.password, api.lockout, api.UpdateJail))

	// ---- 需认证：配置 ---------------------------------------------------------
	s.HandleFunc(httpcontract.RouteGetApiV1Config,
		RequireAuth(api.username, api.password, api.lockout, api.GetConfig))
	s.HandleFunc(httpcontract.RoutePutApiV1Config,
		RequireAuth(api.username, api.password, api.lockout, api.UpdateConfig))

	// ---- 需认证：白名单 -------------------------------------------------------
	s.HandleFunc(httpcontract.RouteGetApiV1Whitelist,
		RequireAuth(api.username, api.password, api.lockout, api.ListWhitelist))
	s.HandleFunc(httpcontract.RoutePostApiV1Whitelist,
		RequireAuth(api.username, api.password, api.lockout, api.AddWhitelist))
	s.HandleFunc(httpcontract.RouteDeleteApiV1WhitelistCidr,
		RequireAuth(api.username, api.password, api.lockout, api.RemoveWhitelist))
	s.HandleFunc(httpcontract.RouteGetApiV1WhitelistRecommendations,
		RequireAuth(api.username, api.password, api.lockout, api.GetWhitelistRecommendations))

	// ---- 需认证：速率 ---------------------------------------------------------
	s.HandleFunc(httpcontract.RouteGetApiV1RatesCurrent,
		RequireAuth(api.username, api.password, api.lockout, api.RatesCurrent))
	s.HandleFunc(httpcontract.RouteGetApiV1RatesHistory,
		RequireAuth(api.username, api.password, api.lockout, api.GetRatesHistory))
	s.HandleFunc(httpcontract.RouteGetApiV1RatesWindows,
		RequireAuth(api.username, api.password, api.lockout, api.RatesWindows))

	// ---- 需认证：统计总览与内核快照 -------------------------------------------
	//
	// 这一组全部读事件泵发布的**同一份快照**（telemetry.Snapshot）：面板上的速率、协议
	// 分布与 Top-N 因此出自同一次采样，不会出现「包大小图说 3 秒前、扫描者图说 8 秒前」。
	s.HandleFunc(httpcontract.RouteGetApiV1Stats,
		RequireAuth(api.username, api.password, api.lockout, api.Stats))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsHeatmap,
		RequireAuth(api.username, api.password, api.lockout, api.Heatmap))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsPacketSizes,
		RequireAuth(api.username, api.password, api.lockout, api.PacketSizes))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsTtlDistribution,
		RequireAuth(api.username, api.password, api.lockout, api.TtlDistribution))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsIpFragments,
		RequireAuth(api.username, api.password, api.lockout, api.IpFragments))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsUdpPorts,
		RequireAuth(api.username, api.password, api.lockout, api.UdpPorts))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsIcmpTypes,
		RequireAuth(api.username, api.password, api.lockout, api.IcmpTypes))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsPortScanners,
		RequireAuth(api.username, api.password, api.lockout, api.PortScanners))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsServiceProbes,
		RequireAuth(api.username, api.password, api.lockout, api.ServiceProbes))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsAnomalies,
		RequireAuth(api.username, api.password, api.lockout, api.Anomalies))

	// ---- 需认证：统计子路由（历史库分析面）------------------------------------
	//
	// 三条「在 200 信封内降级」的统计（ban-effectiveness / ban-duration-histogram /
	// attack-geo）与其余各条不同：契约没给它们编业务码，读不到数据时回空读数 + 一句
	// summary，而不是 50002/50003。理由与逐条口径见 handlers.go 的包注释与契约 note。
	s.HandleFunc(httpcontract.RouteGetApiV1StatsRecidivism,
		RequireAuth(api.username, api.password, api.lockout, api.Recidivism))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsReputation,
		RequireAuth(api.username, api.password, api.lockout, api.Reputation))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsBanEffectiveness,
		RequireAuth(api.username, api.password, api.lockout, api.BanEffectiveness))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsBanDurationHistogram,
		RequireAuth(api.username, api.password, api.lockout, api.BanDurationHistogram))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsAttackGeo,
		RequireAuth(api.username, api.password, api.lockout, api.AttackGeo))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsPeriodicAttackers,
		RequireAuth(api.username, api.password, api.lockout, api.PeriodicAttackers))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsCollaborativeAttacks,
		RequireAuth(api.username, api.password, api.lockout, api.CollaborativeAttacks))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsNetworkDistribution,
		RequireAuth(api.username, api.password, api.lockout, api.NetworkDistribution))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsAttackPredictions,
		RequireAuth(api.username, api.password, api.lockout, api.AttackPredictions))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsBanDurationRecommendations,
		RequireAuth(api.username, api.password, api.lockout, api.BanDurationRecommendations))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsThresholdRecommendations,
		RequireAuth(api.username, api.password, api.lockout, api.ThresholdRecommendations))
	s.HandleFunc(httpcontract.RouteGetApiV1StatsSseStatus,
		RequireAuth(api.username, api.password, api.lockout, api.SSEStatus))

	// ---- 需认证：日志 ---------------------------------------------------------
	s.HandleFunc(httpcontract.RouteGetApiV1Logs,
		RequireAuth(api.username, api.password, api.lockout, api.GetLogs))
	if api.logStream != nil {
		s.HandleFunc(httpcontract.RouteGetApiV1LogsStream,
			RequireAuth(api.username, api.password, api.lockout, api.StreamLogs))
	}
}

type APIHandlers struct {
	server    *Server
	db        *persist.DB
	sse       *SSEBroker
	logStream *SSEStream
	metrics   *Metrics
	kernelBan KernelBan
	lockout   *AuthLockout

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

	// startedAt 是进程开始装配的时刻（uptime_seconds 的起点）。
	startedAt time.Time
	// getRateSamples 取回速率历史采样点，供 /rates/history 与异常检测共用。
	getRateSamples func(n int) []telemetry.RateSample
	// kernelVersion 读内核模块自报的版本号。
	kernelVersion func() string

	// statsWindow 缓存「今日 / 近 5 分钟」两个封禁窗口（GET /stats 首屏每刷新一次就打
	// 三条 SQL，看板按秒轮询时这个开销没有读数价值）。
	statsWindow windowCache
}

func NewAPIHandlers(cfg APIConfig) *APIHandlers {
	return &APIHandlers{
		server:            cfg.Server,
		db:                cfg.DB,
		sse:               cfg.SSE,
		logStream:         cfg.LogStream,
		metrics:           cfg.Metrics,
		kernelBan:         cfg.KernelBan,
		lockout:           cfg.Lockout,
		username:          cfg.Username,
		password:          cfg.Password,
		getCurrentConfig:  cfg.GetCurrentConfig,
		getConfigPath:     cfg.GetConfigPath,
		jailController:    cfg.JailController,
		logFilePath:       cfg.LogFilePath,
		getKernelSnapshot: cfg.GetKernelSnapshot,
		kmodPresent:       cfg.KmodPresent,
		startedAt:         cfg.StartedAt,
		getRateSamples:    cfg.GetRateSamples,
		kernelVersion:     cfg.KernelVersion,
	}
}

// currentConfig 读当前配置；未注入来源或来源报 nil 时报 nil。
//
// 读侧（统计面）拿到 nil 时的动作是「那一项没有读数」而不是 panic：装配测试里 APIHandlers
// 可以完全不接配置，而 /api/v1/stats 仍要能回答形状正确的载荷。写侧（PUT /config）自己
// 检查来源是否存在并回错误码，不走这里。
func (h *APIHandlers) currentConfig() *config.Config {
	if h.getCurrentConfig == nil {
		return nil
	}
	return h.getCurrentConfig()
}

// rateSamples 取回最近 n 个速率采样点；来源未接线时报 nil（异常检测据此给出「没有基线」）。
func (h *APIHandlers) rateSamples(n int) []telemetry.RateSample {
	if h.getRateSamples == nil {
		return nil
	}
	return h.getRateSamples(n)
}

// SSEStatus 报两条 SSE 流各自的连接诊断（GET /api/v1/stats/sse-status）。
//
// 必须**按流**报：契约给 events 定 10、给 logs 定 5，前端拿 `events.limit_reached` 决定
// 要不要停止重连。用 HTTP 服务器级的单一 active/max 推断，日志流被拒时前端会判成「还没
// 满」，于是把 503 当网络故障无限重连。两条流的读数各自来自它的 SSEStream 名额账本，
// 不在这里复算上限。
func (h *APIHandlers) SSEStatus(w http.ResponseWriter, r *http.Request) {
	WriteSuccess(w, SseStatusResponse{
		Events: streamStatus(h.eventsStream()),
		Logs:   streamStatus(h.logStream),
	})
}

// eventsStream 返回事件流的名额账本；broker 缺席时为 nil。
func (h *APIHandlers) eventsStream() *SSEStream {
	if h.sse == nil {
		return nil
	}
	return h.sse.SSEStream
}

// streamStatus 把一条流的可观测语义摊成契约载荷 SseStreamStatus。
//
// 流为 nil 表示这条流没接线（未配置凭据或组合根没建）：报 current=0、max=0，
// `limit_reached` 因此为 false，前端照常尝试连接并由 503/失败自己收敛。
func streamStatus(s *SSEStream) SseStreamStatus {
	if s == nil {
		return SseStreamStatus{}
	}
	return SseStreamStatus{
		CurrentConnections: s.Active(),
		MaxConnections:     s.Max(),
		LimitReached:       s.AtLimit(),
	}
}
