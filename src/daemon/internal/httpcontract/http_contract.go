// 由 contract/http.fwidl 生成 —— 请勿手工编辑。
//
// 守护进程 HTTP 接口的注册串、业务码、SSE 上限与安全头单一真相源：路由在
// net/http.ServeMux 上注册时引用这里的常量与表，实现里不得再手打一遍路径
// 字面量。contract/verify_http.py 拿 routes.go 里出现的注册串与本表的
// Pattern 逐项核对，任何一侧多出来都算门禁失败。
//
// 消费方式：本文件由 gen.py 直接写进 daemon 的 module 内
// （src/daemon/internal/httpcontract/）——Go 只认 module 根之下的目录为包，
// 放在 contract/ 下就 import 不到。字面量的唯一来源仍是 contract/http.fwidl。
package httpcontract

// 契约标识。
const (
	// ContractName 是契约名（httpproto 块声明）。
	ContractName = "firewall_daemon_http"
	// APIBase 是 RESTful 端点共用的前缀；SPA 页面、静态资源与健康检查在其外。
	APIBase = "/api/v2"
)

// 鉴权参数。凭据来自配置的 metrics_username / metrics_password，两项都为空
// 才视为「未配置认证」；连续失败达到阈值后锁定的窗口内一律拒绝（含正确凭据）。
const (
	// AuthFailureThreshold 是触发锁定前的连续失败次数。
	AuthFailureThreshold = 10
	// AuthLockoutSeconds 是一次锁定持续的秒数。
	AuthLockoutSeconds = 60
	// AuthUnauthorizedStatus 是凭据缺失/错误时的 HTTP 状态码（纯文本形状，不经信封）。
	AuthUnauthorizedStatus = 401
	// AuthTokenQuery 是允许以查询参数携带凭据的键名（重定向必须原样保留 query）。
	AuthTokenQuery = "access_token"
	// AuthScheme 是 Authorization 头里的凭据方案。
	AuthScheme = "Basic"
)

// 路由表字段的取值域，与契约里的枚举一一对应。
const (
	// AuthNone 表示带与不带凭据都放行。
	AuthNone = "none"
	// AuthRequired 表示未带凭据（或凭据不符）必须返回未授权状态码。
	AuthRequired = "required"
	// ReturnsType 经信封返回 JSON 载荷。
	ReturnsType = "type"
	// ReturnsText 不经信封，直接返回纯文本。
	ReturnsText = "text"
	// ReturnsBytes 是二进制响应（静态文件）。
	ReturnsBytes = "bytes"
	// ReturnsStream 是长连接 SSE，必须声明连接上限与事件名。
	ReturnsStream = "stream"
	// HeaderScopeAll 表示安全头施加在所有响应上。
	HeaderScopeAll = "all"
	// HeaderScopeAPI 表示只施加在 API 响应上。
	HeaderScopeAPI = "api"
	// HeaderScopeWebUI 表示只施加在面板页面响应上。
	HeaderScopeWebUI = "webui"
)

// EnvelopeFields 是统一信封的 JSON key，顺序即契约顺序。三字段恒定存在：
// 成功时 code=0、data 为载荷；失败时 code 为业务码、data 为 null。
var EnvelopeFields = []string{"code", "data", "message"}

// 业务码（信封里的 code 字段）。它与 HTTP 状态码是两套编号：状态码表达
// 「请求是否被处理」，业务码表达「为什么失败」，映射见 CodeHTTPStatus。
const (
	// CodeOK：成功；message 为空串
	CodeOK = 0
	// Code40001：封禁失败（内核未确认、IP 非法、或内核返回错误）
	Code40001 = 40001
	// Code40002：解封失败（IP 非法或内核拒绝）
	Code40002 = 40002
	// Code40003：批量解封临时封禁失败 / 添加白名单失败
	Code40003 = 40003
	// Code40004：更新配置失败 / 移除白名单失败
	Code40004 = 40004
	// Code40005：批量封禁参数非法（列表为空或超过 100 条）/ 日志查询参数非法
	Code40005 = 40005
	// Code40006：封禁详情查询失败（IP 非法）
	Code40006 = 40006
	// Code40007：请求体不是合法 JSON 或字段类型不符（daemon 解析，框架不会自产此码）
	Code40007 = 40007
	// Code40008：Content-Type 不是 application/json（本 API 只说这一种媒体类型）
	Code40008 = 40008
	// Code404：Jail 不存在
	Code404 = 404
	// Code50002：服务端内部错误（历史库查询任务 join 失败等），message 含具体原因
	Code50002 = 50002
	// Code50003：依赖未就绪：历史库未初始化 / 日志文件未配置或不可读 / jail 控制器缺席 / SSE 连接名额已满
	Code50003 = 50003
)

// CodeHTTPStatus 是业务码到成功/失败 HTTP 状态码的映射。
var CodeHTTPStatus = map[int]int{
	// 成功；message 为空串
	CodeOK: 200,
	// 封禁失败（内核未确认、IP 非法、或内核返回错误）
	Code40001: 400,
	// 解封失败（IP 非法或内核拒绝）
	Code40002: 400,
	// 批量解封临时封禁失败 / 添加白名单失败
	Code40003: 400,
	// 更新配置失败 / 移除白名单失败
	Code40004: 400,
	// 批量封禁参数非法（列表为空或超过 100 条）/ 日志查询参数非法
	Code40005: 400,
	// 封禁详情查询失败（IP 非法）
	Code40006: 400,
	// 请求体不是合法 JSON 或字段类型不符（daemon 解析，框架不会自产此码）
	Code40007: 422,
	// Content-Type 不是 application/json（本 API 只说这一种媒体类型）
	Code40008: 415,
	// Jail 不存在
	Code404: 404,
	// 服务端内部错误（历史库查询任务 join 失败等），message 含具体原因
	Code50002: 500,
	// 依赖未就绪：历史库未初始化 / 日志文件未配置或不可读 / jail 控制器缺席 / SSE 连接名额已满
	Code50003: 503,
}

// 路由注册串（net/http.ServeMux 的 "METHOD /path" 模式）。注释里的路径是
// 契约原文，鉴权列的是契约语义：required = 未带凭据必须 401，none = 带与不带
// 都放行。
const (
	// GET /api/v2/health → Health（无认证）
	RouteGetApiV2Health = "GET /api/v2/health"
	// GET /api/v2/healthz → Health（无认证）
	RouteGetApiV2Healthz = "GET /api/v2/healthz"
	// GET / → redirectRoot（无认证）
	RouteGet = "GET /"
	// GET /dashboard → spaShell（无认证）
	RouteGetDashboard = "GET /dashboard"
	// GET /bans → spaShell（无认证）
	RouteGetBans = "GET /bans"
	// GET /whitelist → spaShell（无认证）
	RouteGetWhitelist = "GET /whitelist"
	// GET /jails → spaShell（无认证）
	RouteGetJails = "GET /jails"
	// GET /ddos → spaShell（无认证）
	RouteGetDdos = "GET /ddos"
	// GET /logs → spaShell（无认证）
	RouteGetLogs = "GET /logs"
	// GET /settings → spaShell（无认证）
	RouteGetSettings = "GET /settings"
	// GET /more → spaShell（无认证）
	RouteGetMore = "GET /more"
	// GET /static/*path → serveAsset（无认证）
	RouteGetStaticPath = "GET /static/{path...}"
	// GET /sw.js → serviceWorker（无认证）
	RouteGetSwJs = "GET /sw.js"
	// GET /metrics → ServeHTTP（需认证）
	RouteGetMetrics = "GET /metrics"
	// GET /api/v2/events → ServeHTTP（需认证）
	RouteGetApiV2Events = "GET /api/v2/events"
	// GET /api/v2/logs/stream → StreamLogs（需认证）
	RouteGetApiV2LogsStream = "GET /api/v2/logs/stream"
	// GET /api/v2/stats → Stats（需认证）
	RouteGetApiV2Stats = "GET /api/v2/stats"
	// GET /api/v2/bans → ListBans（需认证）
	RouteGetApiV2Bans = "GET /api/v2/bans"
	// POST /api/v2/bans → CreateBan（需认证）
	RoutePostApiV2Bans = "POST /api/v2/bans"
	// DELETE /api/v2/bans/:ip → DeleteBan（需认证）
	RouteDeleteApiV2BansIp = "DELETE /api/v2/bans/{ip}"
	// GET /api/v2/bans/:ip/detail → BanDetail（需认证）
	RouteGetApiV2BansIpDetail = "GET /api/v2/bans/{ip}/detail"
	// POST /api/v2/bans/unban-temporary → UnbanAllTemporary（需认证）
	RoutePostApiV2BansUnbanTemporary = "POST /api/v2/bans/unban-temporary"
	// POST /api/v2/bans/batch → BatchBan（需认证）
	RoutePostApiV2BansBatch = "POST /api/v2/bans/batch"
	// GET /api/v2/jails → ListJails（需认证）
	RouteGetApiV2Jails = "GET /api/v2/jails"
	// PUT /api/v2/jails/:name → UpdateJail（需认证）
	RoutePutApiV2JailsName = "PUT /api/v2/jails/{name}"
	// GET /api/v2/config → GetConfig（需认证）
	RouteGetApiV2Config = "GET /api/v2/config"
	// PUT /api/v2/config → UpdateConfig（需认证）
	RoutePutApiV2Config = "PUT /api/v2/config"
	// GET /api/v2/whitelist → ListWhitelist（需认证）
	RouteGetApiV2Whitelist = "GET /api/v2/whitelist"
	// POST /api/v2/whitelist → AddWhitelist（需认证）
	RoutePostApiV2Whitelist = "POST /api/v2/whitelist"
	// DELETE /api/v2/whitelist/:cidr → RemoveWhitelist（需认证）
	RouteDeleteApiV2WhitelistCidr = "DELETE /api/v2/whitelist/{cidr}"
	// GET /api/v2/whitelist/recommendations → GetWhitelistRecommendations（需认证）
	RouteGetApiV2WhitelistRecommendations = "GET /api/v2/whitelist/recommendations"
	// GET /api/v2/rates/current → RatesCurrent（需认证）
	RouteGetApiV2RatesCurrent = "GET /api/v2/rates/current"
	// GET /api/v2/rates/history → GetRatesHistory（需认证）
	RouteGetApiV2RatesHistory = "GET /api/v2/rates/history"
	// GET /api/v2/rates/windows → RatesWindows（需认证）
	RouteGetApiV2RatesWindows = "GET /api/v2/rates/windows"
	// GET /api/v2/stats/heatmap → Heatmap（需认证）
	RouteGetApiV2StatsHeatmap = "GET /api/v2/stats/heatmap"
	// GET /api/v2/stats/recidivism → Recidivism（需认证）
	RouteGetApiV2StatsRecidivism = "GET /api/v2/stats/recidivism"
	// GET /api/v2/stats/ban-effectiveness → BanEffectiveness（需认证）
	RouteGetApiV2StatsBanEffectiveness = "GET /api/v2/stats/ban-effectiveness"
	// GET /api/v2/stats/periodic-attackers → PeriodicAttackers（需认证）
	RouteGetApiV2StatsPeriodicAttackers = "GET /api/v2/stats/periodic-attackers"
	// GET /api/v2/stats/collaborative-attacks → CollaborativeAttacks（需认证）
	RouteGetApiV2StatsCollaborativeAttacks = "GET /api/v2/stats/collaborative-attacks"
	// GET /api/v2/stats/udp-ports → UdpPorts（需认证）
	RouteGetApiV2StatsUdpPorts = "GET /api/v2/stats/udp-ports"
	// GET /api/v2/stats/icmp-types → IcmpTypes（需认证）
	RouteGetApiV2StatsIcmpTypes = "GET /api/v2/stats/icmp-types"
	// GET /api/v2/stats/sse-status → SSEStatus（需认证）
	RouteGetApiV2StatsSseStatus = "GET /api/v2/stats/sse-status"
	// GET /api/v2/stats/ban-duration-histogram → BanDurationHistogram（需认证）
	RouteGetApiV2StatsBanDurationHistogram = "GET /api/v2/stats/ban-duration-histogram"
	// GET /api/v2/stats/packet-sizes → PacketSizes（需认证）
	RouteGetApiV2StatsPacketSizes = "GET /api/v2/stats/packet-sizes"
	// GET /api/v2/stats/ttl-distribution → TtlDistribution（需认证）
	RouteGetApiV2StatsTtlDistribution = "GET /api/v2/stats/ttl-distribution"
	// GET /api/v2/stats/ip-fragments → IpFragments（需认证）
	RouteGetApiV2StatsIpFragments = "GET /api/v2/stats/ip-fragments"
	// GET /api/v2/stats/port-scanners → PortScanners（需认证）
	RouteGetApiV2StatsPortScanners = "GET /api/v2/stats/port-scanners"
	// GET /api/v2/stats/service-probes → ServiceProbes（需认证）
	RouteGetApiV2StatsServiceProbes = "GET /api/v2/stats/service-probes"
	// GET /api/v2/stats/ban-duration-recommendations → BanDurationRecommendations（需认证）
	RouteGetApiV2StatsBanDurationRecommendations = "GET /api/v2/stats/ban-duration-recommendations"
	// GET /api/v2/stats/reputation → Reputation（需认证）
	RouteGetApiV2StatsReputation = "GET /api/v2/stats/reputation"
	// GET /api/v2/risk/vectors/:ip → RiskVectors（需认证）
	RouteGetApiV2RiskVectorsIp = "GET /api/v2/risk/vectors/{ip}"
	// GET /api/v2/risk/events/:ip → RiskEvents（需认证）
	RouteGetApiV2RiskEventsIp = "GET /api/v2/risk/events/{ip}"
	// GET /api/v2/risk/vectors → ListRiskVectors（需认证）
	RouteGetApiV2RiskVectors = "GET /api/v2/risk/vectors"
	// GET /api/v2/stats/threshold-recommendations → ThresholdRecommendations（需认证）
	RouteGetApiV2StatsThresholdRecommendations = "GET /api/v2/stats/threshold-recommendations"
	// GET /api/v2/stats/network-distribution → NetworkDistribution（需认证）
	RouteGetApiV2StatsNetworkDistribution = "GET /api/v2/stats/network-distribution"
	// GET /api/v2/stats/attack-predictions → AttackPredictions（需认证）
	RouteGetApiV2StatsAttackPredictions = "GET /api/v2/stats/attack-predictions"
	// GET /api/v2/stats/anomalies → Anomalies（需认证）
	RouteGetApiV2StatsAnomalies = "GET /api/v2/stats/anomalies"
	// GET /api/v2/stats/attack-geo → AttackGeo（需认证）
	RouteGetApiV2StatsAttackGeo = "GET /api/v2/stats/attack-geo"
	// GET /api/v2/logs → GetLogs（需认证）
	RouteGetApiV2Logs = "GET /api/v2/logs"
	// GET /api/v2/threat-feeds → ListThreatFeeds（需认证）
	RouteGetApiV2ThreatFeeds = "GET /api/v2/threat-feeds"
	// POST /api/v2/threat-feeds/sync → SyncThreatFeed（需认证）
	RoutePostApiV2ThreatFeedsSync = "POST /api/v2/threat-feeds/sync"
	// GET /api/v2/threat-feeds/:id → GetThreatFeed（需认证）
	RouteGetApiV2ThreatFeedsId = "GET /api/v2/threat-feeds/{id}"
	// GET /api/v2/analysis/summary → AnalysisSummary（需认证）
	RouteGetApiV2AnalysisSummary = "GET /api/v2/analysis/summary"
	// GET /api/v2/analysis/ip/:ip → AnalysisIp（需认证）
	RouteGetApiV2AnalysisIpIp = "GET /api/v2/analysis/ip/{ip}"
)

// 两条 SSE 流各自独立计数：上限与心跳按流声明，互不共享。诊断端点必须
// 同时报告两条流，否则前端按一条流的上限推断另一条会误判 503。
const (
	// SSEMaxConnectionsApiV2Events 是 GET /api/v2/events 的并发连接上限。
	SSEMaxConnectionsApiV2Events = 10
	// SSEKeepaliveSecondsApiV2Events 是 GET /api/v2/events 的心跳间隔。
	SSEKeepaliveSecondsApiV2Events = 15
	// SSEMaxConnectionsApiV2LogsStream 是 GET /api/v2/logs/stream 的并发连接上限。
	SSEMaxConnectionsApiV2LogsStream = 5
	// SSEKeepaliveSecondsApiV2LogsStream 是 GET /api/v2/logs/stream 的心跳间隔。
	SSEKeepaliveSecondsApiV2LogsStream = 15
)

// 各流的事件名。发布侧必须逐字发这些名字（event: 行），前端订阅侧同此。
var SSEEventNamesApiV2Events = []string{"connected", "stats", "bans", "jails", "whitelist", "rates"}
var SSEEventNamesApiV2LogsStream = []string{"connected", "log", "error"}

// Route 是契约里的一条路由。Pattern 用于注册，Path 用于生成链接与重定向。
type Route struct {
	// Pattern 是 ServeMux 注册串，逐字用于 mux.HandleFunc(Route.X, handler)。
	Pattern string
	// Path 是去掉方法的路径，参数槽为 Go 写法（契约的 `:ip` 写作 `{ip}`）。
	Path string
	// Method 是 HTTP 方法，与 Pattern 的前缀一致。
	Method string
	// Auth 取 AuthNone / AuthRequired。
	Auth string
	// Handler 是 Go 侧的注册符号名（`api.ListBans`、`spaShell`、`ServeHTTP` 等），
	// 契约与源码逐条对账的锚点；诊断输出也取它。
	Handler string
	// Returns 取 Returns* 之一。
	Returns string
	// Status 是成功路径的 HTTP 状态码。
	Status int
	// AltStatus 是同一路由上「成功但语义不同」的另一个状态码，0 表示没有。
	AltStatus int
	// Codes 是该路由可能返回的信封业务码，空表示只有成功路径。
	Codes []int
	// MaxConnections 是 stream 路由的连接上限，0 表示非 stream。
	MaxConnections int
	// Events 是 stream 路由的事件名全集。
	Events []string
	// KeepaliveSecs 是 stream 路由的心跳间隔，0 表示契约未声明。
	KeepaliveSecs int
}

// Routes 是完整路由表，顺序与 contract/http.fwidl 的声明顺序一致。
var Routes = []Route{
	{Pattern: RouteGetApiV2Health, Path: "/api/v2/health", Method: "GET", Auth: AuthNone, Handler: "Health", Returns: ReturnsType, Status: 200, AltStatus: 503},
	{Pattern: RouteGetApiV2Healthz, Path: "/api/v2/healthz", Method: "GET", Auth: AuthNone, Handler: "Health", Returns: ReturnsType, Status: 200, AltStatus: 503},
	{Pattern: RouteGet, Path: "/", Method: "GET", Auth: AuthNone, Handler: "redirectRoot", Returns: ReturnsText, Status: 303},
	{Pattern: RouteGetDashboard, Path: "/dashboard", Method: "GET", Auth: AuthNone, Handler: "spaShell", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetBans, Path: "/bans", Method: "GET", Auth: AuthNone, Handler: "spaShell", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetWhitelist, Path: "/whitelist", Method: "GET", Auth: AuthNone, Handler: "spaShell", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetJails, Path: "/jails", Method: "GET", Auth: AuthNone, Handler: "spaShell", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetDdos, Path: "/ddos", Method: "GET", Auth: AuthNone, Handler: "spaShell", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetLogs, Path: "/logs", Method: "GET", Auth: AuthNone, Handler: "spaShell", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetSettings, Path: "/settings", Method: "GET", Auth: AuthNone, Handler: "spaShell", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetMore, Path: "/more", Method: "GET", Auth: AuthNone, Handler: "spaShell", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetStaticPath, Path: "/static/{path...}", Method: "GET", Auth: AuthNone, Handler: "serveAsset", Returns: ReturnsBytes, Status: 200, AltStatus: 404},
	{Pattern: RouteGetSwJs, Path: "/sw.js", Method: "GET", Auth: AuthNone, Handler: "serviceWorker", Returns: ReturnsBytes, Status: 200, AltStatus: 404},
	{Pattern: RouteGetMetrics, Path: "/metrics", Method: "GET", Auth: AuthRequired, Handler: "ServeHTTP", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetApiV2Events, Path: "/api/v2/events", Method: "GET", Auth: AuthRequired, Handler: "ServeHTTP", Returns: ReturnsStream, Status: 200, AltStatus: 503, Codes: []int{Code50003}, MaxConnections: SSEMaxConnectionsApiV2Events, Events: SSEEventNamesApiV2Events, KeepaliveSecs: SSEKeepaliveSecondsApiV2Events},
	{Pattern: RouteGetApiV2LogsStream, Path: "/api/v2/logs/stream", Method: "GET", Auth: AuthRequired, Handler: "StreamLogs", Returns: ReturnsStream, Status: 200, AltStatus: 503, Codes: []int{Code50003}, MaxConnections: SSEMaxConnectionsApiV2LogsStream, Events: SSEEventNamesApiV2LogsStream, KeepaliveSecs: SSEKeepaliveSecondsApiV2LogsStream},
	{Pattern: RouteGetApiV2Stats, Path: "/api/v2/stats", Method: "GET", Auth: AuthRequired, Handler: "Stats", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV2Bans, Path: "/api/v2/bans", Method: "GET", Auth: AuthRequired, Handler: "ListBans", Returns: ReturnsType, Status: 200, Codes: []int{CodeOK}},
	{Pattern: RoutePostApiV2Bans, Path: "/api/v2/bans", Method: "POST", Auth: AuthRequired, Handler: "CreateBan", Returns: ReturnsType, Status: 201, AltStatus: 200, Codes: []int{Code40001, Code40007, Code40008}},
	{Pattern: RouteDeleteApiV2BansIp, Path: "/api/v2/bans/{ip}", Method: "DELETE", Auth: AuthRequired, Handler: "DeleteBan", Returns: ReturnsType, Status: 200, Codes: []int{Code40002}},
	{Pattern: RouteGetApiV2BansIpDetail, Path: "/api/v2/bans/{ip}/detail", Method: "GET", Auth: AuthRequired, Handler: "BanDetail", Returns: ReturnsType, Status: 200, Codes: []int{Code40006}},
	{Pattern: RoutePostApiV2BansUnbanTemporary, Path: "/api/v2/bans/unban-temporary", Method: "POST", Auth: AuthRequired, Handler: "UnbanAllTemporary", Returns: ReturnsType, Status: 200, Codes: []int{Code40003}},
	{Pattern: RoutePostApiV2BansBatch, Path: "/api/v2/bans/batch", Method: "POST", Auth: AuthRequired, Handler: "BatchBan", Returns: ReturnsType, Status: 201, AltStatus: 200, Codes: []int{Code40005, Code40007, Code40008}},
	{Pattern: RouteGetApiV2Jails, Path: "/api/v2/jails", Method: "GET", Auth: AuthRequired, Handler: "ListJails", Returns: ReturnsType, Status: 200},
	{Pattern: RoutePutApiV2JailsName, Path: "/api/v2/jails/{name}", Method: "PUT", Auth: AuthRequired, Handler: "UpdateJail", Returns: ReturnsType, Status: 200, Codes: []int{Code404, Code40007, Code40008, Code50003}},
	{Pattern: RouteGetApiV2Config, Path: "/api/v2/config", Method: "GET", Auth: AuthRequired, Handler: "GetConfig", Returns: ReturnsType, Status: 200, Codes: []int{Code50003}},
	{Pattern: RoutePutApiV2Config, Path: "/api/v2/config", Method: "PUT", Auth: AuthRequired, Handler: "UpdateConfig", Returns: ReturnsType, Status: 200, Codes: []int{Code40004, Code40007, Code40008, Code50003}},
	{Pattern: RouteGetApiV2Whitelist, Path: "/api/v2/whitelist", Method: "GET", Auth: AuthRequired, Handler: "ListWhitelist", Returns: ReturnsType, Status: 200},
	{Pattern: RoutePostApiV2Whitelist, Path: "/api/v2/whitelist", Method: "POST", Auth: AuthRequired, Handler: "AddWhitelist", Returns: ReturnsType, Status: 201, AltStatus: 200, Codes: []int{Code40003, Code40007, Code40008}},
	{Pattern: RouteDeleteApiV2WhitelistCidr, Path: "/api/v2/whitelist/{cidr}", Method: "DELETE", Auth: AuthRequired, Handler: "RemoveWhitelist", Returns: ReturnsType, Status: 200, Codes: []int{Code40004}},
	{Pattern: RouteGetApiV2WhitelistRecommendations, Path: "/api/v2/whitelist/recommendations", Method: "GET", Auth: AuthRequired, Handler: "GetWhitelistRecommendations", Returns: ReturnsType, Status: 200, Codes: []int{Code50002, Code50003}},
	{Pattern: RouteGetApiV2RatesCurrent, Path: "/api/v2/rates/current", Method: "GET", Auth: AuthRequired, Handler: "RatesCurrent", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV2RatesHistory, Path: "/api/v2/rates/history", Method: "GET", Auth: AuthRequired, Handler: "GetRatesHistory", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV2RatesWindows, Path: "/api/v2/rates/windows", Method: "GET", Auth: AuthRequired, Handler: "RatesWindows", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV2StatsHeatmap, Path: "/api/v2/stats/heatmap", Method: "GET", Auth: AuthRequired, Handler: "Heatmap", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV2StatsRecidivism, Path: "/api/v2/stats/recidivism", Method: "GET", Auth: AuthRequired, Handler: "Recidivism", Returns: ReturnsType, Status: 200, Codes: []int{Code50002, Code50003}},
	{Pattern: RouteGetApiV2StatsBanEffectiveness, Path: "/api/v2/stats/ban-effectiveness", Method: "GET", Auth: AuthRequired, Handler: "BanEffectiveness", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV2StatsPeriodicAttackers, Path: "/api/v2/stats/periodic-attackers", Method: "GET", Auth: AuthRequired, Handler: "PeriodicAttackers", Returns: ReturnsType, Status: 200, Codes: []int{Code50002, Code50003}},
	{Pattern: RouteGetApiV2StatsCollaborativeAttacks, Path: "/api/v2/stats/collaborative-attacks", Method: "GET", Auth: AuthRequired, Handler: "CollaborativeAttacks", Returns: ReturnsType, Status: 200, Codes: []int{Code50002, Code50003}},
	{Pattern: RouteGetApiV2StatsUdpPorts, Path: "/api/v2/stats/udp-ports", Method: "GET", Auth: AuthRequired, Handler: "UdpPorts", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV2StatsIcmpTypes, Path: "/api/v2/stats/icmp-types", Method: "GET", Auth: AuthRequired, Handler: "IcmpTypes", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV2StatsSseStatus, Path: "/api/v2/stats/sse-status", Method: "GET", Auth: AuthRequired, Handler: "SSEStatus", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV2StatsBanDurationHistogram, Path: "/api/v2/stats/ban-duration-histogram", Method: "GET", Auth: AuthRequired, Handler: "BanDurationHistogram", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV2StatsPacketSizes, Path: "/api/v2/stats/packet-sizes", Method: "GET", Auth: AuthRequired, Handler: "PacketSizes", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV2StatsTtlDistribution, Path: "/api/v2/stats/ttl-distribution", Method: "GET", Auth: AuthRequired, Handler: "TtlDistribution", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV2StatsIpFragments, Path: "/api/v2/stats/ip-fragments", Method: "GET", Auth: AuthRequired, Handler: "IpFragments", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV2StatsPortScanners, Path: "/api/v2/stats/port-scanners", Method: "GET", Auth: AuthRequired, Handler: "PortScanners", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV2StatsServiceProbes, Path: "/api/v2/stats/service-probes", Method: "GET", Auth: AuthRequired, Handler: "ServiceProbes", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV2StatsBanDurationRecommendations, Path: "/api/v2/stats/ban-duration-recommendations", Method: "GET", Auth: AuthRequired, Handler: "BanDurationRecommendations", Returns: ReturnsType, Status: 200, Codes: []int{Code50002, Code50003}},
	{Pattern: RouteGetApiV2StatsReputation, Path: "/api/v2/stats/reputation", Method: "GET", Auth: AuthRequired, Handler: "Reputation", Returns: ReturnsType, Status: 200, Codes: []int{Code50002, Code50003}},
	{Pattern: RouteGetApiV2RiskVectorsIp, Path: "/api/v2/risk/vectors/{ip}", Method: "GET", Auth: AuthRequired, Handler: "RiskVectors", Returns: ReturnsType, Status: 200, Codes: []int{Code50003, Code40006}},
	{Pattern: RouteGetApiV2RiskEventsIp, Path: "/api/v2/risk/events/{ip}", Method: "GET", Auth: AuthRequired, Handler: "RiskEvents", Returns: ReturnsType, Status: 200, Codes: []int{Code50003, Code40006}},
	{Pattern: RouteGetApiV2RiskVectors, Path: "/api/v2/risk/vectors", Method: "GET", Auth: AuthRequired, Handler: "ListRiskVectors", Returns: ReturnsType, Status: 200, Codes: []int{Code50003}},
	{Pattern: RouteGetApiV2StatsThresholdRecommendations, Path: "/api/v2/stats/threshold-recommendations", Method: "GET", Auth: AuthRequired, Handler: "ThresholdRecommendations", Returns: ReturnsType, Status: 200, Codes: []int{Code50002, Code50003}},
	{Pattern: RouteGetApiV2StatsNetworkDistribution, Path: "/api/v2/stats/network-distribution", Method: "GET", Auth: AuthRequired, Handler: "NetworkDistribution", Returns: ReturnsType, Status: 200, Codes: []int{Code50002, Code50003}},
	{Pattern: RouteGetApiV2StatsAttackPredictions, Path: "/api/v2/stats/attack-predictions", Method: "GET", Auth: AuthRequired, Handler: "AttackPredictions", Returns: ReturnsType, Status: 200, Codes: []int{Code50002, Code50003}},
	{Pattern: RouteGetApiV2StatsAnomalies, Path: "/api/v2/stats/anomalies", Method: "GET", Auth: AuthRequired, Handler: "Anomalies", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV2StatsAttackGeo, Path: "/api/v2/stats/attack-geo", Method: "GET", Auth: AuthRequired, Handler: "AttackGeo", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV2Logs, Path: "/api/v2/logs", Method: "GET", Auth: AuthRequired, Handler: "GetLogs", Returns: ReturnsType, Status: 200, Codes: []int{Code40005, Code50002, Code50003}},
	{Pattern: RouteGetApiV2ThreatFeeds, Path: "/api/v2/threat-feeds", Method: "GET", Auth: AuthRequired, Handler: "ListThreatFeeds", Returns: ReturnsType, Status: 200, Codes: []int{Code50003}},
	{Pattern: RoutePostApiV2ThreatFeedsSync, Path: "/api/v2/threat-feeds/sync", Method: "POST", Auth: AuthRequired, Handler: "SyncThreatFeed", Returns: ReturnsType, Status: 200, Codes: []int{Code50002, Code50003}},
	{Pattern: RouteGetApiV2ThreatFeedsId, Path: "/api/v2/threat-feeds/{id}", Method: "GET", Auth: AuthRequired, Handler: "GetThreatFeed", Returns: ReturnsType, Status: 200, Codes: []int{Code404, Code50003}},
	{Pattern: RouteGetApiV2AnalysisSummary, Path: "/api/v2/analysis/summary", Method: "GET", Auth: AuthRequired, Handler: "AnalysisSummary", Returns: ReturnsType, Status: 200, Codes: []int{Code50002, Code50003}},
	{Pattern: RouteGetApiV2AnalysisIpIp, Path: "/api/v2/analysis/ip/{ip}", Method: "GET", Auth: AuthRequired, Handler: "AnalysisIp", Returns: ReturnsType, Status: 200, Codes: []int{Code40006, Code50002, Code50003}},
}

// 安全头的名与值：中间件逐条引用这里的常量写响应头，实现里不出现第二份字符串。
// 标识符由头名派生（`X-Frame-Options` -> HeaderXFrameOptions），值由契约声明派生；
// `…ValueWebUI` 仅在契约给了 webui 分支值时存在。
const (
	// HeaderXContentTypeOptions 是头名 `X-Content-Type-Options`（scope=all）。
	HeaderXContentTypeOptions = "X-Content-Type-Options"
	// HeaderXContentTypeOptionsValue 是契约声明的 X-Content-Type-Options 取值。
	HeaderXContentTypeOptionsValue = "nosniff"
	// HeaderXFrameOptions 是头名 `X-Frame-Options`（scope=all）。
	HeaderXFrameOptions = "X-Frame-Options"
	// HeaderXFrameOptionsValue 是契约声明的 X-Frame-Options 取值。
	HeaderXFrameOptionsValue = "DENY"
	// HeaderContentSecurityPolicy 是头名 `Content-Security-Policy`（scope=all）。
	HeaderContentSecurityPolicy = "Content-Security-Policy"
	// HeaderContentSecurityPolicyValue 是契约声明的 Content-Security-Policy 取值。
	HeaderContentSecurityPolicyValue = "default-src 'none'"
	// HeaderContentSecurityPolicyValueWebUI 是面板（HTML/JS 同源加载）响应用值。
	HeaderContentSecurityPolicyValueWebUI = "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; connect-src 'self'; font-src 'self' data: https://fonts.gstatic.com"
	// HeaderCacheControl 是头名 `Cache-Control`（scope=all）。
	HeaderCacheControl = "Cache-Control"
	// HeaderCacheControlValue 是契约声明的 Cache-Control 取值。
	HeaderCacheControlValue = "no-store"
)

// SecurityHeader 是中间件统一施加的安全头。
type SecurityHeader struct {
	Name string
	// Scope 取 HeaderScope* 之一，指明头施加在哪一类响应上。
	Scope string
	Value string
	// ValueWebUI 非空时，Web UI 页面响应用它替代 Value（SPA 需要更宽的 CSP）。
	ValueWebUI string
}

// SecurityHeaders 是安全头全集，顺序与契约声明顺序一致。
var SecurityHeaders = []SecurityHeader{
	{Name: "X-Content-Type-Options", Scope: HeaderScopeAll, Value: "nosniff"},
	{Name: "X-Frame-Options", Scope: HeaderScopeAll, Value: "DENY"},
	{Name: "Content-Security-Policy", Scope: HeaderScopeAll, Value: "default-src 'none'", ValueWebUI: "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; connect-src 'self'; font-src 'self' data: https://fonts.gstatic.com"},
	{Name: "Cache-Control", Scope: HeaderScopeAll, Value: "no-store"},
}
