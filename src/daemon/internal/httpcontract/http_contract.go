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
	APIBase = "/api/v1"
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
	// Code404：Jail 不存在
	Code404 = 404
	// Code50002：服务端内部错误（历史库查询任务 join 失败等），message 含具体原因
	Code50002 = 50002
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
	// Jail 不存在
	Code404: 404,
	// 服务端内部错误（历史库查询任务 join 失败等），message 含具体原因
	Code50002: 500,
}

// 路由注册串（net/http.ServeMux 的 "METHOD /path" 模式）。注释里的路径是
// 契约原文，鉴权列的是契约语义：required = 未带凭据必须 401，none = 带与不带
// 都放行。
const (
	// GET /health → handle_health（无认证）
	RouteGetHealth = "GET /health"
	// GET /healthz → handle_health（无认证）
	RouteGetHealthz = "GET /healthz"
	// GET / → handle_redirect（无认证）
	RouteGet = "GET /"
	// GET /dashboard → handle_dashboard（无认证）
	RouteGetDashboard = "GET /dashboard"
	// GET /bans → handle_spa_bans（无认证）
	RouteGetBans = "GET /bans"
	// GET /whitelist → handle_spa_whitelist（无认证）
	RouteGetWhitelist = "GET /whitelist"
	// GET /jails → handle_spa_jails（无认证）
	RouteGetJails = "GET /jails"
	// GET /ddos → handle_spa_ddos（无认证）
	RouteGetDdos = "GET /ddos"
	// GET /globe → handle_spa_globe（无认证）
	RouteGetGlobe = "GET /globe"
	// GET /logs → handle_spa_logs（无认证）
	RouteGetLogs = "GET /logs"
	// GET /settings → handle_spa_settings（无认证）
	RouteGetSettings = "GET /settings"
	// GET /more → handle_spa_more（无认证）
	RouteGetMore = "GET /more"
	// GET /static/*path → handle_static（无认证）
	RouteGetStaticPath = "GET /static/{path...}"
	// GET /sw.js → handle_sw（无认证）
	RouteGetSwJs = "GET /sw.js"
	// GET /metrics → handle_metrics（需认证）
	RouteGetMetrics = "GET /metrics"
	// GET /api/v1/events → handle_sse（需认证）
	RouteGetApiV1Events = "GET /api/v1/events"
	// GET /api/v1/logs/stream → handle_log_stream（需认证）
	RouteGetApiV1LogsStream = "GET /api/v1/logs/stream"
	// GET /api/v1/stats → handle_api_stats（需认证）
	RouteGetApiV1Stats = "GET /api/v1/stats"
	// GET /api/v1/bans → handle_api_bans（需认证）
	RouteGetApiV1Bans = "GET /api/v1/bans"
	// POST /api/v1/bans → handle_create_ban（需认证）
	RoutePostApiV1Bans = "POST /api/v1/bans"
	// DELETE /api/v1/bans/:ip → handle_delete_ban（需认证）
	RouteDeleteApiV1BansIp = "DELETE /api/v1/bans/{ip}"
	// GET /api/v1/bans/:ip/detail → handle_ban_detail（需认证）
	RouteGetApiV1BansIpDetail = "GET /api/v1/bans/{ip}/detail"
	// POST /api/v1/bans/unban-temporary → handle_unban_temporary（需认证）
	RoutePostApiV1BansUnbanTemporary = "POST /api/v1/bans/unban-temporary"
	// POST /api/v1/bans/batch → handle_batch_ban（需认证）
	RoutePostApiV1BansBatch = "POST /api/v1/bans/batch"
	// GET /api/v1/jails → handle_api_jails（需认证）
	RouteGetApiV1Jails = "GET /api/v1/jails"
	// PUT /api/v1/jails/:name → handle_update_jail（需认证）
	RoutePutApiV1JailsName = "PUT /api/v1/jails/{name}"
	// GET /api/v1/config → handle_api_config（需认证）
	RouteGetApiV1Config = "GET /api/v1/config"
	// PUT /api/v1/config → handle_update_config（需认证）
	RoutePutApiV1Config = "PUT /api/v1/config"
	// GET /api/v1/whitelist → handle_api_whitelist（需认证）
	RouteGetApiV1Whitelist = "GET /api/v1/whitelist"
	// POST /api/v1/whitelist → handle_create_whitelist（需认证）
	RoutePostApiV1Whitelist = "POST /api/v1/whitelist"
	// DELETE /api/v1/whitelist/:cidr → handle_delete_whitelist（需认证）
	RouteDeleteApiV1WhitelistCidr = "DELETE /api/v1/whitelist/{cidr}"
	// GET /api/v1/whitelist/recommendations → handle_whitelist_recommendations（需认证）
	RouteGetApiV1WhitelistRecommendations = "GET /api/v1/whitelist/recommendations"
	// GET /api/v1/rates/current → handle_api_rates_current（需认证）
	RouteGetApiV1RatesCurrent = "GET /api/v1/rates/current"
	// GET /api/v1/rates/history → handle_api_rates_history（需认证）
	RouteGetApiV1RatesHistory = "GET /api/v1/rates/history"
	// GET /api/v1/rates/windows → handle_api_rates_windows（需认证）
	RouteGetApiV1RatesWindows = "GET /api/v1/rates/windows"
	// GET /api/v1/stats/heatmap → handle_api_heatmap（需认证）
	RouteGetApiV1StatsHeatmap = "GET /api/v1/stats/heatmap"
	// GET /api/v1/stats/recidivism → handle_api_recidivism（需认证）
	RouteGetApiV1StatsRecidivism = "GET /api/v1/stats/recidivism"
	// GET /api/v1/stats/ban-effectiveness → handle_api_ban_effectiveness（需认证）
	RouteGetApiV1StatsBanEffectiveness = "GET /api/v1/stats/ban-effectiveness"
	// GET /api/v1/stats/periodic-attackers → handle_api_periodic_attackers（需认证）
	RouteGetApiV1StatsPeriodicAttackers = "GET /api/v1/stats/periodic-attackers"
	// GET /api/v1/stats/collaborative-attacks → handle_api_collaborative_attacks（需认证）
	RouteGetApiV1StatsCollaborativeAttacks = "GET /api/v1/stats/collaborative-attacks"
	// GET /api/v1/stats/udp-ports → handle_api_udp_ports（需认证）
	RouteGetApiV1StatsUdpPorts = "GET /api/v1/stats/udp-ports"
	// GET /api/v1/stats/icmp-types → handle_api_icmp_types（需认证）
	RouteGetApiV1StatsIcmpTypes = "GET /api/v1/stats/icmp-types"
	// GET /api/v1/stats/sse-status → handle_api_sse_status（需认证）
	RouteGetApiV1StatsSseStatus = "GET /api/v1/stats/sse-status"
	// GET /api/v1/stats/ban-duration-histogram → handle_api_ban_duration_histogram（需认证）
	RouteGetApiV1StatsBanDurationHistogram = "GET /api/v1/stats/ban-duration-histogram"
	// GET /api/v1/stats/packet-sizes → handle_api_packet_sizes（需认证）
	RouteGetApiV1StatsPacketSizes = "GET /api/v1/stats/packet-sizes"
	// GET /api/v1/stats/ttl-distribution → handle_api_ttl_distribution（需认证）
	RouteGetApiV1StatsTtlDistribution = "GET /api/v1/stats/ttl-distribution"
	// GET /api/v1/stats/ip-fragments → handle_api_ip_fragments（需认证）
	RouteGetApiV1StatsIpFragments = "GET /api/v1/stats/ip-fragments"
	// GET /api/v1/stats/port-scanners → handle_api_port_scanners（需认证）
	RouteGetApiV1StatsPortScanners = "GET /api/v1/stats/port-scanners"
	// GET /api/v1/stats/service-probes → handle_api_service_probes（需认证）
	RouteGetApiV1StatsServiceProbes = "GET /api/v1/stats/service-probes"
	// GET /api/v1/stats/ban-duration-recommendations → handle_api_ban_duration_recommendations（需认证）
	RouteGetApiV1StatsBanDurationRecommendations = "GET /api/v1/stats/ban-duration-recommendations"
	// GET /api/v1/stats/reputation → handle_api_reputation（需认证）
	RouteGetApiV1StatsReputation = "GET /api/v1/stats/reputation"
	// GET /api/v1/stats/threshold-recommendations → handle_api_threshold_recommendations（需认证）
	RouteGetApiV1StatsThresholdRecommendations = "GET /api/v1/stats/threshold-recommendations"
	// GET /api/v1/stats/network-distribution → handle_api_network_distribution（需认证）
	RouteGetApiV1StatsNetworkDistribution = "GET /api/v1/stats/network-distribution"
	// GET /api/v1/stats/attack-predictions → handle_api_attack_predictions（需认证）
	RouteGetApiV1StatsAttackPredictions = "GET /api/v1/stats/attack-predictions"
	// GET /api/v1/stats/anomalies → handle_api_anomalies（需认证）
	RouteGetApiV1StatsAnomalies = "GET /api/v1/stats/anomalies"
	// GET /api/v1/stats/attack-geo → handle_api_attack_geo（需认证）
	RouteGetApiV1StatsAttackGeo = "GET /api/v1/stats/attack-geo"
	// GET /api/v1/logs → handle_api_logs（需认证）
	RouteGetApiV1Logs = "GET /api/v1/logs"
)

// 两条 SSE 流各自独立计数：上限与心跳按流声明，互不共享。诊断端点必须
// 同时报告两条流，否则前端按一条流的上限推断另一条会误判 503。
const (
	// SSEMaxConnectionsApiV1Events 是 GET /api/v1/events 的并发连接上限。
	SSEMaxConnectionsApiV1Events = 10
	// SSEKeepaliveSecondsApiV1Events 是 GET /api/v1/events 的心跳间隔。
	SSEKeepaliveSecondsApiV1Events = 15
	// SSEMaxConnectionsApiV1LogsStream 是 GET /api/v1/logs/stream 的并发连接上限。
	SSEMaxConnectionsApiV1LogsStream = 5
	// SSEKeepaliveSecondsApiV1LogsStream 是 GET /api/v1/logs/stream 的心跳间隔。
	SSEKeepaliveSecondsApiV1LogsStream = 15
)

// 各流的事件名。发布侧必须逐字发这些名字（event: 行），前端订阅侧同此。
var SSEEventNamesApiV1Events = []string{"connected", "stats", "bans", "jails", "whitelist", "rates"}
var SSEEventNamesApiV1LogsStream = []string{"connected", "log", "error"}

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
	// Handler 是契约里的逻辑 handler 名（`handle_*`），用于对账与诊断输出；
	// 不要求 Go 侧存在同名符号——注册串才是锚点。
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
	{Pattern: RouteGetHealth, Path: "/health", Method: "GET", Auth: AuthNone, Handler: "handle_health", Returns: ReturnsType, Status: 200, AltStatus: 503},
	{Pattern: RouteGetHealthz, Path: "/healthz", Method: "GET", Auth: AuthNone, Handler: "handle_health", Returns: ReturnsType, Status: 200, AltStatus: 503},
	{Pattern: RouteGet, Path: "/", Method: "GET", Auth: AuthNone, Handler: "handle_redirect", Returns: ReturnsText, Status: 303},
	{Pattern: RouteGetDashboard, Path: "/dashboard", Method: "GET", Auth: AuthNone, Handler: "handle_dashboard", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetBans, Path: "/bans", Method: "GET", Auth: AuthNone, Handler: "handle_spa_bans", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetWhitelist, Path: "/whitelist", Method: "GET", Auth: AuthNone, Handler: "handle_spa_whitelist", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetJails, Path: "/jails", Method: "GET", Auth: AuthNone, Handler: "handle_spa_jails", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetDdos, Path: "/ddos", Method: "GET", Auth: AuthNone, Handler: "handle_spa_ddos", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetGlobe, Path: "/globe", Method: "GET", Auth: AuthNone, Handler: "handle_spa_globe", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetLogs, Path: "/logs", Method: "GET", Auth: AuthNone, Handler: "handle_spa_logs", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetSettings, Path: "/settings", Method: "GET", Auth: AuthNone, Handler: "handle_spa_settings", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetMore, Path: "/more", Method: "GET", Auth: AuthNone, Handler: "handle_spa_more", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetStaticPath, Path: "/static/{path...}", Method: "GET", Auth: AuthNone, Handler: "handle_static", Returns: ReturnsBytes, Status: 200, AltStatus: 404},
	{Pattern: RouteGetSwJs, Path: "/sw.js", Method: "GET", Auth: AuthNone, Handler: "handle_sw", Returns: ReturnsBytes, Status: 200, AltStatus: 404},
	{Pattern: RouteGetMetrics, Path: "/metrics", Method: "GET", Auth: AuthRequired, Handler: "handle_metrics", Returns: ReturnsText, Status: 200},
	{Pattern: RouteGetApiV1Events, Path: "/api/v1/events", Method: "GET", Auth: AuthRequired, Handler: "handle_sse", Returns: ReturnsStream, Status: 200, AltStatus: 503, MaxConnections: SSEMaxConnectionsApiV1Events, Events: SSEEventNamesApiV1Events, KeepaliveSecs: SSEKeepaliveSecondsApiV1Events},
	{Pattern: RouteGetApiV1LogsStream, Path: "/api/v1/logs/stream", Method: "GET", Auth: AuthRequired, Handler: "handle_log_stream", Returns: ReturnsStream, Status: 200, AltStatus: 503, MaxConnections: SSEMaxConnectionsApiV1LogsStream, Events: SSEEventNamesApiV1LogsStream, KeepaliveSecs: SSEKeepaliveSecondsApiV1LogsStream},
	{Pattern: RouteGetApiV1Stats, Path: "/api/v1/stats", Method: "GET", Auth: AuthRequired, Handler: "handle_api_stats", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1Bans, Path: "/api/v1/bans", Method: "GET", Auth: AuthRequired, Handler: "handle_api_bans", Returns: ReturnsType, Status: 200, Codes: []int{CodeOK}},
	{Pattern: RoutePostApiV1Bans, Path: "/api/v1/bans", Method: "POST", Auth: AuthRequired, Handler: "handle_create_ban", Returns: ReturnsType, Status: 201, AltStatus: 200, Codes: []int{Code40001}},
	{Pattern: RouteDeleteApiV1BansIp, Path: "/api/v1/bans/{ip}", Method: "DELETE", Auth: AuthRequired, Handler: "handle_delete_ban", Returns: ReturnsType, Status: 200, Codes: []int{Code40002}},
	{Pattern: RouteGetApiV1BansIpDetail, Path: "/api/v1/bans/{ip}/detail", Method: "GET", Auth: AuthRequired, Handler: "handle_ban_detail", Returns: ReturnsType, Status: 200, Codes: []int{Code40006}},
	{Pattern: RoutePostApiV1BansUnbanTemporary, Path: "/api/v1/bans/unban-temporary", Method: "POST", Auth: AuthRequired, Handler: "handle_unban_temporary", Returns: ReturnsType, Status: 200, Codes: []int{Code40003}},
	{Pattern: RoutePostApiV1BansBatch, Path: "/api/v1/bans/batch", Method: "POST", Auth: AuthRequired, Handler: "handle_batch_ban", Returns: ReturnsType, Status: 201, AltStatus: 200, Codes: []int{Code40005}},
	{Pattern: RouteGetApiV1Jails, Path: "/api/v1/jails", Method: "GET", Auth: AuthRequired, Handler: "handle_api_jails", Returns: ReturnsType, Status: 200},
	{Pattern: RoutePutApiV1JailsName, Path: "/api/v1/jails/{name}", Method: "PUT", Auth: AuthRequired, Handler: "handle_update_jail", Returns: ReturnsType, Status: 200, Codes: []int{Code404}},
	{Pattern: RouteGetApiV1Config, Path: "/api/v1/config", Method: "GET", Auth: AuthRequired, Handler: "handle_api_config", Returns: ReturnsType, Status: 200},
	{Pattern: RoutePutApiV1Config, Path: "/api/v1/config", Method: "PUT", Auth: AuthRequired, Handler: "handle_update_config", Returns: ReturnsType, Status: 200, Codes: []int{Code40004}},
	{Pattern: RouteGetApiV1Whitelist, Path: "/api/v1/whitelist", Method: "GET", Auth: AuthRequired, Handler: "handle_api_whitelist", Returns: ReturnsType, Status: 200},
	{Pattern: RoutePostApiV1Whitelist, Path: "/api/v1/whitelist", Method: "POST", Auth: AuthRequired, Handler: "handle_create_whitelist", Returns: ReturnsType, Status: 201, AltStatus: 200, Codes: []int{Code40003}},
	{Pattern: RouteDeleteApiV1WhitelistCidr, Path: "/api/v1/whitelist/{cidr}", Method: "DELETE", Auth: AuthRequired, Handler: "handle_delete_whitelist", Returns: ReturnsType, Status: 200, Codes: []int{Code40004}},
	{Pattern: RouteGetApiV1WhitelistRecommendations, Path: "/api/v1/whitelist/recommendations", Method: "GET", Auth: AuthRequired, Handler: "handle_whitelist_recommendations", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1RatesCurrent, Path: "/api/v1/rates/current", Method: "GET", Auth: AuthRequired, Handler: "handle_api_rates_current", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1RatesHistory, Path: "/api/v1/rates/history", Method: "GET", Auth: AuthRequired, Handler: "handle_api_rates_history", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1RatesWindows, Path: "/api/v1/rates/windows", Method: "GET", Auth: AuthRequired, Handler: "handle_api_rates_windows", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsHeatmap, Path: "/api/v1/stats/heatmap", Method: "GET", Auth: AuthRequired, Handler: "handle_api_heatmap", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsRecidivism, Path: "/api/v1/stats/recidivism", Method: "GET", Auth: AuthRequired, Handler: "handle_api_recidivism", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsBanEffectiveness, Path: "/api/v1/stats/ban-effectiveness", Method: "GET", Auth: AuthRequired, Handler: "handle_api_ban_effectiveness", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsPeriodicAttackers, Path: "/api/v1/stats/periodic-attackers", Method: "GET", Auth: AuthRequired, Handler: "handle_api_periodic_attackers", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsCollaborativeAttacks, Path: "/api/v1/stats/collaborative-attacks", Method: "GET", Auth: AuthRequired, Handler: "handle_api_collaborative_attacks", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsUdpPorts, Path: "/api/v1/stats/udp-ports", Method: "GET", Auth: AuthRequired, Handler: "handle_api_udp_ports", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsIcmpTypes, Path: "/api/v1/stats/icmp-types", Method: "GET", Auth: AuthRequired, Handler: "handle_api_icmp_types", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsSseStatus, Path: "/api/v1/stats/sse-status", Method: "GET", Auth: AuthRequired, Handler: "handle_api_sse_status", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsBanDurationHistogram, Path: "/api/v1/stats/ban-duration-histogram", Method: "GET", Auth: AuthRequired, Handler: "handle_api_ban_duration_histogram", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsPacketSizes, Path: "/api/v1/stats/packet-sizes", Method: "GET", Auth: AuthRequired, Handler: "handle_api_packet_sizes", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsTtlDistribution, Path: "/api/v1/stats/ttl-distribution", Method: "GET", Auth: AuthRequired, Handler: "handle_api_ttl_distribution", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsIpFragments, Path: "/api/v1/stats/ip-fragments", Method: "GET", Auth: AuthRequired, Handler: "handle_api_ip_fragments", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsPortScanners, Path: "/api/v1/stats/port-scanners", Method: "GET", Auth: AuthRequired, Handler: "handle_api_port_scanners", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsServiceProbes, Path: "/api/v1/stats/service-probes", Method: "GET", Auth: AuthRequired, Handler: "handle_api_service_probes", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsBanDurationRecommendations, Path: "/api/v1/stats/ban-duration-recommendations", Method: "GET", Auth: AuthRequired, Handler: "handle_api_ban_duration_recommendations", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsReputation, Path: "/api/v1/stats/reputation", Method: "GET", Auth: AuthRequired, Handler: "handle_api_reputation", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsThresholdRecommendations, Path: "/api/v1/stats/threshold-recommendations", Method: "GET", Auth: AuthRequired, Handler: "handle_api_threshold_recommendations", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsNetworkDistribution, Path: "/api/v1/stats/network-distribution", Method: "GET", Auth: AuthRequired, Handler: "handle_api_network_distribution", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsAttackPredictions, Path: "/api/v1/stats/attack-predictions", Method: "GET", Auth: AuthRequired, Handler: "handle_api_attack_predictions", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsAnomalies, Path: "/api/v1/stats/anomalies", Method: "GET", Auth: AuthRequired, Handler: "handle_api_anomalies", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1StatsAttackGeo, Path: "/api/v1/stats/attack-geo", Method: "GET", Auth: AuthRequired, Handler: "handle_api_attack_geo", Returns: ReturnsType, Status: 200},
	{Pattern: RouteGetApiV1Logs, Path: "/api/v1/logs", Method: "GET", Auth: AuthRequired, Handler: "handle_api_logs", Returns: ReturnsType, Status: 200, Codes: []int{Code40005}},
}

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

// RouteByPattern 按注册串查契约路由。
func RouteByPattern(pattern string) (Route, bool) {
	for _, r := range Routes {
		if r.Pattern == pattern {
			return r, true
		}
	}
	return Route{}, false
}

// RouteByMethodPath 按方法与路径查契约路由；路径可传契约写法（`:ip`）或
// Go 写法（`{ip}`），两种拼写在 GoPath 里归一。
func RouteByMethodPath(method, path string) (Route, bool) {
	want := method + " " + GoPath(path)
	for _, r := range Routes {
		if r.Pattern == want {
			return r, true
		}
	}
	return Route{}, false
}

// Patterns 返回全部注册串，顺序同 Routes；契约测试用它逐条比对实现侧的注册。
func Patterns() []string {
	out := make([]string, 0, len(Routes))
	for _, r := range Routes {
		out = append(out, r.Pattern)
	}
	return out
}

// GoPath 把契约路径的参数槽 `:name` 转成 ServeMux 的 `{name}`，把多段通配
// `*name` 转成 `{name...}`，其余原样。通配必须转：ServeMux 只在**没有**方法前缀
// 时才认旧式 `*name`，而本契约的注册串条条带方法，留着 `*name` 就变成匹配字面量。
func GoPath(path string) string {
	out := []byte{}
	for i := 0; i < len(path); i++ {
		if path[i] == ':' && i+1 < len(path) && isIdentStart(path[i+1]) {
			out = append(out, '{')
			i++
			for i < len(path) && isIdentByte(path[i]) {
				out = append(out, path[i])
				i++
			}
			out = append(out, '}')
			i--
			continue
		}
		if path[i] == '*' && i+1 < len(path) && isIdentStart(path[i+1]) {
			out = append(out, '{')
			i++
			for i < len(path) && isIdentByte(path[i]) {
				out = append(out, path[i])
				i++
			}
			out = append(out, '.', '.', '.', '}')
			i--
			continue
		}
		out = append(out, path[i])
	}
	return string(out)
}

func isIdentStart(b byte) bool {
	return b == '_' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func isIdentByte(b byte) bool {
	return isIdentStart(b) || (b >= '0' && b <= '9')
}
