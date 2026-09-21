//! 由 contract/http.fwidl 生成 —— 请勿手工编辑。
//!
//! 守护进程 HTTP 接口的路径、方法与业务码单一真相源。

#![allow(dead_code)]

/// 契约名：firewall_daemon_http
pub const NAME: &str = "firewall_daemon_http";

/// API 前缀：/api/v1
pub const BASE: &str = "/api/v1";

/// 路由路径常量（与 axum 注册的字面量逐字一致）
#[rustfmt::skip]
pub mod path {
    /// `GET /health` → `handle_health`
    pub const ROUTE_GET_HEALTH: &str = "/health";
    /// `GET /healthz` → `handle_health`
    pub const ROUTE_GET_HEALTHZ: &str = "/healthz";
    /// `GET /` → `handle_redirect`
    pub const ROUTE_GET: &str = "/";
    /// `GET /dashboard` → `handle_dashboard`
    pub const ROUTE_GET_DASHBOARD: &str = "/dashboard";
    /// `GET /bans` → `handle_spa_bans`
    pub const ROUTE_GET_BANS: &str = "/bans";
    /// `GET /whitelist` → `handle_spa_whitelist`
    pub const ROUTE_GET_WHITELIST: &str = "/whitelist";
    /// `GET /jails` → `handle_spa_jails`
    pub const ROUTE_GET_JAILS: &str = "/jails";
    /// `GET /ddos` → `handle_spa_ddos`
    pub const ROUTE_GET_DDOS: &str = "/ddos";
    /// `GET /logs` → `handle_spa_logs`
    pub const ROUTE_GET_LOGS: &str = "/logs";
    /// `GET /settings` → `handle_spa_settings`
    pub const ROUTE_GET_SETTINGS: &str = "/settings";
    /// `GET /more` → `handle_spa_more`
    pub const ROUTE_GET_MORE: &str = "/more";
    /// `GET /static/*path` → `handle_static`
    pub const ROUTE_GET_STATIC_PATH: &str = "/static/*path";
    /// `GET /sw.js` → `handle_sw`
    pub const ROUTE_GET_SW_JS: &str = "/sw.js";
    /// `GET /metrics` → `handle_metrics`
    pub const ROUTE_GET_METRICS: &str = "/metrics";
    /// `GET /api/v1/events` → `handle_sse`
    pub const ROUTE_GET_API_V1_EVENTS: &str = "/api/v1/events";
    /// `GET /api/v1/logs/stream` → `handle_log_stream`
    pub const ROUTE_GET_API_V1_LOGS_STREAM: &str = "/api/v1/logs/stream";
    /// `GET /api/v1/stats` → `handle_api_stats`
    pub const ROUTE_GET_API_V1_STATS: &str = "/api/v1/stats";
    /// `GET /api/v1/bans` → `handle_api_bans`
    pub const ROUTE_GET_API_V1_BANS: &str = "/api/v1/bans";
    /// `POST /api/v1/bans` → `handle_create_ban`
    pub const ROUTE_POST_API_V1_BANS: &str = "/api/v1/bans";
    /// `DELETE /api/v1/bans/:ip` → `handle_delete_ban`
    pub const ROUTE_DELETE_API_V1_BANS_IP: &str = "/api/v1/bans/:ip";
    /// `GET /api/v1/bans/:ip/detail` → `handle_ban_detail`
    pub const ROUTE_GET_API_V1_BANS_IP_DETAIL: &str = "/api/v1/bans/:ip/detail";
    /// `POST /api/v1/bans/unban-temporary` → `handle_unban_temporary`
    pub const ROUTE_POST_API_V1_BANS_UNBAN_TEMPORARY: &str = "/api/v1/bans/unban-temporary";
    /// `POST /api/v1/bans/batch` → `handle_batch_ban`
    pub const ROUTE_POST_API_V1_BANS_BATCH: &str = "/api/v1/bans/batch";
    /// `GET /api/v1/jails` → `handle_api_jails`
    pub const ROUTE_GET_API_V1_JAILS: &str = "/api/v1/jails";
    /// `PUT /api/v1/jails/:name` → `handle_update_jail`
    pub const ROUTE_PUT_API_V1_JAILS_NAME: &str = "/api/v1/jails/:name";
    /// `GET /api/v1/config` → `handle_api_config`
    pub const ROUTE_GET_API_V1_CONFIG: &str = "/api/v1/config";
    /// `PUT /api/v1/config` → `handle_update_config`
    pub const ROUTE_PUT_API_V1_CONFIG: &str = "/api/v1/config";
    /// `GET /api/v1/whitelist` → `handle_api_whitelist`
    pub const ROUTE_GET_API_V1_WHITELIST: &str = "/api/v1/whitelist";
    /// `POST /api/v1/whitelist` → `handle_create_whitelist`
    pub const ROUTE_POST_API_V1_WHITELIST: &str = "/api/v1/whitelist";
    /// `DELETE /api/v1/whitelist/:cidr` → `handle_delete_whitelist`
    pub const ROUTE_DELETE_API_V1_WHITELIST_CIDR: &str = "/api/v1/whitelist/:cidr";
    /// `GET /api/v1/whitelist/recommendations` → `handle_whitelist_recommendations`
    pub const ROUTE_GET_API_V1_WHITELIST_RECOMMENDATIONS: &str = "/api/v1/whitelist/recommendations";
    /// `GET /api/v1/rates/current` → `handle_api_rates_current`
    pub const ROUTE_GET_API_V1_RATES_CURRENT: &str = "/api/v1/rates/current";
    /// `GET /api/v1/rates/history` → `handle_api_rates_history`
    pub const ROUTE_GET_API_V1_RATES_HISTORY: &str = "/api/v1/rates/history";
    /// `GET /api/v1/rates/windows` → `handle_api_rates_windows`
    pub const ROUTE_GET_API_V1_RATES_WINDOWS: &str = "/api/v1/rates/windows";
    /// `GET /api/v1/stats/heatmap` → `handle_api_heatmap`
    pub const ROUTE_GET_API_V1_STATS_HEATMAP: &str = "/api/v1/stats/heatmap";
    /// `GET /api/v1/stats/recidivism` → `handle_api_recidivism`
    pub const ROUTE_GET_API_V1_STATS_RECIDIVISM: &str = "/api/v1/stats/recidivism";
    /// `GET /api/v1/stats/ban-effectiveness` → `handle_api_ban_effectiveness`
    pub const ROUTE_GET_API_V1_STATS_BAN_EFFECTIVENESS: &str = "/api/v1/stats/ban-effectiveness";
    /// `GET /api/v1/stats/periodic-attackers` → `handle_api_periodic_attackers`
    pub const ROUTE_GET_API_V1_STATS_PERIODIC_ATTACKERS: &str = "/api/v1/stats/periodic-attackers";
    /// `GET /api/v1/stats/collaborative-attacks` → `handle_api_collaborative_attacks`
    pub const ROUTE_GET_API_V1_STATS_COLLABORATIVE_ATTACKS: &str = "/api/v1/stats/collaborative-attacks";
    /// `GET /api/v1/stats/udp-ports` → `handle_api_udp_ports`
    pub const ROUTE_GET_API_V1_STATS_UDP_PORTS: &str = "/api/v1/stats/udp-ports";
    /// `GET /api/v1/stats/icmp-types` → `handle_api_icmp_types`
    pub const ROUTE_GET_API_V1_STATS_ICMP_TYPES: &str = "/api/v1/stats/icmp-types";
    /// `GET /api/v1/stats/sse-status` → `handle_api_sse_status`
    pub const ROUTE_GET_API_V1_STATS_SSE_STATUS: &str = "/api/v1/stats/sse-status";
    /// `GET /api/v1/stats/ban-duration-histogram` → `handle_api_ban_duration_histogram`
    pub const ROUTE_GET_API_V1_STATS_BAN_DURATION_HISTOGRAM: &str = "/api/v1/stats/ban-duration-histogram";
    /// `GET /api/v1/stats/packet-sizes` → `handle_api_packet_sizes`
    pub const ROUTE_GET_API_V1_STATS_PACKET_SIZES: &str = "/api/v1/stats/packet-sizes";
    /// `GET /api/v1/stats/ttl-distribution` → `handle_api_ttl_distribution`
    pub const ROUTE_GET_API_V1_STATS_TTL_DISTRIBUTION: &str = "/api/v1/stats/ttl-distribution";
    /// `GET /api/v1/stats/ip-fragments` → `handle_api_ip_fragments`
    pub const ROUTE_GET_API_V1_STATS_IP_FRAGMENTS: &str = "/api/v1/stats/ip-fragments";
    /// `GET /api/v1/stats/port-scanners` → `handle_api_port_scanners`
    pub const ROUTE_GET_API_V1_STATS_PORT_SCANNERS: &str = "/api/v1/stats/port-scanners";
    /// `GET /api/v1/stats/service-probes` → `handle_api_service_probes`
    pub const ROUTE_GET_API_V1_STATS_SERVICE_PROBES: &str = "/api/v1/stats/service-probes";
    /// `GET /api/v1/stats/ban-duration-recommendations` → `handle_api_ban_duration_recommendations`
    pub const ROUTE_GET_API_V1_STATS_BAN_DURATION_RECOMMENDATIONS: &str = "/api/v1/stats/ban-duration-recommendations";
    /// `GET /api/v1/stats/reputation` → `handle_api_reputation`
    pub const ROUTE_GET_API_V1_STATS_REPUTATION: &str = "/api/v1/stats/reputation";
    /// `GET /api/v1/stats/threshold-recommendations` → `handle_api_threshold_recommendations`
    pub const ROUTE_GET_API_V1_STATS_THRESHOLD_RECOMMENDATIONS: &str = "/api/v1/stats/threshold-recommendations";
    /// `GET /api/v1/stats/network-distribution` → `handle_api_network_distribution`
    pub const ROUTE_GET_API_V1_STATS_NETWORK_DISTRIBUTION: &str = "/api/v1/stats/network-distribution";
    /// `GET /api/v1/stats/attack-predictions` → `handle_api_attack_predictions`
    pub const ROUTE_GET_API_V1_STATS_ATTACK_PREDICTIONS: &str = "/api/v1/stats/attack-predictions";
    /// `GET /api/v1/logs` → `handle_api_logs`
    pub const ROUTE_GET_API_V1_LOGS: &str = "/api/v1/logs";
}

/// 业务码（信封里的 `code` 字段）
pub mod code {
    /// HTTP 200：成功；message 为空串
    pub const OK: i32 = 0;
    /// HTTP 400：封禁失败（内核未确认、IP 非法、或内核返回错误）
    pub const CODE_40001: i32 = 40001;
    /// HTTP 400：解封失败（IP 非法或内核拒绝）
    pub const CODE_40002: i32 = 40002;
    /// HTTP 400：批量解封临时封禁失败 / 添加白名单失败
    pub const CODE_40003: i32 = 40003;
    /// HTTP 400：更新配置失败 / 移除白名单失败
    pub const CODE_40004: i32 = 40004;
    /// HTTP 400：批量封禁参数非法（列表为空或超过 100 条）/ 日志查询参数非法
    pub const CODE_40005: i32 = 40005;
    /// HTTP 400：封禁详情查询失败（IP 非法）
    pub const CODE_40006: i32 = 40006;
    /// HTTP 404：Jail 不存在
    pub const CODE_404: i32 = 404;
    /// HTTP 500：服务端内部错误（历史库查询任务 join 失败等），message 含具体原因
    pub const CODE_50002: i32 = 50002;
}

/// 认证策略
pub mod auth {
    pub const FAILURE_THRESHOLD: u32 = 10;
    pub const LOCKOUT_SECONDS: u64 = 60;
    pub const UNAUTHORIZED_STATUS: u16 = 401;
    pub const TOKEN_QUERY: &str = "access_token";
}

/// SSE 连接上限（两条流各自独立）
#[rustfmt::skip]
pub mod sse {
    /// `/api/v1/events`
    pub const MAX_CONNECTIONS_API_V1_EVENTS: usize = 10;
    pub const EVENTS_API_V1_EVENTS: &[&str] = &["connected", "stats", "bans", "jails", "whitelist", "rates"];
    /// `/api/v1/logs/stream`
    pub const MAX_CONNECTIONS_API_V1_LOGS_STREAM: usize = 5;
    pub const EVENTS_API_V1_LOGS_STREAM: &[&str] = &["connected", "log", "error"];
}
