//! 数据缺口端口：`api` 只依赖这些窄接口，不依赖任何具体 owner。
//!
//! # 为什么需要端口
//!
//! `api` 的载荷里有几类字段**不由 `state` 决定**：历史库趋势、IP 信誉、
//! Jail 的配置面（阈值/时长）、Web UI 配置、运行时就绪态、Prometheus 文本。
//! 这些数据的所有者（`history_snapshot` / `ip_reputation` / `jail` / `config` /
//! `runtime_status`）尚未重写。
//!
//! 与其让 `api` 直接伸手去够旧全局（那样 2.E-4 之后 `api` 依然绑死在旧模块上，
//! 退役只能重写路由），这里把缺口收成三个窄 trait：`api` 只认这些方法，
//! 生产实现由组合根注入，各 owner 重写时**换实现即可，路由代码不动**。
//!
//! # 为什么不是「先写占位实现」
//!
//! 占位实现会返回假数据，而假数据无法与真数据区分——`api` 一旦长出「今天先返回
//! 空」的分支，这个分支就会留在代码里成为永久行为。端口相反：缺口在**类型上**
//! 显式存在（没有端口就无法构造路由），补上端口才可能返回真数据。

use std::net::IpAddr;

use serde::Serialize;

/// 一条封禁详情的历史面（`state` 不知道、只有历史库知道的部分）。
///
/// `state::bans::BanEntry` 提供当前封禁的活性信息；本结构补上「解封过没有」
/// 「信誉如何」「下一次封多久」这类需要历史才能回答的字段。
#[derive(Debug, Clone, PartialEq)]
pub struct BanHistoryView {
    /// 累计封禁次数（已在封禁中时以 `state` 的条目为准）。
    pub ban_count: u32,
    /// 上次解封时间（Unix 秒）；`0` 表示当前仍在封禁中。
    pub last_unbanned_at: i64,
    /// 是否曾被永久封禁。
    pub was_permanent: bool,
    /// IP 信誉分（0–100，100 = 完全信任）。
    pub reputation_score: u32,
    /// 信誉阈值乘数（0.5 / 0.8 / 1.0）。
    pub reputation_multiplier: f64,
}

impl Default for BanHistoryView {
    fn default() -> Self {
        Self {
            ban_count: 0,
            last_unbanned_at: 0,
            was_permanent: false,
            reputation_score: 100,
            reputation_multiplier: 1.0,
        }
    }
}

/// 图表数据（契约里的 `ChartData`）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ChartData {
    /// 横轴标签。
    pub labels: Vec<String>,
    /// 与标签一一对应的值。
    pub values: Vec<u64>,
}

/// `GET /api/v1/stats` 里来自历史库的两个趋势序列。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrendsView {
    /// 封禁次数趋势。
    pub ban_trend: ChartData,
    /// 失败尝试趋势。
    pub failed_attempts_trend: ChartData,
}

/// 一个 Jail 的配置面（`state` 不知道、只有配置 owner 知道的部分）。
#[derive(Debug, Clone, PartialEq)]
pub struct JailView {
    /// Jail 名称。
    pub name: String,
    /// 是否启用。
    pub enabled: bool,
    /// 配置的失败阈值（未经系数放大的原始值）。
    pub max_retries: u32,
    /// 当前有效阈值（业务高峰期可能放宽）。
    pub effective_max_retries: u32,
    /// 滑动窗口（秒）。
    pub findtime: u32,
    /// 封禁时长（秒）；负值表示永久。
    pub ban_time: i32,
    /// 是否处于业务高峰期。
    pub is_peak_hours: bool,
    /// 高峰期阈值放宽倍数。
    pub peak_hours_multiplier: f64,
    /// 内网 IP 阈值放宽倍数。
    pub internal_ip_multiplier: f64,
}

/// Web UI 配置视图（线上字段名见契约 `WebuiConfigResponse`）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WebuiConfigView {
    /// SSE 推送间隔（秒，1–60）。
    pub sse_push_interval: u32,
    /// 速率警告阈值（pps）。
    pub rate_warning_pps: u64,
    /// 速率严重阈值（pps）。
    pub rate_critical_pps: u64,
    /// SYN 警告阈值（pps）。
    pub rate_warning_syn: u64,
    /// SYN 严重阈值（pps）。
    pub rate_critical_syn: u64,
    /// SYN 每秒上限。
    pub max_syn_per_second: u32,
    /// UDP 每秒上限。
    pub max_udp_per_second: u32,
    /// ICMP 每秒上限。
    pub max_icmp_per_second: u32,
    /// ACK 每秒上限。
    pub max_ack_per_second: u32,
    /// RST 每秒上限。
    pub max_rst_per_second: u32,
    /// FIN 每秒上限。
    pub max_fin_per_second: u32,
    /// 静态阈值算法开关。
    pub static_threshold: bool,
    /// 动态阈值算法开关。
    pub dynamic_threshold: bool,
    /// DDoS 检测总开关。
    pub ddos_detection: bool,
    /// 封禁表容量。
    pub max_ban_entries: u32,
    /// 白名单容量。
    pub max_whitelist_entries: u32,
    /// 速率表容量。
    pub max_rate_entries: u32,
    /// 本地 IP 缓存容量。
    pub max_local_ip_cache: u32,
    /// 日志视图过滤起点；`None` 表示不过滤。
    pub clear_logs_at: Option<String>,
}

/// Web UI 配置的更新补丁（每个字段可选）。
///
/// 校验（`warning < critical`、非零容量……）由实现侧负责：阈值之间的大小关系
/// 是配置语义，不属于 HTTP 层形状。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct WebuiConfigPatch {
    /// SSE 推送间隔。
    pub sse_push_interval: Option<u32>,
    /// 速率警告阈值。
    pub rate_warning_pps: Option<u64>,
    /// 速率严重阈值。
    pub rate_critical_pps: Option<u64>,
    /// SYN 警告阈值。
    pub rate_warning_syn: Option<u64>,
    /// SYN 严重阈值。
    pub rate_critical_syn: Option<u64>,
    /// SYN 每秒上限。
    pub max_syn_per_second: Option<u32>,
    /// UDP 每秒上限。
    pub max_udp_per_second: Option<u32>,
    /// ICMP 每秒上限。
    pub max_icmp_per_second: Option<u32>,
    /// ACK 每秒上限。
    pub max_ack_per_second: Option<u32>,
    /// RST 每秒上限。
    pub max_rst_per_second: Option<u32>,
    /// FIN 每秒上限。
    pub max_fin_per_second: Option<u32>,
    /// 静态阈值算法开关。
    pub static_threshold: Option<bool>,
    /// 动态阈值算法开关。
    pub dynamic_threshold: Option<bool>,
    /// DDoS 检测总开关。
    pub ddos_detection: Option<bool>,
    /// 封禁表容量。
    pub max_ban_entries: Option<u32>,
    /// 白名单容量。
    pub max_whitelist_entries: Option<u32>,
    /// 速率表容量。
    pub max_rate_entries: Option<u32>,
    /// 本地 IP 缓存容量。
    pub max_local_ip_cache: Option<u32>,
    /// 日志视图过滤起点；`Some("")` 表示取消过滤。
    pub clear_logs_at: Option<String>,
}

/// 运行时就绪态视图（`GET /health`、`GET /healthz`）。
///
/// 字段名与契约 `RuntimeSnapshot` 逐字一致；旧实现以 HTTP 状态码承载语义
/// （`ok` → 200，其余 → 503），缺陷处置结论是「有意保留裸状态码」，故本结构
/// **不经信封**序列化。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeView {
    /// `"ok"` 或 `"degraded"`。
    pub status: &'static str,
    /// 内核是否会接受本进程的指令（租约已持有）。
    pub netlink_ready: bool,
    /// `/proc/firewall` 是否存在。
    pub kmod_proc_present: bool,
    /// 封禁缓存是否已初始化。
    pub ban_cache_initialized: bool,
    /// 封禁历史库是否已初始化。
    pub ban_history_initialized: bool,
    /// 当前活跃封禁数。
    pub active_bans: usize,
    /// 内核单实例注册租约的状态（`none`/`idle`/`held`/`refused`/`lost`）。
    pub lease_state: &'static str,
    /// 进入 `lost` 的累计次数。
    pub lease_losses: u64,
}

impl RuntimeView {
    /// 是否全部就绪（决定 `/health` 的 HTTP 状态码）。
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        self.netlink_ready && self.kmod_proc_present
    }
}

/// 配置面端口：Web UI 配置读写 + Jail 配置视图。
///
/// `PUT /api/v1/jails/:name` 的语义是「改配置并持久化」，故也落在这里——它是
/// 配置写入而非状态写入。
pub trait ConfigPort: Send + Sync + 'static {
    /// 读取当前 Web UI 配置。
    fn webui(&self) -> WebuiConfigView;

    /// 应用一个补丁并持久化；失败返回人类可读原因（进信封 `message`）。
    ///
    /// # Errors
    ///
    /// 阈值关系非法（警告 ≥ 严重）、容量为 0、持久化失败时返回错误消息。
    fn apply(&self, patch: WebuiConfigPatch) -> Result<WebuiConfigView, String>;

    /// 列出业务正在考虑的 Jail（可能是「已启用」的子集）。
    fn jails(&self) -> Vec<JailView>;

    /// 启用/禁用某个 Jail 并持久化，返回更新后的视图。
    ///
    /// # Errors
    ///
    /// Jail 不存在或持久化失败时返回错误消息。
    fn set_jail_enabled(&self, name: &str, enabled: bool) -> Result<JailView, String>;
}

/// 运行时与指标端口。
pub trait RuntimePort: Send + Sync + 'static {
    /// 当前运行时就绪态快照。
    fn snapshot(&self) -> RuntimeView;

    /// Prometheus 文本（`text/plain; version=0.0.4; charset=utf-8`）。
    fn metrics_text(&self) -> String;
}

/// 历史与信誉端口。
pub trait HistoryPort: Send + Sync + 'static {
    /// 两个趋势序列（来自历史库）。
    fn trends(&self) -> TrendsView;

    /// 某个 IP 的历史面（信誉、上次解封、是否曾永久）。
    fn ban_history(&self, ip: IpAddr) -> Option<BanHistoryView>;

    /// 当前速率窗口倍率（用于威胁等级的 `pps_ratio` 与基线冻结判定）。
    fn threat_inputs(&self) -> ThreatInputs;
}

/// 威胁等级计算所需的外部输入。
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ThreatInputs {
    /// 短期窗口内的全局 pps。
    pub current_pps: u64,
    /// 基线是否已冻结。
    pub baseline_frozen: bool,
    /// 是否处于业务高峰期。
    pub peak_hours: bool,
}

/// 一条封禁指令（`api` 不直接碰内核，只把意图交给控制面）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanCommand {
    /// 目标 IP。
    pub ip: IpAddr,
    /// 指定时长（秒）。
    ///
    /// **`None` 与 `Some(0)` 都表示永久封禁**（与内核 `ban_time=-1` 语义一致）：
    /// 控制端口把它原样交给 `create_ban`，后者按此判定 `permanent`。想封一段时间
    /// 就必须给出具体秒数，**不要**把「不指定」当成「用配置里的默认时长」——那会
    /// 静默变成永久封禁。
    pub duration: Option<u64>,
    /// 原因；`None` 表示手工封禁。
    pub reason: Option<String>,
}

/// 一次封禁的结果（成功投递并被内核确认后的参数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanOutcome {
    /// 是否永久封禁。
    pub permanent: bool,
    /// 时长（秒）；永久为 `None`。
    pub duration_seconds: Option<u64>,
}

/// 一条批量操作的结果（`api` 侧汇总，不经端口）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchOutcome {
    /// 本次请求涉及的条目总数。
    pub total: u64,
    /// 成功数。
    pub succeeded: u64,
    /// 逐条失败原因。
    pub failed: Vec<String>,
}

impl BatchOutcome {
    /// 由成功数与失败原因汇总。
    #[must_use]
    pub fn new(succeeded: u64, failed: Vec<String>) -> Self {
        Self {
            total: succeeded + failed.len() as u64,
            succeeded,
            failed,
        }
    }
}

/// 控制面端口：把封禁/解封/白名单意图交给内核侧。
///
/// 只有四个方法，且都不返回「已执行」而是「已确认」——`kernel::client` 已经把
/// 「已投递」与「已确认」分成两种类型，本端口沿用同一口径：`Ok` 表示内核确认，
/// `Err` 才可能落到信封的 40001 / 40002 / 40003 / 40004。
pub trait ControlPort: Send + Sync + 'static {
    /// 下发一条封禁指令。
    ///
    /// # Errors
    ///
    /// IP 非法、内核未确认或内核返回错误时返回人类可读原因。
    fn ban(&self, cmd: BanCommand) -> Result<BanOutcome, String>;

    /// 下发一条解封指令。
    ///
    /// # Errors
    ///
    /// IP 非法或内核拒绝时返回人类可读原因。
    fn unban(&self, ip: IpAddr) -> Result<(), String>;

    /// 添加一条白名单。
    ///
    /// 返回内核接受的**规范化 CIDR 文本**（前端可原样用于删除）。
    ///
    /// # Errors
    ///
    /// CIDR 非法、前缀超限或内核拒绝时返回人类可读原因。
    fn add_whitelist(&self, cidr: &str) -> Result<String, String>;

    /// 移除一条白名单。
    ///
    /// # Errors
    ///
    /// CIDR 非法或内核拒绝时返回人类可读原因。
    fn remove_whitelist(&self, cidr: &str) -> Result<String, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chart_data_serializes_with_the_contract_field_names() {
        let chart = ChartData {
            labels: vec!["a".to_string()],
            values: vec![1],
        };
        let json = serde_json::to_value(&chart).expect("可序列化");
        assert_eq!(json["labels"][0], "a");
        assert_eq!(json["values"][0], 1);
    }

    #[test]
    fn the_config_patch_matches_the_contract_field_names() {
        // 字段名写错会让 PUT /config 静默忽略整个补丁。
        let patch: WebuiConfigPatch =
            serde_json::from_str(r#"{"sse_push_interval":2,"max_ban_entries":100}"#)
                .expect("可反序列化");
        assert_eq!(patch.sse_push_interval, Some(2));
        assert_eq!(patch.max_ban_entries, Some(100));
        assert_eq!(patch.max_whitelist_entries, None);
    }

    #[test]
    fn an_empty_patch_is_valid_and_changes_nothing() {
        let patch: WebuiConfigPatch = serde_json::from_str("{}").expect("可反序列化");
        assert_eq!(patch, WebuiConfigPatch::default());
    }

    #[test]
    fn readiness_follows_netlink_and_the_kernel_module() {
        let mut view = RuntimeView {
            status: "ok",
            netlink_ready: true,
            kmod_proc_present: true,
            ban_cache_initialized: true,
            ban_history_initialized: true,
            active_bans: 0,
            lease_state: "held",
            lease_losses: 0,
        };
        assert!(view.is_ready());
        view.netlink_ready = false;
        assert!(!view.is_ready(), "netlink 未就绪即视为未就绪");
        view.netlink_ready = true;
        view.kmod_proc_present = false;
        assert!(!view.is_ready(), "内核模块缺失即视为未就绪");
    }

    #[test]
    fn a_default_ban_history_view_is_a_trusted_never_unbanned_ip() {
        let view = BanHistoryView::default();
        assert_eq!(view.ban_count, 0);
        assert_eq!(view.last_unbanned_at, 0, "0 表示当前仍在封禁中");
        assert!(!view.was_permanent);
        assert_eq!(view.reputation_score, 100, "默认应为完全信任");
        assert!((view.reputation_multiplier - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_batch_outcome_counts_total_as_success_plus_failure() {
        let outcome = BatchOutcome::new(3, vec!["10.0.0.9: 内核拒绝".to_string()]);
        assert_eq!(outcome.total, 4);
        assert_eq!(outcome.succeeded, 3);
        assert_eq!(outcome.failed.len(), 1);
    }
}
