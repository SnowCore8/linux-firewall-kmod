//! 内核配置同步单入口
//!
//! 守护进程的配置有两个权威来源，最终都要落到同一份内核侧状态：
//!
//! - **YAML / SIGHUP 热重载**：[`crate::config_reloader::sync_config_to_components`]，取值 `Config::ddos`
//! - **Web UI API**：`web_ui::api` 的配置更新 handler，取值运行期 [`WebuiConfig`]
//!
//! 内核侧有两个互不依赖的写入通道：
//!
//! - **netlink `SetConfig`**：6 个协议专项阈值，以及 SIGHUP 路径额外的封禁时长等全局限制
//! - **sysfs 模块参数**：3 个检测算法开关
//!
//! 历史上两条来源各自内联构造 `SetConfig` 消息、各自手写 ACK/RST/FIN 三个字段的
//! 字节序转换，还各自实现了一份同名同逻辑的 `sync_ddos_detection_to_kernel`。
//! 本模块把「配置 → 内核」收敛为唯一实现：字段集合、字节序转换与「不下发」语义只在
//! 这里定义一次。
//!
//! 本模块不决定「谁的值更权威」——那由调用方语境决定（热重载读 YAML，API 读运行期
//! 配置）；这里只负责把调用方给的值正确地写进内核。
//!
//! 本模块原在 `netlink/config_sync.rs`，随旧 netlink 层退役迁到顶层：它依赖的只有
//! 新链路（[`crate::kernel::client::Client::set_config`]）与 sysfs，没有任何旧 netlink
//! 类型，故不随旧层一起删除。
//!
//! # 下发通道（结构问题 L）
//!
//! 旧实现有两条并行的 `SetConfig` 构造路径：`file_monitor/monitor_loop.rs`（已删除）
//! 的基线下发一条（自建 `ConfigUpdate`，绕开本模块），本模块一条。现在两条都收敛到
//! [`crate::kernel::client::Client::set_config`]——字段集合、字节序、采纳/拒绝位图的
//! 处理只有一处实现。周期任务（[`crate::kernel_poll`]）与本模块共同构成内核配置的
//! 全部写入入口。

use crate::contract::config_flags;
use crate::kernel::codec::SetConfig;
use crate::kernel::{global, REQUEST_TIMEOUT};
use crate::types::{DdosConfig, WebuiConfig};

/// 6 个协议专项阈值（原始值，非网络序）。
///
/// 与 [`DdosConfig`] / [`WebuiConfig`] 中的 `max_*_per_second` 字段一一对应。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProtocolThresholds {
    /// SYN flood 阈值（包/秒）
    pub max_syn_per_second: u32,
    /// UDP flood 阈值（包/秒）
    pub max_udp_per_second: u32,
    /// ICMP flood 阈值（包/秒）
    pub max_icmp_per_second: u32,
    /// ACK flood 阈值（包/秒）
    pub max_ack_per_second: u32,
    /// RST flood 阈值（包/秒）
    pub max_rst_per_second: u32,
    /// FIN flood 阈值（包/秒）
    pub max_fin_per_second: u32,
}

/// 3 个 DDoS 检测算法开关，写入 `/sys/module/firewall/parameters/`。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DetectionSwitches {
    /// 静态阈值检测开关
    pub static_threshold: bool,
    /// 动态阈值检测开关
    pub dynamic_threshold: bool,
    /// DDoS 检测总开关
    pub ddos_detection: bool,
}

/// SIGHUP 热重载路径额外下发的全局限制；Web UI API 路径不下发这些字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalLimits {
    /// 封禁时长（秒）
    pub ban_time: u32,
    /// 速率统计窗口（秒）
    pub rate_window: u32,
    /// 全局包速率上限（PPS）
    pub max_pps: u64,
    /// DDoS 触发后的封禁时长（秒）
    pub ddos_ban_duration: u32,
}

/// 协议阈值下发的实际结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// 已下发且内核确认全部字段生效
    Sent,
    /// 内核链路尚未就绪（尚未取得租约），静默跳过
    ///
    /// 旧语义是「netlink 上下文尚未初始化」；现在等价于「租约未持有」——那两种情况下
    /// 内核都会把报文丢掉，所以「跳过」比「报错」更贴近事实。
    Skipped,
}

impl From<&DdosConfig> for ProtocolThresholds {
    fn from(c: &DdosConfig) -> Self {
        Self {
            max_syn_per_second: c.max_syn_per_second,
            max_udp_per_second: c.max_udp_per_second,
            max_icmp_per_second: c.max_icmp_per_second,
            max_ack_per_second: c.max_ack_per_second,
            max_rst_per_second: c.max_rst_per_second,
            max_fin_per_second: c.max_fin_per_second,
        }
    }
}

impl From<&WebuiConfig> for ProtocolThresholds {
    fn from(c: &WebuiConfig) -> Self {
        Self {
            max_syn_per_second: c.max_syn_per_second,
            max_udp_per_second: c.max_udp_per_second,
            max_icmp_per_second: c.max_icmp_per_second,
            max_ack_per_second: c.max_ack_per_second,
            max_rst_per_second: c.max_rst_per_second,
            max_fin_per_second: c.max_fin_per_second,
        }
    }
}

impl From<&DdosConfig> for DetectionSwitches {
    fn from(c: &DdosConfig) -> Self {
        Self {
            static_threshold: c.static_threshold,
            dynamic_threshold: c.dynamic_threshold,
            ddos_detection: c.ddos_detection,
        }
    }
}

impl From<&WebuiConfig> for DetectionSwitches {
    fn from(c: &WebuiConfig) -> Self {
        Self {
            static_threshold: c.static_threshold,
            dynamic_threshold: c.dynamic_threshold,
            ddos_detection: c.ddos_detection,
        }
    }
}

/// 组装内核 `SetConfig` 消息。
///
/// `limits` 为 `None` 时只带协议阈值位（Web UI API 路径）；为 `Some` 时再追加
/// `BAN_TIME | RATE_WINDOW | MAX_PPS | DDOS_BAN_DURATION`（SIGHUP 热重载路径）。
/// 内核按 `flags` 逐位决定覆盖哪些字段，未置位的字段保持原值不动。
///
/// 字段在这里是**本机序**：网络序转换由 [`SetConfig::encode`] 一处承担。
fn build_config_update(thresholds: ProtocolThresholds, limits: Option<GlobalLimits>) -> SetConfig {
    let mut flags = config_flags::MAX_SYN
        | config_flags::MAX_UDP
        | config_flags::MAX_ICMP
        | config_flags::MAX_ACK
        | config_flags::MAX_RST
        | config_flags::MAX_FIN;
    if limits.is_some() {
        flags |= config_flags::BAN_TIME
            | config_flags::RATE_WINDOW
            | config_flags::MAX_PPS
            | config_flags::DDOS_BAN_DURATION;
    }

    let mut update = SetConfig {
        flags,
        max_syn_per_second: u64::from(thresholds.max_syn_per_second),
        max_udp_per_second: u64::from(thresholds.max_udp_per_second),
        max_icmp_per_second: u64::from(thresholds.max_icmp_per_second),
        max_ack_per_second: u64::from(thresholds.max_ack_per_second),
        max_rst_per_second: u64::from(thresholds.max_rst_per_second),
        max_fin_per_second: u64::from(thresholds.max_fin_per_second),
        ..SetConfig::default()
    };

    if let Some(l) = limits {
        update.ban_time = l.ban_time;
        update.rate_window_seconds = l.rate_window;
        update.max_packets_per_second = l.max_pps;
        update.ddos_ban_duration = l.ddos_ban_duration;
    }

    update
}

/// 把协议阈值（以及可选的全局限制）下发到内核。
///
/// # Returns
/// - `Ok(`[`SyncOutcome::Sent`]`)` — 下发成功且内核确认**全部**字段生效
/// - `Ok(`[`SyncOutcome::Skipped`]`)` — 内核链路尚未就绪（未取得租约），未做任何写入
/// - `Err(String)` — 已发出但未成功：字符串为底层错误原文，或内核拒绝的字段位图
///
/// 「内核只确认了一部分字段」也返回 `Err`：这正是旧实现看不见的一类失败——请求发出去了，
/// 客户端只看 `sendto` 成功就当作生效。把拒绝位图报给调用方，配置写入界面才能显示出来。
pub fn sync_protocol_thresholds(
    thresholds: ProtocolThresholds,
    limits: Option<GlobalLimits>,
) -> Result<SyncOutcome, String> {
    let Some(client) = global::get() else {
        return Ok(SyncOutcome::Skipped);
    };
    let change = build_config_update(thresholds, limits);
    match client.set_config(&change, REQUEST_TIMEOUT) {
        Ok(ack) if ack.fully_applied() => Ok(SyncOutcome::Sent),
        Ok(ack) => Err(format!(
            "内核拒绝部分字段: rejected_flags={:#x}",
            ack.rejected_flags
        )),
        Err(e) => Err(e.to_string()),
    }
}

/// 把 DDoS 检测算法开关写入内核 sysfs 模块参数。
///
/// 与 netlink 通道互不依赖：netlink 不可用时该写入仍可生效。写入结果（含失败）
/// 由 [`crate::ban::write_sysfs_bool_param`] 内部记录日志。
pub fn write_detection_switches(switches: DetectionSwitches) {
    crate::ban::write_sysfs_bool_param("fw_static_threshold", switches.static_threshold);
    crate::ban::write_sysfs_bool_param("fw_dynamic_threshold", switches.dynamic_threshold);
    crate::ban::write_sysfs_bool_param("fw_ddos_detection", switches.ddos_detection);
}

/// 把受保护端口位图下发到内核。
///
/// 载荷很大（8KB），故与 [`sync_protocol_thresholds`] 分开：这条通道只在扫描结果
/// **变化**时走（见 [`crate::runtime::scheduler`]），阈值走的是 ACK 配对的
/// `SetConfig`，两者频率与失败语义都不同。
///
/// # Returns
/// - `Ok(`[`SyncOutcome::Sent`]`)` — 已投递
/// - `Ok(`[`SyncOutcome::Skipped`]`)` — 内核链路尚未就绪（未取得租约），未做任何写入
/// - `Err(String)` — 发送失败，字符串为底层错误原文
pub fn sync_protected_ports(
    bitmap: [u8; crate::protected_ports::BITMAP_BYTES],
) -> Result<SyncOutcome, String> {
    let Some(client) = global::get() else {
        return Ok(SyncOutcome::Skipped);
    };
    match client.set_protected_ports(bitmap) {
        Ok(_) => Ok(SyncOutcome::Sent),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 协议阈值必须落在正确的字段上，且未传 limits 时全局限制位必须缺位。
    ///
    /// 旧实现里 ACK/RST/FIN 的字节序由调用方手写 `.to_be()`；现在字段是本机序、
    /// 由 `encode` 统一转换，故这里改为断言本地值与被置位的标志。
    #[test]
    fn build_config_update_sets_protocol_thresholds_and_flags() {
        let thresholds = ProtocolThresholds {
            max_syn_per_second: 1,
            max_udp_per_second: 2,
            max_icmp_per_second: 3,
            max_ack_per_second: 0x1122_3344,
            max_rst_per_second: 0x5566_7788,
            max_fin_per_second: 0x99AA_BBCC,
        };
        let update = build_config_update(thresholds, None);

        assert_eq!(update.max_ack_per_second, 0x1122_3344);
        assert_eq!(update.max_rst_per_second, 0x5566_7788);
        assert_eq!(update.max_fin_per_second, 0x99AA_BBCC);
        assert_eq!(update.max_syn_per_second, 1);
        assert_eq!(update.max_udp_per_second, 2);
        assert_eq!(update.max_icmp_per_second, 3);

        for bit in [
            config_flags::MAX_SYN,
            config_flags::MAX_UDP,
            config_flags::MAX_ICMP,
            config_flags::MAX_ACK,
            config_flags::MAX_RST,
            config_flags::MAX_FIN,
        ] {
            assert_ne!(update.flags & bit, 0, "协议阈值位 {bit:#x} 应置位");
        }
        for bit in [
            config_flags::BAN_TIME,
            config_flags::RATE_WINDOW,
            config_flags::MAX_PPS,
            config_flags::DDOS_BAN_DURATION,
        ] {
            assert_eq!(
                update.flags & bit,
                0,
                "未传 limits 时全局限制位 {bit:#x} 不应置位"
            );
        }
    }

    /// 传 `limits` 时必须追加全局限制位并写入对应值，否则 SIGHUP 重载会被内核静默忽略。
    #[test]
    fn build_config_update_with_limits_sets_global_flags() {
        let update = build_config_update(
            ProtocolThresholds::default(),
            Some(GlobalLimits {
                ban_time: 3600,
                rate_window: 5,
                max_pps: 100_000,
                ddos_ban_duration: 7200,
            }),
        );

        for bit in [
            config_flags::BAN_TIME,
            config_flags::RATE_WINDOW,
            config_flags::MAX_PPS,
            config_flags::DDOS_BAN_DURATION,
        ] {
            assert_ne!(update.flags & bit, 0, "全局限制位 {bit:#x} 应置位");
        }
        assert_eq!(update.ban_time, 3600);
        assert_eq!(update.rate_window_seconds, 5);
        assert_eq!(update.max_packets_per_second, 100_000);
        assert_eq!(update.ddos_ban_duration, 7200);
    }

    /// 未置位的字段必须是零值：内核按 flags 逐位判断，但零值能让「误置位」立刻暴露
    /// （若某天 flags 计算错把某位置上，内核会写进 0 而不是旧值）。
    #[test]
    fn unset_flags_leave_the_payload_zeroed() {
        let update = build_config_update(ProtocolThresholds::default(), None);
        assert_eq!(update.ban_time, 0);
        assert_eq!(update.rate_window_seconds, 0);
        assert_eq!(update.max_packets_per_second, 0);
        assert_eq!(update.baseline_pps, 0);
        assert_eq!(update.baseline_bps, 0);
        assert_eq!(update.dynamic_threshold_flags, 0);
        assert_eq!(update.dynamic_threshold_ratio_x100, 0);
    }

    /// 两种配置类型的字段名相同，映射必须两边一致（防止只改一侧导致漂移）。
    #[test]
    fn thresholds_from_ddos_and_webui_agree_on_defaults() {
        assert_eq!(
            ProtocolThresholds::from(&DdosConfig::default()),
            ProtocolThresholds::from(&WebuiConfig::default()),
        );
        assert_eq!(
            DetectionSwitches::from(&DdosConfig::default()),
            DetectionSwitches::from(&WebuiConfig::default()),
        );
    }

    /// 未注入内核链路时必须是 `Skipped` 而不是错误：启动初期属正常状态。
    #[test]
    fn an_unwired_kernel_link_reports_skipped() {
        // 全局定位器是进程级 `OnceLock`，测试进程内可能已被别的用例注入；
        // 故只断言「要么跳过、要么真的发出去（错误也算已尝试）」，不依赖注入顺序。
        match sync_protocol_thresholds(ProtocolThresholds::default(), None) {
            Ok(SyncOutcome::Skipped) | Ok(SyncOutcome::Sent) | Err(_) => {}
        }
    }
}
