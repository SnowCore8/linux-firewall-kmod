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

use super::protocol::{config_flags, FwNlConfigUpdate as ConfigUpdate};
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
    /// 已通过 netlink 下发成功
    Sent,
    /// netlink 上下文尚未初始化，静默跳过（守护进程启动初期属正常状态）
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
fn build_config_update(
    thresholds: ProtocolThresholds,
    limits: Option<GlobalLimits>,
) -> ConfigUpdate {
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

    let mut update = ConfigUpdate::new(flags)
        .with_max_syn(thresholds.max_syn_per_second as u64)
        .with_max_udp(thresholds.max_udp_per_second as u64)
        .with_max_icmp(thresholds.max_icmp_per_second as u64)
        .with_max_ack(thresholds.max_ack_per_second as u64)
        .with_max_rst(thresholds.max_rst_per_second as u64)
        .with_max_fin(thresholds.max_fin_per_second as u64);

    if let Some(l) = limits {
        update = update
            .with_ban_time(l.ban_time)
            .with_rate_window(l.rate_window)
            .with_max_pps(l.max_pps)
            .with_ddos_ban_duration(l.ddos_ban_duration);
    }

    update
}

/// 把协议阈值（以及可选的全局限制）下发到内核。
///
/// # Returns
/// - `Ok(`[`SyncOutcome::Sent`]`)` — netlink 下发成功
/// - `Ok(`[`SyncOutcome::Skipped`]`)` — 全局 netlink 上下文尚未建立，未做任何写入
/// - `Err(String)` — netlink 已建立但发送失败，字符串为底层错误原文
pub fn sync_protocol_thresholds(
    thresholds: ProtocolThresholds,
    limits: Option<GlobalLimits>,
) -> Result<SyncOutcome, String> {
    match super::get_global_netlink_ctx() {
        Some(netlink) => match netlink.send_config_update(&build_config_update(thresholds, limits))
        {
            Ok(()) => Ok(SyncOutcome::Sent),
            Err(e) => Err(e.to_string()),
        },
        None => Ok(SyncOutcome::Skipped),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// ACK/RST/FIN 曾经只能靠调用方手写 `.to_be()`，是两处重复实现的根源。
    /// 本测试锁定：三个字段的字节序转换由 builder 承担，且 `new()` 的零值不被误用。
    #[test]
    fn build_config_update_sets_ack_rst_fin_big_endian() {
        let thresholds = ProtocolThresholds {
            max_syn_per_second: 1,
            max_udp_per_second: 2,
            max_icmp_per_second: 3,
            max_ack_per_second: 0x1122_3344,
            max_rst_per_second: 0x5566_7788,
            max_fin_per_second: 0x99AA_BBCC,
        };
        let update = build_config_update(thresholds, None);

        // `FwNlConfigUpdate` 是 `#[repr(C, packed)]`，不能对其字段取引用；
        // 先按值读出再断言，等价于调用方此前的 `.to_be()` 手写转换
        let ack = update.max_ack_per_second;
        let rst = update.max_rst_per_second;
        let fin = update.max_fin_per_second;

        assert_eq!(
            ack,
            0x1122_3344u64.to_be(),
            "ACK 阈值必须按大端写入（内核按网络序解析）"
        );
        assert_eq!(rst, 0x5566_7788u64.to_be());
        assert_eq!(fin, 0x99AA_BBCCu64.to_be());
        // 6 个协议阈值位置位；未传 limits 时全局限制位必须缺位
        let flags = u32::from_be(update.flags);
        for bit in [
            config_flags::MAX_SYN,
            config_flags::MAX_UDP,
            config_flags::MAX_ICMP,
            config_flags::MAX_ACK,
            config_flags::MAX_RST,
            config_flags::MAX_FIN,
        ] {
            assert_ne!(flags & bit, 0, "协议阈值位 {bit:#x} 应置位");
        }
        for bit in [
            config_flags::BAN_TIME,
            config_flags::RATE_WINDOW,
            config_flags::MAX_PPS,
            config_flags::DDOS_BAN_DURATION,
        ] {
            assert_eq!(flags & bit, 0, "未传 limits 时全局限制位 {bit:#x} 不应置位");
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

        let flags = u32::from_be(update.flags);
        for bit in [
            config_flags::BAN_TIME,
            config_flags::RATE_WINDOW,
            config_flags::MAX_PPS,
            config_flags::DDOS_BAN_DURATION,
        ] {
            assert_ne!(flags & bit, 0, "全局限制位 {bit:#x} 应置位");
        }
        assert_eq!(u32::from_be(update.ban_time), 3600);
        assert_eq!(u32::from_be(update.rate_window_seconds), 5);
        assert_eq!(u64::from_be(update.max_packets_per_second), 100_000);
        assert_eq!(u32::from_be(update.ddos_ban_duration), 7200);
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
}
