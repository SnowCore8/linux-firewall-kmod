//! 统一数据模型 — 所有页面共享

/// 威胁等级（全局统一）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatLevel {
    Normal,
    Warning,
    Critical,
}

impl ThreatLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Normal => "NORMAL",
            Self::Warning => "WARNING",
            Self::Critical => "CRITICAL",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            Self::Normal => "var(--color-green)",
            Self::Warning => "var(--color-orange)",
            Self::Critical => "var(--color-red)",
        }
    }

    /// 全局统一判断逻辑（所有页面共用）
    pub fn from_rates(rates: &[crate::api::RateResponse]) -> Self {
        if rates.is_empty() {
            return Self::Normal;
        }
        let max_pps = rates.iter().map(|r| r.packets_per_sec).max().unwrap_or(0);
        let max_syn = rates
            .iter()
            .map(|r| r.syn_packets_per_sec)
            .max()
            .unwrap_or(0);

        if max_pps > 10000 || max_syn > 1000 {
            Self::Critical
        } else if max_pps > 1000 || max_syn > 100 {
            Self::Warning
        } else {
            Self::Normal
        }
    }
}

/// 统一速率格式化（所有页面共用）
pub fn format_rate(value: u64, unit: &str) -> String {
    if value >= 1_000_000 {
        format!("{:.1}M {}", value as f64 / 1_000_000.0, unit)
    } else if value >= 1_000 {
        format!("{:.1}K {}", value as f64 / 1_000.0, unit)
    } else {
        format!("{} {}", value, unit)
    }
}

/// 统一数字格式化（所有页面共用）
pub fn format_number(value: u64, compact: bool) -> String {
    if compact {
        if value >= 1_000_000 {
            format!("{:.1}M", value as f64 / 1_000_000.0)
        } else if value >= 1_000 {
            format!("{:.1}K", value as f64 / 1_000.0)
        } else {
            value.to_string()
        }
    } else {
        value.to_string()
    }
}

/// 统一时间格式化（所有页面共用）
pub fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let mins = (seconds % 3600) / 60;

    if days > 0 {
        format!("{}d {}h", days, hours)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else {
        format!("{}m", mins)
    }
}

/// 协议类型判断（所有页面共用）
pub fn dominant_protocol(rate: &crate::api::RateResponse) -> &'static str {
    if rate.syn_packets_per_sec > rate.udp_packets_per_sec
        && rate.syn_packets_per_sec > rate.icmp_packets_per_sec
    {
        "SYN"
    } else if rate.udp_packets_per_sec > rate.icmp_packets_per_sec {
        "UDP"
    } else {
        "ICMP"
    }
}

/// 攻击者威胁等级（所有页面共用）
pub fn attacker_threat_level(rate: &crate::api::RateResponse) -> &'static str {
    if rate.packets_per_sec > 10000 || rate.syn_packets_per_sec > 1000 {
        "critical"
    } else if rate.packets_per_sec > 1000 || rate.syn_packets_per_sec > 100 {
        "warning"
    } else {
        "normal"
    }
}

/// 攻击者威胁标签（所有页面共用）
pub fn attacker_threat_label(rate: &crate::api::RateResponse) -> &'static str {
    match attacker_threat_level(rate) {
        "critical" => "CRIT",
        "warning" => "WARN",
        _ => "LOW",
    }
}
