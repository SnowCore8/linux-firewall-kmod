//! 格式化工具函数

/// 数字格式化（支持 K/M/G 单位转换）
pub fn format_number(num: u64, convert_units: bool) -> String {
    if !convert_units {
        return format_with_separator(num);
    }
    if num >= 1_000_000_000 {
        format!("{:.1}G", num as f64 / 1_000_000_000.0)
    } else if num >= 1_000_000 {
        format!("{:.1}M", num as f64 / 1_000_000.0)
    } else if num >= 1_000 {
        format!("{:.1}K", num as f64 / 1_000.0)
    } else {
        num.to_string()
    }
}

fn format_with_separator(num: u64) -> String {
    let s = num.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, c);
    }
    result
}

/// 运行时间格式化
pub fn format_uptime(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let mins = (seconds % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

/// 日期时间格式化（使用浏览器本地时区）
pub fn format_datetime(timestamp: i64) -> String {
    if timestamp <= 0 {
        return "N/A".to_string();
    }
    // SAFETY: js_sys::Date 接受毫秒时间戳，i64 转 f64 在合理范围内精度足够
    let date = js_sys::Date::new(&(timestamp as f64 * 1000.0).into());
    let year = date.get_full_year();
    let month = date.get_month() + 1;
    let day = date.get_date();
    let hours = date.get_hours();
    let minutes = date.get_minutes();
    let seconds = date.get_seconds();
    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02}")
}

/// 剩余时间格式化
pub fn format_duration(seconds: i64) -> String {
    if seconds < 0 {
        return "永久".to_string();
    }
    let secs = seconds as u64;
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    if hours > 0 {
        format!("{hours}h {mins}m")
    } else if mins > 0 {
        format!("{mins}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// 速率格式化
pub fn format_rate(value: u64, kind: &str) -> String {
    match kind {
        "bps" => {
            if value >= 1_000_000_000 {
                format!("{:.2} Gbps", value as f64 / 1_000_000_000.0)
            } else if value >= 1_000_000 {
                format!("{:.1} Mbps", value as f64 / 1_000_000.0)
            } else if value >= 1_000 {
                format!("{:.1} Kbps", value as f64 / 1_000.0)
            } else {
                format!("{value} bps")
            }
        }
        _ => {
            if value >= 1_000_000 {
                format!("{:.1} Mpps", value as f64 / 1_000_000.0)
            } else if value >= 1_000 {
                format!("{:.1} Kpps", value as f64 / 1_000.0)
            } else {
                format!("{value} pps")
            }
        }
    }
}
