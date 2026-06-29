//! 攻击源网络分布——按 /24 子网（IPv4）或 /48 前缀（IPv6）分组统计

use super::history_db;

/// 单个子网的攻击统计
#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkBlock {
    /// 子网前缀（如 "192.168.1" 或 "10.0"）
    pub subnet: String,
    /// 该子网内被封禁的唯一 IP 数
    pub unique_ips: u32,
    /// 该子网的总封禁次数
    pub total_bans: u32,
    /// 该子网最近一次封禁时间（Unix 秒）
    pub last_banned_at: i64,
    /// 代表性 IP（该子网内封禁次数最多的 IP）
    pub top_ip: String,
}

/// 查询近 7 天 ban_events，按 /24 子网（IPv4）或 /48 前缀（IPv6）分组
pub fn get_network_distribution() -> Vec<NetworkBlock> {
    let db = history_db();
    let conn = match db.as_ref() {
        Some(c) => c,
        None => return Vec::new(),
    };

    let cutoff = crate::types::now_secs() - 7 * 86400;

    // 查询所有封禁事件的 IP + 时间
    let mut stmt = match conn.prepare(
        "SELECT ip, COUNT(*) as cnt, MAX(banned_at) as last_ts
     FROM ban_events
     WHERE banned_at >= ?1
     GROUP BY ip
     ORDER BY cnt DESC",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let rows = match stmt.query_map([cutoff], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, u32>(1)?,
            row.get::<_, i64>(2)?,
        ))
    }) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    // 按子网聚合
    struct SubnetAgg {
        unique_ips: u32,
        total_bans: u32,
        last_banned_at: i64,
        top_ip: String,
        top_ip_bans: u32,
    }
    let mut subnet_map: std::collections::HashMap<String, SubnetAgg> =
        std::collections::HashMap::new();

    for row in rows.flatten() {
        let (ip, cnt, last_ts) = row;
        let subnet = extract_subnet(&ip);
        let agg = subnet_map.entry(subnet).or_insert_with(|| SubnetAgg {
            unique_ips: 0,
            total_bans: 0,
            last_banned_at: 0,
            top_ip: String::new(),
            top_ip_bans: 0,
        });
        agg.unique_ips += 1;
        agg.total_bans += cnt;
        if last_ts > agg.last_banned_at {
            agg.last_banned_at = last_ts;
        }
        if cnt > agg.top_ip_bans {
            agg.top_ip = ip;
            agg.top_ip_bans = cnt;
        }
    }

    // 转为 Vec 并按总封禁数降序排列
    let mut blocks: Vec<NetworkBlock> = subnet_map
        .into_iter()
        .map(|(subnet, agg)| NetworkBlock {
            subnet,
            unique_ips: agg.unique_ips,
            total_bans: agg.total_bans,
            last_banned_at: agg.last_banned_at,
            top_ip: agg.top_ip,
        })
        .collect();
    blocks.sort_by_key(|b| std::cmp::Reverse(b.total_bans));
    blocks.truncate(50); // 取 TOP 50
    blocks
}

/// 提取 IP 的子网前缀
///
/// - IPv4: 取前 3 段（/24），如 "192.168.1.100" → "192.168.1"
/// - IPv6: 取前 3 段（/48），如 "2001:db8:abcd:..." → "2001:db8:abcd"
/// - 其他: 返回原始 IP
fn extract_subnet(ip: &str) -> String {
    if ip.contains(':') {
        // IPv6: 取前 3 段
        let parts: Vec<&str> = ip.split(':').collect();
        if parts.len() >= 3 {
            parts[..3].join(":")
        } else {
            ip.to_string()
        }
    } else {
        // IPv4: 取前 3 段（/24）
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() >= 3 {
            parts[..3].join(".")
        } else {
            ip.to_string()
        }
    }
}
