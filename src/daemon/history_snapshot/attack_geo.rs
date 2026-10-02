//! 攻击源地理分布——把封禁 IP 按地理位置聚合。
//!
//! 与 [`super::network_distribution`] 的区别：那个按 /24 子网分组（不需要外部数据），
//! 本模块按**真实地理位置**（国家/城市/经纬度）分组，依赖 [`crate::geoip`] 提供的
//! 城市级数据库。
//!
//! # 降级语义
//!
//! GeoIP 数据库未装配时（[`crate::geoip::is_enabled`] 为假），本模块返回空结果——
//! 调用方按「无地理数据」渲染，不影响其余统计。

use std::collections::HashMap;

use super::history_db;
use crate::geoip;

/// 单个地理位置的攻击统计。
#[derive(Debug, Clone, serde::Serialize)]
pub struct GeoPoint {
    /// 纬度
    pub latitude: f64,
    /// 经度
    pub longitude: f64,
    /// 国家 ISO 代码（如 `CN`）
    pub country_code: String,
    /// 国家名
    pub country: String,
    /// 城市名（可为空）
    pub city: String,
    /// 一级行政区名（可为空）
    pub subdivision: String,
    /// 该位置被封禁的唯一 IP 数
    pub unique_ips: u32,
    /// 该位置的总封禁次数
    pub total_bans: u32,
    /// 该位置的代表性 IP（封禁次数最多者）
    pub top_ip: String,
    /// 该位置最近一次封禁时间（Unix 秒）
    pub last_banned_at: i64,
}

/// 地理分布查询结果。
#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackGeoResponse {
    /// 地理解析是否可用（数据库是否已装配且可用）
    pub geoip_enabled: bool,
    /// 按总封禁数降序排列的地点（最多 [`MAX_POINTS`] 个）
    pub points: Vec<GeoPoint>,
    /// 参与本次统计的 IP 总数（含无法定位的）
    pub total_ips: u32,
    /// 成功定位的 IP 数
    pub located_ips: u32,
    /// 本机（服务器）纬度；未配置且未探测到时为 `None`。
    ///
    /// 前端据此画「本机」标记与「攻击源 → 本机」的弧线；为 `None` 时不绘制，
    /// 不会退回到任何占位坐标。与 `server_longitude` 同步取值、与
    /// `server_location_source` 同源（三者在同一处派生，不会互相矛盾）。
    pub server_latitude: Option<f64>,
    /// 本机（服务器）经度；未配置且未探测到时为 `None`。语义见 `server_latitude`。
    pub server_longitude: Option<f64>,
    /// 本机坐标的来源（配置／探测／无）。探测结果不是权威坐标，前端据此分别标注。
    pub server_location_source: geoip::ServerLocationSource,
}

/// 输出地点数上限。
const MAX_POINTS: usize = 200;

/// 参与定位的 IP 数上限。
///
/// 与 [`super::network_distribution`] 一样只取封禁次数最多的那批——数据库有上亿条
/// 记录，但攻击源长尾里绝大多数只封过一次，全量逐个解析收益极低。
const MAX_IPS: usize = 2000;

/// 本机坐标三件套：纬度 / 经度 / 来源。
///
/// 三者在同一处派生后向下传递，避免「经纬度说有、来源说没有」这类自相矛盾的组合。
#[derive(Clone, Copy)]
struct ServerCoords {
    latitude: Option<f64>,
    longitude: Option<f64>,
    source: geoip::ServerLocationSource,
}

/// 从 GeoIP 模块读已解析好的本机坐标（配置优先，其次启动期探测）。
///
/// 本函数无参，配置只能从**既有的全局通道**取——与其它读配置的统计函数一样走模块
/// 级访问器（[`geoip::get_server_location`]，由启动装配写入），不在本模块自建单例。
fn server_coords() -> ServerCoords {
    match geoip::get_server_location() {
        Some(location) => ServerCoords {
            latitude: Some(location.latitude),
            longitude: Some(location.longitude),
            source: location.source,
        },
        None => ServerCoords {
            latitude: None,
            longitude: None,
            source: geoip::ServerLocationSource::None,
        },
    }
}

/// 同一地点的聚合累加器。键是「经纬度四舍五入到 2 位小数」——避免同一城市
/// 因库中微小的坐标差异被拆成多个点（DB-IP 对同一城市给出同一坐标，但
/// 不同数据版本间可能漂移）。
struct Agg {
    point: GeoPoint,
    /// 当前代表 IP 的封禁次数，用于判断是否替换。
    top_ip_bans: u32,
}

/// 把一条 `(ip, 封禁次数, 最近封禁时间)` 并入聚合表。
///
/// 抽成独立函数是为了能直接对聚合规则写断言（坐标量化、代表 IP 取舍、时间取最新）：
/// 这些规则原先内嵌在 [`get_attack_geo`] 的循环里，只能靠「装一个真实地理库 + 造库
/// 数据」间接覆盖，而地理库是 60MB 级的外部数据，测试里不该依赖。
///
/// `geo` 为 `None` 表示该 IP 无法定位（库中无记录），此时只累加 `total_ips`。
fn merge_row(
    map: &mut HashMap<(i64, i64), Agg>,
    ip_str: &str,
    cnt: u32,
    last_ts: i64,
    geo: Option<&geoip::GeoLocation>,
    located_ips: &mut u32,
) {
    let Some(geo) = geo else { return };
    *located_ips += 1;

    // 坐标量化到 2 位小数（约 1km）作为聚合键。
    let key = (
        (geo.latitude * 100.0).round() as i64,
        (geo.longitude * 100.0).round() as i64,
    );

    match map.get_mut(&key) {
        Some(agg) => {
            agg.point.unique_ips += 1;
            agg.point.total_bans += cnt;
            if last_ts > agg.point.last_banned_at {
                agg.point.last_banned_at = last_ts;
            }
            // 代表 IP 取封禁次数最多者；同数时保持先到者（SQL 已按 cnt 降序）。
            if cnt > agg.top_ip_bans {
                agg.top_ip_bans = cnt;
                agg.point.top_ip = ip_str.to_string();
            }
        }
        None => {
            map.insert(
                key,
                Agg {
                    point: GeoPoint {
                        latitude: geo.latitude,
                        longitude: geo.longitude,
                        country_code: geo.country_code.clone(),
                        country: geo.country.clone(),
                        city: geo.city.clone(),
                        subdivision: geo.subdivision.clone(),
                        unique_ips: 1,
                        total_bans: cnt,
                        top_ip: ip_str.to_string(),
                        last_banned_at: last_ts,
                    },
                    top_ip_bans: cnt,
                },
            );
        }
    }
}

/// 查询近 7 天 `ban_events`，按地理位置聚合。
///
/// # 排序
///
/// 地点按总封禁数降序；同数时按唯一 IP 数降序，保证输出稳定可复现。
#[must_use]
pub fn get_attack_geo() -> AttackGeoResponse {
    let coords = server_coords();

    let enabled = geoip::is_enabled();
    if !enabled {
        return empty(false, coords);
    }

    let db = history_db();
    let Some(conn) = db.as_ref() else {
        return empty(true, coords);
    };

    let cutoff = crate::types::now_secs() - 7 * 86400;

    let mut stmt = match conn.prepare(
        "SELECT ip, COUNT(*) as cnt, MAX(banned_at) as last_ts
         FROM ban_events
         WHERE banned_at >= ?1
         GROUP BY ip
         ORDER BY cnt DESC
         LIMIT ?2",
    ) {
        Ok(s) => s,
        Err(_) => return empty(enabled, coords),
    };

    let rows = match stmt.query_map(rusqlite::params![cutoff, MAX_IPS as i64], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, u32>(1)?,
            row.get::<_, i64>(2)?,
        ))
    }) {
        Ok(r) => r,
        Err(_) => return empty(enabled, coords),
    };

    let mut map: HashMap<(i64, i64), Agg> = HashMap::new();
    let mut total_ips: u32 = 0;
    let mut located_ips: u32 = 0;

    for row in rows.flatten() {
        let (ip_str, cnt, last_ts) = row;
        total_ips += 1;

        // 无法解析的 IP 与库中无记录的 IP 都只计入 total_ips（不定位、不聚合）。
        let geo = ip_str
            .parse::<std::net::IpAddr>()
            .ok()
            .and_then(geoip::lookup);
        merge_row(
            &mut map,
            &ip_str,
            cnt,
            last_ts,
            geo.as_ref(),
            &mut located_ips,
        );
    }

    let mut points: Vec<GeoPoint> = map.into_values().map(|a| a.point).collect();
    points.sort_by(|a, b| {
        b.total_bans
            .cmp(&a.total_bans)
            .then_with(|| b.unique_ips.cmp(&a.unique_ips))
            .then_with(|| a.city.cmp(&b.city))
    });
    points.truncate(MAX_POINTS);

    AttackGeoResponse {
        geoip_enabled: true,
        points,
        total_ips,
        located_ips,
        server_latitude: coords.latitude,
        server_longitude: coords.longitude,
        server_location_source: coords.source,
    }
}

/// 空结果（数据库不可用或查询失败）。
fn empty(enabled: bool, coords: ServerCoords) -> AttackGeoResponse {
    AttackGeoResponse {
        geoip_enabled: enabled,
        points: Vec::new(),
        total_ips: 0,
        located_ips: 0,
        server_latitude: coords.latitude,
        server_longitude: coords.longitude,
        server_location_source: coords.source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_when_geoip_off() {
        // 本测试进程若未装配 GeoIP（默认就是），返回禁用态且各计数为零。
        if geoip::is_enabled() {
            return; // 其他测试已装配数据库时跳过
        }
        let r = get_attack_geo();
        assert!(!r.geoip_enabled);
        assert!(r.points.is_empty());
        assert_eq!(r.total_ips, 0);
    }

    /// 造一个地理坐标（其余字段用固定值，测试只关心坐标与聚合规则）。
    fn geo(latitude: f64, longitude: f64, city: &str) -> geoip::GeoLocation {
        geoip::GeoLocation {
            latitude,
            longitude,
            country_code: "CN".to_string(),
            country: "China".to_string(),
            city: city.to_string(),
            subdivision: "Beijing".to_string(),
        }
    }

    #[test]
    fn unlocatable_ips_are_not_aggregated() {
        // 库中无记录的 IP（geo 为 None）只计入调用方维护的 total_ips，不进聚合表。
        let mut map: HashMap<(i64, i64), Agg> = HashMap::new();
        let mut located = 0u32;
        merge_row(&mut map, "8.8.8.8", 3, 100, None, &mut located);
        assert!(map.is_empty(), "无法定位的 IP 不得进入聚合表");
        assert_eq!(located, 0, "无法定位的 IP 不计入 located_ips");
    }

    #[test]
    fn same_quantized_cell_merges_into_one_point() {
        // 两个坐标在小数点后第 3 位不同（量化到 2 位后落同一格）→ 合并为一个点。
        let mut map: HashMap<(i64, i64), Agg> = HashMap::new();
        let mut located = 0u32;
        merge_row(
            &mut map,
            "1.1.1.1",
            2,
            100,
            Some(&geo(39.904_1, 116.407_1, "Beijing")),
            &mut located,
        );
        merge_row(
            &mut map,
            "2.2.2.2",
            5,
            200,
            Some(&geo(39.904_2, 116.407_2, "Beijing")),
            &mut located,
        );

        assert_eq!(map.len(), 1, "量化后应合并为同一个点");
        let agg = map.values().next().expect("应有一个点");
        assert_eq!(agg.point.unique_ips, 2, "唯一 IP 数累加");
        assert_eq!(agg.point.total_bans, 7, "封禁次数累加");
        assert_eq!(
            agg.point.last_banned_at, 200,
            "最近封禁时间取较大者（后到的时间更新）"
        );
        assert_eq!(
            agg.point.top_ip, "2.2.2.2",
            "代表 IP 取封禁次数最多者（5 > 2）"
        );
        assert_eq!(located, 2);
    }

    #[test]
    fn far_apart_coordinates_stay_separate() {
        // 不同城市（量化后不同格）不得被合并。
        let mut map: HashMap<(i64, i64), Agg> = HashMap::new();
        let mut located = 0u32;
        merge_row(
            &mut map,
            "1.1.1.1",
            1,
            100,
            Some(&geo(39.9042, 116.4074, "Beijing")),
            &mut located,
        );
        merge_row(
            &mut map,
            "3.3.3.3",
            1,
            100,
            Some(&geo(31.2304, 121.4737, "Shanghai")),
            &mut located,
        );
        assert_eq!(map.len(), 2, "不同坐标应各成一点");
        assert_eq!(located, 2);
    }

    #[test]
    fn earlier_timestamp_does_not_overwrite_the_newer_one() {
        // 先来晚的、再来早的：last_banned_at 必须保持晚的那个（不得被覆盖）。
        let mut map: HashMap<(i64, i64), Agg> = HashMap::new();
        let mut located = 0u32;
        merge_row(
            &mut map,
            "1.1.1.1",
            1,
            500,
            Some(&geo(1.0, 1.0, "A")),
            &mut located,
        );
        merge_row(
            &mut map,
            "2.2.2.2",
            1,
            300,
            Some(&geo(1.0, 1.0, "A")),
            &mut located,
        );
        let agg = map.values().next().expect("应有一个点");
        assert_eq!(agg.point.last_banned_at, 500, "较早的时间戳不得覆盖较晚的");
    }

    #[test]
    fn equal_ban_counts_keep_the_first_top_ip() {
        // 同封禁次数时代表 IP 保持先到者（SQL 已按 cnt 降序，先到者即更靠前者）。
        let mut map: HashMap<(i64, i64), Agg> = HashMap::new();
        let mut located = 0u32;
        merge_row(
            &mut map,
            "first",
            4,
            100,
            Some(&geo(1.0, 1.0, "A")),
            &mut located,
        );
        merge_row(
            &mut map,
            "second",
            4,
            200,
            Some(&geo(1.0, 1.0, "A")),
            &mut located,
        );
        let agg = map.values().next().expect("应有一个点");
        assert_eq!(agg.point.top_ip, "first", "同次数时不得替换代表 IP");
        assert_eq!(agg.point.total_bans, 8);
        assert_eq!(agg.point.unique_ips, 2);
    }
}
