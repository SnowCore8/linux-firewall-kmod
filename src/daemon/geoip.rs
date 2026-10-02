//! GeoIP 地理位置解析（MaxMind DB / DB-IP City Lite 兼容格式）。
//!
//! # 定位
//!
//! IP → 经纬度/城市/国家的唯一解析入口。攻击源地理分布、3D 地球都从这里取数据。
//! 本模块**不做聚合**——聚合在 [`super::history_snapshot`] 侧，本模块只负责「一个 IP → 一个地点」。
//!
//! # 降级语义（重要）
//!
//! 数据库文件缺失、损坏、或格式不符时，**整个模块进入禁用态**：`lookup` 一律返回
//! `None`，调用方按「无地理数据」处理。绝不 panic、绝不阻止 daemon 启动——
//! 地理展示是可选增强，不该成为启动依赖。
//!
//! # 为什么不缓存解析结果
//!
//! 攻击源地理聚合每轮只解析 TOP N 个 IP（N 由 API 限制），而 `lookup` 是纯内存
//! 二分查找（微秒级）。加缓存只会引入失效问题，收益为负。

use std::net::IpAddr;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use maxminddb::Reader;

/// 内置的出口 IP 探测地址。
///
/// 选它是因为响应就是一个扁平 JSON，`ip` 字段直白可读，不需要额外解析规则；
/// 这是**唯一**的对外请求目标（仅在该探测被显式开启且未配置本机坐标时发起）。
pub const DEFAULT_EGRESS_PROBE_URL: &str = "https://api.ip.sb/geoip";

/// 出口 IP 探测的超时（秒）。
///
/// 短超时是有意的：探测只是可选的展示增强，卡住启动（进而卡住封禁主链路）
/// 是不可接受的代价。实测该上游响应在 0.5s 量级，4s 留了一个数量级的余量。
const EGRESS_PROBE_TIMEOUT: Duration = Duration::from_secs(4);

/// 上游响应体的读取上限（字节）。
///
/// 本探测只关心响应里的一个 IP 字面量，正常响应在 1KB 以内；给 64KB 上限是为了
/// 「上游换成了返回超大 HTML 的端点」时不至于把内存吃满——超限即视为探测失败。
const EGRESS_BODY_LIMIT: u64 = 64 * 1024;

/// 本机坐标的来源。
///
/// 透出到 [`crate::history_snapshot::AttackGeoResponse`]，前端据此标注来源——
/// 探测结果**不是**权威坐标，界面必须能把它与手填配置区分开。
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerLocationSource {
    /// 来自配置项 `server_latitude` / `server_longitude`（权威，优先于探测）
    Config,
    /// 由出口 IP 探测 + 本地 GeoIP 库解析得到（非权威，仅供参考）
    Detected,
    /// 既未配置也未探测到 → 前端不绘制本机标记与弧线
    None,
}

/// 本机（服务器）坐标及其来源。
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ServerLocation {
    /// 纬度（十进制度，-90..90）
    pub latitude: f64,
    /// 经度（十进制度，-180..180）
    pub longitude: f64,
    /// 该坐标是怎么来的
    pub source: ServerLocationSource,
}

/// 全局本机坐标。`None` = 未配置且未探测到（前端不画本机标记）。
///
/// 与 [`GEOIP`] 同样的 `OnceLock` 语义：进程内只解析一次，之后读缓存。
static SERVER_LOCATION: OnceLock<Option<ServerLocation>> = OnceLock::new();

/// 单个 IP 的地理信息。
#[derive(Clone, Debug, PartialEq)]
pub struct GeoLocation {
    /// 纬度（-90..90）
    pub latitude: f64,
    /// 经度（-180..180）
    pub longitude: f64,
    /// 城市名（中文优先，无则英文；可为空）
    pub city: String,
    /// 国家 ISO 代码（如 `CN`、`US`；可为空）
    pub country_code: String,
    /// 国家名（中文优先，无则英文；可为空）
    pub country: String,
    /// 一级行政区名（省/州；可为空）
    pub subdivision: String,
}

impl GeoLocation {
    /// 是否满足「可在地球上定位」的最低条件。
    ///
    /// 经纬度必须都在合法范围内且非零值——DB-IP 对某些保留段会给出 `0,0`，
    /// 那是几内亚湾海面，不是真实位置。
    #[must_use]
    pub fn is_mappable(&self) -> bool {
        self.latitude.is_finite()
            && self.longitude.is_finite()
            && (-90.0..=90.0).contains(&self.latitude)
            && (-180.0..=180.0).contains(&self.longitude)
            && !(self.latitude == 0.0 && self.longitude == 0.0)
    }
}

/// 全局 GeoIP 解析器。`None` = 未装配或库不可用（禁用态）。
static GEOIP: OnceLock<Option<Reader<Vec<u8>>>> = OnceLock::new();

/// 加载 GeoIP 数据库。**只生效一次**（`OnceLock` 语义），后续调用为空操作。
///
/// # 返回
///
/// - `Ok(true)`：加载成功，地理解析可用
/// - `Ok(false)`：路径为空或文件不存在（禁用态，非错误）
/// - `Err(_)`：文件存在但读取/解析失败（调用方应记 warn 但不中止启动）
///
/// # Errors
///
/// 文件存在但无法作为 MaxMind DB 打开时返回 [`maxminddb::MaxMindDbError`]。
pub fn init(db_path: Option<&str>) -> Result<bool, maxminddb::MaxMindDbError> {
    let Some(path) = db_path.filter(|p| !p.is_empty()) else {
        let _ = GEOIP.set(None);
        return Ok(false);
    };
    if !Path::new(path).exists() {
        let _ = GEOIP.set(None);
        return Ok(false);
    }

    let reader = Reader::open_readfile(path)?;
    // `set` 在已初始化时返回 Err（含值），忽略即可——重复加载是幂等的空操作。
    match GEOIP.set(Some(reader)) {
        Ok(()) => Ok(true),
        Err(_) => Ok(is_enabled()),
    }
}

/// 地理解析是否可用。
#[must_use]
pub fn is_enabled() -> bool {
    matches!(GEOIP.get(), Some(Some(_)))
}

/// 解析一个 IP 的地理位置。
///
/// 禁用态、私网地址、库中无记录、或字段缺失时返回 `None`。
#[must_use]
pub fn lookup(ip: IpAddr) -> Option<GeoLocation> {
    // 私网/回环/链路本地地址不查库：它们要么是内网，要么根本不是攻击源。
    if is_private(ip) {
        return None;
    }

    let reader = GEOIP.get()?.as_ref()?;
    // `decode` 返回 `Ok(None)` 表示库中无该 IP 的记录（非错误）；解析失败亦按无记录处理。
    let city: maxminddb::geoip2::City = reader.lookup(ip).ok()?.decode().ok()??;

    // DB-IP / MaxMind 的城市级记录：经纬度是国家/城市级近似值，缺失时无法定位。
    let latitude = city.location.latitude?;
    let longitude = city.location.longitude?;

    let geo = GeoLocation {
        latitude,
        longitude,
        city: pick_name(&city.city.names),
        country_code: city.country.iso_code.unwrap_or("").to_string(),
        country: pick_name(&city.country.names),
        subdivision: city
            .subdivisions
            .first()
            .map(|s| pick_name(&s.names))
            .unwrap_or_default(),
    };

    if geo.is_mappable() {
        Some(geo)
    } else {
        None
    }
}

// ============================================================================
// 本机坐标：配置优先，其次探测出口 IP
// ============================================================================

/// 从上游响应体里抽出出口 IP。
///
/// 各上游形状不同，这里统一按两步解析，不为每个上游各写一段规则：
/// 1. 能当 JSON 解析时，取顶层 `ip`（api.ip.sb / ipwho.is）或 `data.ip`（myip.ipip.net）；
/// 2. 退回到「在原始文本里找第一个长得像公网 IP 的字面量」，覆盖纯文本端点与形状变化。
///
/// 私网/回环等不可路由地址一律不算——探测端点回一个私网地址说明链路上有代理或上游
/// 异常，拿它去查地理库也没有意义。
#[must_use]
pub fn parse_egress_ip(body: &str) -> Option<IpAddr> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        let from_top = value.get("ip").and_then(|v| v.as_str());
        let from_data = value
            .get("data")
            .and_then(|v| v.get("ip"))
            .and_then(|v| v.as_str());
        if let Some(ip) = from_top.or(from_data).and_then(parse_public_ip) {
            return Some(ip);
        }
    }
    first_public_ip_token(body)
}

/// 解析一个 IP 字面量；非公网地址（私网/回环/链路本地/CGNAT）返回 `None`。
fn parse_public_ip(text: &str) -> Option<IpAddr> {
    let ip: IpAddr = text.trim().parse().ok()?;
    if is_private(ip) {
        None
    } else {
        Some(ip)
    }
}

/// 在任意文本里找出第一个公网 IP 字面量（以非 IP 字符为分隔切词后逐个尝试）。
fn first_public_ip_token(text: &str) -> Option<IpAddr> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == ':'))
        .find_map(parse_public_ip)
}

/// 发一次请求取回探测端点的响应体，并从中抽出出口 IP。
///
/// 网络失败、非 2xx、读体失败、体超限、解析不出 IP —— 一律返回 `None`（由调用方
/// 记日志），绝不 panic、绝不重试。
fn probe_egress_ip(url: &str) -> Option<IpAddr> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(EGRESS_PROBE_TIMEOUT))
        .build()
        .into();
    let mut response = agent.get(url).call().ok()?;
    let body = response
        .body_mut()
        .with_config()
        .limit(EGRESS_BODY_LIMIT)
        .read_to_string()
        .ok()?;
    parse_egress_ip(&body)
}

/// 探测出口 IP，并用**本地** GeoIP 库把它解析成本机坐标。
///
/// 只从上游拿 IP 字符串、经纬度一律走 [`lookup`]：这样「本机」标记与攻击源散点出自
/// 同一个地理库，不会出现两套库互相矛盾的坐标。上游自带的经纬度一概不用——这也是
/// 探测地址可以随便换（哪怕上游不返回经纬度）的原因。
///
/// 返回 `None` 表示未能确定（地理库未启用／网络失败／解析不出 IP／该 IP 在库中无
/// 城市级记录），调用方一律按「未配置」处理：不猜、不退回占位坐标。
#[must_use]
pub fn detect_server_location(probe_url: &str) -> Option<ServerLocation> {
    // 没有地理库就没有「IP → 经纬度」这一步，探测本身也就没有意义（只会白发一次请求）。
    if !is_enabled() {
        return None;
    }
    let ip = probe_egress_ip(probe_url)?;
    let geo = lookup(ip)?;
    Some(ServerLocation {
        latitude: geo.latitude,
        longitude: geo.longitude,
        source: ServerLocationSource::Detected,
    })
}

/// 解析并缓存本机坐标：**配置优先**，其次（仅当启用且未配置时）探测出口 IP。
///
/// 只生效一次（`OnceLock` 语义），之后由 [`get_server_location`] 读缓存——探测是
/// 启动期的一次性动作，绝不进热路径、不会被每次请求触发。
///
/// # Arguments
/// - `configured`：来自 `server_latitude` / `server_longitude`（解析层保证成对）
/// - `detect_egress`：配置开关；关闭时**不发任何请求**
/// - `probe_url`：自定义探测地址；`None` 用内置 [`DEFAULT_EGRESS_PROBE_URL`]
///
/// 返回缓存后的最终值；调用方若只关心副作用（装配缓存）可以直接忽略返回值——失败
/// 情形已在函数内记 warn，不会静默。
pub fn init_server_location(
    configured: Option<(f64, f64)>,
    detect_egress: bool,
    probe_url: Option<&str>,
) -> Option<ServerLocation> {
    let resolved = if let Some((latitude, longitude)) = configured {
        // 配置优先：已有权威坐标就不再发任何对外请求。
        Some(ServerLocation {
            latitude,
            longitude,
            source: ServerLocationSource::Config,
        })
    } else if detect_egress {
        let url = probe_url.unwrap_or(DEFAULT_EGRESS_PROBE_URL);
        // 隐私与可发现性：这是本守护进程唯一的对外请求，必须在启动日志里说清楚，
        // 不允许悄悄发出。日志里带上完整 URL，便于用户在日志里核对出去了什么。
        crate::logger::info!(
            crate::logger::get(),
            "已向 {} 探测出口 IP（本机坐标未配置且 geoip_detect_egress 已开启）",
            url
        );
        let detected = detect_server_location(url);
        match detected {
            Some(location) => crate::logger::info!(
                crate::logger::get(),
                "本机坐标已由出口 IP 探测确定（非权威值，仅供展示）";
                "latitude" => location.latitude,
                "longitude" => location.longitude
            ),
            None => crate::logger::warn!(
                crate::logger::get(),
                "出口 IP 探测未取得本机坐标（网络失败／响应无法解析／库中无该 IP 记录）";
                "url" => url
            ),
        }
        detected
    } else {
        None
    };

    // `set` 在已初始化时返回 Err（含值），忽略即可——重复调用是幂等的空操作。
    let _ = SERVER_LOCATION.set(resolved);
    get_server_location()
}

/// 取已缓存的本机坐标；未装配、未配置且未探测到时为 `None`。
#[must_use]
pub fn get_server_location() -> Option<ServerLocation> {
    SERVER_LOCATION.get().copied().flatten()
}

/// 从 MaxMind 的 `names` 结构挑名字：中文优先，其次英文/日文，最后任一语言。
///
/// `Names` 是**具名语言字段**的结构体（`simplified_chinese` / `english` / …），
/// 不是 map，故只能逐个字段尝试。DB-IP 的免费库通常只带英文名。
fn pick_name(names: &maxminddb::geoip2::Names<'_>) -> String {
    names
        .simplified_chinese
        .or(names.english)
        .or(names.japanese)
        .or(names.german)
        .or(names.french)
        .or(names.spanish)
        .or(names.russian)
        .or(names.brazilian_portuguese)
        .unwrap_or("")
        .to_string()
}

/// 是否为私网/不可路由地址（不应出现在地理库中的段）。
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                // 100.64.0.0/10 CGNAT
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 唯一本地地址
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 链路本地
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_addresses_are_filtered() {
        for s in [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(is_private(ip), "{s} 应判为私网");
            assert!(lookup(ip).is_none(), "{s} 是私网，不应返回地理信息");
        }
    }

    #[test]
    fn public_addresses_not_filtered() {
        for s in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_private(ip), "{s} 应判为公网");
        }
    }

    #[test]
    fn disabled_when_no_path() {
        // 空路径 → 禁用态（本测试可能与其他测试共享 OnceLock，故只断言不 panic）
        let _ = init(None);
        let _ = init(Some(""));
        // 未加载库时 lookup 必须返回 None 而不是 panic
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let _ = lookup(ip);
    }

    #[test]
    fn nonexistent_path_is_not_error() {
        let r = init(Some("/nonexistent/path/to/db.mmdb"));
        assert!(matches!(r, Ok(false)), "文件不存在应返回 Ok(false)，非 Err");
    }

    #[test]
    fn mappable_rejects_null_island_and_out_of_range() {
        let mut g = GeoLocation {
            latitude: 0.0,
            longitude: 0.0,
            city: String::new(),
            country_code: String::new(),
            country: String::new(),
            subdivision: String::new(),
        };
        assert!(!g.is_mappable(), "0,0 不是真实位置");

        g.latitude = 30.0;
        g.longitude = 120.0;
        assert!(g.is_mappable());

        g.latitude = 91.0;
        assert!(!g.is_mappable(), "纬度超范围应拒绝");

        g.latitude = f64::NAN;
        assert!(!g.is_mappable(), "NaN 应拒绝");

        g.latitude = 30.0;
        g.longitude = 200.0;
        assert!(!g.is_mappable(), "经度超范围应拒绝");
    }

    // ------------------------------------------------------------------
    // 出口 IP 探测：只测解析函数，绝不发真实网络请求
    // ------------------------------------------------------------------

    /// 各上游的真实响应形状 → 都能抽出其中的 IP。
    ///
    /// 这些都是实测过的响应体形状（字段名照上游原样），改动解析规则时这些用例会
    /// 指出哪一家先破。IP 用可路由的公网地址：`192.0.2.0/24` 这类文档保留段会被
    /// 私网判定挡掉（见 `rejects_bodies_without_a_public_ip`），与本用例无关。
    /// 全程不涉及任何网络请求。
    #[test]
    fn parses_real_upstream_shapes() {
        let cases: &[(&str, &str)] = &[
            // api.ip.sb/geoip：扁平 JSON，顶层 ip
            (
                r#"{"organization":"Example Hosting","longitude":116.4074,"latitude":39.9042,"ip":"8.8.8.8","timezone":"Asia/Shanghai"}"#,
                "8.8.8.8",
            ),
            // ipwho.is：顶层 ip（success/type 等字段无关紧要）
            (
                r#"{"ip":"1.1.1.1","success":true,"type":"IPv4","continent":"Asia"}"#,
                "1.1.1.1",
            ),
            // myip.ipip.net/json：嵌套在 data.ip，另带文字位置数组
            (
                r#"{"ret":"ok","data":{"ip":"9.9.9.9","location":["中国","北京","北京",""]}}"#,
                "9.9.9.9",
            ),
            // 纯文本端点（如 ifconfig.me/ip）只回一个 IP 加换行
            ("208.67.222.222\n", "208.67.222.222"),
            // 带行尾逗号/引号的纯文本形态
            ("\"64.6.64.6\",", "64.6.64.6"),
            // IPv6 出口
            (r#"{"ip":"2001:4860:4860::8888"}"#, "2001:4860:4860::8888"),
        ];
        for (body, expected) in cases {
            let got = parse_egress_ip(body);
            assert_eq!(
                got,
                Some(expected.parse().unwrap()),
                "响应体应解析出 {expected}: {body}"
            );
        }
    }

    /// 空体、非 IP 内容、以及各种不可路由地址 —— 一律 `None`。
    ///
    /// 「带 ip 字段但值非法」这一条是关键：不能因为字段名对了就放行。文档保留段
    /// （`192.0.2.0/24` / `198.51.100.0/24` / `203.0.113.0/24`）同样不算出口 IP
    /// ——它们永远不可能出现在真实链路上。
    #[test]
    fn rejects_bodies_without_a_public_ip() {
        for body in [
            "",                                 // 空体
            "   \n\t ",                         // 只有空白
            "{}",                               // 空 JSON
            r#"{"error":"rate limited"}"#,      // 上游报错
            "<html><body>502</body></html>",    // 反代返回的 HTML
            r#"{"ip":"not-an-ip"}"#,            // 字段名对、值非法
            r#"{"ip":""}"#,                     // 字段名对、值为空
            r#"{"ip":"10.0.0.1"}"#,             // 私网地址不算出口 IP
            r#"{"ip":"127.0.0.1"}"#,            // 回环不算
            r#"{"ip":"169.254.1.1"}"#,          // 链路本地不算
            r#"{"ip":"100.64.0.1"}"#,           // CGNAT 不算
            r#"{"ip":"203.0.113.7"}"#,          // 文档保留段不算
            r#"{"data":{"ip":"192.168.1.1"}}"#, // 嵌套里的私网地址同样不算
            "upstream is down",
        ] {
            assert_eq!(parse_egress_ip(body), None, "应判为无法解析: {body:?}");
        }
    }

    /// 探测端点不可达时必须返回 `None` 而不是 panic。
    ///
    /// 目标故意选回环端口 1：不需要 DNS、不产生任何对外流量（连接被立刻拒绝），
    /// 因此这个用例在离线环境里也能跑。
    #[test]
    fn unreachable_probe_endpoint_yields_none() {
        assert_eq!(probe_egress_ip("http://127.0.0.1:1/never"), None);
    }

    /// 未装配地理库时探测直接短路为 `None`（不发请求、也不 panic）。
    #[test]
    fn detect_is_none_without_geoip() {
        if is_enabled() {
            return; // 其他测试已装配数据库时跳过
        }
        assert_eq!(detect_server_location("http://127.0.0.1:1/never"), None);
    }

    /// 配置了坐标 → 直接用配置值，且来源标为 `config`；探测开关打开也不会发请求
    /// （这里用一个必然失败的探测地址，若真发了请求结果仍会是 `config`，但耗时暴露它）。
    #[test]
    fn configured_coordinates_win_over_probing() {
        let configured = init_server_location(
            Some((39.9042, 116.4074)),
            true,
            Some("http://127.0.0.1:1/never"),
        );
        // `OnceLock` 只能写一次：同进程内别的用例先装配过时读到的是那次的值（`None`
        // 或别的坐标），故只在拿到本用例写入的值时断言；重点是这条路径不 panic。
        if let Some(location) = configured {
            assert_eq!(location.source, ServerLocationSource::Config);
            assert!((location.latitude - 39.9042).abs() < 1e-9);
            assert!((location.longitude - 116.4074).abs() < 1e-9);
        }
    }
}
