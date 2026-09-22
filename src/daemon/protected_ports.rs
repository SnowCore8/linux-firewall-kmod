//! 对外监听端口发现与受保护端口位图下发。
//!
//! 语义：**纳入防护**。公网能打到本机的只有对外监听端口，DDoS 速率判定的
//! 作用面就聚焦在它们身上；未对外监听的端口不参与速率判定，避免内部流量误封。
//! 封禁表不受影响——jail 判定与手工下发的封禁对所有端口一律生效。
//!
//! # 发现来源为什么是 procfs 的 net 表
//!
//! 唯一可靠来源是本机 `/proc/net/{tcp,tcp6,udp,udp6}`：内核在这里给出每个
//! 套接字的**实际**绑定地址与状态。两个看似相关但不是依据的来源：
//!
//! - **frpc 配置**：隧道路径是「外部 → frps → 隧道 → frpc(本机) → 本机端口」，
//!   外部包到不了本机 netfilter，到达时源地址已是环回、早被本机地址判定短路。
//!   「frp 发布 ≠ 本机对外监听」，解析 frpc.toml 只会引入会漂移的依赖。
//! - **本机接口地址表**（`fw_local.c` 的集合）：那是「哪些地址属于本机」，
//!   与「哪些端口在对外监听」是两个问题。
//!
//! # 分类规则
//!
//! 按 `local_address` 判定绑定范围（`is_external_bind`）：
//!
//! - `0.0.0.0`（`00000000`）或 `::`（32 个 0）= 全部接口 ⇒ 对外；
//! - 环回（`::1`，或 IPv4 地址**以 `7F` 结尾**）= 仅本机 ⇒ 不算对外；
//! - 其余具体地址（含非环回的本机地址）= 至少在一个非环回接口上可达 ⇒ 对外。
//!
//! **环回判据是整个 127.0.0.0/8，不是只有 127.0.0.1**：`/proc` 里 IPv4 地址
//! 是小端十六进制，首字节落在最后一个字节对上，故 `127.0.0.53` 写作
//! `3500007F`——只看 `0100007F` 会把 systemd-resolved 的 `127.0.0.53:53`
//! 误判成对外，进而把 53 端口错误纳入保护（实测踩过）。
//!
//! # 套接字状态
//!
//! - TCP（`TableKind::Tcp`）：只取 `st == 0A`（LISTEN）；
//! - UDP（`TableKind::Udp`）：没有 LISTEN，取未连接的绑定套接字 `st == 07`，
//!   **必须排除 `st == 01`**（已连接）——否则客户端套接字会被当成服务。
//!
//! # 语义边界（诚实声明）
//!
//! `/proc` 只是**本机视角**：路由器 NAT、上游防火墙是否真的把某个端口放通，
//! 本机无从得知。因此本模块的语义是「**本机对外监听的端口**」，取保守超集
//! （宁可多保护，不放过）。这与威胁模型（入站单向守护）一致。

use std::collections::BTreeSet;
use std::io::Read;

/// 位图字节数（65536 位，一端口一位）。与契约 `SetProtectedPorts.bitmap` 一致。
pub const BITMAP_BYTES: usize = 8192;

/// net 表的种类：决定「在监听」用哪个状态码。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TableKind {
    /// TCP 表：`st == 0A` 即 LISTEN。
    Tcp,
    /// UDP 表：无 LISTEN，`st == 07` 是未连接的绑定套接字。
    Udp,
}

impl TableKind {
    /// 该表「在提供服务」的状态码。
    fn active_state(self) -> &'static str {
        match self {
            Self::Tcp => "0A",
            Self::Udp => "07",
        }
    }
}

/// 待扫描的表：(路径, 地址族, 表种类)。
const NET_TABLES: &[(&str, bool, TableKind)] = &[
    ("/proc/net/tcp", false, TableKind::Tcp),
    ("/proc/net/tcp6", true, TableKind::Tcp),
    ("/proc/net/udp", false, TableKind::Udp),
    ("/proc/net/udp6", true, TableKind::Udp),
];

/// 扫描结果：对外监听端口的集合（去重、升序）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtectedPorts {
    ports: BTreeSet<u16>,
}

impl ProtectedPorts {
    /// 端口数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.ports.len()
    }

    /// 是否为空集。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ports.is_empty()
    }

    /// 是否包含某端口。
    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        self.ports.contains(&port)
    }

    /// 迭代端口（升序）。
    pub fn iter(&self) -> impl Iterator<Item = u16> + '_ {
        self.ports.iter().copied()
    }

    /// 编码为下发位图（65536 位，位 i = 端口 i 受保护）。
    #[must_use]
    pub fn to_bitmap(&self) -> [u8; BITMAP_BYTES] {
        let mut bitmap = [0u8; BITMAP_BYTES];
        for &port in &self.ports {
            let p = usize::from(port);
            // 端口范围保证索引落在 8192 字节内；用 if-let 而非 expect，
            // 保持本函数（周期任务里跑）无 panic 面。
            if let Some(byte) = bitmap.get_mut(p / 8) {
                *byte |= 1 << (p % 8);
            }
        }
        bitmap
    }
}

/// 扫描四张 net 表，返回对外监听端口集合。
///
/// # Errors
///
/// 任一表读取失败且错误不是「表不存在」时返回该错误（见 [`scan_from`] 的错误策略）。
pub fn scan_external_ports() -> std::io::Result<ProtectedPorts> {
    scan_from(NET_TABLES, |path| {
        let mut buf = String::new();
        std::fs::File::open(path)?.read_to_string(&mut buf)?;
        Ok(buf)
    })
}

/// 扫描的可注入核心：`read` 负责取回某张表的文本内容。
///
/// 与 [`scan_external_ports`] 拆开是为了让分类规则可被单元测试覆盖——
/// 表格解析是纯函数，不该依赖真实 `/proc`。
///
/// # 错误策略：只容忍「表不存在」
///
/// 扫描结果用于**收窄**速率判定作用面，故不能凭残缺数据下结论：
///
/// - `NotFound`（未启用 IPv6 的内核没有 `/proc/net/tcp6`）等价于空表——该表中确实
///   无套接字可列，按空处理是准确的；
/// - 其余错误（权限、IO 失败）意味着「**可能有数据但看不到**」。若照样下发，漏掉
///   那张表里的端口就会静默失去速率判定。故整次扫描失败，由调用方保留上一次已下发的
///   集合（或维持「未下发 = 全端口受保护」）：宁可继续按旧集合防护，也不因读不到
///   `/proc` 就把保护面收窄。
fn scan_from<F>(tables: &[(&str, bool, TableKind)], mut read: F) -> std::io::Result<ProtectedPorts>
where
    F: FnMut(&str) -> std::io::Result<String>,
{
    let mut ports = BTreeSet::new();

    for &(path, ipv6, kind) in tables {
        match read(path) {
            Ok(text) => collect_ports(&text, ipv6, kind, &mut ports),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(std::io::Error::new(e.kind(), format!("{path}: {e}"))),
        }
    }

    Ok(ProtectedPorts { ports })
}

/// 从一张表的文本里挑出对外监听端口。
///
/// 行格式（见 `proc(5)` 的 `/proc/net/tcp` 一节）：
///
/// ```text
///   sl  local_address rem_address   st ...
///    0: 0100007F:1F90 00000000:0000 0A ...
/// ```
///
/// 只依赖第 2 列（`local_address`，形如 `<hex地址>:<hex端口>`）与第 4 列
/// （`st`），其余列不解析——列数变化时不至于误判。
fn collect_ports(text: &str, ipv6: bool, kind: TableKind, out: &mut BTreeSet<u16>) {
    let want_state = kind.active_state();

    for line in text.lines().skip(1) {
        // 表头之后每行以 "  <序号>: " 开头；split_whitespace 对空行与表头都
        // 天然安全（列数不足即 continue）。
        let mut cols = line.split_whitespace();
        let _sl = cols.next();
        let Some(local) = cols.next() else { continue };
        let _rem = cols.next();
        let Some(state) = cols.next() else { continue };

        if state != want_state {
            continue;
        }

        let Some((addr, port)) = local.rsplit_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port, 16) else {
            continue;
        };

        if is_external_bind(addr, ipv6) {
            out.insert(port);
        }
    }
}

/// 判定 `/proc` 中 `local_address` 的地址部分是否表示「对外可达」。
///
/// - IPv4：`00000000` = 0.0.0.0（全部接口）⇒ 对外；以 `7F` 结尾 = 127.0.0.0/8
///   环回 ⇒ 不算；其余 ⇒ 对外。
/// - IPv6：32 个 0 = `::`（全部接口）⇒ 对外；`::1` ⇒ 不算；其余 ⇒ 对外。
///
/// 长度不符时返回 `false`（保守：不认识的形式不算对外，宁可漏保护也不误判）。
fn is_external_bind(addr_hex: &str, ipv6: bool) -> bool {
    if ipv6 {
        if addr_hex.len() != 32 {
            return false;
        }
        if addr_hex.bytes().all(|b| b == b'0') {
            return true; // ::
        }
        // ::1 在小端十六进制下末 8 个字符是 01000000
        !addr_hex.ends_with("01000000")
    } else {
        if addr_hex.len() != 8 {
            return false;
        }
        if addr_hex == "00000000" {
            return true; // 0.0.0.0
        }
        // 环回：首字节 127 落在最末一个字节对上
        !addr_hex.ends_with("7F")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造 net 表文本：表头 + 若干 `本地地址:端口 远端 st` 行。
    fn net_table(rows: &[(&str, u16, &str)]) -> String {
        let mut s = String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt\n",
        );
        for (i, (addr, port, st)) in rows.iter().enumerate() {
            s.push_str(&format!(
                "  {i:>2}: {addr}:{port:04X} 00000000:0000 {st} 00000000:00000000 00:00000000 00000000     0        0\n"
            ));
        }
        s
    }

    #[test]
    fn external_bind_classification() {
        // 全部接口 ⇒ 对外
        assert!(is_external_bind("00000000", false));
        assert!(is_external_bind("00000000000000000000000000000000", true));
        // 环回 ⇒ 不算对外。整个 127.0.0.0/8，不只是 127.0.0.1
        assert!(!is_external_bind("0100007F", false)); // 127.0.0.1
        assert!(!is_external_bind("3500007F", false)); // 127.0.0.53
        assert!(!is_external_bind("3600007F", false)); // 127.0.0.54
        assert!(!is_external_bind("00000000000000000000000001000000", true)); // ::1
                                                                              // 具体非环回地址 ⇒ 对外
        assert!(is_external_bind("010200C0", false)); // 192.168.2.1
        assert!(is_external_bind("01000A0A", false)); // 10.0.0.1
                                                      // 长度不对 ⇒ 不认（保守）
        assert!(!is_external_bind("00", false));
        assert!(!is_external_bind("0100007F00", false));
        assert!(!is_external_bind("0100007F", true));
    }

    #[test]
    fn tcp_takes_listen_only_and_excludes_loopback() {
        let table = net_table(&[
            ("0100007F", 631, "0A"),   // 127.0.0.1:631 环回 ⇒ 排除
            ("3500007F", 53, "0A"),    // 127.0.0.53:53 环回 ⇒ 排除（曾经的误判点）
            ("00000000", 22, "0A"),    // 0.0.0.0:22 ⇒ 对外
            ("00000000", 9119, "0A"),  // 0.0.0.0:9119 ⇒ 对外
            ("00000000", 40000, "01"), // 已连接 ⇒ 排除
            ("010200C0", 16299, "0A"), // 192.168.2.1:16299 ⇒ 对外
        ]);
        let out = scan_from(&[("/proc/net/tcp", false, TableKind::Tcp)], |_| {
            Ok(table.clone())
        })
        .expect("扫描");

        let ports: Vec<u16> = out.iter().collect();
        assert_eq!(ports, vec![22, 9119, 16299]);
    }

    #[test]
    fn udp_takes_bound_only_and_excludes_connected() {
        let table = net_table(&[
            ("00000000", 5353, "07"),  // 绑定 ⇒ 对外
            ("00000000", 55169, "01"), // 已连接（客户端）⇒ 排除
            ("0100007F", 9421, "07"),  // 环回绑定 ⇒ 排除
            ("00000000", 19132, "0A"), // UDP 表里出现 TCP 状态码 ⇒ 不认
        ]);
        let out = scan_from(&[("/proc/net/udp", false, TableKind::Udp)], |_| {
            Ok(table.clone())
        })
        .expect("扫描");

        let ports: Vec<u16> = out.iter().collect();
        assert_eq!(ports, vec![5353], "st=01 与环回都必须排除");
    }

    #[test]
    fn bitmap_encodes_ports() {
        let mut ports = BTreeSet::new();
        ports.insert(22u16);
        ports.insert(9119u16);
        ports.insert(65535u16);
        let out = ProtectedPorts { ports };
        let bitmap = out.to_bitmap();

        assert_eq!(bitmap[22 / 8] & (1 << (22 % 8)), 1 << (22 % 8));
        assert_eq!(bitmap[9119 / 8] & (1 << (9119 % 8)), 1 << (9119 % 8));
        assert_eq!(bitmap[BITMAP_BYTES - 1] & 0x80, 0x80);
        // 未置位端口必须为 0
        assert_eq!(bitmap[80 / 8] & (1 << (80 % 8)), 0);
        assert_eq!(out.len(), 3);
        assert!(!out.is_empty());
        assert!(out.contains(9119));
        assert!(!out.contains(80));
    }

    /// 表不存在（未启用 IPv6 的内核）等价于空表：不能因为读不到就让整次扫描失败，
    /// 否则位图永不更新。
    #[test]
    fn missing_tables_are_treated_as_empty() {
        let out = scan_from(
            &[
                ("/proc/net/tcp", false, TableKind::Tcp),
                ("/proc/net/tcp6", true, TableKind::Tcp),
            ],
            |_| Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no")),
        )
        .expect("表不存在应等价于空表");
        assert!(out.is_empty());
    }

    /// 非「表不存在」的读取失败必须让整次扫描失败：那意味着「可能有数据但看不到」，
    /// 若照样下发就会让漏读表里的端口静默失去速率判定。
    #[test]
    fn unreadable_table_aborts_the_scan() {
        let table = net_table(&[("00000000", 22, "0A")]);
        let mut calls = 0;
        let err = scan_from(
            &[
                ("/proc/net/tcp", false, TableKind::Tcp),
                ("/proc/net/tcp6", true, TableKind::Tcp),
            ],
            |_| {
                calls += 1;
                if calls == 1 {
                    Ok(table.clone())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "denied",
                    ))
                }
            },
        )
        .expect_err("读到一半失败必须报错，不能下发残缺集合");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string().contains("/proc/net/tcp6"),
            "错误须带上出错路径"
        );
    }
}
