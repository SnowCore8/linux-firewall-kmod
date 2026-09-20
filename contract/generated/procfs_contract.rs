// 本文件由 contract/gen.py 从 .fwidl 生成，请勿手改。
// 单一真相源: procfs.fwidl（文本协议契约，非二进制线格式）

#![allow(dead_code)]

/// procfs 根目录。
pub const FW_PROCFS_ROOT: &str = "/proc/firewall";

/// 各条目路径。
pub mod path {
    pub const BANS: &str = "/proc/firewall/bans";
    pub const WHITELIST: &str = "/proc/firewall/whitelist";
    pub const CONFIG: &str = "/proc/firewall/config";
    pub const STATS: &str = "/proc/firewall/stats";
    pub const RATES: &str = "/proc/firewall/rates";
    pub const UDP_PORTS: &str = "/proc/firewall/udp_ports";
    pub const ICMP_TYPES: &str = "/proc/firewall/icmp_types";
    pub const PKT_SIZES: &str = "/proc/firewall/pkt_sizes";
    pub const TTL_DIST: &str = "/proc/firewall/ttl_dist";
    pub const IP_FRAGS: &str = "/proc/firewall/ip_frags";
    pub const PORT_SCANNERS: &str = "/proc/firewall/port_scanners";
    pub const SERVICE_PROBES: &str = "/proc/firewall/service_probes";
}

/// 各条目权限位（八进制，与 proc_create 的 mode 一致）。
pub mod mode {
    pub const BANS: u32 = 0o600;
    pub const WHITELIST: u32 = 0o600;
    pub const CONFIG: u32 = 0o600;
    pub const STATS: u32 = 0o400;
    pub const RATES: u32 = 0o400;
    pub const UDP_PORTS: u32 = 0o400;
    pub const ICMP_TYPES: u32 = 0o400;
    pub const PKT_SIZES: u32 = 0o400;
    pub const TTL_DIST: u32 = 0o400;
    pub const IP_FRAGS: u32 = 0o400;
    pub const PORT_SCANNERS: u32 = 0o400;
    pub const SERVICE_PROBES: u32 = 0o400;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanOp {
    BanDefault = 0,
    BanTimed = 1,
    BanPermanent = 2,
    Unban = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhitelistOp {
    Add = 0,
    AddImplicit = 1,
    Remove = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigParam {
    BanTime = 0,
}

/// `bans` 接受的命令形式（占位符仅供人读，非正则）。
pub const BANS_FORMS: &[(BanOp, &str)] = &[(BanOp::BanDefault, "<ip>"), (BanOp::BanTimed, "<ip> <seconds>"), (BanOp::BanPermanent, "<ip> 0"), (BanOp::Unban, "unban <ip>")];

/// `whitelist` 接受的命令形式（占位符仅供人读，非正则）。
pub const WHITELIST_FORMS: &[(WhitelistOp, &str)] = &[(WhitelistOp::Add, "add <subnet>"), (WhitelistOp::AddImplicit, "<subnet>"), (WhitelistOp::Remove, "remove <subnet>")];

/// `config` 接受的命令形式（占位符仅供人读，非正则）。
pub const CONFIG_FORMS: &[(ConfigParam, &str)] = &[(ConfigParam::BanTime, "ban_time <seconds>")];

/// `stats` 的机器可读字段名。
pub mod key {
    pub const TOTAL_BANS: &str = "total_bans"; // u32
    pub const TOTAL_UNBANS: &str = "total_unbans"; // u32
    pub const WHITELIST_REJECTS: &str = "whitelist_rejects"; // u32
    pub const BAN_TABLE_FULL_REJECTS: &str = "ban_table_full_rejects"; // u32
    pub const ALLOC_FAILURES: &str = "alloc_failures"; // u32
    pub const PACKETS_DROPPED: &str = "packets_dropped"; // u64
    pub const PACKETS_ACCEPTED: &str = "packets_accepted"; // u64
    pub const TCP_ANOMALY_DROPPED: &str = "tcp_anomaly_dropped"; // u64
    pub const CLEANUP_CYCLES: &str = "cleanup_cycles"; // u32
    pub const CLEANUP_EXPIRED_TOTAL: &str = "cleanup_expired_total"; // u32
    pub const CURRENT_BANS: &str = "current_bans"; // i32
    pub const CURRENT_WHITELIST: &str = "current_whitelist"; // i32
    pub const RECENT_ADDITIONS: &str = "recent_additions"; // u32
}

/// 容量上限；未列出的表表示实现中无条目上限。
pub mod limit {
    pub const BANS: usize = 65535;
    pub const WHITELIST: usize = 65535;
    pub const RATES: usize = 65536;
    pub const UDP_PORTS: usize = 512;
    pub const ICMP_TYPES: usize = 128;
    pub const PORT_SCANNERS: usize = 20;
    pub const SERVICE_PROBES: usize = 20;
}
