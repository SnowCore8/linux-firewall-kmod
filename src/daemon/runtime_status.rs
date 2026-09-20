//! 运行时子系统快照（缓解全局 OnceLock 服务定位器的可观测性/可测性债务）
//!
//! 不重构 AppState：提供一次性只读聚合，供 `/health` 与单测断言就绪态。

use serde::Serialize;

/// 关键全局定位器与内核侧就绪态的只读快照
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    /// `"ok"` 或 `"degraded"`
    pub status: &'static str,
    pub netlink_ready: bool,
    pub kmod_proc_present: bool,
    pub ban_cache_initialized: bool,
    pub ban_history_initialized: bool,
    pub active_bans: usize,
}

/// 聚合当前进程内 OnceLock 与 `/proc/firewall` 存在性。
pub fn runtime_snapshot() -> RuntimeSnapshot {
    let netlink_ready = crate::netlink::get_global_netlink_ctx().is_some();
    let kmod_proc_present = std::path::Path::new("/proc/firewall").is_dir();
    let ban_cache = crate::types::ACTIVE_BAN_CACHE.get();
    let ban_history_initialized = crate::types::BAN_HISTORY.get().is_some();
    let active_bans = ban_cache.map(|c| c.len()).unwrap_or(0);
    let ban_cache_initialized = ban_cache.is_some();

    let ok = netlink_ready && kmod_proc_present;
    RuntimeSnapshot {
        status: if ok { "ok" } else { "degraded" },
        netlink_ready,
        kmod_proc_present,
        ban_cache_initialized,
        ban_history_initialized,
        active_bans,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reports_degraded_without_kmod_or_netlink() {
        let snap = runtime_snapshot();
        // status 的唯一输入是两个就绪位：这里独立重算一遍，改变判定口径就会失败
        // （例如只按 netlink_ready 判定时，netlink 就绪但 procfs 缺失即被抓出）
        let expected = if snap.netlink_ready && snap.kmod_proc_present {
            "ok"
        } else {
            "degraded"
        };
        assert_eq!(snap.status, expected, "status 与两个就绪位不一致");
        // 序列化字段名与取值都要落地：字段被改名/跳过会在这里失败
        let json = serde_json::to_string(&snap).expect("RuntimeSnapshot serializes");
        assert!(
            json.contains(&format!("\"status\":\"{}\"", snap.status)),
            "序列化结果与快照不一致: {json}"
        );
    }
}
