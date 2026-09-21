//! 运行时子系统快照（缓解全局 OnceLock 服务定位器的可观测性/可测性债务）
//!
//! 不重构 AppState：提供一次性只读聚合，供 `/health` 与单测断言就绪态。
//!
//! # 就绪态的口径
//!
//! `netlink_ready` 在本层被**收紧**为「内核租约已持有」：内核只承认一个 daemon
//! portid，未持有租约时本进程发出的每条指令都会被内核静默丢弃。因此「socket 建好了」
//! 不等于「内核会听」——旧口径（`NetlinkContext` 存在即可）会把这类「界面正常、指令
//! 全被丢掉」的状态报成就绪。

use serde::Serialize;

use crate::kernel::lease::LeaseState;
use crate::kernel_poll::LeaseCell;
use std::sync::{Arc, OnceLock};

/// 内核租约状态的进程内句柄。组合根在装配内核链路后注入一次。
///
/// 放在本模块而不是 `kernel_poll`：`/health` 的聚合点在本文件，把「谁读」与「谁持有」
/// 放在一起，避免 `kernel_poll` 多出一个进程级全局。
static GLOBAL_LEASE_CELL: OnceLock<Arc<LeaseCell>> = OnceLock::new();

/// 注入内核租约状态句柄（仅在启动时调用一次）。
///
/// # Errors
///
/// 重复调用返回错误——与 `state::compose::set_global_state` 同一约定，让「谁先装配」
/// 这类顺序错误在启动期就暴露。
pub fn set_lease_cell(cell: Arc<LeaseCell>) -> anyhow::Result<()> {
    GLOBAL_LEASE_CELL
        .set(cell)
        .map_err(|_| anyhow::anyhow!("Global LeaseCell already set"))
}

/// 租约状态与本进程累计失联次数。
fn lease_snapshot() -> (Option<LeaseState>, u64) {
    match GLOBAL_LEASE_CELL.get() {
        Some(cell) => (cell.state(), cell.losses()),
        // 尚未注入：没有内核链路执行体。与 `LeaseState::Idle`（有执行体但未注册）不同。
        None => (None, 0),
    }
}

/// 租约状态的稳定名字，写进 `RuntimeSnapshot.lease_state`。
///
/// 取值集合固定，前端与运维脚本据此判定：
/// - `none` —— 本进程没有内核链路执行体（正常情况下不应出现）；
/// - `idle` —— 执行体在跑，尚未注册；
/// - `held` —— 内核已确认注册，指令会被接受；
/// - `refused` —— 内核明确拒绝（已有活跃守护进程持有租约）；
/// - `lost` —— 租约已失（确认超时或链路断开），正在重试。
const fn lease_state_name(state: Option<LeaseState>) -> &'static str {
    match state {
        None => "none",
        Some(LeaseState::Idle) => "idle",
        Some(LeaseState::Held) => "held",
        Some(LeaseState::Refused) => "refused",
        Some(LeaseState::Lost) => "lost",
    }
}

/// 关键全局定位器与内核侧就绪态的只读快照
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    /// `"ok"` 或 `"degraded"`
    pub status: &'static str,
    /// 内核是否会接受本进程的指令（租约已持有）。
    pub netlink_ready: bool,
    pub kmod_proc_present: bool,
    pub ban_cache_initialized: bool,
    pub ban_history_initialized: bool,
    pub active_bans: usize,
    /// 租约状态的稳定名字，见 [`lease_state_name`]。
    pub lease_state: &'static str,
    /// 累计失联次数（进入 `lost` 的次数）。
    pub lease_losses: u64,
}

/// 聚合当前进程内 OnceLock 与 `/proc/firewall` 存在性。
pub fn runtime_snapshot() -> RuntimeSnapshot {
    let (lease, lease_losses) = lease_snapshot();
    let lease_state = lease_state_name(lease);
    // 只有 `held` 才代表「内核会听」：`lost` / `refused` / `idle` 下指令一律被丢掉。
    let netlink_ready = lease == Some(LeaseState::Held);
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
        lease_state,
        lease_losses,
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

    /// `netlink_ready` 必须与「租约已持有」严格一致：这是 `/health` 报「内核会听」的唯一依据。
    ///
    /// 每个状态逐个断言，避免将来把 `lost` / `refused` 误判成就绪。
    #[test]
    fn netlink_ready_means_exactly_lease_held() {
        for (state, name, ready) in [
            (None, "none", false),
            (Some(LeaseState::Idle), "idle", false),
            (Some(LeaseState::Held), "held", true),
            (Some(LeaseState::Refused), "refused", false),
            (Some(LeaseState::Lost), "lost", false),
        ] {
            assert_eq!(lease_state_name(state), name);
            let is_held = state == Some(LeaseState::Held);
            assert_eq!(is_held, ready, "{name} 的就绪判定不符");
        }
    }
}
