//! 全局 [`Client`] 定位器：把「唯一的 netlink 请求入口」暴露给不在构造链上的调用方。
//!
//! # 这是过渡物，不是新架构的一部分
//!
//! 设计上 `kernel/` 没有服务定位器——[`Client`] 只存在于构造它的组合根手里。但旧代码
//! 有约 15 处调用点（`ban/`、`web_ui/`、`http_exporter/`、`config_reloader/`、
//! `file_monitor/`、`runtime_status`）拿的是旧层的
//! `netlink::get_global_netlink_ctx()`，它们不在 `main.rs` 的构造链上，无法通过参数
//! 拿到 `Client`。
//!
//! 2.H-3 的生产切换必须原子完成（内核侧同一时刻只接受一个 daemon portid 注册），
//! 因此不能一边拆调用点一边换传输层。**本模块就是为了让切换发生在同一批提交里**：
//! 组合根在启动期 `init` 一次，调用点改读 `get()`，先恢复功能、把结构改动留到后续批次。
//! 与 2.H-4 同批删除——届时调用点已按依赖注入改造完毕。
//!
//! # 与 `state::compose::set_global_state` 的不同
//!
//! 两者都是「启动期注入一次的全局」，但生命周期不同：`Global State` 是**长期**所有
//! 权安排（新 SSE/REST 的数据源），本定位器是**过渡**物。故分开存放，且本模块在文档
//! 里被明确标记为待删。

use std::sync::OnceLock;

use super::client::Client;

/// 全局客户端。组合根在启动期注入一次；之后所有模块读它拿同一个请求入口。
///
/// 存 `Client` 而非 `Arc<Client>`：`Client` 自身可克隆（内部只有 `Arc` 与原子计数），
/// 克隆共享同一 socket 与路由器，正是这里要的语义。多一层 `Arc` 只会让 `get()` 的
/// 返回类型多一次解引用。
static GLOBAL_CLIENT: OnceLock<Client> = OnceLock::new();

/// 注入全局客户端。
///
/// # Errors
///
/// 重复调用返回 [`GlobalError::AlreadySet`]。与 `netlink::set_global_netlink_ctx`
/// 以及 `state::compose::set_global_state` 同一约定：让「谁先装配」这类顺序错误在启动
/// 期就暴露，而不是静默覆盖成一个指向已关闭 socket 的句柄。
pub fn init(client: Client) -> Result<(), GlobalError> {
    GLOBAL_CLIENT
        .set(client)
        .map_err(|_| GlobalError::AlreadySet)
}

/// 取全局客户端；组合根尚未装配时返回 `None`。
///
/// 返回 `Option` 而不是 panic：单元测试（不经 `main` 装配）与启动早期的调用点上，
/// 定位器为空是正常状态，调用方自行决定是告警、跳过还是退避，而不是让整个进程崩掉。
#[must_use]
pub fn get() -> Option<Client> {
    GLOBAL_CLIENT.get().cloned()
}

/// 组合根是否已注入客户端。
#[must_use]
pub fn is_initialized() -> bool {
    GLOBAL_CLIENT.get().is_some()
}

/// 注入失败的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalError {
    /// 已经注入过一次（`OnceLock` 只能设置一次）。
    AlreadySet,
}

impl std::fmt::Display for GlobalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadySet => write!(f, "Global Client already set"),
        }
    }
}

impl std::error::Error for GlobalError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    /// 本模块只有一个测试：`OnceLock` 是进程级的，多个测试各自 `init` 会互相污染。
    ///
    /// 断言的是「注入一次后 `get` 拿得到同一个入口」与「重复 `init` 报错」两条语义。
    /// `Client` 需要一个真实的 socket（`Transport::open` 不需要 `CAP_NET_ADMIN`），
    /// 本机没有内核模块也能建。
    #[test]
    fn the_global_client_is_injected_once_and_readable_afterwards() {
        assert!(!is_initialized(), "测试起始时定位器应为空");

        let transport = Arc::new(crate::kernel::transport::Transport::open().expect("建 socket"));
        let (router, _rx, _stats, _liveness) =
            crate::kernel::reactor::event_channel(crate::kernel::reactor::default_event_queue());
        let client = Client::new(Arc::clone(&transport), router);

        // 尚未注入：get 为空。
        assert!(get().is_none());

        init(client).expect("首次注入应成功");
        assert!(is_initialized());

        // 取回的是同一个入口：可克隆、可用（对未加载内核模块的环境，查询会失败但
        // 类型是可用的——这里只断言拿得到句柄，不等回复）。
        let got = get().expect("注入后应能取到");
        let _ = got.query_stats(Duration::from_millis(1));

        // 第二次注入必须失败，且不覆盖既有句柄。
        let transport2 = Arc::new(crate::kernel::transport::Transport::open().expect("建 socket"));
        let (router2, _rx2, _stats2, _liveness2) =
            crate::kernel::reactor::event_channel(crate::kernel::reactor::default_event_queue());
        let client2 = Client::new(transport2, router2);
        assert_eq!(init(client2), Err(GlobalError::AlreadySet));

        assert!(get().is_some(), "失败的注入不应清空既有句柄");
    }
}
