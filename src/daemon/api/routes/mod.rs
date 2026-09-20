//! 路由处理函数：**薄适配层**，读路径零副作用（修缺陷 E）。
//!
//! # 唯一的职责
//!
//! 从 `state` 取不可变快照 / 调端口，交给 [`super::views`] 派生载荷，套信封返回。
//! 本文件里不出现：purge、统计自增、限流、缓存刷新、`OnceLock` 全局。旧
//! `web_ui/ban_ops.rs::get_active_bans()` 在读路径上同时做了前两项，SSE 每秒读
//! 一次，统计就被读路径每秒改写——那是缺陷 E。
//!
//! # 分页形状唯一
//!
//! `GET /api/v1/bans` **一律**返回分页信封，不再有裸数组分支（缺陷
//! `HTTP_BANS_DUAL_SHAPE` 的处置结论）。

pub mod admin;
pub mod bans;
pub mod readings;
pub mod runtime;
pub mod whitelist;

pub use admin::{handle_api_config, handle_api_jails, handle_update_config, handle_update_jail};
pub use bans::{
    handle_api_bans, handle_ban_detail, handle_batch_ban, handle_create_ban, handle_delete_ban,
    handle_unban_temporary,
};
pub use readings::{handle_api_rates_current, handle_api_sse_status, handle_api_stats};
pub use runtime::{handle_health, handle_metrics};
pub use whitelist::{
    handle_api_whitelist, handle_create_whitelist, handle_delete_whitelist,
    handle_whitelist_recommendations,
};

use std::sync::Arc;

use crate::state::State;

use super::ports::{ConfigPort, ControlPort, HistoryPort, RuntimePort};
use super::sse::SseStatus;

/// 路由共享的依赖集合。
///
/// 全部在构造期注入：`State` 里没有的东西（配置/运行时/历史）经端口拿。没有
/// 服务定位器，也没有 `get_global_*()` 家族。
pub struct ApiState {
    /// 状态所有者。
    pub state: Arc<State>,
    /// 配置面端口。
    pub config: Arc<dyn ConfigPort>,
    /// 运行时与指标端口。
    pub runtime: Arc<dyn RuntimePort>,
    /// 历史与信誉端口。
    pub history: Arc<dyn HistoryPort>,
    /// 控制面端口（封禁/解封）。
    pub control: Arc<dyn ControlPort>,
    /// 两条 SSE 流的连接计数（`/events` 与 `/logs/stream` 各自独立）。
    pub sse: Arc<SseStatus>,
    /// 内核版本字符串（启动期固定）。
    pub kernel_version: String,
}

impl ApiState {
    /// 组装依赖集合。
    #[must_use]
    pub fn new(
        state: Arc<State>,
        config: Arc<dyn ConfigPort>,
        runtime: Arc<dyn RuntimePort>,
        history: Arc<dyn HistoryPort>,
        control: Arc<dyn ControlPort>,
        sse: Arc<SseStatus>,
        kernel_version: impl Into<String>,
    ) -> Self {
        Self {
            state,
            config,
            runtime,
            history,
            control,
            sse,
            kernel_version: kernel_version.into(),
        }
    }

    /// 当前 Unix 秒。
    #[must_use]
    pub fn now_secs(&self) -> i64 {
        crate::types::now_secs()
    }
}
