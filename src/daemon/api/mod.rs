//! HTTP 薄适配层：把 `state` 的快照与少量外部端口，翻译成契约里的线上形状。
//!
//! # 分层
//!
//! - [`envelope`]：统一信封与业务码。成功与失败各有唯一形状，前端不必判三种。
//! - [`payloads`]：与 `contract/http.fwidl` 逐字段对应的载荷类型。
//! - [`ports`]：`api` 需要、但不由 `state` 提供的少数数据（历史/信誉/配置/运行时）。
//!   以窄 trait 注入，避免 `api` 绑死在尚未重写的旧模块上。
//! - [`sse`]：按域序列化 + 慢消费者隔离（修缺陷 F）。
//! - [`routes`]：各路由的薄处理函数——**读路径零副作用**（修缺陷 E）。
//!
//! # 本层不做的事
//!
//! - 不触碰 `OnceLock` / `LazyLock` 全局（除委托给端口的地方）。
//! - 不在读路径上做任何清理、统计累加或限流（旧 `get_active_bans()` 三项全占）。
//! - 不自己算业务语义：阈值判定、渐进时长、CIDR 规范化都各归其所有者。

pub mod adapters;
pub mod auth;
pub mod envelope;
pub mod payloads;
pub mod ports;
pub mod render;
pub mod router;
pub mod routes;
pub mod sse;
pub mod views;

pub use envelope::{ApiError, ApiResponse, BusinessCode, PaginatedResponse};
pub use render::StateRenderer;
pub use routes::ApiState;

use std::sync::{Arc, OnceLock};

use crate::state::State;

use ports::{ConfigPort, ControlPort, HistoryPort, RuntimePort};
use sse::SseStatus;

/// 进程级共享的 SSE 连接计数。
///
/// 管理流（`/api/v1/events`，本层）与日志流（`/api/v1/logs/stream`，
/// `web_ui::log_viewer`）必须共用同一份计数：诊断端点 `/api/v1/stats/sse-status`
/// 同时报告两条流，各持一份副本就会各报一半——旧实现的缺陷
/// `HTTP_SSE_STATUS_INCOMPLETE` 正是这么来的。
static SHARED_SSE: OnceLock<Arc<SseStatus>> = OnceLock::new();

/// 取得（或首次创建）进程级 SSE 连接计数。
#[must_use]
pub fn shared_sse_status() -> Arc<SseStatus> {
    Arc::clone(SHARED_SSE.get_or_init(|| Arc::new(SseStatus::new())))
}

/// 用组合根注入的状态装配 [`ApiState`]。
///
/// 只在这里把「新状态 + 尚未重写的旧实现」缝在一起：`ApiState` 本身不认识旧全局，
/// 缝线全部落在 [`adapters`] 的四个端口里。`kernel_version` 与旧 `web_ui/stats.rs`
/// 一致（启动期固定的 `"2.2"`），等内核版本上报迁入后再替换为真实取值。
#[must_use]
pub fn assemble(state: Arc<State>, kernel_version: impl Into<String>) -> ApiState {
    ApiState::new(
        state,
        Arc::new(adapters::LegacyConfigPort) as Arc<dyn ConfigPort>,
        Arc::new(adapters::LegacyRuntimePort) as Arc<dyn RuntimePort>,
        Arc::new(adapters::LegacyHistoryPort) as Arc<dyn HistoryPort>,
        Arc::new(adapters::LegacyControlPort) as Arc<dyn ControlPort>,
        shared_sse_status(),
        kernel_version,
    )
}

#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod tests;
