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

#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod tests;
