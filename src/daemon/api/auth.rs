//! 认证适配：把既有凭据校验接进新路由。
//!
//! # 现状与去向
//!
//! 凭据的**存储**与 Basic 校验逻辑当前归 `http_exporter/auth.rs`（配置面 owner
//! 管凭据，SIGHUP 热重载时更新）。本模块不复制那份实现——复制就会立刻产生
//! 「两套凭据、两套失败计数」的漂移，正是本轮要消灭的问题。这里只做适配：
//! 中间件直接从既有校验函数取结论。
//!
//! 2.E-4 退役 `http_exporter/` 时，`auth.rs` 的实体整体搬到这里（连同
//! `AUTH_FAILURE_THRESHOLD` / `AUTH_LOCKOUT_DURATION` 两个契约常量与
//! `verify_http.py` 里指向旧路径的常量检查），本模块的适配层随之消失。
//!
//! # 契约约束（不可在搬迁中丢失）
//!
//! - 失败连续达到 `AUTH_FAILURE_THRESHOLD` 次后锁定 `AUTH_LOCKOUT_DURATION` 秒。
//! - **不发 `WWW-Authenticate`**：该头会让浏览器弹出原生凭据对话框，且对话框
//!   期间 `fetch` 一直挂起——表现为「输错密码按钮永久转圈」。本项目用应用内登录
//!   表单，故刻意偏离 HTTP 语义，只保留 401 状态码供前端识别为凭据问题。
//! - EventSource 无法自定义请求头，故认证额外接受 `?access_token=<base64(user:pass)>`。

use axum::middleware::Next;
use axum::response::Response;

/// 认证中间件：认证失败返回 401 文本，通过则放行。
///
/// 直接委托给既有实现，凭据每请求读取（支持热重载）。
pub async fn auth_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    crate::http_exporter::auth::auth_middleware(request, next).await
}

#[cfg(test)]
mod tests {
    /// 契约声明的认证常量与旧模块里的取值必须一致。
    ///
    /// 搬迁（2.E-4）时这两个常量会移到本模块，此测试也随之改指向——它存在的
    /// 意义是「搬迁时不会静默改数」。
    #[test]
    fn the_contract_constants_live_in_exactly_one_place() {
        assert_eq!(
            crate::http_exporter::AUTH_FAILURE_THRESHOLD,
            10,
            "契约 auth.failure_threshold = 10"
        );
        assert_eq!(
            crate::http_exporter::AUTH_LOCKOUT_DURATION,
            60,
            "契约 auth.lockout_seconds = 60"
        );
    }
}
