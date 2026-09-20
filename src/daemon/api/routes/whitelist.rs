//! 白名单路由。
//!
//! 白名单的键就是 `state::cidr::CidrKey`——**规范化只有一处**（缺陷 M 的修法）。
//! 故本层不自己做任何 CIDR 处理：`GET` 返回的 `cidr` 字符串可以原样交给 `DELETE`，
//! 前端不必再规范化一次。

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use super::super::envelope::{ApiError, ApiResponse, BusinessCode};
use super::super::payloads::{
    CreateWhitelistRequest, WhitelistEntryResponse, WhitelistOperationResponse,
    WhitelistRecommendation,
};
use super::super::views;
use super::ApiState;

/// `GET /api/v1/whitelist`。
pub async fn handle_api_whitelist(
    State(api): State<Arc<ApiState>>,
) -> Json<ApiResponse<Vec<WhitelistEntryResponse>>> {
    let snapshot = api.state.whitelist().snapshot();
    Json(ApiResponse::ok(views::whitelist_view(&snapshot)))
}

/// `POST /api/v1/whitelist`。
pub async fn handle_create_whitelist(
    State(api): State<Arc<ApiState>>,
    Json(req): Json<CreateWhitelistRequest>,
) -> Response {
    let control = Arc::clone(&api.control);
    let cidr = req.cidr;
    match tokio::task::spawn_blocking(move || control.add_whitelist(&cidr)).await {
        Ok(Ok(normalized)) => (
            StatusCode::CREATED,
            Json(ApiResponse::ok(WhitelistOperationResponse {
                cidr: normalized,
                action: "add".to_string(),
            })),
        )
            .into_response(),
        Ok(Err(msg)) => ApiError::new(BusinessCode::BatchOrWhitelistAddFailed, msg).into_response(),
        Err(e) => ApiError::new(
            BusinessCode::Internal,
            format!("添加白名单任务 join 失败: {e}"),
        )
        .into_response(),
    }
}

/// `DELETE /api/v1/whitelist/:cidr`。
pub async fn handle_delete_whitelist(
    State(api): State<Arc<ApiState>>,
    Path(cidr): Path<String>,
) -> Response {
    let control = Arc::clone(&api.control);
    match tokio::task::spawn_blocking(move || control.remove_whitelist(&cidr)).await {
        Ok(Ok(normalized)) => (
            StatusCode::OK,
            Json(ApiResponse::ok(WhitelistOperationResponse {
                cidr: normalized,
                action: "remove".to_string(),
            })),
        )
            .into_response(),
        Ok(Err(msg)) => {
            ApiError::new(BusinessCode::ConfigOrWhitelistRemoveFailed, msg).into_response()
        }
        Err(e) => ApiError::new(
            BusinessCode::Internal,
            format!("移除白名单任务 join 失败: {e}"),
        )
        .into_response(),
    }
}

/// `GET /api/v1/whitelist/recommendations`：智能白名单推荐。
///
/// 推荐算法依赖 `history_snapshot` 的攻击者统计，属后续批次；本路由先接上端口，
/// 实现未就绪时返回空列表而不是 500——空列表与「无可推荐」语义一致，前端无需特判。
pub async fn handle_whitelist_recommendations(
    State(_api): State<Arc<ApiState>>,
) -> Json<ApiResponse<Vec<WhitelistRecommendation>>> {
    Json(ApiResponse::ok(Vec::new()))
}
