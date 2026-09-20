//! 封禁相关路由。
//!
//! `GET /api/v1/bans` **恒为分页信封**：缺陷 `HTTP_BANS_DUAL_SHAPE` 的处置结论是
//! 「统一为单一形状」，故这里没有裸数组分支，也没有「带没带分页参数」的判断。

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use super::super::envelope::{ApiError, ApiResponse, BusinessCode, PaginatedResponse};
use super::super::payloads::{
    BanDetailResponse, BanOperationResponse, BanResponse, BatchOperationResponse, CreateBanRequest,
    PaginationParams,
};
use super::super::ports::{BanCommand, BatchOutcome};
use super::super::views;
use super::ApiState;

/// 手工封禁的默认原因。
const MANUAL_BAN_REASON: &str = "手工封禁";
/// 批量封禁的默认原因。
const BATCH_BAN_REASON: &str = "批量封禁";

/// `GET /api/v1/bans`：分页返回活跃封禁。
pub async fn handle_api_bans(
    State(api): State<Arc<ApiState>>,
    Query(params): Query<PaginationParams>,
) -> Json<ApiResponse<PaginatedResponse<BanResponse>>> {
    let now = api.now_secs();
    let (page, page_size) = views::normalize_paging(params.page, params.page_size);
    let sort = views::BanSort::parse(params.sort_by.as_deref());
    let snapshot = api.state.bans().snapshot();
    let sorted = views::bans_sorted(&snapshot, sort, now);
    let (items, total) = views::page_slice(sorted, page, page_size);
    Json(ApiResponse::ok(PaginatedResponse::new(
        items, total, page, page_size,
    )))
}

/// `POST /api/v1/bans`：封禁一个 IP。
pub async fn handle_create_ban(
    State(api): State<Arc<ApiState>>,
    Json(req): Json<CreateBanRequest>,
) -> Response {
    let Ok(ip) = req.ip.trim().parse::<IpAddr>() else {
        return ApiError::new(
            BusinessCode::BanFailed,
            format!("无效的 IP 地址: {}", req.ip),
        )
        .into_response();
    };
    let reason = req.reason.unwrap_or_else(|| MANUAL_BAN_REASON.to_string());
    let cmd = BanCommand {
        ip,
        duration: req.duration,
        reason: Some(reason),
    };
    // 封禁要等内核确认，可能阻塞数百毫秒；放进 blocking 池，避免占住
    // tokio worker 让其它 API 与 SSE 排队。
    let control = Arc::clone(&api.control);
    match tokio::task::spawn_blocking(move || control.ban(cmd)).await {
        Ok(Ok(outcome)) => (
            StatusCode::CREATED,
            Json(ApiResponse::ok(BanOperationResponse {
                ip: ip.to_string(),
                action: "ban".to_string(),
                permanent: outcome.permanent,
                duration_seconds: outcome.duration_seconds,
            })),
        )
            .into_response(),
        Ok(Err(msg)) => ApiError::new(BusinessCode::BanFailed, msg).into_response(),
        Err(e) => ApiError::new(BusinessCode::Internal, format!("封禁任务 join 失败: {e}"))
            .into_response(),
    }
}

/// `DELETE /api/v1/bans/:ip`：解封一个 IP。
pub async fn handle_delete_ban(
    State(api): State<Arc<ApiState>>,
    Path(ip): Path<String>,
) -> Response {
    let Ok(addr) = ip.trim().parse::<IpAddr>() else {
        return ApiError::new(BusinessCode::UnbanFailed, format!("无效的 IP 地址: {ip}"))
            .into_response();
    };
    let control = Arc::clone(&api.control);
    match tokio::task::spawn_blocking(move || control.unban(addr)).await {
        Ok(Ok(())) => (
            StatusCode::OK,
            Json(ApiResponse::ok(BanOperationResponse {
                ip: addr.to_string(),
                action: "unban".to_string(),
                permanent: false,
                duration_seconds: None,
            })),
        )
            .into_response(),
        Ok(Err(msg)) => ApiError::new(BusinessCode::UnbanFailed, msg).into_response(),
        Err(e) => ApiError::new(BusinessCode::Internal, format!("解封任务 join 失败: {e}"))
            .into_response(),
    }
}

/// `GET /api/v1/bans/:ip/detail`：封禁详情。
///
/// 当前封禁的**活性**字段来自 `state`；「上次解封」「信誉」等历史字段来自
/// 历史端口。
pub async fn handle_ban_detail(
    State(api): State<Arc<ApiState>>,
    Path(ip): Path<String>,
) -> Response {
    let trimmed = ip.trim();
    if trimmed.is_empty() {
        return ApiError::new(BusinessCode::InvalidBanDetailQuery, "IP 地址不能为空")
            .into_response();
    }
    let Ok(addr) = trimmed.parse::<IpAddr>() else {
        return ApiError::new(
            BusinessCode::InvalidBanDetailQuery,
            format!("无效的 IP 地址格式: {trimmed}"),
        )
        .into_response();
    };

    let now = api.now_secs();
    let snapshot = api.state.bans().snapshot();
    let active = snapshot.get(&addr).cloned();
    let history = api.history.ban_history(addr);

    // 下次封禁时长 = 历史次数对应的档位（当前在封禁中时以条目上的计数为准）。
    let prior = active.as_ref().map_or_else(
        || history.as_ref().map_or(0, |h| h.ban_count),
        |e| e.ban_count,
    );
    let next = crate::decision::policy::progressive_duration(views::NEXT_BAN_BASE_SECS, prior);

    let detail: BanDetailResponse =
        views::ban_detail_view(addr, active.as_ref(), history, next, now);
    (StatusCode::OK, Json(ApiResponse::ok(detail))).into_response()
}

/// `POST /api/v1/bans/unban-temporary`：解封全部临时封禁。
///
/// 目标集合取自快照，然后逐个下发；每个失败都被记录而不是中断整批。
pub async fn handle_unban_temporary(State(api): State<Arc<ApiState>>) -> Response {
    let targets: Vec<IpAddr> = api
        .state
        .bans()
        .snapshot()
        .entries()
        .iter()
        .filter(|e| !e.is_permanent)
        .map(|e| e.ip)
        .collect();

    let control = Arc::clone(&api.control);
    let (succeeded, failed) = tokio::task::spawn_blocking(move || {
        let mut succeeded = 0_u64;
        let mut failed = Vec::new();
        for ip in targets {
            match control.unban(ip) {
                Ok(()) => succeeded += 1,
                Err(msg) => failed.push(format!("{ip}: {msg}")),
            }
        }
        (succeeded, failed)
    })
    .await
    .unwrap_or_else(|e| (0, vec![format!("批量解封任务 join 失败: {e}")]));

    let outcome = BatchOutcome::new(succeeded, failed);
    (
        StatusCode::OK,
        Json(ApiResponse::ok(BatchOperationResponse {
            total: outcome.total,
            succeeded: outcome.succeeded,
            failed_count: outcome.failed.len() as u64,
            details: outcome.failed,
        })),
    )
        .into_response()
}

/// `POST /api/v1/bans/batch`：批量封禁。
pub async fn handle_batch_ban(
    State(api): State<Arc<ApiState>>,
    Json(ips): Json<Vec<String>>,
) -> Response {
    if ips.is_empty() || ips.len() > views::MAX_BATCH_SIZE {
        return ApiError::new(
            BusinessCode::InvalidBatchOrLogQuery,
            format!("批量封禁条目数必须在 1..={} 之间", views::MAX_BATCH_SIZE),
        )
        .into_response();
    }

    let control = Arc::clone(&api.control);
    let (succeeded, failed) = tokio::task::spawn_blocking(move || {
        let mut succeeded = 0_u64;
        let mut failed = Vec::new();
        for text in ips {
            match text.trim().parse::<IpAddr>() {
                Ok(ip) => {
                    let cmd = BanCommand {
                        ip,
                        duration: None,
                        reason: Some(BATCH_BAN_REASON.to_string()),
                    };
                    match control.ban(cmd) {
                        Ok(_) => succeeded += 1,
                        Err(msg) => failed.push(format!("{ip}: {msg}")),
                    }
                }
                Err(_) => failed.push(format!("{}: 无效的 IP 地址", text.trim())),
            }
        }
        (succeeded, failed)
    })
    .await
    .unwrap_or_else(|e| (0, vec![format!("批量封禁任务 join 失败: {e}")]));

    let outcome = BatchOutcome::new(succeeded, failed);
    (
        StatusCode::CREATED,
        Json(ApiResponse::ok(BatchOperationResponse {
            total: outcome.total,
            succeeded: outcome.succeeded,
            failed_count: outcome.failed.len() as u64,
            details: outcome.failed,
        })),
    )
        .into_response()
}
