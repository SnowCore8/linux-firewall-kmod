//! 统一响应信封与业务码。
//!
//! # 为什么信封是类型而非约定
//!
//! 契约把「成功 = `code: 0`，`message` 为空串」「失败 = 业务码 + `data: null`」写成
//! 单一形状，且**没有**任何 `skip_serializing_if`——成功与失败响应里 `data` 与
//! `message` 都必然存在。旧实现让信封 / 纯文本 / axum 提取器默认三套形状并存，
//! 前端必须同时处理三种；这里用两个类型把它压成一种：成功走
//! [`ApiResponse::ok`]，失败走 [`ApiError`]，后者自己实现 `IntoResponse`。
//!
//! # 业务码与 HTTP 状态码是两套编号
//!
//! HTTP 状态码表达「请求是否被处理」，业务码表达「为什么失败」。同一个业务码在
//! 不同路由上可能配不同的状态码，故 [`BusinessCode`] 同时携带两者，避免实现里
//! 出现「码对了状态码错了」的漂移。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// 契约里的业务码（信封内的 `code`）。
///
/// 取值与 `contract/http.fwidl` 的 `code` 块一一对应。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusinessCode {
    /// 成功；`message` 为空串。
    Ok,
    /// 封禁失败（内核未确认、IP 非法、或内核返回错误）。
    BanFailed,
    /// 解封失败（IP 非法或内核拒绝）。
    UnbanFailed,
    /// 批量解封临时封禁失败 / 添加白名单失败。
    BatchOrWhitelistAddFailed,
    /// 更新配置失败 / 移除白名单失败。
    ConfigOrWhitelistRemoveFailed,
    /// 批量封禁参数非法（列表为空或超过 100 条）/ 日志查询参数非法。
    InvalidBatchOrLogQuery,
    /// 封禁详情查询失败（IP 非法）。
    InvalidBanDetailQuery,
    /// Jail 不存在。
    JailNotFound,
    /// 服务端内部错误（历史库查询任务 join 失败等）。
    Internal,
}

impl BusinessCode {
    /// 信封里的 `code` 数值。
    #[must_use]
    pub const fn raw(self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::BanFailed => 40001,
            Self::UnbanFailed => 40002,
            Self::BatchOrWhitelistAddFailed => 40003,
            Self::ConfigOrWhitelistRemoveFailed => 40004,
            Self::InvalidBatchOrLogQuery => 40005,
            Self::InvalidBanDetailQuery => 40006,
            Self::JailNotFound => 404,
            Self::Internal => 50002,
        }
    }

    /// 该业务码对应的 HTTP 状态码。
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::Ok => StatusCode::OK,
            Self::JailNotFound => StatusCode::NOT_FOUND,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

/// 成功响应信封。
///
/// 契约要求 `data` 与 `message` 恒定存在，故不提供任何跳过序列化的手段。
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    /// 业务码，成功恒为 0。
    pub code: i32,
    /// 载荷。
    pub data: T,
    /// 提示信息，成功时为空串（不是 `"ok"`）。
    pub message: String,
}

impl<T> ApiResponse<T> {
    /// 包装一个成功载荷。
    #[must_use]
    pub fn ok(data: T) -> Self {
        Self {
            code: BusinessCode::Ok.raw(),
            data,
            message: String::new(),
        }
    }
}

/// 分页信封。
///
/// `GET /api/v1/bans` 一律返回本形状：缺陷 `HTTP_BANS_DUAL_SHAPE` 的处置结论是
/// 「统一为单一形状」，不再有裸数组分支，故这里不提供无分页变体。
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    /// 本页条目。
    pub items: Vec<T>,
    /// 过滤后的总条目数（不是本页长度）。
    pub total: u64,
    /// 页码，从 1 开始。
    pub page: u32,
    /// 每页条数。
    pub page_size: u32,
    /// 总页数；`total == 0` 时为 1，与「至少一页」的直觉一致。
    pub total_pages: u32,
}

impl<T> PaginatedResponse<T> {
    /// 由本页条目与总数构造。
    ///
    /// `page_size == 0` 视为「未分页」，此时总页数为 1，避免除零。
    #[must_use]
    pub fn new(items: Vec<T>, total: u64, page: u32, page_size: u32) -> Self {
        let total_pages = if page_size == 0 {
            1
        } else {
            let pages = total.div_ceil(u64::from(page_size));
            u32::try_from(pages).unwrap_or(u32::MAX).max(1)
        };
        Self {
            items,
            total,
            page,
            page_size,
            total_pages,
        }
    }
}

/// 失败响应：业务码 + HTTP 状态码 + 消息。
///
/// `data` 序列化为 `null`（Rust 侧的 `()`），与契约一致。
#[derive(Debug)]
pub struct ApiError {
    code: BusinessCode,
    message: String,
}

impl ApiError {
    /// 以业务码与消息构造；HTTP 状态码取自业务码。
    #[must_use]
    pub fn new(code: BusinessCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// 本错误的业务码。
    #[must_use]
    pub const fn code(&self) -> BusinessCode {
        self.code
    }

    /// 本错误的 HTTP 状态码。
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.code.status()
    }
}

/// 失败信封。
#[derive(Debug, Serialize)]
struct ErrorBody {
    code: i32,
    data: (),
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.code.status();
        let body = ErrorBody {
            code: self.code.raw(),
            data: (),
            message: self.message,
        };
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_business_code_matches_the_contract() {
        // 数值是契约的一部分，改一个数字前端就会误判。
        assert_eq!(BusinessCode::Ok.raw(), 0);
        assert_eq!(BusinessCode::BanFailed.raw(), 40001);
        assert_eq!(BusinessCode::UnbanFailed.raw(), 40002);
        assert_eq!(BusinessCode::BatchOrWhitelistAddFailed.raw(), 40003);
        assert_eq!(BusinessCode::ConfigOrWhitelistRemoveFailed.raw(), 40004);
        assert_eq!(BusinessCode::InvalidBatchOrLogQuery.raw(), 40005);
        assert_eq!(BusinessCode::InvalidBanDetailQuery.raw(), 40006);
        assert_eq!(BusinessCode::JailNotFound.raw(), 404);
        assert_eq!(BusinessCode::Internal.raw(), 50002);
    }

    #[test]
    fn status_codes_follow_the_contract() {
        assert_eq!(BusinessCode::Ok.status(), StatusCode::OK);
        assert_eq!(BusinessCode::BanFailed.status(), StatusCode::BAD_REQUEST);
        assert_eq!(BusinessCode::JailNotFound.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            BusinessCode::Internal.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn a_success_envelope_has_an_empty_message_and_always_present_data() {
        let json = serde_json::to_value(ApiResponse::ok(7)).expect("可序列化");
        assert_eq!(json["code"], 0);
        assert_eq!(json["data"], 7);
        assert_eq!(json["message"], "");
        assert!(
            json.get("data").is_some(),
            "成功响应里 data 必须存在（契约禁止 skip_serializing_if）"
        );
    }

    #[test]
    fn an_error_envelope_carries_no_borrowed_shape() {
        let err = ApiError::new(BusinessCode::BanFailed, "内核未确认");
        assert_eq!(err.code(), BusinessCode::BanFailed);
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn pagination_reports_total_not_page_length() {
        let paged = PaginatedResponse::new(vec![1, 2], 42, 2, 10);
        assert_eq!(paged.total, 42);
        assert_eq!(paged.page, 2);
        assert_eq!(paged.page_size, 10);
        assert_eq!(paged.total_pages, 5);
    }

    #[test]
    fn an_empty_result_still_reports_one_page() {
        let paged = PaginatedResponse::<u8>::new(Vec::new(), 0, 1, 10);
        assert_eq!(paged.total_pages, 1, "空结果也应为 1 页而不是 0");
    }

    #[test]
    fn a_zero_page_size_does_not_divide_by_zero() {
        let paged = PaginatedResponse::<u8>::new(Vec::new(), 5, 1, 0);
        assert_eq!(paged.total_pages, 1);
    }

    #[test]
    fn a_full_last_page_does_not_gain_an_extra_empty_page() {
        // 20 条 / 每页 10 → 恰好 2 页，不能算出 3 页。
        let paged = PaginatedResponse::<u8>::new(vec![0; 10], 20, 2, 10);
        assert_eq!(paged.total_pages, 2);
    }
}
