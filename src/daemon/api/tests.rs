//! 路由行为测试：读路径零副作用、信封形状、业务码映射、分页。
//!
//! 这些断言都是**可失败**的：`reading_paths_do_not_mutate_any_state` 会在任何
//! 读路径写状态时失败，`a_failed_ban_lands_on_code_40001` 会在业务码错位时失败。
//! 它们是设计文档「测试债务」一节要求的形态——不是恒真保护。

#![cfg(test)]

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Json;

use super::envelope::BusinessCode;
use super::payloads::{
    CreateBanRequest, CreateWhitelistRequest, PaginationParams, UpdateConfigRequest,
    UpdateJailRequest,
};
use super::routes::{
    handle_api_bans, handle_api_config, handle_api_jails, handle_api_rates_current,
    handle_api_sse_status, handle_api_stats, handle_api_whitelist, handle_ban_detail,
    handle_batch_ban, handle_create_ban, handle_create_whitelist, handle_delete_ban,
    handle_delete_whitelist, handle_health, handle_update_config, handle_update_jail,
};
use super::testing::Harness;
use crate::state::hub::Domain;
use crate::state::{BanEntry, CidrKey, RateSample};

/// 从 `Response` 里取出状态码与 JSON 体。
async fn response_parts(response: axum::response::Response) -> (u16, serde_json::Value) {
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body 应可读");
    let json = serde_json::from_slice(&bytes).expect("响应体应为 JSON");
    (status, json)
}

fn ip(s: &str) -> std::net::IpAddr {
    s.parse().expect("测试输入应为合法 IP")
}

/// 放一条封禁进状态。
fn seed_ban(h: &Harness, ip_str: &str, jail: &str, banned_at: i64, expires_at: i64) {
    h.state.bans().insert(BanEntry::new(
        ip(ip_str),
        jail,
        "test",
        banned_at,
        expires_at,
        false,
        1,
        5,
    ));
}

// ============================================================================
// 缺陷 E：读路径零副作用
// ============================================================================

#[tokio::test]
async fn reading_paths_do_not_mutate_any_state() {
    // 缺陷 E 的核心断言：把全部「读」端点各调一遍，状态与版本必须不变。
    let h = Harness::new().with_jail("sshd");
    seed_ban(&h, "10.0.0.1", "sshd", 100, 200);
    h.state
        .whitelist()
        .insert(CidrKey::parse("10.0.0.0/24").expect("合法 CIDR"), "");
    h.state.rates().apply(RateSample {
        global_pps: 10,
        global_bps: 100,
        per_ip: std::collections::BTreeMap::new(),
    });

    let before_versions = h.state.hub().versions();
    let before_stats = h.state.stats().snapshot();
    let before_bans = h.state.bans().len();
    let before_whitelist = h.state.whitelist().len();

    // 反复读，模拟 SSE 每秒读一次的历史行为。
    for _ in 0..5 {
        let _ = handle_api_stats(State(Arc::clone(&h.api))).await;
        let _ = handle_api_bans(
            State(Arc::clone(&h.api)),
            Query(PaginationParams::default()),
        )
        .await;
        let _ = handle_api_whitelist(State(Arc::clone(&h.api))).await;
        let _ = handle_api_rates_current(State(Arc::clone(&h.api))).await;
        let _ = handle_api_jails(State(Arc::clone(&h.api))).await;
        let _ = handle_api_config(State(Arc::clone(&h.api))).await;
        let _ = handle_api_sse_status(State(Arc::clone(&h.api))).await;
        let _ = handle_health(State(Arc::clone(&h.api))).await;
    }

    assert_eq!(
        h.state.hub().versions(),
        before_versions,
        "读路径不得推进任何域的版本"
    );
    assert_eq!(h.state.stats().snapshot(), before_stats, "读路径不得改统计");
    assert_eq!(h.state.bans().len(), before_bans, "读路径不得清理封禁");
    assert_eq!(
        h.state.whitelist().len(),
        before_whitelist,
        "读路径不得改白名单"
    );
}

#[tokio::test]
async fn reading_does_not_purge_expired_bans() {
    // 过期条目在读路径上必须原样保留：清理只由 scheduler 的独立任务做。
    let h = Harness::new();
    seed_ban(&h, "10.0.0.1", "sshd", 100, 150); // 早已过期
    let _ = handle_api_bans(
        State(Arc::clone(&h.api)),
        Query(PaginationParams::default()),
    )
    .await;
    assert_eq!(h.state.bans().len(), 1, "读列表不得顺手清理过期封禁");
}

// ============================================================================
// 缺陷 HTTP_BANS_DUAL_SHAPE：单一形状
// ============================================================================

#[tokio::test]
async fn the_bans_endpoint_always_returns_the_paginated_envelope() {
    // 不论有没有传分页参数，data 都必须是对象（分页信封），不是裸数组。
    let h = Harness::new();
    seed_ban(&h, "10.0.0.1", "sshd", 100, 200);

    let json = serde_json::to_value(
        handle_api_bans(
            State(Arc::clone(&h.api)),
            Query(PaginationParams::default()),
        )
        .await
        .0,
    )
    .expect("可序列化");
    assert!(
        json["data"].is_object(),
        "不带分页参数时 data 也必须是对象（缺陷 HTTP_BANS_DUAL_SHAPE 的修法）"
    );
    assert_eq!(json["data"]["total"], 1);
    assert_eq!(json["data"]["page_size"], 20, "缺省每页 20 条");

    let json = serde_json::to_value(
        handle_api_bans(
            State(Arc::clone(&h.api)),
            Query(PaginationParams {
                page: Some(2),
                page_size: Some(5),
                sort_by: None,
            }),
        )
        .await
        .0,
    )
    .expect("可序列化");
    assert!(json["data"].is_object());
    assert_eq!(json["data"]["page"], 2);
    assert_eq!(json["data"]["page_size"], 5);
}

#[tokio::test]
async fn pagination_is_clamped_to_the_contract_limits() {
    let h = Harness::new();
    let json = serde_json::to_value(
        handle_api_bans(
            State(Arc::clone(&h.api)),
            Query(PaginationParams {
                page: Some(0),
                page_size: Some(9999),
                sort_by: None,
            }),
        )
        .await
        .0,
    )
    .expect("可序列化");
    assert_eq!(json["data"]["page"], 1, "页码至少为 1");
    assert_eq!(json["data"]["page_size"], 100, "每页最多 100 条");
}

// ============================================================================
// 缺陷 HTTP_SSE_STATUS_INCOMPLETE：两条流各自报告
// ============================================================================

#[tokio::test]
async fn the_sse_status_reports_both_streams() {
    let h = Harness::new();
    let _guard = h.sse.acquire_events().expect("应能占位");
    let json = serde_json::to_value(handle_api_sse_status(State(Arc::clone(&h.api))).await.0)
        .expect("可序列化");
    assert_eq!(json["data"]["events"]["current_connections"], 1);
    assert_eq!(json["data"]["events"]["max_connections"], 10);
    assert_eq!(json["data"]["logs"]["current_connections"], 0);
    assert_eq!(
        json["data"]["logs"]["max_connections"], 5,
        "日志流上限必须独立上报（缺陷 HTTP_SSE_STATUS_INCOMPLETE）"
    );
}

// ============================================================================
// 缺陷 HTTP_HEALTH_NOT_ENVELOPED：有意保留的裸状态码
// ============================================================================

#[tokio::test]
async fn health_is_not_enveloped_and_uses_the_status_code() {
    let h = Harness::new();
    let ready = handle_health(State(Arc::clone(&h.api))).await;
    assert_eq!(ready.status().as_u16(), 200, "就绪应为 200");

    let degraded = Harness::with_readiness(false);
    let response = handle_health(State(Arc::clone(&degraded.api))).await;
    assert_eq!(response.status().as_u16(), 503, "未就绪应为 503");
    let (_, json) = response_parts(response).await;
    assert_eq!(json["status"], "degraded");
    assert!(
        json.get("code").is_none(),
        "/health 有意不经信封（探针语义），不得出现 code 字段"
    );
}

// ============================================================================
// 业务码映射
// ============================================================================

#[tokio::test]
async fn a_failed_ban_lands_on_code_40001() {
    let h = Harness::new();
    *h.control.ban_error.lock().expect("锁未中毒") = Some("内核未确认".to_string());
    let response = handle_create_ban(
        State(Arc::clone(&h.api)),
        Json(CreateBanRequest {
            ip: "10.0.0.1".to_string(),
            duration: None,
            reason: None,
        }),
    )
    .await;
    let (status, json) = response_parts(response).await;
    assert_eq!(status, 400);
    assert_eq!(json["code"], BusinessCode::BanFailed.raw());
    assert_eq!(
        json["data"],
        serde_json::Value::Null,
        "失败时 data 必须为 null"
    );
    assert_eq!(json["message"], "内核未确认");
}

#[tokio::test]
async fn an_invalid_ip_never_reaches_the_kernel() {
    let h = Harness::new();
    let response = handle_create_ban(
        State(Arc::clone(&h.api)),
        Json(CreateBanRequest {
            ip: "not-an-ip".to_string(),
            duration: None,
            reason: None,
        }),
    )
    .await;
    let (status, json) = response_parts(response).await;
    assert_eq!(status, 400);
    assert_eq!(json["code"], BusinessCode::BanFailed.raw());
    assert!(
        h.control.bans.lock().expect("锁未中毒").is_empty(),
        "IP 非法时不得下发到内核"
    );
}

#[tokio::test]
async fn a_failed_unban_lands_on_code_40002() {
    let h = Harness::new();
    *h.control.unban_error.lock().expect("锁未中毒") = Some("内核拒绝".to_string());
    let response = handle_delete_ban(State(Arc::clone(&h.api)), Path("10.0.0.1".to_string())).await;
    let (status, json) = response_parts(response).await;
    assert_eq!(status, 400);
    assert_eq!(json["code"], BusinessCode::UnbanFailed.raw());
}

#[tokio::test]
async fn a_missing_jail_lands_on_http_404_with_code_404() {
    let h = Harness::new();
    let response = handle_update_jail(
        State(Arc::clone(&h.api)),
        Path("absent".to_string()),
        Json(UpdateJailRequest { enabled: true }),
    )
    .await;
    let (status, json) = response_parts(response).await;
    assert_eq!(status, 404);
    assert_eq!(json["code"], BusinessCode::JailNotFound.raw());
}

#[tokio::test]
async fn an_empty_or_invalid_ban_detail_ip_lands_on_code_40006() {
    let h = Harness::new();
    let response = handle_ban_detail(State(Arc::clone(&h.api)), Path(String::new())).await;
    let (status, json) = response_parts(response).await;
    assert_eq!(status, 400);
    assert_eq!(json["code"], BusinessCode::InvalidBanDetailQuery.raw());

    let response = handle_ban_detail(State(Arc::clone(&h.api)), Path("bogus".to_string())).await;
    let (status, json) = response_parts(response).await;
    assert_eq!(status, 400);
    assert_eq!(json["code"], BusinessCode::InvalidBanDetailQuery.raw());
}

#[tokio::test]
async fn a_batch_outside_the_allowed_size_lands_on_code_40005() {
    let h = Harness::new();
    let ips: Vec<String> = (0..101).map(|i| format!("10.0.1.{i}")).collect();
    let response = handle_batch_ban(State(Arc::clone(&h.api)), Json(ips)).await;
    let (status, json) = response_parts(response).await;
    assert_eq!(status, 400);
    assert_eq!(json["code"], BusinessCode::InvalidBatchOrLogQuery.raw());

    let empty = handle_batch_ban(State(Arc::clone(&h.api)), Json(Vec::new())).await;
    let (status, json) = response_parts(empty).await;
    assert_eq!(status, 400, "空列表同样是 40005");
    assert_eq!(json["code"], BusinessCode::InvalidBatchOrLogQuery.raw());
}

/// 批量封禁必须是**限时**封禁。
///
/// 回归：端口重写时把 `duration` 写成了 `None`，而 `None` 在真实控制面里等于
/// 永久封禁（`create_ban` 的判定），于是「选中一批 IP 批量封禁」会在用户以为
/// 只封 1 小时的情况下把对方永久封掉。前端两处文案承诺 3600 秒。
#[tokio::test]
async fn a_batch_ban_is_time_limited_not_permanent() {
    let h = Harness::new();
    let ips: Vec<String> = (1..=3).map(|i| format!("10.0.2.{i}")).collect();
    let response = handle_batch_ban(State(Arc::clone(&h.api)), Json(ips)).await;
    let (status, json) = response_parts(response).await;
    assert_eq!(status, 201);
    assert_eq!(json["data"]["succeeded"], 3);

    let sent = h.control.bans.lock().expect("锁未中毒").clone();
    assert_eq!(sent.len(), 3, "三条 IP 都要真的下发");
    for cmd in &sent {
        assert_eq!(
            cmd.duration,
            Some(3600),
            "批量封禁必须带 3600 秒时长；None 会被判成永久封禁"
        );
        assert_eq!(cmd.reason.as_deref(), Some("批量封禁"));
    }
}

#[tokio::test]
async fn a_config_error_lands_on_code_40004() {
    let h = Harness::new();
    *h.config.apply_error.lock().expect("锁未中毒") =
        Some("速率警告阈值必须小于严重阈值".to_string());
    let response = handle_update_config(
        State(Arc::clone(&h.api)),
        Json(UpdateConfigRequest::default()),
    )
    .await;
    let (status, json) = response_parts(response).await;
    assert_eq!(status, 400);
    assert_eq!(
        json["code"],
        BusinessCode::ConfigOrWhitelistRemoveFailed.raw()
    );
}

#[tokio::test]
async fn a_bad_cidr_on_add_lands_on_code_40003_and_on_remove_lands_on_40004() {
    let h = Harness::new();
    let response = handle_create_whitelist(
        State(Arc::clone(&h.api)),
        Json(CreateWhitelistRequest {
            cidr: String::new(),
        }),
    )
    .await;
    let (status, json) = response_parts(response).await;
    assert_eq!(status, 400);
    assert_eq!(json["code"], BusinessCode::BatchOrWhitelistAddFailed.raw());

    let response = handle_delete_whitelist(State(Arc::clone(&h.api)), Path(String::new())).await;
    let (status, json) = response_parts(response).await;
    assert_eq!(status, 400);
    assert_eq!(
        json["code"],
        BusinessCode::ConfigOrWhitelistRemoveFailed.raw()
    );
}

// ============================================================================
// 成功路径
// ============================================================================

#[tokio::test]
async fn a_successful_ban_returns_201_and_the_operation_shape() {
    let h = Harness::new();
    let response = handle_create_ban(
        State(Arc::clone(&h.api)),
        Json(CreateBanRequest {
            ip: "10.0.0.1".to_string(),
            duration: Some(600),
            reason: None,
        }),
    )
    .await;
    let (status, json) = response_parts(response).await;
    assert_eq!(status, 201);
    assert_eq!(json["code"], 0);
    assert_eq!(json["message"], "", "成功时 message 必须是空串");
    assert_eq!(json["data"]["action"], "ban");
    assert_eq!(json["data"]["duration_seconds"], 600);
    assert_eq!(
        h.control.bans.lock().expect("锁未中毒").len(),
        1,
        "指令应已下发"
    );
}

#[tokio::test]
async fn a_permanent_ban_carries_no_duration() {
    let h = Harness::new();
    let response = handle_create_ban(
        State(Arc::clone(&h.api)),
        Json(CreateBanRequest {
            ip: "10.0.0.1".to_string(),
            duration: Some(0),
            reason: None,
        }),
    )
    .await;
    let (_, json) = response_parts(response).await;
    assert_eq!(json["data"]["permanent"], true);
    assert!(json["data"]["duration_seconds"].is_null());
}

#[tokio::test]
async fn a_whitelist_add_echoes_the_normalized_cidr() {
    // 前端用 GET 拿到的字符串可以原样交给 DELETE，故 POST 的返回值必须是
    // 规范化后的形态（缺陷 M 的对外可见面）。
    let h = Harness::new();
    let response = handle_create_whitelist(
        State(Arc::clone(&h.api)),
        Json(CreateWhitelistRequest {
            cidr: "10.0.0.5/24".to_string(),
        }),
    )
    .await;
    let (status, json) = response_parts(response).await;
    assert_eq!(status, 201);
    assert_eq!(json["data"]["cidr"], "10.0.0.0/24", "必须回传规范化结果");
    assert_eq!(json["data"]["action"], "add");
}

#[tokio::test]
async fn the_whitelist_list_exposes_normalized_cidrs() {
    let h = Harness::new();
    h.state
        .whitelist()
        .insert(CidrKey::parse("10.0.0.5/24").expect("合法 CIDR"), "eth0");
    let json = serde_json::to_value(handle_api_whitelist(State(Arc::clone(&h.api))).await.0)
        .expect("可序列化");
    assert_eq!(json["data"][0]["cidr"], "10.0.0.0/24");
    assert_eq!(json["data"][0]["device"], "eth0");
}

#[tokio::test]
async fn the_jail_list_takes_its_ban_count_from_the_state_owner() {
    let h = Harness::new().with_jail("sshd");
    seed_ban(&h, "10.0.0.1", "sshd", 100, 200);
    seed_ban(&h, "10.0.0.2", "sshd", 100, 200);
    seed_ban(&h, "10.0.0.3", "nginx", 100, 200);

    let json = serde_json::to_value(handle_api_jails(State(Arc::clone(&h.api))).await.0)
        .expect("可序列化");
    assert_eq!(json["data"][0]["name"], "sshd");
    assert_eq!(
        json["data"][0]["ban_count"], 2,
        "jail 的封禁数必须来自 state 所有者"
    );
}

#[tokio::test]
async fn the_stats_counter_fields_come_from_the_state_owner() {
    let h = Harness::new();
    h.state.stats().add(crate::state::Counter::IpsBanned, 7);
    h.state.stats().add(crate::state::Counter::TotalUnbans, 3);
    h.state
        .stats()
        .add(crate::state::Counter::PacketsDropped, 11);

    let json = serde_json::to_value(handle_api_stats(State(Arc::clone(&h.api))).await.0)
        .expect("可序列化");
    assert_eq!(json["data"]["total_bans"], 7);
    assert_eq!(json["data"]["total_unbans"], 3);
    assert_eq!(json["data"]["packets_dropped"], 11);
}

#[tokio::test]
async fn the_stats_whitelist_count_comes_from_the_whitelist_owner() {
    // 旧实现另有一枚近似计数值，与白名单表迟早漂移；新实现只认所有者。
    let h = Harness::new();
    h.state
        .whitelist()
        .insert(CidrKey::parse("10.0.0.0/24").expect("合法 CIDR"), "");
    h.state
        .whitelist()
        .insert(CidrKey::parse("10.0.1.0/24").expect("合法 CIDR"), "");
    // 同时把计数器拨到别的数：它不该被采纳。
    h.state.stats().add(crate::state::Counter::IpsExtracted, 99);

    let json = serde_json::to_value(handle_api_stats(State(Arc::clone(&h.api))).await.0)
        .expect("可序列化");
    assert_eq!(
        json["data"]["whitelist_count"], 2,
        "白名单数必须来自白名单所有者，而不是计数器"
    );
}

#[tokio::test]
async fn the_statistics_read_does_not_advance_any_version() {
    let h = Harness::new();
    h.state.bans().insert(BanEntry::new(
        ip("10.0.0.1"),
        "sshd",
        "r",
        100,
        200,
        false,
        1,
        5,
    ));
    let before = h.state.hub().versions();
    let _ = handle_api_stats(State(Arc::clone(&h.api))).await;
    assert_eq!(h.state.hub().versions(), before);
    assert_eq!(h.state.hub().versions().get(Domain::Stats), 0);
}
