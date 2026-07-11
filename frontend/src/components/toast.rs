//! Toast 通知系统 — 全局操作反馈
//!
//! 通过 `ToastState` context 在任意组件中显示操作结果通知。
//! 通知自动 3 秒后消失，支持 success/error/info 三种类型。

use leptos::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// Toast 类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ToastType {
    Success,
    Error,
    Info,
}

impl ToastType {
    pub fn css_class(self) -> &'static str {
        match self {
            Self::Success => "toast-success",
            Self::Error => "toast-error",
            Self::Info => "toast-info",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Self::Success => "✓",
            Self::Error => "✕",
            Self::Info => "ℹ",
        }
    }
}

/// 单条 Toast 通知
#[derive(Debug, Clone)]
pub struct ToastItem {
    pub id: u64,
    pub message: String,
    pub toast_type: ToastType,
}

/// 全局 Toast 状态 — 通过 Leptos context 共享
#[derive(Debug, Clone, Copy)]
pub struct ToastState {
    toasts: RwSignal<Vec<ToastItem>>,
}

/// 全局 ID 生成器
static TOAST_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

impl ToastState {
    /// 创建新的 Toast 状态
    pub fn new() -> Self {
        Self {
            toasts: create_rw_signal(Vec::new()),
        }
    }

    /// 显示一条 Toast 通知（自动 3 秒后消失）
    pub fn show(&self, message: impl Into<String>, toast_type: ToastType) {
        let id = TOAST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let item = ToastItem {
            id,
            message: message.into(),
            toast_type,
        };

        self.toasts.update(|list| list.push(item));

        // 3 秒后自动移除
        let toasts = self.toasts;
        set_timeout(
            move || {
                toasts.update(|list| list.retain(|t| t.id != id));
            },
            std::time::Duration::from_secs(3),
        );
    }

    /// 显示成功通知
    pub fn success(&self, message: impl Into<String>) {
        self.show(message, ToastType::Success);
    }

    /// 显示错误通知
    pub fn error(&self, message: impl Into<String>) {
        self.show(message, ToastType::Error);
    }

    /// 显示信息通知
    #[allow(dead_code)]
    pub fn info(&self, message: impl Into<String>) {
        self.show(message, ToastType::Info);
    }

    /// 手动关闭一条 Toast
    pub fn dismiss(&self, id: u64) {
        self.toasts.update(|list| list.retain(|t| t.id != id));
    }

    /// 获取 Toast 列表信号（供 ToastContainer 使用）
    pub fn signal(&self) -> RwSignal<Vec<ToastItem>> {
        self.toasts
    }
}

impl Default for ToastState {
    fn default() -> Self {
        Self::new()
    }
}

/// Toast 容器组件 — 渲染在页面右上角
#[component]
pub fn ToastContainer() -> impl IntoView {
    let state = use_context::<ToastState>()
        .expect("ToastState context not found — 必须在顶层 provide_context");

    // 最多显示 5 条，取最新的 5 条
    let visible_toasts = move || {
        let all = state.signal().get();
        let len = all.len();
        if len <= 5 {
            all
        } else {
            all[len - 5..].to_vec()
        }
    };

    view! {
        <div class="toast-container" role="region" aria-live="polite" aria-label="操作通知">
            <For
                each=visible_toasts
                key=|item| item.id
                children=move |item| {
                    let item_id = item.id;
                    let dismiss_state = state;
                    view! {
                        <div class=format!("toast-item {}", item.toast_type.css_class())
                            role="alert"
                            aria-atomic="true">
                            <span class="toast-icon" aria-hidden="true">{item.toast_type.icon()}</span>
                            <span class="toast-message">{item.message.clone()}</span>
                            <button class="toast-close"
                                aria-label="关闭"
                                on:click=move |_| dismiss_state.dismiss(item_id)>
                                "✕"
                            </button>
                        </div>
                    }
                }
            />
        </div>
    }
}
