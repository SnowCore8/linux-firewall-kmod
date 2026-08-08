//! 空态 — 统一无 emoji 占位

use leptos::*;

/// 页面/区块空态
#[component]
pub fn EmptyState(
    /// 主标题
    #[prop(into)]
    title: String,
    /// 说明（可为空）
    #[prop(into, optional)]
    hint: String,
    /// 可选自定义图标（SVG view）
    #[prop(optional)]
    children: Option<Children>,
) -> impl IntoView {
    let show_hint = !hint.is_empty();
    view! {
        <div class="empty-state" role="status">
            <div class="empty-state-icon" aria-hidden="true">
                {match children {
                    Some(c) => c().into_view(),
                    None => view! {
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                            <rect x="3" y="3" width="18" height="18" rx="1"/>
                            <path d="M8 12h8M12 8v8"/>
                        </svg>
                    }.into_view(),
                }}
            </div>
            <h3 class="empty-state-title">{title}</h3>
            {show_hint.then(|| view! {
                <p class="empty-state-hint">{hint.clone()}</p>
            })}
        </div>
    }
}
