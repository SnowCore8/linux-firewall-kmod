//! 页面顶栏 — 标题 / 副标题 / 操作区

use leptos::*;

#[component]
pub fn PageHeader(
    #[prop(into)]
    title: String,
    #[prop(into, optional)]
    subtitle: String,
    #[prop(optional)]
    children: Option<Children>,
) -> impl IntoView {
    let show_sub = !subtitle.is_empty();
    view! {
        <header class="page-header">
            <div class="page-header-text">
                <h1 class="page-title">{title}</h1>
                {show_sub.then(|| view! {
                    <p class="page-subtitle">{subtitle.clone()}</p>
                })}
            </div>
            {children.map(|c| view! {
                <div class="page-actions">{c()}</div>
            })}
        </header>
    }
}
