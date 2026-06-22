//! 统计卡片组件 — 安全产品风格（发光边框 + 大数值 + 迷你图）

use leptos::*;

#[component]
pub fn StatCard(
    label: &'static str,
    value: Signal<String>,
    accent: &'static str,
    #[prop(optional)] trend: Signal<Vec<f64>>,
) -> impl IntoView {
    let accent_color = match accent {
        "danger" => "var(--color-red)",
        "primary" => "var(--color-cyan)",
        "warning" => "var(--color-orange)",
        "purple" => "var(--color-purple)",
        "success" => "var(--color-green)",
        "info" => "var(--color-blue)",
        _ => "var(--color-cyan)",
    };

    let accent_dim = match accent {
        "danger" => "var(--color-red-dim)",
        "primary" => "var(--color-cyan-dim)",
        "warning" => "var(--color-orange-dim)",
        "purple" => "var(--color-purple-dim)",
        "success" => "var(--color-green-dim)",
        "info" => "var(--color-blue-dim)",
        _ => "var(--color-cyan-dim)",
    };

    let icon_view = match accent {
        "danger" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <circle cx="12" cy="12" r="10"/><path d="M4.93 4.93l14.14 14.14"/>
            </svg>
        }.into_view(),
        "primary" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
            </svg>
        }.into_view(),
        "warning" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
        }.into_view(),
        "purple" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
            </svg>
        }.into_view(),
        "success" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
            </svg>
        }.into_view(),
        "info" => view! {
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="10"/>
            </svg>
        }.into_view(),
        _ => view! { <div/> }.into_view(),
    };

    let sparkline = move || {
        let data = trend.get();
        if data.len() < 2 {
            return view! { <div class="stat-spark-placeholder"/> }.into_view();
        }
        let width = 80.0_f64;
        let height = 18.0_f64;
        let min = data.iter().cloned().fold(f64::MAX, f64::min);
        let max = data.iter().cloned().fold(f64::MIN, f64::max);
        let range = max - min;
        let step = width / (data.len() - 1) as f64;

        let points: Vec<String> = data
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let x = i as f64 * step;
                let y = if range > 0.0 {
                    height - ((v - min) / range) * height
                } else {
                    height / 2.0
                };
                format!("{x:.1},{y:.1}")
            })
            .collect();
        let polyline = points.join(" ");

        let area = format!("{polyline} {width:.1},{height:.1} 0,{height:.1}");

        view! {
            <svg width="80" height="18" viewBox="0 0 80 18" class="stat-spark">
                <polygon points=area fill=accent_color opacity="0.06"/>
                <polyline
                    points=polyline
                    fill="none"
                    stroke=accent_color
                    stroke-width="1.5"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                />
            </svg>
        }
        .into_view()
    };

    let card_style = move || {
        format!(
            "--card-accent:{};--card-accent-dim:{}",
            accent_color, accent_dim
        )
    };

    view! {
        <div class="stat-card" style=card_style>
            <div class="stat-card-header">
                <div class="stat-card-icon"
                    style=move || format!("background:{};color:{}", accent_dim, accent_color)>
                    {icon_view}
                </div>
                <span class="stat-card-label">{label}</span>
            </div>
            <div class="stat-card-value">{value}</div>
            <div class="stat-card-footer">{sparkline}</div>
        </div>
    }
}
