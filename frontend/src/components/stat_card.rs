//! 统计卡片组件 — 支持迷你图趋势线

use leptos::*;

#[component]
pub fn StatCard(
    label: &'static str,
    value: Signal<String>,
    accent: &'static str,
    #[prop(optional)] trend: Signal<Vec<f64>>,
) -> impl IntoView {
    let accent_color = match accent {
        "danger" => "var(--accent-danger)",
        "primary" => "var(--accent-primary)",
        "warning" => "var(--accent-warning)",
        "purple" => "var(--accent-purple)",
        "success" => "var(--accent-success)",
        "info" => "var(--accent-info)",
        _ => "var(--accent-primary)",
    };

    let accent_dim = match accent {
        "danger" => "var(--accent-danger-dim)",
        "primary" => "var(--accent-primary-dim)",
        "warning" => "var(--accent-warning-dim)",
        "purple" => "var(--accent-purple-dim)",
        "success" => "var(--accent-success-dim)",
        "info" => "var(--accent-info-dim)",
        _ => "var(--accent-primary-dim)",
    };

    let sparkline = move || {
        let data = trend.get();
        if data.len() < 2 {
            return view! { <div class="stat-spark-placeholder"/> }.into_view();
        }
        let width = 80.0_f64;
        let height = 24.0_f64;
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

        view! {
            <svg width="80" height="24" viewBox="0 0 80 24" class="stat-spark">
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
                <div class="stat-card-icon" style=move || format!("background:{};color:{}", accent_dim, accent_color)/>
                <span class="stat-card-label">{label}</span>
            </div>
            <div class="stat-card-value mono">{value}</div>
            <div class="stat-card-footer">{sparkline}</div>
        </div>
    }
}
