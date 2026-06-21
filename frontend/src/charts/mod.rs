//! SVG 图表组件 — 纯 Rust 实现，无外部依赖

use leptos::*;

// ============================================================================
// 折线图
// ============================================================================

#[component]
pub fn LineChart(
    labels: Signal<Vec<String>>,
    data: Signal<Vec<u64>>,
    #[prop(default = "var(--accent-primary)")] color: &'static str,
    #[prop(default = 280)] height: u32,
) -> impl IntoView {
    let width = 600.0_f64;
    let height_f = height as f64;
    let pad_left = 50.0_f64;
    let pad_bottom = 28.0_f64;
    let pad_top = 10.0_f64;
    let pad_right = 16.0_f64;
    let chart_w = width - pad_left - pad_right;
    let chart_h = height_f - pad_top - pad_bottom;

    let path_data = move || {
        let d = data.get();
        if d.is_empty() {
            return (String::new(), String::new(), Vec::new());
        }
        let max_val = d.iter().cloned().max().unwrap_or(1).max(1) as f64;
        let step = if d.len() > 1 {
            chart_w / (d.len() - 1) as f64
        } else {
            chart_w
        };

        let points: Vec<(f64, f64)> = d
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let x = pad_left + i as f64 * step;
                let y = pad_top + chart_h - (v as f64 / max_val) * chart_h;
                (x, y)
            })
            .collect();

        let line: String = points
            .iter()
            .enumerate()
            .map(|(i, &(x, y))| {
                if i == 0 {
                    format!("M{x:.1},{y:.1}")
                } else {
                    format!("L{x:.1},{y:.1}")
                }
            })
            .collect();

        let area = format!(
            "{}L{:.1},{:.1}L{:.1},{:.1}Z",
            line,
            points.last().map(|p| p.0).unwrap_or(pad_left),
            pad_top + chart_h,
            pad_left,
            pad_top + chart_h
        );

        // Y 轴刻度
        let grid_lines = (0..=4)
            .map(|i| {
                let y = pad_top + chart_h * (1.0 - i as f64 / 4.0);
                let val = (max_val * i as f64 / 4.0) as u64;
                (y, val)
            })
            .collect();

        (line, area, grid_lines)
    };

    let x_labels = move || {
        let l = labels.get();
        if l.is_empty() {
            return Vec::new();
        }
        let step = if l.len() > 1 {
            chart_w / (l.len() - 1) as f64
        } else {
            0.0
        };
        let max_labels = 8;
        let skip = (l.len() / max_labels).max(1);
        l.iter()
            .enumerate()
            .filter(|(i, _)| i % skip == 0)
            .map(|(i, label)| {
                let x = pad_left + i as f64 * step;
                (x, label.clone())
            })
            .collect()
    };

    view! {
        <svg viewBox=move || format!("0 0 {width} {height_f}") preserveAspectRatio="xMidYMid meet" style="width:100%;height:100%">
            // 网格线
            <For
                each=move || {
                    let (_, _, grid) = path_data();
                    grid
                }
                key=|(y, _)| format!("{y:.0}")
                children=move |(y, val)| {
                    let label = if val >= 1_000_000 {
                        format!("{:.1}M", val as f64 / 1_000_000.0)
                    } else if val >= 1_000 {
                        format!("{:.0}K", val as f64 / 1_000.0)
                    } else {
                        val.to_string()
                    };
                    view! {
                        <g>
                            <line x1=pad_left y1=y x2=width - pad_right y2=y
                                stroke="var(--border-subtle)" stroke-width="1"/>
                            <text x=pad_left - 6.0 y=y + 3.0
                                text-anchor="end" fill="var(--text-muted)"
                                font-size="10" font-family="var(--font-mono)">{label}</text>
                        </g>
                    }
                }
            />

            // 面积填充
            <path d=move || path_data().1
                fill=color
                opacity="0.08"/>

            // 折线
            <path d=move || path_data().0
                fill="none" stroke=color stroke-width="2"
                stroke-linecap="round" stroke-linejoin="round"/>

            // X 轴标签
            <For
                each=move || x_labels()
                key=|(x, label)| format!("{x:.0}-{label}")
                children=move |(x, label)| {
                    view! {
                        <text x=x y=height_f - 6.0
                            text-anchor="middle" fill="var(--text-muted)"
                            font-size="10" font-family="var(--font-mono)">{label}</text>
                    }
                }
            />
        </svg>
    }
}

// ============================================================================
// 饼图（环形）
// ============================================================================

#[component]
pub fn PieChart(
    labels: Signal<Vec<String>>,
    data: Signal<Vec<u64>>,
    #[prop(default = 200)] size: u32,
) -> impl IntoView {
    let center = size as f64 / 2.0;
    let outer_r = size as f64 * 0.39;
    let inner_r = size as f64 * 0.275;

    const COLORS: &[&str] = &[
        "#3b82f6", "#22c55e", "#f59e0b", "#ef4444", "#a855f7", "#06b6d4",
    ];

    let slices = move || {
        let d = data.get();
        let l = labels.get();
        let total: u64 = d.iter().sum();
        if total == 0 {
            return Vec::new();
        }

        let mut start_angle = -90.0_f64;
        d.iter()
            .zip(l.iter())
            .enumerate()
            .filter(|(_, (&v, _))| v > 0)
            .map(|(i, (&v, label))| {
                let angle = v as f64 / total as f64 * 360.0;
                let end_angle = start_angle + angle;
                let path = arc_path(center, center, outer_r, inner_r, start_angle, end_angle);
                let color = COLORS[i % COLORS.len()].to_string();
                let pct = format!("{:.1}%", v as f64 / total as f64 * 100.0);
                start_angle = end_angle;
                (path, color, label.clone(), pct)
            })
            .collect()
    };

    view! {
        <div style=move || format!("display:flex;align-items:center;gap:16px")>
            <svg width=size height=size viewBox=move || format!("0 0 {size} {size}")>
                <For
                    each=move || slices()
                    key=|(_, color, label, _)| format!("{color}-{label}")
                    children=move |(path, color, _, _)| {
                        view! {
                            <path d=path fill=color
                                stroke="var(--bg-card)" stroke-width="2"/>
                        }
                    }
                />
            </svg>

            <div style="display:flex;flex-direction:column;gap:6px">
                <For
                    each=move || {
                        let d = data.get();
                        let l = labels.get();
                        let total: u64 = d.iter().sum();
                        l.into_iter()
                            .zip(d.into_iter())
                            .enumerate()
                            .filter(|(_, (_, v))| *v > 0)
                            .map(|(i, (label, v))| {
                                let color = COLORS[i % COLORS.len()].to_string();
                                let pct = if total > 0 {
                                    format!("{:.1}%", v as f64 / total as f64 * 100.0)
                                } else {
                                    "0%".to_string()
                                };
                                (color, label, v, pct)
                            })
                            .collect::<Vec<_>>()
                    }
                    key=|(_, label, _, _)| label.clone()
                    children=move |(color, label, _v, pct)| {
                        view! {
                            <div style="display:flex;align-items:center;gap:6px;font-size:11px">
                                <span style=move || format!("width:8px;height:8px;border-radius:2px;background:{color};flex-shrink:0")/>
                                <span style="color:var(--text-secondary)">{label}</span>
                                <span style="color:var(--text-muted);font-family:var(--font-mono)">{pct}</span>
                            </div>
                        }
                    }
                />
            </div>
        </div>
    }
}

/// 计算环形扇区的 SVG path
fn arc_path(cx: f64, cy: f64, outer_r: f64, inner_r: f64, start_deg: f64, end_deg: f64) -> String {
    let start_rad = start_deg.to_radians();
    let end_rad = end_deg.to_radians();

    let x1 = cx + outer_r * start_rad.cos();
    let y1 = cy + outer_r * start_rad.sin();
    let x2 = cx + outer_r * end_rad.cos();
    let y2 = cy + outer_r * end_rad.sin();
    let x3 = cx + inner_r * end_rad.cos();
    let y3 = cy + inner_r * end_rad.sin();
    let x4 = cx + inner_r * start_rad.cos();
    let y4 = cy + inner_r * start_rad.sin();

    let large = if (end_deg - start_deg) > 180.0 { 1 } else { 0 };

    format!(
        "M{x1:.2},{y1:.2} A{outer_r:.2},{outer_r:.2} 0 {large} 1 {x2:.2},{y2:.2} \
         L{x3:.2},{y3:.2} A{inner_r:.2},{inner_r:.2} 0 {large} 0 {x4:.2},{y4:.2} Z"
    )
}
