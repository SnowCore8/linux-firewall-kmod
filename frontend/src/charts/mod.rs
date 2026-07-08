//! SVG 图表组件 — 安全产品风格（固定结构，无数据时叠加提示）

use leptos::*;
use std::cell::Cell;

// 全局图表 ID 计数器，确保每个图表实例的 SVG gradient/filter ID 唯一
thread_local! {
    static CHART_COUNTER: Cell<u32> = const { Cell::new(0) };
}

fn next_chart_id() -> String {
    let id = CHART_COUNTER.with(|c| {
        let v = c.get();
        c.set(v + 1);
        v
    });
    format!("chart-{id}")
}

// ============================================================================
// 折线图 — 始终渲染固定结构
// ============================================================================

#[component]
pub fn LineChart(
    labels: Signal<Vec<String>>,
    data: Signal<Vec<u64>>,
    #[prop(default = "var(--color-cyan)")] color: &'static str,
    #[prop(default = 160)] height: u32,
) -> impl IntoView {
    let width = 600.0_f64;
    let height_f = height as f64;
    let pad_left = 48.0_f64;
    let pad_bottom = 26.0_f64;
    let pad_top = 8.0_f64;
    let pad_right = 12.0_f64;
    let chart_w = width - pad_left - pad_right;
    let chart_h = height_f - pad_top - pad_bottom;

    let chart_id = next_chart_id();

    let path_data = move || {
        let d = data.get();
        if d.is_empty() {
            return (String::new(), String::new(), Vec::new(), None);
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

        let last_point = points.last().copied();

        let grid_lines = (0..=4)
            .map(|i| {
                let y = pad_top + chart_h * (1.0 - i as f64 / 4.0);
                let val_f = max_val * i as f64 / 4.0;
                // 小数值使用浮点精度，避免整除为 0
                let val = if max_val < 10.0 {
                    val_f
                } else {
                    val_f as u64 as f64
                };
                (y, val)
            })
            .collect();

        (line, area, grid_lines, last_point)
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
        let max_labels = 7;

        // 去重:保留每个标签首次出现的索引
        let mut seen = std::collections::HashSet::new();
        let mut unique_indices: Vec<usize> = Vec::new();
        for (i, label) in l.iter().enumerate() {
            if seen.insert(label.as_str()) {
                unique_indices.push(i);
            }
        }

        // 均匀采样去重后的标签
        let skip = if unique_indices.len() > max_labels {
            (unique_indices.len() / max_labels).max(1)
        } else {
            1
        };

        unique_indices
            .into_iter()
            .enumerate()
            .filter(|(i, _)| i % skip == 0)
            .map(|(_, idx)| {
                let x = pad_left + idx as f64 * step;
                (x, l[idx].clone())
            })
            .collect()
    };

    let has_data = move || !data.get().is_empty();

    view! {
        <svg viewBox=move || format!("0 0 {width} {height_f}") preserveAspectRatio="none" style="width:100%;height:100%">
            <defs>
                <linearGradient id=chart_id.clone() x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color=color stop-opacity="0.25"/>
                    <stop offset="100%" stop-color=color stop-opacity="0.02"/>
                </linearGradient>
                <filter id=format!("glow-{}", chart_id)>
                    <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
                    <feMerge>
                        <feMergeNode in="coloredBlur"/>
                        <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                </filter>
            </defs>

            // 网格线（始终渲染，Y 轴标签跟随数据动态更新）
            <g>
                {(0..=4).map(|i| {
                    let grid_y = pad_top + chart_h * (1.0 - i as f64 / 4.0);
                    let grid_val = move || {
                        let d = data.get();
                        if d.is_empty() { return 0.0_f64; }
                        let max_val = d.iter().cloned().max().unwrap_or(1).max(1) as f64;
                        let v = max_val * i as f64 / 4.0;
                        if max_val < 10.0 { v } else { v as u64 as f64 }
                    };
                    let label = move || {
                        let v = grid_val();
                        if v >= 1_000_000.0 {
                            format!("{:.1}M", v / 1_000_000.0)
                        } else if v >= 1_000.0 {
                            format!("{:.0}K", v / 1_000.0)
                        } else if v >= 10.0 {
                            format!("{:.0}", v)
                        } else {
                            format!("{:.1}", v)
                        }
                    };
                    view! {
                        <g>
                            <line x1=pad_left y1=grid_y x2=width - pad_right y2=grid_y
                                stroke="var(--border-subtle)" stroke-width="1"/>
                            <text x=pad_left - 6.0 y=grid_y + 3.0
                                text-anchor="end" fill="var(--text-faint)"
                                font-size="9" font-family="var(--font-mono)">{label}</text>
                        </g>
                    }
                }).collect::<Vec<_>>()}
            </g>

            // 数据图表（有数据时渲染，无数据时不渲染但保持 SVG 结构）
            <Show
                when=has_data
                fallback=|| ()
            >
                <path d=move || path_data().1
                    fill=format!("url(#{})", chart_id)/>

                <path d=move || path_data().0
                    fill="none" stroke=color stroke-width="2"
                    stroke-linecap="round" stroke-linejoin="round"
                    filter=format!("url(#glow-{})", chart_id)/>

                {move || {
                    let (_, _, _, last) = path_data();
                    if let Some((x, y)) = last {
                        view! {
                            <g>
                                <circle cx=x cy=y r="5" fill=color opacity="0.15"/>
                                <circle cx=x cy=y r="3" fill=color/>
                            </g>
                        }.into_view()
                    } else {
                        view! { <g/> }.into_view()
                    }
                }}

                <For
                    each=move || x_labels()
                    key=|(x, label)| format!("{x:.0}-{label}")
                    children=move |(x, label)| {
                        view! {
                            <text x=x y=height_f - 4.0
                                text-anchor="middle" fill="var(--text-faint)"
                                font-size="9" font-family="var(--font-mono)">{label}</text>
                        }
                    }
                />
            </Show>

            // 无数据提示（叠加在网格上，不切换 DOM）
            <Show
                when=move || !has_data()
                fallback=|| ()
            >
                <text x=width / 2.0 y=height_f / 2.0
                    text-anchor="middle" fill="var(--text-faint)"
                    font-size="12" font-family="var(--font-sans)"
                    font-weight="500" letter-spacing="0.1em">
                    "NO DATA"
                </text>
            </Show>
        </svg>
    }
}

// ============================================================================
// 饼图（环形）— 始终渲染固定结构
// ============================================================================

#[component]
pub fn PieChart(
    labels: Signal<Vec<String>>,
    data: Signal<Vec<u64>>,
    #[prop(default = 160)] size: u32,
) -> impl IntoView {
    let center = size as f64 / 2.0;
    let outer_r = size as f64 * 0.38;
    let inner_r = size as f64 * 0.26;

    const COLORS: &[&str] = &[
        "#00f0ff", "#00ff88", "#ff8800", "#ff0040", "#b000ff", "#0088ff",
    ];

    let slices = move || {
        let d = data.get();
        let l = labels.get();
        let total: u64 = d.iter().sum();
        if total == 0 {
            return Vec::new();
        }

        // 统计非零值数量
        let non_zero: Vec<(usize, u64, &String)> = d
            .iter()
            .zip(l.iter())
            .enumerate()
            .filter(|(_, (&v, _))| v > 0)
            .map(|(i, (&v, label))| (i, v, label))
            .collect();

        // 如果只有一个非零值,画一个完整的圆
        if non_zero.len() == 1 {
            let (i, v, label) = non_zero[0];
            let color = COLORS[i % COLORS.len()].to_string();
            let pct = format!("{:.1}%", v as f64 / total as f64 * 100.0);
            // 用两个 180° 半圆拼接成完整圆
            let path = format!(
                "M{cx},{top} A{r},{r} 0 0 1 {cx},{bottom} A{r},{r} 0 0 1 {cx},{top} \
                 M{cx},{top2} A{r2},{r2} 0 0 0 {cx},{bottom2} A{r2},{r2} 0 0 0 {cx},{top2} Z",
                cx = center,
                top = center - outer_r,
                bottom = center + outer_r,
                r = outer_r,
                top2 = center - inner_r,
                bottom2 = center + inner_r,
                r2 = inner_r,
            );
            return vec![(path, color, label.clone(), pct)];
        }

        let mut start_angle = -90.0_f64;
        non_zero
            .iter()
            .map(|&(i, v, label)| {
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

    let total_display = move || {
        let d = data.get();
        let total: u64 = d.iter().sum();
        if total >= 1_000_000 {
            format!("{:.1}M", total as f64 / 1_000_000.0)
        } else if total >= 1_000 {
            format!("{:.0}K", total as f64 / 1_000.0)
        } else {
            total.to_string()
        }
    };

    let has_data = move || !data.get().is_empty() && data.get().iter().sum::<u64>() > 0;

    // 始终渲染所有图例（包括 0 值）
    let legend_items = move || {
        let d = data.get();
        let l = labels.get();
        let total: u64 = d.iter().sum();
        l.into_iter()
            .zip(d)
            .enumerate()
            .map(|(i, (label, v))| {
                let color = COLORS[i % COLORS.len()].to_string();
                let pct = if total > 0 {
                    format!("{:.1}%", v as f64 / total as f64 * 100.0)
                } else {
                    "0.0%".to_string()
                };
                (color, label, v, pct)
            })
            .collect::<Vec<_>>()
    };

    view! {
        <div style="display:flex;align-items:center;gap:20px;height:100%;min-height:120px">
            <svg width=size height=size viewBox=move || format!("0 0 {size} {size}")>
                // 饼图扇区（有数据时渲染）
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

                // 中心文字（始终渲染，无数据时显示 NO DATA）
                <Show
                    when=has_data
                    fallback=move || view! {
                        <text x=center y=center
                            text-anchor="middle" fill="var(--text-faint)"
                            font-size="11" font-family="var(--font-sans)"
                            font-weight="500" letter-spacing="0.1em">
                            "NO DATA"
                        </text>
                    }
                >
                    <text x=center y=center - 4.0
                        text-anchor="middle" fill="var(--text-primary)"
                        font-size="16" font-weight="800" font-family="var(--font-mono)">
                        {total_display}
                    </text>
                    <text x=center y=center + 12.0
                        text-anchor="middle" fill="var(--text-muted)"
                        font-size="9" font-family="var(--font-sans)">
                        "TOTAL"
                    </text>
                </Show>
            </svg>

            // 图例（始终渲染固定结构，无数据时为空但保持高度）
            <div style="display:flex;flex-direction:column;gap:8px;min-height:80px;justify-content:center">
                <For
                    each=legend_items
                    key=|(_, label, _, _)| label.clone()
                    children=move |(color, label, _v, pct)| {
                        view! {
                            <div style="display:flex;align-items:center;gap:8px;font-size:11px">
                                <span style=move || format!("width:8px;height:8px;border-radius:2px;background:{color};flex-shrink:0")/>
                                <span style="color:var(--text-secondary);min-width:60px;font-weight:500">{label}</span>
                                <span style="color:var(--text-muted);font-family:var(--font-mono);font-size:10px;font-weight:600">{pct}</span>
                            </div>
                        }
                    }
                />
            </div>
        </div>
    }
}

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

// ============================================================================
// 雷达图（6 轴协议分布）— 纯 SVG
// ============================================================================

/// 6 轴协议分布雷达图
///
/// 6 个轴：SYN / UDP / ICMP / ACK / RST / FIN
/// 多边形面积表示各协议占比，颜色表示异常程度
#[component]
pub fn RadarChart(
    labels: Signal<Vec<String>>,
    data: Signal<Vec<u64>>,
    #[prop(default = 180)] size: u32,
) -> impl IntoView {
    let center = size as f64 / 2.0;
    let max_r = size as f64 * 0.36;
    let axis_count: usize = 6;

    // 计算每个轴的角度（从顶部开始顺时针）
    let angle_for = move |i: usize| -> f64 { -90.0_f64 + (i as f64 * 360.0 / axis_count as f64) };

    let point_on_axis = move |i: usize, ratio: f64| -> (f64, f64) {
        let angle = angle_for(i).to_radians();
        let r = max_r * ratio;
        (center + r * angle.cos(), center + r * angle.sin())
    };

    // 生成同心环多边形路径
    let ring_path = move |ratio: f64| -> String {
        (0..axis_count)
            .map(|i| {
                let (x, y) = point_on_axis(i, ratio);
                if i == 0 {
                    format!("M{x:.1},{y:.1}")
                } else {
                    format!("L{x:.1},{y:.1}")
                }
            })
            .collect::<Vec<_>>()
            .join("")
            + "Z"
    };

    // 数据多边形路径 + 颜色
    let data_polygon = move || {
        let d = data.get();
        let l = labels.get();
        let total: u64 = d.iter().sum();

        if total == 0 || d.len() < axis_count {
            return (String::new(), "var(--color-cyan)".to_string(), Vec::new());
        }

        let max_val = d.iter().cloned().max().unwrap_or(1).max(1) as f64;

        let points: Vec<(f64, f64, String, u64)> = d
            .iter()
            .zip(l.iter())
            .enumerate()
            .map(|(i, (&v, label))| {
                let ratio = v as f64 / max_val;
                let (x, y) = point_on_axis(i, ratio);
                (x, y, label.clone(), v)
            })
            .collect();

        let path: String = points
            .iter()
            .enumerate()
            .map(|(i, &(x, y, _, _))| {
                if i == 0 {
                    format!("M{x:.1},{y:.1}")
                } else {
                    format!("L{x:.1},{y:.1}")
                }
            })
            .collect();
        let path = path + "Z";

        // 根据主导协议决定颜色
        let dominant_idx = d
            .iter()
            .enumerate()
            .max_by_key(|(_, &v)| v)
            .map(|(i, _)| i)
            .unwrap_or(0);
        let dominant_ratio = d[dominant_idx] as f64 / total as f64;

        let color = if dominant_ratio > 0.6 {
            // 主导协议占比 >60% — 异常
            match dominant_idx {
                0 => "#ff0040", // SYN Flood
                1 => "#ff8800", // UDP Flood
                2 => "#ffdd00", // ICMP Flood
                _ => "var(--color-cyan)",
            }
        } else {
            "var(--color-cyan)" // 正常
        };

        (path, color.to_string(), points)
    };

    // 缓存 data_polygon 结果，避免在响应式闭包中重复计算
    let polygon_memo = create_memo(move |_| data_polygon());

    let has_data = move || {
        let d = data.get();
        !d.is_empty() && d.iter().sum::<u64>() > 0
    };

    // 标签和百分比
    let axis_info = move || {
        let d = data.get();
        let l = labels.get();
        let total: u64 = d.iter().sum();
        l.into_iter()
            .zip(d)
            .map(|(label, v)| {
                let pct = if total > 0 {
                    format!("{:.0}%", v as f64 / total as f64 * 100.0)
                } else {
                    "0%".to_string()
                };
                (label, v, pct)
            })
            .collect::<Vec<_>>()
    };

    view! {
        <div class="radar-chart-wrapper">
            <svg width=size height=size viewBox=move || format!("0 0 {size} {size}")>
                // 同心环网格（4 层：25%, 50%, 75%, 100%）
                <g>
                    {[0.25, 0.5, 0.75, 1.0].map(|ratio| {
                        view! {
                            <path d=ring_path(ratio)
                                fill="none" stroke="var(--border-subtle)" stroke-width="1"/>
                        }
                    }).collect_view()}
                </g>

                // 6 条轴线
                <g>
                    {(0..axis_count).map(|i| {
                        let (x, y) = point_on_axis(i, 1.0);
                        view! {
                            <line x1=center y1=center x2=x y2=y
                                stroke="var(--border-default)" stroke-width="1"
                                stroke-dasharray="2,2"/>
                        }
                    }).collect_view()}
                </g>

                // 数据多边形
                <Show when=has_data fallback=|| ()>
                    <path d=move || polygon_memo.get().0
                        fill=move || polygon_memo.get().1
                        fill-opacity="0.15"
                        stroke=move || polygon_memo.get().1
                        stroke-width="2"/>

                    // 数据顶点
                    {move || {
                        let (_, _, points) = polygon_memo.get();
                        let color = polygon_memo.get().1;
                        points.into_iter().map(move |(x, y, label, val)| {
                            let tooltip = format!("{label}: {val}");
                            let color_clone = color.clone();
                            view! {
                                <circle cx=x cy=y r="3"
                                    fill=move || color_clone.clone()
                                    stroke="var(--bg-card)" stroke-width="1">
                                    <title>{tooltip}</title>
                                </circle>
                            }
                        }).collect_view()
                    }}
                </Show>

                // 轴标签
                <g>
                    {move || {
                        let info = axis_info();
                        (0..axis_count).map(|i| {
                            let (x, y) = point_on_axis(i, 1.22);
                            let anchor = if x < center - 5.0 {
                                "end"
                            } else if x > center + 5.0 {
                                "start"
                            } else {
                                "middle"
                            };
                            let (label, _, pct) = info.get(i).cloned().unwrap_or_default();
                        view! {
                            <g>
                                <text x=x y=y
                                    text-anchor=anchor fill="var(--text-muted)"
                                    font-size="9" font-weight="700"
                                    font-family="var(--font-sans)"
                                    letter-spacing="0.05em">
                                    {label}
                                </text>
                                <text x=x y=y + 11.0
                                    text-anchor=anchor fill="var(--text-faint)"
                                    font-size="8" font-family="var(--font-mono)">
                                    {pct}
                                </text>
                            </g>
                        }
                        }).collect_view()
                    }}
                </g>

                // 无数据提示
                <Show when=move || !has_data() fallback=|| ()>
                    <text x=center y=center
                        text-anchor="middle" fill="var(--text-faint)"
                        font-size="12" font-family="var(--font-sans)"
                        font-weight="500" letter-spacing="0.1em">
                        "NO DATA"
                    </text>
                </Show>
            </svg>
        </div>
    }
}
