/**
 * 空数据占位（纯函数 + 常量）
 *
 * 用途：SSE 首帧到达前 / 首次 REST 请求返回前，视图需要一份结构完整的对象来渲染骨架，
 * 避免到处写 `stats?.today_bans ?? 0` 这类散落的空值判断。
 *
 * 关键约束：`emptyStats()` 的字段必须与后端 `StatsResponse`
 * （`src/daemon/web_ui/stats.rs`）**逐字段对齐** —— 返回类型标注为 `StatsResponse`，
 * 少了或多了字段都会在 `tsc --noEmit` 阶段报错，这是刻意的编译期保护。
 */

import type { ChartData, StatsResponse } from '../api/types'

/**
 * 空图表数据（labels/values 均为空数组）。
 *
 * 约定：本对象是**共享常量，调用方不得就地修改**（如 `EMPTY_CHART.values.push(...)`）。
 * 需要可写副本时自行构造新对象。
 */
export const EMPTY_CHART: ChartData = {
  labels: [],
  values: [],
}

/**
 * 生成空统计快照，字段与后端 `StatsResponse` 完全一致。
 * 每次调用返回新对象，避免多个视图共用同一份可变状态。
 */
export function emptyStats(): StatsResponse {
  return {
    daemon_version: '—',
    kernel_version: '—',
    today_bans: 0,
    failed_attempts: 0,
    ddos_events: 0,
    uptime_seconds: 0,
    ban_trend: { labels: [], values: [] },
    jail_distribution: { labels: [], values: [] },
    failure_reasons: { labels: [], values: [] },
    failed_attempts_trend: { labels: [], values: [] },
    current_bans: 0,
    total_bans: 0,
    total_unbans: 0,
    whitelist_count: 0,
    packets_dropped: 0,
    packets_accepted: 0,
    threat_level: {
      level: 'safe',
      score: 0,
      // 首帧提示语：让威胁等级面板在实时数据到达前也有可读内容
      factors: ['等待实时数据…'],
      current_pps: 0,
      pps_ratio: 0,
      ban_table_usage: 0,
      recent_bans: 0,
      baseline_frozen: false,
      peak_hours: false,
    },
  }
}

/**
 * 按值降序排序图表数据，值相同时按标签升序（保证渲染顺序稳定，不会每次刷新跳动）。
 * 不修改入参：返回新的 `ChartData`。
 *
 * labels 与 values 长度不一致时（理论上后端不会产生）缺失的值按 0 处理，
 * 以免排序过程中读取越界。
 */
export function sortChartDesc(data: ChartData): ChartData {
  const pairs = data.labels.map((label, index) => ({
    label,
    value: data.values[index] ?? 0,
  }))
  pairs.sort((a, b) => b.value - a.value || a.label.localeCompare(b.label))
  return {
    labels: pairs.map((pair) => pair.label),
    values: pairs.map((pair) => pair.value),
  }
}
