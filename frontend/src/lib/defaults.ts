import type { ChartData, StatsResponse } from '../api/types.ts'

// ---------------------------------------------------------------------------
// 空数据占位：首屏在第一条 REST/SSE 帧到达前，需要一个形状正确的「零值」，
// 免得每个消费点各自判空。字段与 StatsResponse 一一对齐——用返回类型标注把它
// 钉成编译期约束，后端加字段时这里会立刻报错，而不是悄悄漏一个。
// ---------------------------------------------------------------------------

export function emptyChartData(): ChartData {
  return { labels: [], values: [] }
}

export function emptyStats(): StatsResponse {
  return {
    daemon_version: '',
    kernel_version: '',
    today_bans: 0,
    failed_attempts: 0,
    ddos_events: 0,
    uptime_seconds: 0,
    ban_trend: emptyChartData(),
    jail_distribution: emptyChartData(),
    failure_reasons: emptyChartData(),
    failed_attempts_trend: emptyChartData(),
    current_bans: 0,
    total_bans: 0,
    total_unbans: 0,
    whitelist_count: 0,
    packets_dropped: 0,
    packets_accepted: 0,
    state_save_truncated: 0,
    threat_level: {
      level: 'safe',
      score: 0,
      factors: [],
      current_pps: 0,
      pps_ratio: 0,
      ban_table_usage: 0,
      recent_bans: 0,
      baseline_frozen: false,
      peak_hours: false,
    },
  }
}

export const EMPTY_CHART: ChartData = emptyChartData()

// ---------------------------------------------------------------------------
// 图表序列整理：后端给的 ChartData 是「按维度键序」的无序对，多数看板要按数值
// 降序展示 Top-N。这里就地排出一份新对象（不改入参），labels/values 同步换序。
// ---------------------------------------------------------------------------

export function sortChartDesc(data: ChartData, limit?: number): ChartData {
  const pairs = data.labels.map((label, i) => ({ label, value: data.values[i] ?? 0 }))
  pairs.sort((a, b) => b.value - a.value)
  const kept = limit != null && limit >= 0 ? pairs.slice(0, limit) : pairs
  return {
    labels: kept.map((p) => p.label),
    values: kept.map((p) => p.value),
  }
}
