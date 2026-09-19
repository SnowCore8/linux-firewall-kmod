// 总览仪表盘（移动优先）
//
// 做什么：聚合展示守护进程的运行态势——实时威胁等级、今日封禁/失败尝试/DDoS 事件/运行时长、
//        封禁与失败尝试趋势、Jail 分布、失败原因排行、封禁复发率、内核累计计数。
// 影响什么：本页全部为只读展示，不触发任何写操作，不改变内核或守护进程状态。
//
// 数据来源优先级（任何一级都取自真实端点，无占位假数据）：
//   1) 全局 SSE（useSse().stats）—— 首帧到达后持续复用，不再额外请求；
//   2) REST GET /api/v1/stats —— 实时通道未就绪或不可用时的回退；
//   3) emptyStats() —— 两者皆空时用零值占位，保证渲染期不崩、UI 不闪烁空屏。

import { Card, Grid, List, NoticeBar, ProgressBar, PullToRefresh, Skeleton, Tag } from 'antd-mobile'
import type { CSSProperties } from 'react'
import type { ConnectionStatus } from '../hooks/useSse'
import { useSse } from '../hooks/useSse'
import { useAsync } from '../hooks/useAsync'
import { getJson } from '../api/client'
import type { StatsResponse } from '../api/types'
import { PageHeader } from '../components/PageHeader'
import { StatCard } from '../components/StatCard'
import { EmptyState } from '../components/EmptyState'
import { RecidivismPanel } from '../components/RecidivismPanel'
import { LineChart } from '../charts/LineChart'
import { PieChart } from '../charts/PieChart'
import { emptyStats, sortChartDesc } from '../lib/defaults'
import { formatNumber, formatRate, formatUptime } from '../lib/format'

/** 威胁等级端点：SSE 未就绪时的回退数据源（handler.rs: GET /api/v1/stats） */
const STATS_URL = '/api/v1/stats'

/** 次要说明文字样式：颜色走 antd-mobile 主题变量，深浅色模式自动适配 */
const MUTED: CSSProperties = { color: 'var(--adm-color-text-secondary)', fontSize: 12 }
/** 行内两端对齐容器：左标签 + 右数值 */
const ROW: CSSProperties = { display: 'flex', justifyContent: 'space-between', alignItems: 'center' }

/** Tag 组件允许的颜色取值（显式列出以便 TS 收窄） */
type TagColor = 'default' | 'primary' | 'success' | 'warning' | 'danger'

/** 威胁等级 → 中文标签 + 展示色；未知等级回退为灰色「未知」 */
const THREAT_META: Record<string, { label: string; color: TagColor }> = {
  safe: { label: '安全', color: 'success' },
  low: { label: '低风险', color: 'primary' },
  medium: { label: '中风险', color: 'warning' },
  high: { label: '高风险', color: 'danger' },
  critical: { label: '严重', color: 'danger' },
}

/** 实时通道状态 → 用户可见的提示文案（connected 不提示，故为空串） */
const SSE_HINT: Record<ConnectionStatus, string> = {
  connecting: '正在建立实时通道，页面数据暂为一次性拉取…',
  connected: '',
  disconnected: '实时通道已断开，正在自动重连；期间数据回退为 REST 拉取。',
  connection_limit: '服务端实时连接数已达上限，页面已回退为 REST 拉取；关闭其它标签页后刷新可恢复实时。',
}

/** 比值（0~1，可能超过 1）转为百分比文本；用于 PPS 阈值比率与封禁表使用率 */
function formatRatio(value: number): string {
  return `${(value * 100).toFixed(1)}%`
}

export default function Dashboard() {
  const { stats: sseStats, status } = useSse()
  // SSE 已给出数据时不拉 REST；空数组/空对象常量避免 useMemo 依赖抖动
  const restStats = useAsync(() => getJson<StatsResponse>(STATS_URL), [])

  const stats = sseStats ?? restStats.data ?? emptyStats()
  const threat = stats.threat_level
  const threatMeta = THREAT_META[threat.level] ?? { label: `未知(${threat.level})`, color: 'default' as TagColor }

  // 图表数据按数值降序，让「最大来源」一眼可见；sortChartDesc 不改动入参
  const jailDist = sortChartDesc(stats.jail_distribution)
  const reasons = sortChartDesc(stats.failure_reasons)
  // 进度条基准取最大值；空数据时基准为 0，percent 统一按 0 渲染
  const reasonMax = reasons.values.reduce((max, v) => (v > max ? v : max), 0)

  // 首屏加载：SSE 与 REST 都还没有结果时展示骨架屏，避免误报「暂无数据」
  if (sseStats === null && restStats.loading) {
    return (
      <>
        <PageHeader title="总览" subtitle="加载中…" />
        <div style={{ padding: 7 }}>
          <Skeleton.Title animated />
          <Skeleton.Paragraph lineCount={8} animated />
        </div>
      </>
    )
  }

  return (
    <>
      <PageHeader
        title="总览"
        subtitle={`守护进程 v${stats.daemon_version} · 内核 v${stats.kernel_version}`}
      />

      <PullToRefresh
        onRefresh={async () => {
          restStats.reload()
        }}
      >
        {/* 外层 .fw-main 已提供 12px 内边距，这里只补底部留白 */}
        <div style={{ paddingBottom: 7 }}>
          {/* 实时通道异常时明确告知用户当前数据来源，避免误以为页面是实时的 */}
          {status !== 'connected' && <NoticeBar color="info" content={SSE_HINT[status]} wrap />}

          {/* REST 回退也失败且 SSE 无数据：错误必须可见并提供重试入口 */}
          {sseStats === null && restStats.error !== null && (
            <NoticeBar
              color="error"
              wrap
              content={`统计数据加载失败：${restStats.error}`}
              extra={
                <a onClick={() => restStats.reload()} style={{ color: 'inherit', textDecoration: 'underline' }}>
                  重试
                </a>
              }
            />
          )}

          <Card title="实时威胁等级">
            <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 7 }}>
              <Tag color={threatMeta.color} fill="solid">
                {threatMeta.label}
              </Tag>
              <span style={MUTED}>评分 {threat.score}/4</span>
              {threat.baseline_frozen && (
                <Tag color="warning" fill="outline">
                  基线已冻结
                </Tag>
              )}
              {threat.peak_hours && (
                <Tag color="primary" fill="outline">
                  业务高峰期
                </Tag>
              )}
            </div>

            <div style={{ display: 'grid', gap: 6 }}>
              <div>
                <div style={ROW}>
                  <span style={MUTED}>短期包速率 / 告警阈值</span>
                  <span>{formatRatio(threat.pps_ratio)}</span>
                </div>
                {/* 比率可超过 1，进度条封顶 100% 但文本保留真实倍数 */}
                <ProgressBar percent={Math.min(threat.pps_ratio * 100, 100)} text={false} />
                <div style={MUTED}>
                  当前 {formatRate(threat.current_pps, 'pps')} · 近 5 分钟封禁 {formatNumber(threat.recent_bans, false)} 次
                </div>
              </div>

              <div>
                <div style={ROW}>
                  <span style={MUTED}>内核封禁表使用率（4096 桶）</span>
                  <span>{formatRatio(threat.ban_table_usage)}</span>
                </div>
                <ProgressBar percent={Math.min(threat.ban_table_usage * 100, 100)} text={false} />
              </div>
            </div>

            <List header="评估依据">
              {threat.factors.map((factor, i) => (
                <List.Item key={`${i}:${factor}`}>{factor}</List.Item>
              ))}
            </List>
          </Card>

          {/* 四个关键指标：今日封禁 / 失败尝试 / DDoS 事件 / 运行时长 */}
          <Grid columns={2} gap={5} style={{ marginTop: 7 }}>
            <Grid.Item>
              <StatCard label="今日封禁" value={formatNumber(stats.today_bans, false)} tone="danger" />
            </Grid.Item>
            <Grid.Item>
              <StatCard label="失败尝试" value={formatNumber(stats.failed_attempts, true)} tone="warning" />
            </Grid.Item>
            <Grid.Item>
              <StatCard label="DDoS 事件" value={formatNumber(stats.ddos_events, false)} tone="primary" />
            </Grid.Item>
            <Grid.Item>
              <StatCard label="运行时长" value={formatUptime(stats.uptime_seconds)} tone="success" />
            </Grid.Item>
          </Grid>

          <Card title="封禁趋势（近 24 小时）" style={{ marginTop: 7 }}>
            <LineChart
              labels={stats.ban_trend.labels}
              series={[{ name: '封禁次数', values: stats.ban_trend.values }]}
              height={180}
              area
              yUnit="次"
              emptyHint="暂无封禁趋势数据"
            />
          </Card>

          <Card title="失败尝试趋势" style={{ marginTop: 7 }}>
            <LineChart
              labels={stats.failed_attempts_trend.labels}
              series={[{ name: '失败次数', values: stats.failed_attempts_trend.values }]}
              height={180}
              area
              yUnit="次"
              emptyHint="暂无失败尝试趋势数据"
            />
          </Card>

          <Card title="Jail 封禁分布" style={{ marginTop: 7 }}>
            <PieChart
              slices={jailDist.labels.map((name, i) => ({ name, value: jailDist.values[i] ?? 0 }))}
              height={240}
              donut
              emptyHint="当前没有活跃封禁"
            />
          </Card>

          <Card title="失败原因排行" style={{ marginTop: 7 }}>
            {reasons.labels.length === 0 ? (
              <EmptyState title="当前没有活跃封禁" description="失败原因按活跃封禁记录聚合，无封禁时为空" />
            ) : (
              reasons.labels.map((label, i) => {
                const count = reasons.values[i] ?? 0
                return (
                  <div key={`${i}:${label}`} style={{ marginBottom: 7 }}>
                    <div style={ROW}>
                      <span style={{ wordBreak: 'break-all' }}>{label}</span>
                      <span>{formatNumber(count, false)}</span>
                    </div>
                    <ProgressBar percent={reasonMax > 0 ? (count / reasonMax) * 100 : 0} text={false} />
                  </div>
                )
              })
            )}
          </Card>

          {/* 复发率面板自取数（GET /api/v1/stats/recidivism）并自带空态/错误态与刷新按钮 */}
          <Card title="封禁效果追踪" style={{ marginTop: 7 }}>
            <RecidivismPanel />
          </Card>

          <Card title="内核累计计数" style={{ marginTop: 7 }}>
            <List>
              <List.Item extra={formatNumber(stats.current_bans, false)}>当前封禁</List.Item>
              <List.Item extra={formatNumber(stats.total_bans, false)}>累计封禁</List.Item>
              <List.Item extra={formatNumber(stats.total_unbans, false)}>累计解封</List.Item>
              <List.Item extra={formatNumber(stats.whitelist_count, false)}>白名单条目</List.Item>
              <List.Item extra={formatNumber(stats.packets_dropped, true)}>丢弃数据包</List.Item>
              <List.Item extra={formatNumber(stats.packets_accepted, true)}>放行数据包</List.Item>
            </List>
          </Card>
        </div>
      </PullToRefresh>
    </>
  )
}
