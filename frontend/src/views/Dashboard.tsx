import { useMemo } from 'react'
import { Alert, Button, Flex, Space, Tag, Tooltip, Typography } from 'antd'
import {
  ClockCircleOutlined,
  DeleteOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  StopOutlined,
  ThunderboltOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import { PageHeader } from '../components/PageHeader.tsx'
import { StatCard } from '../components/StatCard.tsx'
import { ChartCard } from '../components/ChartCard.tsx'
import { BaseChart, useChartBase } from '../components/charts/BaseChart.tsx'
import { LoadingState } from '../components/state/LoadingState.tsx'
import { ErrorState } from '../components/state/ErrorState.tsx'
import { StaleNotice } from '../components/state/StaleNotice.tsx'
import { useLiveData } from '../hooks/useLiveData.ts'
import { useAsync } from '../hooks/useAsync.ts'
import { useRefreshSignal } from '../hooks/useRefreshSignal.ts'
import { useIsBelow } from '../hooks/useMediaQuery.ts'
import { useSseDomain } from '../providers/SseProvider.tsx'
import { getStats, getRecidivism } from '../api/endpoints.ts'
import { formatNumber, formatUptime } from '../lib/format.ts'
import { emptyStats } from '../lib/defaults.ts'
import { gaugeOption, lineOption, pieOption, barOption } from '../lib/charts.ts'
import { threatLabel, THREAT_COLORS } from '../theme/tokens.ts'
import type { StatsResponse } from '../api/types.ts'

/**
 * 概览仪表盘 —— 全站落地页，一屏给出「现在安全吗、发生了什么、趋势如何」。
 *
 * 数据来源合流：stats 域同时有 SSE 帧（秒级）与 REST 拉取（30s 校准），用 useLiveData 按
 * 新鲜度序号仲裁，视图只消费一个值；实时徽标显示连接态，断连/降级时 REST 轮询自动兜底。
 *
 * 布局自上而下按「先结论后细节」：威胁等级仪表 + 关键计数 → 趋势折线 → 结构占比 → Top 攻击源。
 * 全部走设计系统的 StatCard/ChartCard/BaseChart，四态（加载/空/错误/实时）由封装统一兜。
 */

const STAT_POLL_MS = 30_000
const EMPTY_STATS = emptyStats()

export default function Dashboard() {
  const navigate = useNavigate()
  const base = useChartBase()
  const isNarrow = useIsBelow('md')
  const statsDomain = useSseDomain('stats')

  const live = useLiveData<StatsResponse>({
    sseValue: statsDomain.value,
    sseSeq: statsDomain.seq,
    rest: getStats,
    refreshInterval: STAT_POLL_MS,
  })

  const stats = live.value ?? EMPTY_STATS
  const hasData = live.value != null

  // Top 复发攻击源：按累计封禁次数排名的复发榜（REST 独占，SSE 不推这个视图）
  const topAttackers = useAsync((signal) => getRecidivism(signal), {
    refreshInterval: STAT_POLL_MS,
  })

  useRefreshSignal(() => {
    live.refetch()
    topAttackers.refetch()
  })

  const threatColor = THREAT_COLORS[stats.threat_level.level] ?? base.palette[0]

  const trendOption = useMemo(
    () => lineOption(base, stats.ban_trend, { name: '封禁数', area: true, color: base.palette[0] }),
    [base, stats.ban_trend],
  )
  const failureTrendOption = useMemo(
    () =>
      lineOption(base, stats.failed_attempts_trend, {
        name: '失败尝试',
        area: true,
        color: base.palette[3],
      }),
    [base, stats.failed_attempts_trend],
  )
  const jailOption = useMemo(
    () =>
      pieOption(
        base,
        stats.jail_distribution.labels.map((name, i) => ({ name, value: stats.jail_distribution.values[i] ?? 0 })),
        { legend: true },
      ),
    [base, stats.jail_distribution],
  )
  const reasonOption = useMemo(
    () =>
      pieOption(
        base,
        stats.failure_reasons.labels.map((name, i) => ({ name, value: stats.failure_reasons.values[i] ?? 0 })),
        { legend: true },
      ),
    [base, stats.failure_reasons],
  )
  const gauge = useMemo(
    () => gaugeOption(base, stats.threat_level.score, { max: 100, color: threatColor, label: '威胁分数' }),
    [base, stats.threat_level.score, threatColor],
  )

  const topOption = useMemo(() => {
    const items = (topAttackers.data?.top_recidivists ?? []).slice(0, 8)
    return barOption(
      base,
      { labels: items.map((b) => b.ip), values: items.map((b) => b.ban_count) },
      { name: '封禁次数', horizontal: true, color: base.palette[5] },
    )
  }, [base, topAttackers.data])

  const chartEmpty = (data: { values: number[] }) =>
    data.values.length === 0 || data.values.every((v) => v === 0)

  return (
    <>
      {/* 徽标自订阅连接态与新鲜度：本页只消费 stats 域，不因别的域推帧或时间戳刷新而重渲染 */}
      <PageHeader
        title="概览"
        description="威胁态势、实时速率与封禁趋势的一页总览"
        breadcrumb={[{ title: '总览' }, { title: '概览' }]}
        realtimeLive
        extra={
          <Space>
            {/* 无条件渲染：外层条件为真时内层回退永远走不到，模块未加载就会整块消失 */}
            <Tooltip title="内核模块版本">
              <Tag className="fw-mono">kmod {stats.kernel_version || '未加载'}</Tag>
            </Tooltip>
            <Tag className="fw-mono">daemon {stats.daemon_version || '—'}</Tag>
            <Button icon={<ReloadOutlined />} onClick={live.refetch} loading={live.isRefreshing}>
              刷新
            </Button>
          </Space>
        }
      />

      <StaleNotice
        visible={live.isStale && live.source !== 'sse'}
        onRetry={live.refetch}
        style={{ marginBottom: 16 }}
      />


      {stats.state_save_truncated > 0 && (
        <Alert
          type="warning"
          showIcon
          icon={<WarningOutlined />}
          message="状态文件已截断"
          description={`内核模块保存状态文件时条目超过上限，累计 ${stats.state_save_truncated} 次截断。部分封禁或白名单条目可能丢失，重启后无法恢复。`}
          style={{ marginBottom: 16 }}
        />
      )}

      {!hasData && live.isLoading && <LoadingState variant="cards" rows={6} />}
      {!hasData && live.error && <ErrorState error={live.error} onRetry={live.refetch} />}

      {hasData && (
        <Flex vertical gap={16} className="fw-fade-in">
          {/* 第一行：威胁等级仪表（突出显示） */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: isNarrow ? '1fr' : 'minmax(280px, 1fr) 2fr',
              gap: 16,
            }}
          >
            <ChartCard title="威胁态势" className="fw-threat-card">
              <BaseChart option={gauge} height={200} title="威胁态势" />
              <Flex justify="center" gap={12} style={{ marginTop: 8 }}>
                <Tag color={threatColor} style={{ fontWeight: 600, fontSize: 13, padding: '4px 12px' }}>
                  {threatLabel(stats.threat_level.level)}
                </Tag>
                <Tag className="fw-mono" style={{ fontSize: 12 }}>
                  分数 {stats.threat_level.score}
                </Tag>
              </Flex>
            </ChartCard>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(min(180px, 100%), 1fr))',
                gap: 12,
                alignContent: 'start',
              }}
            >
              <StatCard
                label="今日封禁"
                value={formatNumber(stats.today_bans)}
                icon={StopOutlined}
                tone="danger"
                footer={`当前在表 ${formatNumber(stats.current_bans)} · 累计 ${formatNumber(stats.total_bans)}`}
                onClick={() => navigate('/bans')}
              />
              <StatCard
                label="白名单"
                value={formatNumber(stats.whitelist_count)}
                icon={SafetyCertificateOutlined}
                tone="success"
                footer="永不封禁的可信地址/网段"
                onClick={() => navigate('/whitelist')}
              />
              <StatCard
                label="DDoS 命中"
                value={formatNumber(stats.ddos_events)}
                icon={ThunderboltOutlined}
                tone="warning"
                footer="本进程收到的内核 DDoS 事件"
                onClick={() => navigate('/ddos')}
              />
              <StatCard
                label="丢弃数据包"
                value={formatNumber(stats.packets_dropped)}
                icon={DeleteOutlined}
                tone="info"
                footer={`放行 ${formatNumber(stats.packets_accepted)}`}
              />
            </div>
          </div>

          {/* 第二行：补充指标 */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(200px, 100%), 1fr))',
              gap: 16,
            }}
          >
            <StatCard
              label="失败尝试"
              value={formatNumber(stats.failed_attempts)}
              icon={ThunderboltOutlined}
              footer="各 jail 失败尝试之和（本进程配置态）"
            />
            <StatCard
              label="运行时长"
              value={formatUptime(stats.uptime_seconds)}
              icon={ClockCircleOutlined}
              mono={false}
              footer={`解封 ${formatNumber(stats.total_unbans)} 次`}
            />
          </div>

          {/* 第二行：趋势折线 */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(360px, 100%), 1fr))',
              gap: 16,
            }}
          >
            <ChartCard title="封禁趋势">
              <BaseChart option={trendOption} height={240} title="封禁趋势" empty={chartEmpty(stats.ban_trend)} loading={live.isRefreshing} />
            </ChartCard>
            <ChartCard title="失败尝试趋势">
              <BaseChart
                option={failureTrendOption}
                height={240}
                title="失败尝试趋势"
                empty={chartEmpty(stats.failed_attempts_trend)}
                loading={live.isRefreshing}
              />
            </ChartCard>
          </div>

          {/* 第三行：结构占比 + Top 攻击源 */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(320px, 100%), 1fr))',
              gap: 16,
            }}
          >
            <ChartCard title="Jail 分布">
              <BaseChart option={jailOption} height={240} title="Jail 分布" empty={chartEmpty(stats.jail_distribution)} />
            </ChartCard>
            <ChartCard title="失败原因">
              <BaseChart option={reasonOption} height={240} title="失败原因" empty={chartEmpty(stats.failure_reasons)} />
            </ChartCard>
            <ChartCard
              title="Top 复发攻击源"
              extra={
                <Typography.Link onClick={() => navigate('/analysis')} style={{ fontSize: 12 }}>
                  复发分析
                </Typography.Link>
              }
            >
              {topAttackers.data == null ? (
                topAttackers.error ? (
                  <ErrorState error={topAttackers.error} onRetry={topAttackers.refetch} />
                ) : (
                  <LoadingState variant="chart" />
                )
              ) : (
                <BaseChart
                  option={topOption}
                  height={240}
                  title="Top 复发攻击源"
                  empty={topAttackers.data.top_recidivists.length === 0}
                  loading={topAttackers.isRefreshing}
                />
              )}
            </ChartCard>
          </div>
        </Flex>
      )}
    </>
  )
}
