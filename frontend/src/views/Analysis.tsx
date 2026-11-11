import { useCallback, useMemo, useState, type CSSProperties } from 'react'
import {
  App,
  Button,
  Descriptions,
  Drawer,
  Flex,
  Input,
  Progress,
  Space,
  Tabs,
  Tag,
  Typography,
  type TableProps,
} from 'antd'
import {
  AlertOutlined,
  ClockCircleOutlined,
  ReloadOutlined,
  RetweetOutlined,
  TeamOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons'
import { useNavigate, useParams } from 'react-router-dom'
import { PageHeader } from '../components/PageHeader.tsx'
import { DataTable } from '../components/DataTable.tsx'
import { ChartCard } from '../components/ChartCard.tsx'
import { StatCard } from '../components/StatCard.tsx'
import { BaseChart, useChartBase } from '../components/charts/BaseChart.tsx'
import { LoadingState } from '../components/state/LoadingState.tsx'
import { ErrorState } from '../components/state/ErrorState.tsx'
import { EmptyState } from '../components/state/EmptyState.tsx'
import { useAsync, type UseAsyncResult } from '../hooks/useAsync.ts'
import { useRefreshSignal } from '../hooks/useRefreshSignal.ts'
import { emitRefresh } from '../lib/appEvents.ts'
import {
  getAnalysisIp,
  getAnalysisSummary,
  getAttackPredictions,
  getBanDurationHistogram,
  getBanDurationRecommendations,
  getBanEffectiveness,
  getCollaborativeAttacks,
  getNetworkDistribution,
  getPeriodicAttackers,
  getReputation,
  getThresholdRecommendations,
} from '../api/endpoints.ts'
import { formatDatetime, formatDuration, formatNumber, formatPercent } from '../lib/format.ts'
import { barOption, gaugeOption, radarOption } from '../lib/charts.ts'
import { THREAT_COLORS, threatLabel } from '../theme/tokens.ts'
import { isValidIp } from '../lib/validation.ts'
import type {
  AnalysisIpResponse,
  AnalysisSummaryResponse,
  AttackPrediction,
  AttackPredictionSummary,
  BanDurationHistogramResponse,
  BanDurationRecommendation,
  BanDurationRecommendationResponse,
  BanEffectivenessResponse,
  BanLevelEffectiveness,
  BanResponse,
  CollaborativeAttack,
  JailAttackTrend,
  NetworkBlock,
  PeriodicAttacker,
  ReputationEntryResponse,
  RiskVectorResponse,
  ThresholdRecommendation,
  ThresholdRecommendationResponse,
} from '../api/types.ts'

/**
 * 智能分析页 —— 把散落在各统计子路由里的「洞察类」结论聚到一页，用 Tabs 分区按需加载。
 *
 * 设计取舍：
 *   * 每个分区独立取数、独立兜底四态（加载/空/错误/内容），一个分区失败不牵连其它分区；
 *   * 分区懒加载：切到某 Tab 才置 `visited` 并放行对应 `useAsync`（`enabled` 必须传**确定的
 *     布尔**——`useAsync` 对 `enabled === undefined` 会回落到默认 true，故这里一律 `=== true`）；
 *   * 「刷新」按钮与命令面板共用同一条广播信号 `emitRefresh()`：页面订阅后只重取**当前分区**，
 *     若 IP 深链抽屉开着，抽屉自己也订阅、一并重取；
 *   * IP 深链 `/analysis/ip/:ip`（router.tsx 复用本页组件）与页内搜索框都走 `navigate` 到该路由，
 *     由 `useParams` 读出 ip 拉起抽屉——「实时告警点进来」与「手动搜一个 IP」同一条渲染路径。
 *
 * 关于 analysis/summary 与 analysis/ip 两个后端端点当前是桩：本页严格只依赖契约既有字段，桩返回
 * 空数组 / 零值时各分区自然退化为 EmptyState，不崩、不编造数据；其余统计子路由已是真实数据。
 */

type TabKey =
  | 'summary'
  | 'predict'
  | 'periodic'
  | 'collab'
  | 'network'
  | 'reputation'
  | 'threshold'
  | 'effectiveness'

type Columns<T> = NonNullable<TableProps<T>['columns']>

/** 风险向量的 7 个维度（键取自 RiskVectorResponse 的数值字段，标签用于表头与雷达指示器）。 */
type RiskDimKey = 'failure' | 'ban' | 'scan' | 'bruteforce' | 'ddos' | 'geo' | 'cluster'
const RISK_DIMS: ReadonlyArray<{ key: RiskDimKey; label: string }> = [
  { key: 'failure', label: '失败' },
  { key: 'ban', label: '封禁' },
  { key: 'scan', label: '扫描' },
  { key: 'bruteforce', label: '暴破' },
  { key: 'ddos', label: 'DDoS' },
  { key: 'geo', label: '地理' },
  { key: 'cluster', label: '集群' },
]

/** 紧迫度着色（后端枚举取值未知时回落到 default，绝不臆造文案，原样回显）。 */
const URGENCY_COLORS: Record<string, string> = {
  imminent: 'red',
  critical: 'red',
  high: 'volcano',
  soon: 'orange',
  medium: 'gold',
  low: 'blue',
  normal: 'default',
}

/** 趋势文案 + 着色（未识别取值原样回显）。 */
const TREND_META: Record<string, { label: string; color: string }> = {
  up: { label: '↑ 上升', color: 'red' },
  rising: { label: '↑ 上升', color: 'red' },
  increase: { label: '↑ 上升', color: 'red' },
  down: { label: '↓ 下降', color: 'green' },
  falling: { label: '↓ 下降', color: 'green' },
  decrease: { label: '↓ 下降', color: 'green' },
  stable: { label: '→ 平稳', color: 'default' },
  flat: { label: '→ 平稳', color: 'default' },
}

/** 阈值调整方向文案 + 着色（规格要求「上调/下调」；未识别取值原样回显）。 */
const DIRECTION_META: Record<string, { label: string; color: string }> = {
  up: { label: '上调', color: 'orange' },
  raise: { label: '上调', color: 'orange' },
  increase: { label: '上调', color: 'orange' },
  higher: { label: '上调', color: 'orange' },
  down: { label: '下调', color: 'blue' },
  lower: { label: '下调', color: 'blue' },
  decrease: { label: '下调', color: 'blue' },
  keep: { label: '维持', color: 'default' },
  none: { label: '维持', color: 'default' },
}

function urgencyColor(value: string): string {
  return URGENCY_COLORS[value.trim().toLowerCase()] ?? 'default'
}
function trendMeta(value: string): { label: string; color: string } {
  return TREND_META[value.trim().toLowerCase()] ?? { label: value || '—', color: 'default' }
}
function directionMeta(value: string): { label: string; color: string } {
  return DIRECTION_META[value.trim().toLowerCase()] ?? { label: value || '—', color: 'default' }
}

/** 归一化分值（0–1）保留两位；非法值给破折号，不把 NaN 甩到界面上。 */
function fmtScore(value: number): string {
  return Number.isFinite(value) ? value.toFixed(2) : '—'
}

/**
 * 信誉分配色。假设后端口径为 0–100（越高越可疑）；口径未知时数值仍原样展示，仅配色偏保守。
 * 返回 CSS 颜色变量，供内联 style 使用。
 */
function reputationColor(score: number): string {
  if (!Number.isFinite(score)) return 'var(--fw-text-secondary)'
  if (score >= 80) return 'var(--fw-danger)'
  if (score >= 50) return 'var(--fw-warning)'
  if (score >= 20) return '#ff8a3d'
  if (score > 0) return 'var(--fw-info)'
  return 'var(--fw-success)'
}

/** 图表序列是否为空（无点或全零）——空时渲染 EmptyState 而非空坐标轴。 */
function isEmptySeries(values: number[]): boolean {
  return values.length === 0 || values.every((v) => v === 0)
}

/** IP 单元格：等宽 + 可点，点了拉起该 IP 的综合分析抽屉（走深链路由）。 */
function renderIpLink(ip: string, onOpenIp: (ip: string) => void) {
  return (
    <Typography.Link className="fw-mono" onClick={() => onOpenIp(ip)}>
      {ip}
    </Typography.Link>
  )
}

const GRID_AUTO_FIT: CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
  gap: 16,
}

export default function Analysis() {
  const { message } = App.useApp()
  const navigate = useNavigate()
  const { ip: routeIp } = useParams<{ ip?: string }>()

  const [activeKey, setActiveKey] = useState<TabKey>('summary')
  const [visited, setVisited] = useState<Partial<Record<TabKey, boolean>>>({ summary: true })
  const [searchIp, setSearchIp] = useState('')

  // 各分区独立取数；enabled 一律传确定布尔（=== true），避免 undefined 回落成默认 true
  const summary = useAsync<AnalysisSummaryResponse>((s) => getAnalysisSummary(s), {
    enabled: visited.summary === true,
  })
  const predictions = useAsync<AttackPredictionSummary>((s) => getAttackPredictions(s), {
    enabled: visited.predict === true,
  })
  const periodic = useAsync<PeriodicAttacker[]>((s) => getPeriodicAttackers(s), {
    enabled: visited.periodic === true,
  })
  const collab = useAsync<CollaborativeAttack[]>((s) => getCollaborativeAttacks(s), {
    enabled: visited.collab === true,
  })
  const network = useAsync<NetworkBlock[]>((s) => getNetworkDistribution(s), {
    enabled: visited.network === true,
  })
  const reputation = useAsync<ReputationEntryResponse[]>((s) => getReputation(s), {
    enabled: visited.reputation === true,
  })
  const threshold = useAsync<ThresholdRecommendationResponse>((s) => getThresholdRecommendations(s), {
    enabled: visited.threshold === true,
  })
  const effectiveness = useAsync<BanEffectivenessResponse>((s) => getBanEffectiveness(s), {
    enabled: visited.effectiveness === true,
  })
  const histogram = useAsync<BanDurationHistogramResponse>((s) => getBanDurationHistogram(s), {
    enabled: visited.effectiveness === true,
  })
  const durationRec = useAsync<BanDurationRecommendationResponse>((s) => getBanDurationRecommendations(s), {
    enabled: visited.effectiveness === true,
  })

  const openIp = useCallback(
    (ip: string) => {
      const target = ip.trim()
      if (target) navigate(`/analysis/ip/${target}`)
    },
    [navigate],
  )

  const closeDrawer = useCallback(() => {
    if (routeIp) navigate('/analysis', { replace: true })
  }, [routeIp, navigate])

  const handleSearch = useCallback(
    (value: string) => {
      const ip = value.trim()
      if (!ip) return
      if (!isValidIp(ip)) {
        message.error('请输入合法的 IP 地址（IPv4 / IPv6）')
        return
      }
      openIp(ip)
    },
    [message, openIp],
  )

  const onTabChange = useCallback((key: string) => {
    const k = key as TabKey
    setActiveKey(k)
    setVisited((v) => (v[k] ? v : { ...v, [k]: true }))
  }, [])

  // 命令面板 / 顶栏 / 本页刷新按钮广播的「刷新当前页」——只重取当前分区
  useRefreshSignal(() => {
    switch (activeKey) {
      case 'summary':
        summary.refetch()
        break
      case 'predict':
        predictions.refetch()
        break
      case 'periodic':
        periodic.refetch()
        break
      case 'collab':
        collab.refetch()
        break
      case 'network':
        network.refetch()
        break
      case 'reputation':
        reputation.refetch()
        break
      case 'threshold':
        threshold.refetch()
        break
      case 'effectiveness':
        effectiveness.refetch()
        histogram.refetch()
        durationRec.refetch()
        break
    }
  })

  const tabItems = useMemo(
    () => [
      { key: 'summary', label: '综合摘要', children: <SummarySection result={summary} onOpenIp={openIp} /> },
      { key: 'predict', label: '攻击预测', children: <PredictionSection result={predictions} onOpenIp={openIp} /> },
      { key: 'periodic', label: '周期性攻击者', children: <PeriodicSection result={periodic} onOpenIp={openIp} /> },
      { key: 'collab', label: '协同攻击', children: <CollabSection result={collab} onOpenIp={openIp} /> },
      { key: 'network', label: '网段分布', children: <NetworkSection result={network} /> },
      { key: 'reputation', label: 'IP 信誉', children: <ReputationSection result={reputation} onOpenIp={openIp} /> },
      { key: 'threshold', label: '阈值推荐', children: <ThresholdSection result={threshold} /> },
      {
        key: 'effectiveness',
        label: '封禁成效',
        children: (
          <EffectivenessSection effectiveness={effectiveness} histogram={histogram} durationRec={durationRec} />
        ),
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [openIp, summary, predictions, periodic, collab, network, reputation, threshold, effectiveness, histogram, durationRec],
  )

  // 顶栏「刷新」只重取当前分区（见 useRefreshSignal），故 loading 只反映当前分区取数态；
  // 封禁成效页一次刷三张表，任一在途即视为刷新中
  let activeRefreshing = false
  switch (activeKey) {
    case 'summary':
      activeRefreshing = summary.isUserFetching
      break
    case 'predict':
      activeRefreshing = predictions.isUserFetching
      break
    case 'periodic':
      activeRefreshing = periodic.isUserFetching
      break
    case 'collab':
      activeRefreshing = collab.isUserFetching
      break
    case 'network':
      activeRefreshing = network.isUserFetching
      break
    case 'reputation':
      activeRefreshing = reputation.isUserFetching
      break
    case 'threshold':
      activeRefreshing = threshold.isUserFetching
      break
    case 'effectiveness':
      activeRefreshing =
        effectiveness.isUserFetching || histogram.isUserFetching || durationRec.isUserFetching
      break
  }

  return (
    <>
      <PageHeader
        title="智能分析"
        description="攻击预测、周期性与协同分析、网段与信誉、阈值推荐与封禁成效的综合洞察"
        breadcrumb={[{ title: '智能' }, { title: '智能分析' }]}
        extra={
          <Space wrap>
            <Input.Search
              placeholder="分析指定 IP（如 203.0.113.42）"
              allowClear
              enterButton="分析"
              value={searchIp}
              onChange={(e) => setSearchIp(e.target.value)}
              onSearch={handleSearch}
              style={{ width: 300 }}
            />
            <Button icon={<ReloadOutlined />} onClick={() => emitRefresh()} loading={activeRefreshing}>
              刷新
            </Button>
          </Space>
        }
      />

      <Tabs activeKey={activeKey} onChange={onTabChange} items={tabItems} />

      {routeIp && <IpAnalysisDrawer key={routeIp} ip={routeIp} onClose={closeDrawer} />}
    </>
  )
}

// ---------------------------------------------------------------------------
// 分区 1：综合摘要
// ---------------------------------------------------------------------------

interface SummarySectionProps {
  result: UseAsyncResult<AnalysisSummaryResponse>
  onOpenIp: (ip: string) => void
}

function SummarySection({ result, onOpenIp }: SummarySectionProps) {
  const base = useChartBase()

  const gauge = useMemo(() => {
    const score = result.data?.threat_level.score ?? 0
    const color = THREAT_COLORS[result.data?.threat_level.level ?? ''] ?? base.palette[0]
    return gaugeOption(base, score, { max: 100, color, label: '威胁分数' })
  }, [base, result.data])

  const columns = useMemo<Columns<RiskVectorResponse>>(() => {
    const dims: Columns<RiskVectorResponse> = RISK_DIMS.map((dim) => ({
      title: dim.label,
      dataIndex: dim.key,
      key: dim.key,
      width: 76,
      render: (n: number) => <span className="fw-mono">{fmtScore(n)}</span>,
    }))
    return [
      {
        title: 'IP 地址',
        dataIndex: 'ip',
        key: 'ip',
        width: 160,
        fixed: 'left',
        render: (_: unknown, r: RiskVectorResponse) => renderIpLink(r.ip, onOpenIp),
      },
      {
        title: '总风险',
        dataIndex: 'total_risk',
        key: 'total_risk',
        width: 92,
        render: (n: number) => (
          <span className="fw-mono" style={{ fontWeight: 600 }}>
            {fmtScore(n)}
          </span>
        ),
      },
      ...dims,
    ]
  }, [onOpenIp])

  if (result.isLoading && !result.data) return <LoadingState variant="cards" rows={4} />
  if (result.error && !result.data) return <ErrorState error={result.error} onRetry={result.refetch} />
  const d = result.data
  if (!d) return null

  const level = d.threat_level.level
  const threatColor = THREAT_COLORS[level] ?? base.palette[0]
  const factors = d.threat_level.factors

  return (
    <Flex vertical gap={16} className="fw-fade-in">
      <div style={GRID_AUTO_FIT}>
        <ChartCard title="威胁等级">
          <BaseChart option={gauge} height={180} />
          <Flex justify="center" style={{ marginTop: -8 }}>
            <Tag color={threatColor} style={{ fontWeight: 600 }}>
              {threatLabel(level)}
            </Tag>
          </Flex>
          <Typography.Text
            type="secondary"
            style={{ display: 'block', textAlign: 'center', fontSize: 12, marginTop: 8 }}
          >
            当前 {formatNumber(d.threat_level.current_pps)} pps · 近期封禁{' '}
            {formatNumber(d.threat_level.recent_bans)} · 封禁表占用 {fmtScore(d.threat_level.ban_table_usage)}
          </Typography.Text>
          <Flex justify="center" gap={6} wrap="wrap" style={{ marginTop: 8 }}>
            {d.threat_level.peak_hours && <Tag color="orange">高峰时段</Tag>}
            {d.threat_level.baseline_frozen && <Tag color="blue">基线冻结</Tag>}
          </Flex>
        </ChartCard>

        <StatCard
          label="活跃攻击"
          value={formatNumber(d.active_attacks)}
          icon={ThunderboltOutlined}
          tone="danger"
          footer="当前判定为活跃的攻击源"
        />
        <StatCard
          label="异常计数"
          value={formatNumber(d.anomalies_count)}
          icon={AlertOutlined}
          tone="warning"
          footer="偏离基线的异常观测（只观测不封禁）"
        />
        <StatCard
          label="协同攻击"
          value={formatNumber(d.collaborative_count)}
          icon={TeamOutlined}
          tone="info"
          footer="多 IP 协同的攻击窗口数"
        />
      </div>

      <div>
        <Flex align="center" gap={8} wrap="wrap" style={{ marginBottom: 8 }}>
          <Typography.Text type="secondary" style={{ fontSize: 13 }}>
            风险因子
          </Typography.Text>
          {factors.length > 0 ? (
            factors.map((f, i) => (
              <Tag key={i} color="gold">
                {f}
              </Tag>
            ))
          ) : (
            <Typography.Text type="secondary">—</Typography.Text>
          )}
        </Flex>
        <Typography.Paragraph style={{ marginBottom: 4 }}>
          {d.summary || <Typography.Text type="secondary">暂无综合分析结论</Typography.Text>}
        </Typography.Paragraph>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          数据时刻 {formatDatetime(d.timestamp)}
        </Typography.Text>
      </div>

      <div>
        <Typography.Title level={5} style={{ margin: '0 0 8px' }}>
          高风险分析源
        </Typography.Title>
        <DataTable<RiskVectorResponse>
          data={d.top_risk_ips}
          isFetching={result.isUserFetching}
          rowKey="ip"
          columns={columns}
          emptyScenario="no-data"
          emptyTitle="暂无风险 IP"
          emptyDescription="多维风险引擎尚未产出风险向量（可能未开启 risk_engine）"
          scroll={{ x: 'max-content' }}
          pagination={{ pageSize: 10, hideOnSinglePage: true }}
        />
      </div>
    </Flex>
  )
}

// ---------------------------------------------------------------------------
// 分区 2：攻击预测
// ---------------------------------------------------------------------------

interface PredictionSectionProps {
  result: UseAsyncResult<AttackPredictionSummary>
  onOpenIp: (ip: string) => void
}

function PredictionSection({ result, onOpenIp }: PredictionSectionProps) {
  const base = useChartBase()

  const jailOption = useMemo(() => {
    const trends = result.data?.jail_trends ?? []
    return barOption(
      base,
      { labels: trends.map((t) => t.jail_name), values: trends.map((t) => t.bans_24h) },
      { name: '近 24h 封禁', horizontal: true, color: base.palette[4] },
    )
  }, [base, result.data])

  const predColumns = useMemo<Columns<AttackPrediction>>(
    () => [
      {
        title: 'IP 地址',
        dataIndex: 'ip',
        key: 'ip',
        width: 160,
        fixed: 'left',
        render: (_: unknown, r: AttackPrediction) => renderIpLink(r.ip, onOpenIp),
      },
      {
        title: 'Jail',
        dataIndex: 'jail_name',
        key: 'jail_name',
        width: 130,
        render: (v: string) => (v ? <Tag>{v}</Tag> : <span>—</span>),
      },
      {
        title: '累计封禁',
        dataIndex: 'ban_count',
        key: 'ban_count',
        width: 100,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '紧迫度',
        dataIndex: 'urgency',
        key: 'urgency',
        width: 100,
        render: (v: string) => <Tag color={urgencyColor(v)}>{v || '—'}</Tag>,
      },
      {
        title: '置信度',
        dataIndex: 'confidence',
        key: 'confidence',
        width: 90,
        render: (n: number) => <span className="fw-mono">{formatPercent(n)}</span>,
      },
      {
        title: '预测下次攻击',
        dataIndex: 'predicted_next_attack',
        key: 'predicted_next_attack',
        width: 180,
        render: (ts: number) => <span className="fw-mono">{formatDatetime(ts)}</span>,
      },
      {
        title: '最近封禁',
        dataIndex: 'last_ban_at',
        key: 'last_ban_at',
        width: 180,
        render: (ts: number) => <span className="fw-mono">{formatDatetime(ts)}</span>,
      },
      {
        title: '剩余',
        dataIndex: 'remaining_secs',
        key: 'remaining_secs',
        width: 110,
        render: (n: number) => <span className="fw-mono">{formatDuration(n)}</span>,
      },
    ],
    [onOpenIp],
  )

  const trendColumns = useMemo<Columns<JailAttackTrend>>(
    () => [
      {
        title: 'Jail',
        dataIndex: 'jail_name',
        key: 'jail_name',
        render: (v: string) => (v ? <Tag>{v}</Tag> : <span>—</span>),
      },
      {
        title: '近 24h 封禁',
        dataIndex: 'bans_24h',
        key: 'bans_24h',
        width: 120,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '近 7d 封禁',
        dataIndex: 'bans_7d',
        key: 'bans_7d',
        width: 120,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '趋势',
        dataIndex: 'trend',
        key: 'trend',
        width: 110,
        render: (v: string) => {
          const m = trendMeta(v)
          return <Tag color={m.color}>{m.label}</Tag>
        },
      },
      {
        title: '预测攻击者(24h)',
        dataIndex: 'predicted_attackers_24h',
        key: 'predicted_attackers_24h',
        width: 140,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
    ],
    [],
  )

  if (result.isLoading && !result.data) return <LoadingState variant="cards" rows={4} />
  if (result.error && !result.data) return <ErrorState error={result.error} onRetry={result.refetch} />
  const d = result.data
  if (!d) return null

  const trends = d.jail_trends
  const chartEmpty =
    trends.length === 0 || trends.every((t) => t.bans_24h === 0 && t.bans_7d === 0)

  return (
    <Flex vertical gap={16} className="fw-fade-in">
      <div style={GRID_AUTO_FIT}>
        <StatCard
          label="迫近攻击"
          value={formatNumber(d.imminent_count)}
          icon={ThunderboltOutlined}
          tone="danger"
          footer="预测即将再次发起攻击的 IP 数"
        />
        <StatCard
          label="24 小时内"
          value={formatNumber(d.within_24h_count)}
          icon={ClockCircleOutlined}
          tone="warning"
          footer="预测 24 小时内再次攻击的 IP 数"
        />
      </div>

      <div>
        <Typography.Title level={5} style={{ margin: '0 0 8px' }}>
          预测明细
        </Typography.Title>
        <DataTable<AttackPrediction>
          data={d.predictions}
          isFetching={result.isUserFetching}
          rowKey="ip"
          columns={predColumns}
          emptyScenario="no-data"
          emptyTitle="暂无攻击预测"
          emptyDescription="尚无足够封禁历史用于预测下次攻击时间"
          scroll={{ x: 'max-content' }}
          pagination={{ pageSize: 10, hideOnSinglePage: true }}
        />
      </div>

      <div>
        <Typography.Title level={5} style={{ margin: '0 0 8px' }}>
          Jail 攻击趋势
        </Typography.Title>
        <ChartCard title="各 Jail 近 24 小时封禁">
          <BaseChart option={jailOption} height={240} empty={chartEmpty} />
        </ChartCard>
        <div style={{ marginTop: 12 }}>
          <DataTable<JailAttackTrend>
            data={trends}
            isFetching={result.isUserFetching}
            rowKey="jail_name"
            columns={trendColumns}
            emptyScenario="no-data"
            emptyTitle="暂无 Jail 趋势"
            pagination={{ pageSize: 10, hideOnSinglePage: true }}
          />
        </div>
      </div>
    </Flex>
  )
}

// ---------------------------------------------------------------------------
// 分区 3：周期性攻击者
// ---------------------------------------------------------------------------

interface PeriodicSectionProps {
  result: UseAsyncResult<PeriodicAttacker[]>
  onOpenIp: (ip: string) => void
}

function PeriodicSection({ result, onOpenIp }: PeriodicSectionProps) {
  const columns = useMemo<Columns<PeriodicAttacker>>(
    () => [
      {
        title: 'IP 地址',
        dataIndex: 'ip',
        key: 'ip',
        width: 160,
        fixed: 'left',
        render: (_: unknown, r: PeriodicAttacker) => renderIpLink(r.ip, onOpenIp),
      },
      {
        title: 'Jail',
        dataIndex: 'jail_name',
        key: 'jail_name',
        width: 130,
        render: (v: string) => (v ? <Tag>{v}</Tag> : <span>—</span>),
      },
      {
        title: '累计封禁',
        dataIndex: 'ban_count',
        key: 'ban_count',
        width: 100,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '平均间隔',
        dataIndex: 'avg_interval_secs',
        key: 'avg_interval_secs',
        width: 120,
        render: (n: number) => <span className="fw-mono">{formatDuration(n)}</span>,
      },
      {
        title: '间隔标准差',
        dataIndex: 'interval_stddev',
        key: 'interval_stddev',
        width: 120,
        render: (n: number) => <span className="fw-mono">{formatDuration(n)}</span>,
      },
      {
        title: '周期性',
        dataIndex: 'periodicity_score',
        key: 'periodicity_score',
        width: 160,
        render: (n: number) => (
          <Flex align="center" gap={8}>
            <Progress
              percent={Math.round(Math.max(0, Math.min(1, n)) * 100)}
              size="small"
              showInfo={false}
              style={{ width: 80, margin: 0 }}
            />
            <span className="fw-mono">{fmtScore(n)}</span>
          </Flex>
        ),
      },
    ],
    [onOpenIp],
  )

  return (
    <DataTable<PeriodicAttacker>
      data={result.data}
      isLoading={result.isLoading}
      isFetching={result.isUserFetching}
      error={result.error}
      onRetry={result.refetch}
      columns={columns}
      expandable={{
        expandedRowRender: (record: PeriodicAttacker) =>
          record.timestamps.length > 0 ? (
            <Space direction="vertical" size={2}>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                封禁时间点（共 {record.timestamps.length} 次）
              </Typography.Text>
              {record.timestamps.map((ts, i) => (
                <span key={i} className="fw-mono" style={{ fontSize: 12 }}>
                  {formatDatetime(ts)}
                </span>
              ))}
            </Space>
          ) : (
            <Typography.Text type="secondary">无时间戳记录</Typography.Text>
          ),
        rowExpandable: (record: PeriodicAttacker) => record.timestamps.length > 0,
      }}
      emptyScenario="no-data"
      emptyTitle="暂无周期性攻击者"
      emptyDescription="未检测到具有明显周期规律的重复攻击源"
      scroll={{ x: 'max-content' }}
      pagination={{ pageSize: 20, hideOnSinglePage: true }}
    />
  )
}

// ---------------------------------------------------------------------------
// 分区 4：协同攻击
// ---------------------------------------------------------------------------

interface CollabSectionProps {
  result: UseAsyncResult<CollaborativeAttack[]>
  onOpenIp: (ip: string) => void
}

function CollabSection({ result, onOpenIp }: CollabSectionProps) {
  const columns = useMemo<Columns<CollaborativeAttack>>(
    () => [
      {
        title: 'Jail',
        dataIndex: 'jail_name',
        key: 'jail_name',
        width: 140,
        render: (v: string) => (v ? <Tag>{v}</Tag> : <span>—</span>),
      },
      {
        title: '时间窗口',
        key: 'window',
        width: 340,
        render: (_: unknown, r: CollaborativeAttack) => (
          <span className="fw-mono" style={{ fontSize: 12 }}>
            {formatDatetime(r.window_start)} → {formatDatetime(r.window_end)}
          </span>
        ),
      },
      {
        title: '涉及 IP',
        dataIndex: 'ip_count',
        key: 'ip_count',
        width: 100,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '总封禁',
        dataIndex: 'total_bans',
        key: 'total_bans',
        width: 100,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '相关性',
        dataIndex: 'correlation_score',
        key: 'correlation_score',
        width: 100,
        render: (n: number) => <span className="fw-mono">{fmtScore(n)}</span>,
      },
    ],
    [],
  )

  return (
    <DataTable<CollaborativeAttack>
      data={result.data}
      isLoading={result.isLoading}
      isFetching={result.isUserFetching}
      error={result.error}
      onRetry={result.refetch}
      columns={columns}
      expandable={{
        expandedRowRender: (record: CollaborativeAttack) =>
          record.ips.length > 0 ? (
            <Space direction="vertical" size={4}>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                参与 IP（{record.ips.length}）
              </Typography.Text>
              <Flex gap={6} wrap="wrap">
                {record.ips.map((ip) => (
                  <Tag key={ip} className="fw-mono" style={{ cursor: 'pointer' }} onClick={() => onOpenIp(ip)}>
                    {ip}
                  </Tag>
                ))}
              </Flex>
            </Space>
          ) : (
            <Typography.Text type="secondary">无 IP 记录</Typography.Text>
          ),
        rowExpandable: (record: CollaborativeAttack) => record.ips.length > 0,
      }}
      emptyScenario="no-data"
      emptyTitle="暂无协同攻击"
      emptyDescription="未检测到同一时间窗口内多 IP 协同的攻击"
      scroll={{ x: 'max-content' }}
      pagination={{ pageSize: 20, hideOnSinglePage: true }}
    />
  )
}

// ---------------------------------------------------------------------------
// 分区 5：网段分布
// ---------------------------------------------------------------------------

interface NetworkSectionProps {
  result: UseAsyncResult<NetworkBlock[]>
}

function NetworkSection({ result }: NetworkSectionProps) {
  const base = useChartBase()

  const subnetOption = useMemo(() => {
    const rows = [...(result.data ?? [])].sort((a, b) => b.total_bans - a.total_bans).slice(0, 10)
    return barOption(
      base,
      { labels: rows.map((r) => r.subnet), values: rows.map((r) => r.total_bans) },
      { name: '封禁次数', horizontal: true, color: base.palette[1] },
    )
  }, [base, result.data])

  const columns = useMemo<Columns<NetworkBlock>>(
    () => [
      {
        title: '网段',
        dataIndex: 'subnet',
        key: 'subnet',
        width: 180,
        render: (v: string) => <span className="fw-mono">{v}</span>,
      },
      {
        title: '独立 IP',
        dataIndex: 'unique_ips',
        key: 'unique_ips',
        width: 100,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '总封禁',
        dataIndex: 'total_bans',
        key: 'total_bans',
        width: 100,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: 'Top IP',
        dataIndex: 'top_ip',
        key: 'top_ip',
        width: 160,
        render: (v: string) => (v ? <span className="fw-mono">{v}</span> : <span>—</span>),
      },
      {
        title: '最近封禁',
        dataIndex: 'last_banned_at',
        key: 'last_banned_at',
        width: 180,
        render: (ts: number) => <span className="fw-mono">{formatDatetime(ts)}</span>,
      },
    ],
    [],
  )

  if (result.isLoading && !result.data) return <LoadingState variant="cards" rows={4} />
  if (result.error && !result.data) return <ErrorState error={result.error} onRetry={result.refetch} />
  const d = result.data
  if (!d) return null

  return (
    <Flex vertical gap={16} className="fw-fade-in">
      <ChartCard title="封禁最多的网段（Top 10）">
        <BaseChart option={subnetOption} height={280} empty={isEmptySeries(d.map((r) => r.total_bans))} />
      </ChartCard>
      <DataTable<NetworkBlock>
        data={d}
        isFetching={result.isUserFetching}
        rowKey="subnet"
        columns={columns}
        emptyScenario="no-data"
        emptyTitle="暂无网段分布"
        emptyDescription="尚无按网段聚合的封禁记录"
        scroll={{ x: 'max-content' }}
        pagination={{ pageSize: 20, hideOnSinglePage: true }}
      />
    </Flex>
  )
}

// ---------------------------------------------------------------------------
// 分区 6：IP 信誉
// ---------------------------------------------------------------------------

interface ReputationSectionProps {
  result: UseAsyncResult<ReputationEntryResponse[]>
  onOpenIp: (ip: string) => void
}

function ReputationSection({ result, onOpenIp }: ReputationSectionProps) {
  const columns = useMemo<Columns<ReputationEntryResponse>>(
    () => [
      {
        title: 'IP 地址',
        dataIndex: 'ip',
        key: 'ip',
        width: 160,
        fixed: 'left',
        render: (_: unknown, r: ReputationEntryResponse) => renderIpLink(r.ip, onOpenIp),
      },
      {
        title: '信誉分',
        dataIndex: 'score',
        key: 'score',
        width: 100,
        render: (n: number) => (
          <span className="fw-mono" style={{ fontWeight: 600, color: reputationColor(n) }}>
            {formatNumber(n)}
          </span>
        ),
      },
      {
        title: '失败次数',
        dataIndex: 'total_failures',
        key: 'total_failures',
        width: 110,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '封禁次数',
        dataIndex: 'total_bans',
        key: 'total_bans',
        width: 110,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '阈值调整',
        dataIndex: 'threshold_adjustment',
        key: 'threshold_adjustment',
        width: 110,
        render: (n: number) => <span className="fw-mono">{n > 0 ? `+${n}` : n}</span>,
      },
      {
        title: '最近失败',
        dataIndex: 'last_failure_at',
        key: 'last_failure_at',
        width: 180,
        render: (ts: number) => <span className="fw-mono">{formatDatetime(ts)}</span>,
      },
    ],
    [onOpenIp],
  )

  return (
    <DataTable<ReputationEntryResponse>
      data={result.data}
      isLoading={result.isLoading}
      isFetching={result.isUserFetching}
      error={result.error}
      onRetry={result.refetch}
      rowKey="ip"
      columns={columns}
      emptyScenario="no-data"
      emptyTitle="暂无信誉记录"
      emptyDescription="尚无 IP 积累失败/封禁历史形成信誉分"
      scroll={{ x: 'max-content' }}
      pagination={{ pageSize: 20, hideOnSinglePage: true }}
    />
  )
}

// ---------------------------------------------------------------------------
// 分区 7：阈值推荐
// ---------------------------------------------------------------------------

interface ThresholdSectionProps {
  result: UseAsyncResult<ThresholdRecommendationResponse>
}

function ThresholdSection({ result }: ThresholdSectionProps) {
  const columns = useMemo<Columns<ThresholdRecommendation>>(
    () => [
      {
        title: 'Jail',
        dataIndex: 'jail_name',
        key: 'jail_name',
        width: 150,
        render: (v: string) => (v ? <Tag>{v}</Tag> : <span>—</span>),
      },
      {
        title: '阈值调整',
        key: 'adjust',
        width: 220,
        render: (_: unknown, r: ThresholdRecommendation) => {
          const dir = directionMeta(r.direction)
          return (
            <Space size={6}>
              <span className="fw-mono">{formatNumber(r.current_threshold)}</span>
              <span style={{ color: 'var(--fw-text-secondary)' }}>→</span>
              <span className="fw-mono" style={{ fontWeight: 600 }}>
                {formatNumber(r.recommended_threshold)}
              </span>
              <Tag color={dir.color}>{dir.label}</Tag>
            </Space>
          )
        },
      },
      {
        title: '复发率',
        dataIndex: 'recidivism_rate',
        key: 'recidivism_rate',
        width: 100,
        render: (n: number) => <span className="fw-mono">{formatPercent(n)}</span>,
      },
      {
        title: '置信度',
        dataIndex: 'confidence',
        key: 'confidence',
        width: 100,
        render: (n: number) => <span className="fw-mono">{formatPercent(n)}</span>,
      },
      {
        title: '理由',
        dataIndex: 'reason',
        key: 'reason',
        render: (v: string) =>
          v ? (
            <Typography.Text type="secondary" style={{ fontSize: 13 }} ellipsis={{ tooltip: v }}>
              {v}
            </Typography.Text>
          ) : (
            <span>—</span>
          ),
      },
    ],
    [],
  )

  if (result.isLoading && !result.data) return <LoadingState variant="table" rows={5} />
  if (result.error && !result.data) return <ErrorState error={result.error} onRetry={result.refetch} />
  const d = result.data
  if (!d) return null

  return (
    <Flex vertical gap={12} className="fw-fade-in">
      <Typography.Paragraph style={{ marginBottom: 0 }}>
        {d.summary || <Typography.Text type="secondary">暂无阈值推荐结论</Typography.Text>}
      </Typography.Paragraph>
      <DataTable<ThresholdRecommendation>
        data={d.recommendations}
        isFetching={result.isUserFetching}
        rowKey="jail_name"
        columns={columns}
        emptyScenario="no-data"
        emptyTitle="暂无阈值推荐"
        emptyDescription="当前各 Jail 阈值无需调整，或数据不足以给出推荐"
        scroll={{ x: 'max-content' }}
        pagination={{ pageSize: 20, hideOnSinglePage: true }}
      />
    </Flex>
  )
}

// ---------------------------------------------------------------------------
// 分区 8：封禁成效（成效分级 + 时长直方图 + 时长推荐，三条端点各自独立取数/兜底）
// ---------------------------------------------------------------------------

interface EffectivenessSectionProps {
  effectiveness: UseAsyncResult<BanEffectivenessResponse>
  histogram: UseAsyncResult<BanDurationHistogramResponse>
  durationRec: UseAsyncResult<BanDurationRecommendationResponse>
}

function EffectivenessSection({ effectiveness, histogram, durationRec }: EffectivenessSectionProps) {
  return (
    <Flex vertical gap={24} className="fw-fade-in">
      <EffectivenessBlock result={effectiveness} />
      <HistogramBlock result={histogram} />
      <DurationRecBlock result={durationRec} />
    </Flex>
  )
}

function EffectivenessBlock({ result }: { result: UseAsyncResult<BanEffectivenessResponse> }) {
  const columns = useMemo<Columns<BanLevelEffectiveness>>(
    () => [
      { title: '档位', dataIndex: 'label', key: 'label', width: 160, render: (v: string) => v || '—' },
      {
        title: 'IP 数',
        dataIndex: 'total_ips',
        key: 'total_ips',
        width: 100,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '复发 IP',
        dataIndex: 'recidivist_ips',
        key: 'recidivist_ips',
        width: 100,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '复发率',
        dataIndex: 'recidivism_rate',
        key: 'recidivism_rate',
        width: 100,
        render: (n: number) => <span className="fw-mono">{formatPercent(n)}</span>,
      },
      {
        title: '永久封禁',
        dataIndex: 'permanent_bans',
        key: 'permanent_bans',
        width: 100,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '评估',
        dataIndex: 'verdict',
        key: 'verdict',
        render: (v: string) => (v ? <Tag color="blue">{v}</Tag> : <span>—</span>),
      },
    ],
    [],
  )

  if (result.isLoading && !result.data) return <LoadingState variant="cards" rows={2} />
  if (result.error && !result.data) return <ErrorState error={result.error} onRetry={result.refetch} />
  const d = result.data
  if (!d) return null

  return (
    <Flex vertical gap={12}>
      <Typography.Title level={5} style={{ margin: 0 }}>
        分级封禁成效
      </Typography.Title>
      <Typography.Paragraph style={{ marginBottom: 0 }}>
        {d.summary || <Typography.Text type="secondary">暂无成效结论</Typography.Text>}
      </Typography.Paragraph>
      <div style={GRID_AUTO_FIT}>
        <StatCard
          label="总体复发率"
          value={formatPercent(d.overall_recidivism_rate)}
          icon={RetweetOutlined}
          tone="warning"
          mono
          footer="被封禁后再次出现的比例"
        />
        <StatCard
          label="涉及独立 IP"
          value={formatNumber(d.total_unique_ips)}
          icon={TeamOutlined}
          footer="纳入成效统计的独立 IP 数"
        />
      </div>
      <DataTable<BanLevelEffectiveness>
        data={d.levels}
        isFetching={result.isUserFetching}
        rowKey="level"
        columns={columns}
        emptyScenario="no-data"
        emptyTitle="暂无分级成效数据"
        scroll={{ x: 'max-content' }}
        pagination={{ pageSize: 10, hideOnSinglePage: true }}
      />
    </Flex>
  )
}

function HistogramBlock({ result }: { result: UseAsyncResult<BanDurationHistogramResponse> }) {
  const base = useChartBase()
  const option = useMemo(() => {
    const labels = result.data?.labels ?? []
    const counts = result.data?.counts ?? []
    return barOption(base, { labels, values: counts }, { name: '封禁数', color: base.palette[0] })
  }, [base, result.data])

  if (result.isLoading && !result.data) return <LoadingState variant="chart" />
  if (result.error && !result.data) return <ErrorState error={result.error} onRetry={result.refetch} />
  const d = result.data
  if (!d) return null

  return (
    <div>
      <Typography.Title level={5} style={{ margin: '0 0 8px' }}>
        封禁时长直方图
      </Typography.Title>
      <ChartCard title="按时长分布的封禁数" footnote={`合计 ${formatNumber(d.total)} 条`}>
        <BaseChart option={option} height={260} empty={isEmptySeries(d.counts)} />
      </ChartCard>
    </div>
  )
}

function DurationRecBlock({ result }: { result: UseAsyncResult<BanDurationRecommendationResponse> }) {
  const columns = useMemo<Columns<BanDurationRecommendation>>(
    () => [
      {
        title: 'Jail',
        dataIndex: 'jail_name',
        key: 'jail_name',
        width: 150,
        render: (v: string) => (v ? <Tag>{v}</Tag> : <span>—</span>),
      },
      {
        title: '封禁时长调整',
        key: 'adjust',
        width: 220,
        render: (_: unknown, r: BanDurationRecommendation) => (
          <Space size={6}>
            <span className="fw-mono">{formatDuration(r.current_ban_time)}</span>
            <span style={{ color: 'var(--fw-text-secondary)' }}>→</span>
            <span className="fw-mono" style={{ fontWeight: 600 }}>
              {formatDuration(r.recommended_ban_time)}
            </span>
          </Space>
        ),
      },
      {
        title: '复发数',
        dataIndex: 'recidivist_count',
        key: 'recidivist_count',
        width: 100,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '中位回归',
        dataIndex: 'median_return_secs',
        key: 'median_return_secs',
        width: 120,
        render: (n: number) => <span className="fw-mono">{formatDuration(n)}</span>,
      },
      {
        title: '需调整',
        dataIndex: 'needs_adjustment',
        key: 'needs_adjustment',
        width: 100,
        render: (v: boolean) => (v ? <Tag color="orange">需调整</Tag> : <Tag color="green">维持</Tag>),
      },
      {
        title: '理由',
        dataIndex: 'reason',
        key: 'reason',
        render: (v: string) =>
          v ? (
            <Typography.Text type="secondary" style={{ fontSize: 13 }} ellipsis={{ tooltip: v }}>
              {v}
            </Typography.Text>
          ) : (
            <span>—</span>
          ),
      },
    ],
    [],
  )

  if (result.isLoading && !result.data) return <LoadingState variant="table" rows={4} />
  if (result.error && !result.data) return <ErrorState error={result.error} onRetry={result.refetch} />
  const d = result.data
  if (!d) return null

  return (
    <Flex vertical gap={12}>
      <Typography.Title level={5} style={{ margin: 0 }}>
        封禁时长推荐
      </Typography.Title>
      <Typography.Paragraph style={{ marginBottom: 0 }}>
        {d.summary || <Typography.Text type="secondary">暂无时长推荐结论</Typography.Text>}
      </Typography.Paragraph>
      <DataTable<BanDurationRecommendation>
        data={d.recommendations}
        isFetching={result.isUserFetching}
        rowKey="jail_name"
        columns={columns}
        emptyScenario="no-data"
        emptyTitle="暂无时长推荐"
        scroll={{ x: 'max-content' }}
        pagination={{ pageSize: 20, hideOnSinglePage: true }}
      />
    </Flex>
  )
}

// ---------------------------------------------------------------------------
// IP 综合分析抽屉（深链 /analysis/ip/:ip 与页内搜索共用）
// ---------------------------------------------------------------------------

interface IpAnalysisDrawerProps {
  ip: string
  onClose: () => void
}

function IpAnalysisDrawer({ ip, onClose }: IpAnalysisDrawerProps) {
  const base = useChartBase()
  const detail = useAsync<AnalysisIpResponse>((signal) => getAnalysisIp(ip, signal))

  // 抽屉开着时，「刷新当前页」也重取本 IP 的分析
  useRefreshSignal(() => detail.refetch())

  const radar = useMemo(() => {
    const r = detail.data?.risk
    if (!r) return null
    const values = RISK_DIMS.map((dim) => r[dim.key])
    // 雷达量程按当前向量动态取：维度是原始分（可 >1），固定 0-1 量程会把图形压满外环
    const dimMax = Math.ceil(Math.max(1, ...values))
    return radarOption(base, {
      indicators: RISK_DIMS.map((dim) => ({ name: dim.label, max: dimMax })),
      values,
      name: '风险向量',
    })
  }, [base, detail.data])

  const banColumns = useMemo<Columns<BanResponse>>(
    () => [
      {
        title: 'Jail',
        dataIndex: 'jail',
        key: 'jail',
        width: 120,
        render: (v: string) => (v ? <Tag>{v}</Tag> : <span>—</span>),
      },
      {
        title: '封禁时间',
        dataIndex: 'banned_at',
        key: 'banned_at',
        width: 170,
        render: (ts: number) => <span className="fw-mono">{formatDatetime(ts)}</span>,
      },
      {
        title: '剩余',
        dataIndex: 'remaining_seconds',
        key: 'remaining_seconds',
        width: 110,
        render: (_: unknown, r: BanResponse) =>
          r.is_permanent ? <Tag color="red">永久</Tag> : <span className="fw-mono">{formatDuration(r.remaining_seconds)}</span>,
      },
      {
        title: '累计',
        dataIndex: 'ban_count',
        key: 'ban_count',
        width: 80,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '原因',
        dataIndex: 'reason',
        key: 'reason',
        render: (v: string) =>
          v ? (
            <Typography.Text type="secondary" style={{ fontSize: 13 }} ellipsis={{ tooltip: v }}>
              {v}
            </Typography.Text>
          ) : (
            <span>—</span>
          ),
      },
    ],
    [],
  )

  const reputationItems = useMemo(() => {
    const rep = detail.data?.reputation
    if (!rep) return []
    return [
      {
        key: 'score',
        label: '信誉分',
        children: (
          <span className="fw-mono" style={{ fontWeight: 600, color: reputationColor(rep.score) }}>
            {formatNumber(rep.score)}
          </span>
        ),
      },
      { key: 'total_failures', label: '失败次数', children: formatNumber(rep.total_failures) },
      { key: 'total_bans', label: '封禁次数', children: formatNumber(rep.total_bans) },
      { key: 'threshold_adjustment', label: '阈值调整', children: rep.threshold_adjustment > 0 ? `+${rep.threshold_adjustment}` : `${rep.threshold_adjustment}` },
      {
        key: 'last_failure_at',
        label: '最近失败',
        children: <span className="fw-mono">{formatDatetime(rep.last_failure_at)}</span>,
      },
    ]
  }, [detail.data])

  const predictionItems = useMemo(() => {
    const p = detail.data?.prediction
    if (!p) return []
    return [
      { key: 'urgency', label: '紧迫度', children: <Tag color={urgencyColor(p.urgency)}>{p.urgency || '—'}</Tag> },
      { key: 'confidence', label: '置信度', children: formatPercent(p.confidence) },
      {
        key: 'predicted_next_attack',
        label: '预测下次攻击',
        children: <span className="fw-mono">{formatDatetime(p.predicted_next_attack)}</span>,
      },
      {
        key: 'last_ban_at',
        label: '最近封禁',
        children: <span className="fw-mono">{formatDatetime(p.last_ban_at)}</span>,
      },
      { key: 'remaining_secs', label: '剩余时间', children: formatDuration(p.remaining_secs) },
      { key: 'median_interval_secs', label: '中位间隔', children: formatDuration(p.median_interval_secs) },
      { key: 'ban_count', label: '累计封禁', children: formatNumber(p.ban_count) },
      { key: 'jail_name', label: '来源 Jail', children: p.jail_name || '—' },
    ]
  }, [detail.data])

  const data = detail.data

  return (
    <Drawer
      open
      title={
        <Space size={8}>
          <span>IP 综合分析</span>
          <span className="fw-mono" style={{ color: 'var(--fw-text-secondary)' }}>
            {ip}
          </span>
          {data && (data.is_whitelisted ? <Tag color="green">白名单</Tag> : <Tag>非白名单</Tag>)}
        </Space>
      }
      width={680}
      onClose={onClose}
      destroyOnHidden
      footer={
        <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <Button icon={<ReloadOutlined />} onClick={detail.refetch} loading={detail.isRefreshing}>
            刷新
          </Button>
          <Button onClick={onClose}>关闭</Button>
        </Space>
      }
    >
      {detail.isLoading && !data && <LoadingState variant="detail" />}
      {detail.error && !data && <ErrorState error={detail.error} onRetry={detail.refetch} />}

      {data && (
        <Flex vertical gap={20} className="fw-fade-in">
          {/* 风险向量 */}
          <div>
            <Typography.Title level={5} style={{ margin: '0 0 8px' }}>
              风险向量
            </Typography.Title>
            {data.risk && radar ? (
              <ChartCard
                title="7 维风险分布"
                footnote={
                  <span>
                    总风险 <span className="fw-mono">{fmtScore(data.risk.total_risk)}</span> · 最近事件{' '}
                    <span className="fw-mono">{formatDatetime(data.risk.last_event_at)}</span>
                  </span>
                }
              >
                <BaseChart option={radar} height={280} />
              </ChartCard>
            ) : (
              <EmptyState scenario="no-data" title="无风险向量数据" description="该 IP 暂无多维风险记录（可能未开启 risk_engine）" />
            )}
          </div>

          {/* 封禁历史 */}
          <div>
            <Typography.Title level={5} style={{ margin: '0 0 8px' }}>
              封禁历史
            </Typography.Title>
            <DataTable<BanResponse>
              data={data.ban_history}
              columns={banColumns}
              emptyScenario="no-data"
              emptyTitle="无封禁历史"
              scroll={{ x: 'max-content' }}
              pagination={{ pageSize: 5, hideOnSinglePage: true }}
            />
          </div>

          {/* 信誉 */}
          <div>
            <Typography.Title level={5} style={{ margin: '0 0 8px' }}>
              IP 信誉
            </Typography.Title>
            {data.reputation ? (
              <Descriptions column={1} size="small" bordered items={reputationItems} />
            ) : (
              <Typography.Text type="secondary">无数据</Typography.Text>
            )}
          </div>

          {/* 攻击预测 */}
          <div>
            <Typography.Title level={5} style={{ margin: '0 0 8px' }}>
              攻击预测
            </Typography.Title>
            {data.prediction ? (
              <Descriptions column={1} size="small" bordered items={predictionItems} />
            ) : (
              <Typography.Text type="secondary">无数据</Typography.Text>
            )}
          </div>
        </Flex>
      )}
    </Drawer>
  )
}
