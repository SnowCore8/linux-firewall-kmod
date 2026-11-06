import { useCallback, useMemo, useState } from 'react'
import {
  Button,
  Descriptions,
  Drawer,
  Space,
  Tag,
  Typography,
  type TableProps,
} from 'antd'
import {
  ClockCircleOutlined,
  FireOutlined,
  RadarChartOutlined,
  ReloadOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import { PageHeader } from '../components/PageHeader.tsx'
import { StatCard } from '../components/StatCard.tsx'
import { DataTable } from '../components/DataTable.tsx'
import { ChartCard } from '../components/ChartCard.tsx'
import { BaseChart, useChartBase } from '../components/charts/BaseChart.tsx'
import { EmptyState } from '../components/state/EmptyState.tsx'
import { ErrorState } from '../components/state/ErrorState.tsx'
import { LoadingState } from '../components/state/LoadingState.tsx'
import { StaleNotice } from '../components/state/StaleNotice.tsx'
import { useAsync } from '../hooks/useAsync.ts'
import { useRefreshSignal } from '../hooks/useRefreshSignal.ts'
import { getRiskVectors, getRiskVector, getRiskEvents } from '../api/endpoints.ts'
import { radarOption } from '../lib/charts.ts'
import { formatDatetime, formatNumber } from '../lib/format.ts'
import { chartColor, THREAT_COLORS } from '../theme/tokens.ts'
import type { RiskEventEntry, RiskVectorResponse } from '../api/types.ts'

/**
 * 风险引擎页 —— 多维风险向量（v2）的只读洞察，受后端 flag `risk_engine.enabled` 控制。
 *
 * 关闭时守护进程对三条 risk 路由一律回 503（业务码 50003「依赖未就绪」，见 http/risk.go 的
 * WriteServiceUnavailable）。本页把「503」当成**功能未启用**而非普通故障：ApiError.status===503
 * 走 EmptyState(scenario="disabled") 并说明如何开启，其余错误才走带重试的 ErrorState。
 *
 * 数据口径（对齐后端，不猜）：7 个维度（failure/ban/scan/bruteforce/ddos/geo/cluster）是**原始
 * 累加分**，范围 [0,+∞)、典型 [0,100]（见 internal/risk/types.go 的 RiskVector 注释），并**不归一
 * 化**；total_risk 是这 7 维的直接相加（见 http/risk.go）。因此「高危」用一条明确标注的绝对阈值
 * 界定，雷达图的量程按当前向量动态取，避免用固定 0-1 量程把数据压成一点。
 *
 * 列表已按 total_risk 降序（服务端），最多 100 条；点击 IP 拉开抽屉，抽屉内并行取单 IP 向量与
 * 攻击事件历史，用雷达图 + 事件表呈现。
 */

/**
 * 高危阈值：total_risk ≥ 该值记为「高危 IP」。
 * total_risk 是 7 维原始分之和，无固定上界；取 50 作为界线并在卡片脚注明确标注，
 * 使「高危」有确定、可复核的含义，而非随列表浮动的相对值。
 */
const HIGH_RISK_THRESHOLD = 50

/** 「近期活跃」窗口（秒）：last_event_at 落在该窗口内计为活跃。 */
const RECENT_WINDOW_SECONDS = 3600

/** 7 个风险维度（雷达轴 / 表格列共用同一份定义，顺序即雷达轴顺序）。 */
type DimKey = 'failure' | 'ban' | 'scan' | 'bruteforce' | 'ddos' | 'geo' | 'cluster'

const DIMENSIONS: ReadonlyArray<{ key: DimKey; label: string }> = [
  { key: 'failure', label: '失败' },
  { key: 'ban', label: '封禁' },
  { key: 'scan', label: '扫描' },
  { key: 'bruteforce', label: '爆破' },
  { key: 'ddos', label: 'DDoS' },
  { key: 'geo', label: '地域' },
  { key: 'cluster', label: '集群' },
]

/** 事件类型 → 中文标签 + 图表调色板配色（复用 theme/tokens 的 chartColor）。 */
const EVENT_TYPE_META: Record<string, { label: string; color: string }> = {
  failure: { label: '认证失败', color: chartColor(0) },
  ban: { label: '封禁历史', color: chartColor(1) },
  scan: { label: '扫描', color: chartColor(2) },
  bruteforce: { label: '爆破', color: chartColor(3) },
  ddos: { label: 'DDoS', color: chartColor(4) },
  geo: { label: '异常地域', color: chartColor(5) },
  cluster: { label: '关联集群', color: chartColor(6) },
}

/** 取事件类型的展示元信息；未知类型原样回显、不上色（便于发现后端新增取值）。 */
function eventMeta(type: string): { label: string; color?: string } {
  const meta = EVENT_TYPE_META[type]
  return meta ? { label: meta.label, color: meta.color } : { label: type }
}

/** 按 total_risk 量级映射到威胁色阶（复用 theme/tokens 的 THREAT_COLORS）。 */
function riskColor(total: number): string {
  if (total >= HIGH_RISK_THRESHOLD) return THREAT_COLORS.critical
  if (total >= HIGH_RISK_THRESHOLD * 0.6) return THREAT_COLORS.high
  if (total >= HIGH_RISK_THRESHOLD * 0.3) return THREAT_COLORS.medium
  if (total > 0) return THREAT_COLORS.low
  return THREAT_COLORS.safe
}

type VectorColumn = NonNullable<TableProps<RiskVectorResponse>['columns']>[number]
type EventColumn = NonNullable<TableProps<RiskEventEntry>['columns']>[number]

export default function Risk() {
  const query = useAsync((signal) => getRiskVectors(signal))
  const [detailIp, setDetailIp] = useState<string | null>(null)

  // 命令面板 / 顶栏广播的「刷新当前页」
  useRefreshSignal(() => query.refetch())

  const openDetail = useCallback((ip: string) => setDetailIp(ip), [])
  const closeDetail = useCallback(() => setDetailIp(null), [])

  const vectors = query.data?.vectors ?? []
  const total = query.data?.total ?? 0

  // 派生指标只用响应里的真实字段：total、total_risk、last_event_at
  const derived = useMemo(() => {
    const nowSec = Math.floor(Date.now() / 1000)
    let high = 0
    let max = 0
    let recent = 0
    for (const v of vectors) {
      if (v.total_risk >= HIGH_RISK_THRESHOLD) high += 1
      if (v.total_risk > max) max = v.total_risk
      if (v.last_event_at > 0 && nowSec - v.last_event_at <= RECENT_WINDOW_SECONDS) recent += 1
    }
    return { high, max, recent }
  }, [vectors])

  const columns = useMemo<VectorColumn[]>(
    () => [
      {
        title: 'IP 地址',
        dataIndex: 'ip',
        key: 'ip',
        width: 160,
        fixed: 'left',
        render: (_: unknown, record: RiskVectorResponse) => (
          <Typography.Link className="fw-mono" onClick={() => openDetail(record.ip)}>
            {record.ip}
          </Typography.Link>
        ),
      },
      {
        title: '总风险',
        dataIndex: 'total_risk',
        key: 'total_risk',
        width: 110,
        sorter: (a: RiskVectorResponse, b: RiskVectorResponse) => a.total_risk - b.total_risk,
        render: (v: number) => (
          <Tag
            color={riskColor(v)}
            className="fw-mono"
            style={{ marginInlineEnd: 0, fontWeight: 600 }}
          >
            {formatNumber(v)}
          </Tag>
        ),
      },
      ...DIMENSIONS.map(
        (d): VectorColumn => ({
          title: d.label,
          dataIndex: d.key,
          key: d.key,
          width: 78,
          align: 'right',
          render: (v: number) => (
            <span
              className="fw-mono"
              style={{ fontSize: 12.5, color: v > 0 ? undefined : 'var(--fw-text-secondary)' }}
            >
              {formatNumber(v)}
            </span>
          ),
        }),
      ),
      {
        title: '最近事件',
        dataIndex: 'last_event_at',
        key: 'last_event_at',
        width: 175,
        render: (ts: number) => <span className="fw-mono">{formatDatetime(ts)}</span>,
      },
      {
        title: '更新时间',
        dataIndex: 'updated_at',
        key: 'updated_at',
        width: 175,
        render: (ts: number) => <span className="fw-mono">{formatDatetime(ts)}</span>,
      },
    ],
    [openDetail],
  )

  // 四态互斥：有数据只看数据；无数据时 503→未启用、其它错误→ErrorState、加载中→骨架
  const hasData = query.data != null
  const isDisabled = !hasData && query.error?.status === 503
  const showError = !hasData && query.error != null && query.error.status !== 503
  const showLoading = !hasData && query.isLoading

  return (
    <>
      <PageHeader
        title="风险引擎"
        description="多维风险向量与攻击事件溯源（需后端开启 risk_engine.enabled）"
        breadcrumb={[{ title: '智能' }, { title: '风险引擎' }]}
        extra={
          <Button
            icon={<ReloadOutlined />}
            onClick={query.refetch}
            loading={query.isRefreshing}
          >
            刷新
          </Button>
        }
      />

      <StaleNotice
        visible={query.isStale}
        onRetry={query.refetch}
        description="最近一次刷新失败，以下为上一次成功获取的风险向量，可能已不是最新状态。"
        style={{ marginBottom: 16 }}
      />

      {showLoading && (
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          <LoadingState variant="cards" rows={4} />
          <LoadingState variant="table" rows={8} />
        </Space>
      )}

      {isDisabled && (
        <EmptyState
          scenario="disabled"
          title="多维风险引擎未启用"
          description={
            <>
              守护进程返回 503（risk_engine.enabled=false）。
              <br />
              请在守护进程配置中开启 risk_engine.enabled 并重启后，再回到本页查看风险向量。
            </>
          }
          actionLabel="重新检测"
          onAction={query.refetch}
        />
      )}

      {showError && <ErrorState error={query.error} onRetry={query.refetch} />}

      {hasData && (
        <>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: 16,
              marginBottom: 16,
            }}
          >
            <StatCard
              label="向量总数"
              value={formatNumber(total)}
              icon={RadarChartOutlined}
              tone="info"
              footer="后端记录的风险向量条数（最多返回 100）"
            />
            <StatCard
              label="高危 IP"
              value={formatNumber(derived.high)}
              icon={WarningOutlined}
              tone="danger"
              footer={`total_risk ≥ ${HIGH_RISK_THRESHOLD}（7 维原始分之和）`}
            />
            <StatCard
              label="最高总风险"
              value={formatNumber(derived.max)}
              icon={FireOutlined}
              tone="warning"
              footer="当前列表中最大的 total_risk"
            />
            <StatCard
              label="近 1 小时活跃"
              value={formatNumber(derived.recent)}
              icon={ClockCircleOutlined}
              footer={`last_event_at 落在最近 ${RECENT_WINDOW_SECONDS / 60} 分钟内`}
            />
          </div>

          <DataTable<RiskVectorResponse>
            data={vectors}
            isLoading={query.isLoading}
            isFetching={query.isUserFetching}
            error={null}
            rowKey="ip"
            columns={columns}
            emptyScenario="no-data"
            emptyTitle="暂无风险向量"
            emptyDescription="风险引擎已启用，但尚未记录任何 IP 的多维风险向量"
            toolbar={
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                按 total_risk 降序 · 共 {formatNumber(total)} 条
                {total > vectors.length ? `（仅显示前 ${vectors.length} 条）` : ''}
              </Typography.Text>
            }
            pagination={{
              pageSize: 20,
              showSizeChanger: true,
              pageSizeOptions: [20, 50, 100],
              showTotal: (t) => `共 ${t} 条`,
            }}
            scroll={{ x: 'max-content' }}
          />
        </>
      )}

      {detailIp && <RiskDetailDrawer key={detailIp} ip={detailIp} onClose={closeDetail} />}
    </>
  )
}

// ---------------------------------------------------------------------------
// 详情抽屉：单 IP 风险向量（雷达）+ 攻击事件历史
// ---------------------------------------------------------------------------

interface RiskDetailDrawerProps {
  ip: string
  onClose: () => void
}

function RiskDetailDrawer({ ip, onClose }: RiskDetailDrawerProps) {
  const base = useChartBase()
  const vector = useAsync((signal) => getRiskVector(ip, signal))
  const events = useAsync((signal) => getRiskEvents(ip, signal))

  const retryAll = useCallback(() => {
    vector.refetch()
    events.refetch()
  }, [vector.refetch, events.refetch])

  // 雷达量程按当前向量动态取：维度是原始分（可 >1），固定 0-1 量程会把图形压满外环
  const radar = useMemo(() => {
    const v = vector.data
    if (!v) return null
    const values = DIMENSIONS.map((d) => v[d.key])
    const dimMax = Math.ceil(Math.max(1, ...values))
    return radarOption(base, {
      indicators: DIMENSIONS.map((d) => ({ name: d.label, max: dimMax })),
      values,
      name: v.ip,
    })
  }, [base, vector.data])

  const allZero = useMemo(() => {
    const v = vector.data
    if (!v) return true
    return DIMENSIONS.every((d) => v[d.key] === 0)
  }, [vector.data])

  const summaryItems = useMemo(() => {
    const v = vector.data
    if (!v) return []
    return [
      {
        key: 'total_risk',
        label: '总风险',
        children: (
          <Tag
            color={riskColor(v.total_risk)}
            className="fw-mono"
            style={{ marginInlineEnd: 0, fontWeight: 600 }}
          >
            {formatNumber(v.total_risk)}
          </Tag>
        ),
      },
      {
        key: 'last_event_at',
        label: '最近事件',
        children: <span className="fw-mono">{formatDatetime(v.last_event_at)}</span>,
      },
      {
        key: 'updated_at',
        label: '更新时间',
        children: <span className="fw-mono">{formatDatetime(v.updated_at)}</span>,
      },
    ]
  }, [vector.data])

  const eventColumns = useMemo<EventColumn[]>(
    () => [
      {
        title: '事件类型',
        dataIndex: 'event_type',
        key: 'event_type',
        width: 130,
        render: (t: string) => {
          const meta = eventMeta(t)
          return (
            <Tag color={meta.color} style={{ marginInlineEnd: 0 }}>
              {meta.label}
            </Tag>
          )
        },
      },
      {
        title: '增量',
        dataIndex: 'increment',
        key: 'increment',
        width: 100,
        align: 'right',
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '发生时间',
        dataIndex: 'occurred_at',
        key: 'occurred_at',
        width: 180,
        render: (ts: number) => <span className="fw-mono">{formatDatetime(ts)}</span>,
      },
    ],
    [],
  )

  return (
    <Drawer
      open
      title={`风险详情 · ${ip}`}
      width={560}
      onClose={onClose}
      destroyOnHidden
      footer={
        <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <Button
            icon={<ReloadOutlined />}
            onClick={retryAll}
            loading={vector.isRefreshing || events.isRefreshing}
          >
            刷新
          </Button>
          <Button onClick={onClose}>关闭</Button>
        </Space>
      }
    >
      {vector.isLoading && vector.data == null && <LoadingState variant="detail" />}
      {vector.error && vector.data == null && (
        <ErrorState error={vector.error} onRetry={retryAll} />
      )}
      {vector.data && (
        <Space direction="vertical" size={16} style={{ width: '100%' }} className="fw-fade-in">
          <Descriptions column={1} size="small" bordered items={summaryItems} />
          <ChartCard title="风险维度雷达">
            <BaseChart
              option={radar ?? {}}
              height={280}
              empty={allZero}
              emptyText="该 IP 暂无风险维度数据"
            />
          </ChartCard>
          <div>
            <Typography.Title level={5} style={{ marginTop: 0, marginBottom: 8 }}>
              攻击事件历史
            </Typography.Title>
            <DataTable<RiskEventEntry>
              data={events.data ? events.data.events : null}
              isLoading={events.isLoading}
              isFetching={events.isUserFetching}
              error={events.error}
              onRetry={events.refetch}
              rowKey="id"
              columns={eventColumns}
              size="small"
              emptyScenario="no-data"
              emptyTitle="暂无攻击事件"
              emptyDescription="该 IP 尚未记录任何攻击事件（最近 100 条）"
              pagination={{
                pageSize: 10,
                showSizeChanger: false,
                hideOnSinglePage: true,
                showTotal: (t) => `共 ${t} 条`,
              }}
              scroll={{ x: 'max-content' }}
            />
          </div>
        </Space>
      )}
    </Drawer>
  )
}
