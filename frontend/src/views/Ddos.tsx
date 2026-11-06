import { useMemo, type ReactNode } from 'react'
import { Alert, Button, Flex, Tabs, Tag, Typography, type TableColumnsType } from 'antd'
import {
  AlertOutlined,
  DashboardOutlined,
  FundOutlined,
  RadarChartOutlined,
  ReloadOutlined,
  SplitCellsOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons'
import type { EChartsOption } from 'echarts-for-react'
import { PageHeader } from '../components/PageHeader.tsx'
import { StatCard } from '../components/StatCard.tsx'
import { ChartCard } from '../components/ChartCard.tsx'
import { DataTable } from '../components/DataTable.tsx'
import { StaleNotice } from '../components/state/StaleNotice.tsx'
import { BaseChart, useChartBase } from '../components/charts/BaseChart.tsx'
import { LoadingState } from '../components/state/LoadingState.tsx'
import { ErrorState } from '../components/state/ErrorState.tsx'
import { useAsync, type UseAsyncResult } from '../hooks/useAsync.ts'
import { useLiveData } from '../hooks/useLiveData.ts'
import { useRefreshSignal } from '../hooks/useRefreshSignal.ts'
import { useSseDomain, useSseState } from '../providers/SseProvider.tsx'
import {
  getAnomalies,
  getCollaborativeAttacks,
  getCurrentRates,
  getIcmpTypes,
  getIpFragments,
  getPacketSizes,
  getPortScanners,
  getRateWindows,
  getRatesHistory,
  getServiceProbes,
  getTtlDistribution,
  getUdpPorts,
} from '../api/endpoints.ts'
import {
  formatBytes,
  formatClock,
  formatDatetime,
  formatNumber,
  formatPercent,
  formatRate,
} from '../lib/format.ts'
import { barOption, gaugeOption, lineOption, pieOption, radarOption } from '../lib/charts.ts'
import { SEMANTIC } from '../theme/tokens.ts'
import type {
  CollaborativeAttack,
  IpAnomalyEntry,
  PortScannerEntry,
  RateResponse,
  ServiceProbeEntry,
} from '../api/types.ts'

/**
 * DDoS 监控页 —— 把内核遥测的四类读数收进一页，用 Tabs 分区避免一屏塞爆。
 *
 * 分区与数据来路：
 *   1. 实时速率：三档窗口快照 + 速率历史折线 + 当前速率表。当前速率是「整表镜像」域，
 *      SSE `rates` 帧（秒级）与 REST 拉取用 useLiveData 按新鲜度仲裁，视图只消费一个值；
 *      分协议速率（syn/udp/icmp/ack/rst/fin）折进可展开行，主表只留 IP/总 pps/字节速率三列。
 *   2. 流量分布：包长/TTL/UDP 端口/ICMP 类型/IP 分片，全部是累计口径的内核计数，
 *      各自独立拉取、独立兜四态，互不干扰。
 *   3. 异常检测：全局异常分（0-100）仪表 + 维度偏差（0-1）雷达 + per-IP 离群表。
 *      global_features 为 null 表示样本未达护栏，此时分数为 0、维度为空——用 Alert + 空态
 *      如实说明，不把「0 分」渲染成「安全」。
 *   4. 扫描探测：端口扫描 / 服务探测 / 协同攻击三张表，检出阈值与总数走行内说明。
 *
 * 每个 Tab 是自足的分区组件：首次激活才挂载（AntD Tabs 惰性渲染），挂载即拉取并轮询，
 * 各自订阅「刷新当前页」信号只重取自己的数据。全部走设计系统的 StatCard/ChartCard/
 * BaseChart/DataTable，加载/空/错误/实时四态由封装统一兜。
 */

/** 当前速率 REST 校准间隔；SSE 活着时兜底校准，断连时充当主数据源。 */
const RATES_POLL_MS = 10_000
/** 速率历史轮询间隔。 */
const HISTORY_POLL_MS = 15_000
/** 分布/异常类累计计数的轮询间隔。 */
const DIST_POLL_MS = 30_000
/** 扫描探测类累计计数的轮询间隔。 */
const SCAN_POLL_MS = 30_000
/** 速率历史取最近 n 个点。 */
const HISTORY_LIMIT = 60
/** 端口/类型分布只画 Top-N。 */
const TOP_N = 10

/** 0-100 分数 → 语义色（越高越危险）。 */
function scoreColor(score: number): string {
  if (score >= 70) return SEMANTIC.danger
  if (score >= 40) return SEMANTIC.warning
  return SEMANTIC.success
}

/** 0-100 分数 → StatCard 语义 tone。 */
function scoreTone(score: number): 'success' | 'warning' | 'danger' {
  if (score >= 70) return 'danger'
  if (score >= 40) return 'warning'
  return 'success'
}

/** 展开行里的小读数单元（标签 + 等宽数值）。 */
function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <Flex vertical gap={2} style={{ minWidth: 108 }}>
      <Typography.Text type="secondary" style={{ fontSize: 11 }}>
        {label}
      </Typography.Text>
      <span className="fw-mono" style={{ fontSize: 14, fontWeight: 600 }}>
        {value}
      </span>
    </Flex>
  )
}

/** 分区小标题（标题 + 一句话说明）。 */
function SectionHeading({ title, description }: { title: string; description?: string }) {
  return (
    <Flex align="baseline" gap={8} wrap="wrap">
      <Typography.Title level={5} style={{ margin: 0 }}>
        {title}
      </Typography.Title>
      {description && (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {description}
        </Typography.Text>
      )}
    </Flex>
  )
}

/**
 * 图表块外壳 —— 把「一次独立拉取」的加载/错误/空态与 ChartCard+BaseChart 缝在一起。
 * 数据未到（null）时按有无错误分别渲染 ErrorState / LoadingState；有数据后交给 BaseChart，
 * 空数据由 empty 标志落成设计系统空态而非一张误导性的空坐标轴。
 */
interface ChartFrameProps<T> {
  title: ReactNode
  query: UseAsyncResult<T>
  option: EChartsOption
  empty: boolean
  emptyText?: string
  height?: number
  footnote?: ReactNode
}

function ChartFrame<T>({
  title,
  query,
  option,
  empty,
  emptyText,
  height = 240,
  footnote,
}: ChartFrameProps<T>) {
  let body: ReactNode
  if (query.data == null) {
    body = query.error ? (
      <ErrorState error={query.error} onRetry={query.refetch} />
    ) : (
      <LoadingState variant="chart" />
    )
  } else {
    body = (
      <BaseChart
        option={option}
        height={height}
        empty={empty}
        emptyText={emptyText}
        loading={query.isRefreshing}
      />
    )
  }
  return (
    <ChartCard title={title} footnote={footnote}>
      {body}
    </ChartCard>
  )
}

/** 当前速率行的分协议明细（展开行）。 */
function ProtocolBreakdown({ record }: { record: RateResponse }) {
  return (
    <Flex wrap="wrap" gap={16}>
      <MiniStat label="SYN pps" value={formatRate(record.syn_packets_per_sec, 'pps')} />
      <MiniStat label="UDP pps" value={formatRate(record.udp_packets_per_sec, 'pps')} />
      <MiniStat label="ICMP pps" value={formatRate(record.icmp_packets_per_sec, 'pps')} />
      <MiniStat label="ACK pps" value={formatRate(record.ack_packets_per_sec, 'pps')} />
      <MiniStat label="RST pps" value={formatRate(record.rst_packets_per_sec, 'pps')} />
      <MiniStat label="FIN pps" value={formatRate(record.fin_packets_per_sec, 'pps')} />
    </Flex>
  )
}

export default function Ddos() {
  const realtimeState = useSseState()

  return (
    <>
      <PageHeader
        title="DDoS 监控"
        description="实时速率、流量分布、异常检测与扫描探测的集中观测面板"
        breadcrumb={[{ title: '防护' }, { title: 'DDoS 监控' }]}
        realtimeState={realtimeState}
      />
      <Tabs
        defaultActiveKey="rates"
        className="fw-fade-in"
        items={[
          { key: 'rates', label: '实时速率', children: <RatesSection /> },
          { key: 'distribution', label: '流量分布', children: <DistributionSection /> },
          { key: 'anomaly', label: '异常检测', children: <AnomalySection /> },
          { key: 'scan', label: '扫描探测', children: <ScanSection /> },
        ]}
      />
    </>
  )
}

// ---------------------------------------------------------------------------
// 分区一：实时速率
// ---------------------------------------------------------------------------

function RatesSection() {
  const base = useChartBase()
  const ratesDomain = useSseDomain('rates')

  const ratesLive = useLiveData<RateResponse[]>({
    sseValue: ratesDomain.value,
    sseSeq: ratesDomain.seq,
    rest: getCurrentRates,
    refreshInterval: RATES_POLL_MS,
  })
  const windows = useAsync((signal) => getRateWindows(signal), { refreshInterval: RATES_POLL_MS })
  const history = useAsync((signal) => getRatesHistory(HISTORY_LIMIT, signal), {
    refreshInterval: HISTORY_POLL_MS,
  })

  useRefreshSignal(() => {
    ratesLive.refetch()
    windows.refetch()
    history.refetch()
  })

  const ppsOption = useMemo(() => {
    const h = history.data ?? []
    return lineOption(
      base,
      { labels: h.map((p) => formatClock(p.timestamp)), values: h.map((p) => p.total_pps) },
      { name: '总 PPS', area: true, color: base.palette[0], yName: 'pps' },
    )
  }, [base, history.data])

  const bpsOption = useMemo(() => {
    const h = history.data ?? []
    return lineOption(
      base,
      { labels: h.map((p) => formatClock(p.timestamp)), values: h.map((p) => p.total_bps) },
      { name: '总字节速率', area: true, color: base.palette[1], yName: 'B/s' },
    )
  }, [base, history.data])

  const rateColumns = useMemo<TableColumnsType<RateResponse>>(
    () => [
      {
        title: '源 IP',
        dataIndex: 'ip',
        key: 'ip',
        width: 180,
        render: (ip: string) => <span className="fw-mono">{ip}</span>,
      },
      {
        title: '总速率',
        dataIndex: 'packets_per_sec',
        key: 'packets_per_sec',
        width: 130,
        align: 'right',
        defaultSortOrder: 'descend',
        sorter: (a, b) => a.packets_per_sec - b.packets_per_sec,
        render: (v: number) => <span className="fw-mono">{formatRate(v, 'pps')}</span>,
      },
      {
        title: '字节速率',
        dataIndex: 'bytes_per_sec',
        key: 'bytes_per_sec',
        width: 140,
        align: 'right',
        sorter: (a, b) => a.bytes_per_sec - b.bytes_per_sec,
        render: (v: number) => <span className="fw-mono">{formatBytes(v)}/s</span>,
      },
    ],
    [],
  )

  const w = windows.data
  const cardsLoading = windows.data == null && !windows.error
  const historyEmpty = (history.data?.length ?? 0) === 0

  return (
    <Flex vertical gap={16}>
      <StaleNotice
        visible={ratesLive.isStale && ratesLive.source !== 'sse'}
        onRetry={ratesLive.refetch}
      />
      {windows.data == null && windows.error ? (
        <ErrorState error={windows.error} onRetry={windows.refetch} />
      ) : (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: 16,
          }}
        >
          <StatCard
            label="PPS · 短窗"
            value={w ? formatRate(w.pps_short, 'pps') : '—'}
            icon={ThunderboltOutlined}
            tone="brand"
            loading={cardsLoading}
            footer="最近突发窗口"
          />
          <StatCard
            label="PPS · 中窗"
            value={w ? formatRate(w.pps_mid, 'pps') : '—'}
            icon={ThunderboltOutlined}
            loading={cardsLoading}
            footer="中期平均"
          />
          <StatCard
            label="PPS · 长窗"
            value={w ? formatRate(w.pps_long, 'pps') : '—'}
            icon={ThunderboltOutlined}
            loading={cardsLoading}
            footer="长期基线"
          />
          <StatCard
            label="字节 · 短窗"
            value={w ? `${formatBytes(w.bps_short)}/s` : '—'}
            icon={FundOutlined}
            tone="info"
            loading={cardsLoading}
            footer="最近突发窗口"
          />
          <StatCard
            label="字节 · 中窗"
            value={w ? `${formatBytes(w.bps_mid)}/s` : '—'}
            icon={FundOutlined}
            loading={cardsLoading}
            footer="中期平均"
          />
          <StatCard
            label="字节 · 长窗"
            value={w ? `${formatBytes(w.bps_long)}/s` : '—'}
            icon={FundOutlined}
            loading={cardsLoading}
            footer="长期基线"
          />
        </div>
      )}

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
          gap: 16,
        }}
      >
        <ChartFrame
          title="速率历史 · PPS"
          query={history}
          option={ppsOption}
          empty={historyEmpty}
          emptyText="暂无速率历史"
          footnote={`最近 ${history.data?.length ?? 0} 个采样点`}
        />
        <ChartFrame
          title="速率历史 · 字节速率"
          query={history}
          option={bpsOption}
          empty={historyEmpty}
          emptyText="暂无速率历史"
          footnote={
            history.data && history.data.length > 0
              ? `最新跟踪 ${formatNumber(history.data[history.data.length - 1].tracked_ips)} 个源`
              : undefined
          }
        />
      </div>

      <DataTable<RateResponse>
        data={ratesLive.value}
        isLoading={ratesLive.isLoading}
        isFetching={ratesLive.isUserFetching}
        error={ratesLive.error}
        onRetry={ratesLive.refetch}
        rowKey="ip"
        columns={rateColumns}
        expandable={{ expandedRowRender: (record) => <ProtocolBreakdown record={record} /> }}
        emptyScenario="no-data"
        emptyTitle="暂无速率记录"
        emptyDescription="当前没有被跟踪的高速源；出现异常流量时会实时列出"
        toolbar={
          <>
            <Tag color={ratesLive.source === 'sse' ? 'green' : 'blue'}>
              {ratesLive.source === 'sse'
                ? '实时推送'
                : ratesLive.source === 'rest'
                  ? 'REST 轮询'
                  : '等待数据'}
            </Tag>
            <Button
              icon={<ReloadOutlined />}
              onClick={ratesLive.refetch}
              loading={ratesLive.isRefreshing}
            >
              刷新
            </Button>
            <Typography.Text type="secondary" style={{ marginLeft: 'auto', fontSize: 12 }}>
              共 {ratesLive.value?.length ?? 0} 个源 · 展开行查看分协议速率
            </Typography.Text>
          </>
        }
        pagination={{
          pageSize: 20,
          showSizeChanger: true,
          hideOnSinglePage: true,
          showTotal: (t) => `共 ${t} 个源`,
        }}
        scroll={{ x: 'max-content' }}
      />
    </Flex>
  )
}

// ---------------------------------------------------------------------------
// 分区二：流量分布
// ---------------------------------------------------------------------------

function DistributionSection() {
  const base = useChartBase()
  const packetSizes = useAsync((signal) => getPacketSizes(signal), {
    refreshInterval: DIST_POLL_MS,
  })
  const ttl = useAsync((signal) => getTtlDistribution(signal), { refreshInterval: DIST_POLL_MS })
  const udpPorts = useAsync((signal) => getUdpPorts(signal), { refreshInterval: DIST_POLL_MS })
  const icmpTypes = useAsync((signal) => getIcmpTypes(signal), { refreshInterval: DIST_POLL_MS })
  const fragments = useAsync((signal) => getIpFragments(signal), { refreshInterval: DIST_POLL_MS })

  useRefreshSignal(() => {
    packetSizes.refetch()
    ttl.refetch()
    udpPorts.refetch()
    icmpTypes.refetch()
    fragments.refetch()
  })

  const sizeOption = useMemo(() => {
    const d = packetSizes.data
    const items = (d?.labels ?? []).map((name, i) => ({ name, value: d?.counts[i] ?? 0 }))
    return pieOption(base, items, { legend: true })
  }, [base, packetSizes.data])

  const ttlOption = useMemo(() => {
    const d = ttl.data
    return barOption(
      base,
      { labels: d?.labels ?? [], values: d?.counts ?? [] },
      { name: 'TTL 包数', color: base.palette[2] },
    )
  }, [base, ttl.data])

  const udpOption = useMemo(() => {
    const ports = [...(udpPorts.data?.ports ?? [])]
      .sort((a, b) => b.packets - a.packets)
      .slice(0, TOP_N)
    return barOption(
      base,
      { labels: ports.map((p) => String(p.port)), values: ports.map((p) => p.packets) },
      { name: 'UDP 包数', horizontal: true, color: base.palette[3] },
    )
  }, [base, udpPorts.data])

  const icmpOption = useMemo(() => {
    const types = [...(icmpTypes.data?.types ?? [])]
      .sort((a, b) => b.packets - a.packets)
      .slice(0, TOP_N)
    return barOption(
      base,
      { labels: types.map((t) => `${t.type}/${t.code}`), values: types.map((t) => t.packets) },
      { name: 'ICMP 包数', horizontal: true, color: base.palette[4] },
    )
  }, [base, icmpTypes.data])

  const fragRatio = fragments.data?.fragment_ratio ?? 0
  const fragOption = useMemo(
    () => gaugeOption(base, fragRatio, { max: 100, color: scoreColor(fragRatio), label: '分片占比' }),
    [base, fragRatio],
  )

  const f = fragments.data
  const fragLoading = fragments.data == null && !fragments.error

  return (
    <Flex vertical gap={16}>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: 16,
        }}
      >
        <ChartFrame
          title="包长分布"
          query={packetSizes}
          option={sizeOption}
          empty={(packetSizes.data?.total ?? 0) === 0}
          emptyText="暂无包长数据"
          footnote={`累计 ${formatNumber(packetSizes.data?.total ?? 0)} 个包`}
        />
        <ChartFrame
          title="TTL 分布"
          query={ttl}
          option={ttlOption}
          empty={(ttl.data?.total ?? 0) === 0}
          emptyText="暂无 TTL 数据"
          footnote={`累计 ${formatNumber(ttl.data?.total ?? 0)} 个包`}
        />
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: 16,
        }}
      >
        <ChartFrame
          title={`UDP 端口 Top ${TOP_N}`}
          query={udpPorts}
          option={udpOption}
          empty={(udpPorts.data?.ports.length ?? 0) === 0}
          emptyText="暂无 UDP 端口数据"
          footnote={
            udpPorts.data
              ? `${formatNumber(udpPorts.data.total_entries)}/${formatNumber(udpPorts.data.max_entries)} 个端口条目`
              : undefined
          }
        />
        <ChartFrame
          title={`ICMP 类型 Top ${TOP_N}`}
          query={icmpTypes}
          option={icmpOption}
          empty={(icmpTypes.data?.types.length ?? 0) === 0}
          emptyText="暂无 ICMP 类型数据"
          footnote={
            icmpTypes.data
              ? `${formatNumber(icmpTypes.data.total_entries)}/${formatNumber(icmpTypes.data.max_entries)} 个类型条目`
              : undefined
          }
        />
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: 16,
        }}
      >
        <ChartFrame
          title="IP 分片占比"
          query={fragments}
          option={fragOption}
          empty={(fragments.data?.total_packets ?? 0) === 0}
          emptyText="暂无分片数据"
          height={200}
        />
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: 16,
            alignContent: 'start',
          }}
        >
          <StatCard
            label="总包数"
            value={f ? formatNumber(f.total_packets) : '—'}
            icon={DashboardOutlined}
            loading={fragLoading}
            footer="累计观测的 IP 包"
          />
          <StatCard
            label="分片包数"
            value={f ? formatNumber(f.fragment_packets) : '—'}
            icon={SplitCellsOutlined}
            tone={f && f.fragment_ratio >= 40 ? 'warning' : 'default'}
            loading={fragLoading}
            footer={f ? `占比 ${formatPercent(f.fragment_ratio)}` : ' '}
          />
        </div>
      </div>
    </Flex>
  )
}

// ---------------------------------------------------------------------------
// 分区三：异常检测
// ---------------------------------------------------------------------------

function AnomalySection() {
  const base = useChartBase()
  const anomalies = useAsync((signal) => getAnomalies(signal), { refreshInterval: DIST_POLL_MS })

  useRefreshSignal(() => anomalies.refetch())

  const data = anomalies.data

  const scoreOption = useMemo(() => {
    const s = data?.global_score ?? 0
    return gaugeOption(base, s, { max: 100, color: scoreColor(s), label: '全局异常分' })
  }, [base, data])

  const radarOpt = useMemo(() => {
    const dims = data?.global_dimensions ?? []
    return radarOption(base, {
      indicators: dims.map((d) => ({ name: d.name, max: 1 })),
      values: dims.map((d) => d.score),
      name: '维度偏差',
    })
  }, [base, data])

  const columns = useMemo<TableColumnsType<IpAnomalyEntry>>(
    () => [
      {
        title: '源 IP',
        dataIndex: 'ip',
        key: 'ip',
        width: 180,
        render: (ip: string) => <span className="fw-mono">{ip}</span>,
      },
      {
        title: '综合异常分',
        dataIndex: 'score',
        key: 'score',
        width: 130,
        align: 'right',
        defaultSortOrder: 'descend',
        sorter: (a, b) => a.score - b.score,
        render: (v: number) => (
          <Tag color={scoreColor(v)} style={{ marginInlineEnd: 0 }}>
            {formatNumber(Math.round(v))}
          </Tag>
        ),
      },
    ],
    [],
  )

  // 单一查询：整段统一兜加载/错误，data 到位后再铺开子块
  if (data == null) {
    if (anomalies.error) return <ErrorState error={anomalies.error} onRetry={anomalies.refetch} />
    return <LoadingState variant="cards" rows={4} />
  }

  const insufficient = data.global_features == null

  return (
    <Flex vertical gap={16}>
      {insufficient && (
        <Alert
          type="warning"
          showIcon
          message="本轮样本不足"
          description="未达最小样本护栏，全局基线与维度偏差暂不可用、异常分记为 0；样本积累后会自动给出读数。"
        />
      )}

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: 16,
        }}
      >
        <StatCard
          label="全局异常分"
          value={formatNumber(Math.round(data.global_score))}
          icon={AlertOutlined}
          tone={scoreTone(data.global_score)}
          footer="0–100，越高越偏离基线"
        />
        <StatCard
          label="样本数"
          value={formatNumber(data.global_sample_count)}
          icon={DashboardOutlined}
          footer="参与基线计算的采样点"
        />
        <StatCard
          label="IP 异常数"
          value={formatNumber(data.ip_anomalies.length)}
          icon={RadarChartOutlined}
          tone={data.ip_anomalies.length > 0 ? 'warning' : 'default'}
          footer="综合分离群的源地址"
        />
        <StatCard
          label="数据时刻"
          value={formatDatetime(data.timestamp)}
          mono={false}
          footer="本次异常检测的时间戳"
        />
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: 16,
        }}
      >
        <ChartCard title="全局异常分">
          <BaseChart
            option={scoreOption}
            height={240}
            empty={insufficient}
            emptyText="样本不足，暂无异常分"
            loading={anomalies.isRefreshing}
          />
        </ChartCard>
        <ChartCard title="维度偏差">
          <BaseChart
            option={radarOpt}
            height={240}
            empty={data.global_dimensions.length === 0}
            emptyText="样本不足，暂无维度偏差"
            loading={anomalies.isRefreshing}
          />
        </ChartCard>
      </div>

      <DataTable<IpAnomalyEntry>
        data={data.ip_anomalies}
        isLoading={false}
        rowKey="ip"
        columns={columns}
        expandable={{
          expandedRowRender: (record) =>
            record.dimensions.length === 0 ? (
              <Typography.Text type="secondary">无维度明细</Typography.Text>
            ) : (
              <Flex wrap="wrap" gap={16}>
                {record.dimensions.map((dim) => (
                  <MiniStat key={dim.name} label={dim.name} value={formatPercent(dim.score * 100)} />
                ))}
              </Flex>
            ),
        }}
        emptyScenario="no-data"
        emptyTitle="暂无离群源地址"
        emptyDescription="当前没有综合分超过阈值的源地址"
        toolbar={
          <>
            <Button
              icon={<ReloadOutlined />}
              onClick={anomalies.refetch}
              loading={anomalies.isRefreshing}
            >
              刷新
            </Button>
            <Typography.Text type="secondary" style={{ marginLeft: 'auto', fontSize: 12 }}>
              共 {data.ip_anomalies.length} 个源 · 展开查看维度偏差
            </Typography.Text>
          </>
        }
        pagination={{ pageSize: 10, hideOnSinglePage: true, showTotal: (t) => `共 ${t} 个源` }}
        scroll={{ x: 'max-content' }}
      />
    </Flex>
  )
}

// ---------------------------------------------------------------------------
// 分区四：扫描探测
// ---------------------------------------------------------------------------

function ScanSection() {
  const scanners = useAsync((signal) => getPortScanners(signal), { refreshInterval: SCAN_POLL_MS })
  const probes = useAsync((signal) => getServiceProbes(signal), { refreshInterval: SCAN_POLL_MS })
  const collaborative = useAsync((signal) => getCollaborativeAttacks(signal), {
    refreshInterval: SCAN_POLL_MS,
  })

  useRefreshSignal(() => {
    scanners.refetch()
    probes.refetch()
    collaborative.refetch()
  })

  const scannerColumns = useMemo<TableColumnsType<PortScannerEntry>>(
    () => [
      {
        title: '源 IP',
        dataIndex: 'ip',
        key: 'ip',
        width: 180,
        render: (ip: string) => <span className="fw-mono">{ip}</span>,
      },
      {
        title: '唯一端口数',
        dataIndex: 'unique_ports',
        key: 'unique_ports',
        width: 130,
        align: 'right',
        defaultSortOrder: 'descend',
        sorter: (a, b) => a.unique_ports - b.unique_ports,
        render: (v: number) => <span className="fw-mono">{formatNumber(v)}</span>,
      },
      {
        title: '包数',
        dataIndex: 'packets',
        key: 'packets',
        width: 120,
        align: 'right',
        sorter: (a, b) => a.packets - b.packets,
        render: (v: number) => <span className="fw-mono">{formatNumber(v)}</span>,
      },
    ],
    [],
  )

  const probeColumns = useMemo<TableColumnsType<ServiceProbeEntry>>(
    () => [
      {
        title: '源 IP',
        dataIndex: 'ip',
        key: 'ip',
        width: 180,
        render: (ip: string) => <span className="fw-mono">{ip}</span>,
      },
      {
        title: '协议种类',
        dataIndex: 'protocol_count',
        key: 'protocol_count',
        width: 130,
        align: 'right',
        defaultSortOrder: 'descend',
        sorter: (a, b) => a.protocol_count - b.protocol_count,
        render: (v: number) => <span className="fw-mono">{formatNumber(v)}</span>,
      },
      {
        title: '包数',
        dataIndex: 'packets',
        key: 'packets',
        width: 120,
        align: 'right',
        sorter: (a, b) => a.packets - b.packets,
        render: (v: number) => <span className="fw-mono">{formatNumber(v)}</span>,
      },
    ],
    [],
  )

  const collabColumns = useMemo<TableColumnsType<CollaborativeAttack>>(
    () => [
      {
        title: 'Jail',
        dataIndex: 'jail_name',
        key: 'jail_name',
        width: 140,
        render: (n: string) => <Tag style={{ marginInlineEnd: 0 }}>{n || '—'}</Tag>,
      },
      {
        title: '时间窗',
        key: 'window',
        width: 360,
        render: (_: unknown, r: CollaborativeAttack) => (
          <span className="fw-mono">
            {formatDatetime(r.window_start)} → {formatDatetime(r.window_end)}
          </span>
        ),
      },
      {
        title: 'IP 数',
        dataIndex: 'ip_count',
        key: 'ip_count',
        width: 90,
        align: 'right',
        sorter: (a, b) => a.ip_count - b.ip_count,
        render: (v: number) => <span className="fw-mono">{formatNumber(v)}</span>,
      },
      {
        title: '封禁数',
        dataIndex: 'total_bans',
        key: 'total_bans',
        width: 100,
        align: 'right',
        sorter: (a, b) => a.total_bans - b.total_bans,
        render: (v: number) => <span className="fw-mono">{formatNumber(v)}</span>,
      },
      {
        title: '关联度',
        dataIndex: 'correlation_score',
        key: 'correlation_score',
        width: 100,
        align: 'right',
        defaultSortOrder: 'descend',
        sorter: (a, b) => a.correlation_score - b.correlation_score,
        render: (v: number) => <span className="fw-mono">{formatPercent(v, 0)}</span>,
      },
    ],
    [],
  )

  return (
    <Flex vertical gap={20}>
      <Flex vertical gap={10}>
        <SectionHeading title="端口扫描检出" description="在窗口内触达大量唯一端口的源地址" />
        <DataTable<PortScannerEntry>
          data={scanners.data ? scanners.data.scanners : null}
          isLoading={scanners.isLoading}
          isFetching={scanners.isUserFetching}
          error={scanners.error}
          onRetry={scanners.refetch}
          rowKey="ip"
          columns={scannerColumns}
          emptyScenario="no-data"
          emptyTitle="未检出端口扫描"
          emptyDescription="当前没有触达大量端口的源地址"
          toolbar={
            <>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                检出阈值 {formatNumber(scanners.data?.threshold ?? 0)} 个唯一端口 · 共{' '}
                {formatNumber(scanners.data?.total_detected ?? 0)} 个源
              </Typography.Text>
              <Button
                icon={<ReloadOutlined />}
                onClick={scanners.refetch}
                loading={scanners.isRefreshing}
                style={{ marginLeft: 'auto' }}
              >
                刷新
              </Button>
            </>
          }
          pagination={{ pageSize: 10, hideOnSinglePage: true }}
          scroll={{ x: 'max-content' }}
        />
      </Flex>

      <Flex vertical gap={10}>
        <SectionHeading title="服务探测检出" description="在窗口内触达多种协议/服务的源地址" />
        <DataTable<ServiceProbeEntry>
          data={probes.data ? probes.data.probes : null}
          isLoading={probes.isLoading}
          isFetching={probes.isUserFetching}
          error={probes.error}
          onRetry={probes.refetch}
          rowKey="ip"
          columns={probeColumns}
          emptyScenario="no-data"
          emptyTitle="未检出服务探测"
          emptyDescription="当前没有跨多协议探测的源地址"
          toolbar={
            <>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                检出阈值 {formatNumber(probes.data?.threshold ?? 0)} 种协议 · 共{' '}
                {formatNumber(probes.data?.total_detected ?? 0)} 个源
              </Typography.Text>
              <Button
                icon={<ReloadOutlined />}
                onClick={probes.refetch}
                loading={probes.isRefreshing}
                style={{ marginLeft: 'auto' }}
              >
                刷新
              </Button>
            </>
          }
          pagination={{ pageSize: 10, hideOnSinglePage: true }}
          scroll={{ x: 'max-content' }}
        />
      </Flex>

      <Flex vertical gap={10}>
        <SectionHeading
          title="协同攻击窗口"
          description="同一时间窗内多源关联封禁，展开查看涉及的 IP"
        />
        <DataTable<CollaborativeAttack>
          data={collaborative.data}
          isLoading={collaborative.isLoading}
          isFetching={collaborative.isUserFetching}
          error={collaborative.error}
          onRetry={collaborative.refetch}
          rowKey={(r) => `${r.jail_name}:${r.window_start}`}
          columns={collabColumns}
          expandable={{
            expandedRowRender: (r) =>
              r.ips.length === 0 ? (
                <Typography.Text type="secondary">无 IP 明细</Typography.Text>
              ) : (
                <Flex wrap="wrap" gap={6}>
                  {r.ips.map((ip) => (
                    <Tag key={ip} className="fw-mono" style={{ marginInlineEnd: 0 }}>
                      {ip}
                    </Tag>
                  ))}
                </Flex>
              ),
          }}
          emptyScenario="no-data"
          emptyTitle="未检出协同攻击"
          emptyDescription="当前没有多源在同一时间窗内关联封禁的记录"
          toolbar={
            <>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                共 {formatNumber(collaborative.data?.length ?? 0)} 个窗口
              </Typography.Text>
              <Button
                icon={<ReloadOutlined />}
                onClick={collaborative.refetch}
                loading={collaborative.isRefreshing}
                style={{ marginLeft: 'auto' }}
              >
                刷新
              </Button>
            </>
          }
          pagination={{ pageSize: 10, hideOnSinglePage: true }}
          scroll={{ x: 'max-content' }}
        />
      </Flex>
    </Flex>
  )
}
