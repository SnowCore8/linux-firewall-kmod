// DDoS 监控页（移动优先）
//
// 做什么：把守护进程暴露的实时速率与内核流量特征集中到一页，按 5 个分区懒加载：
//   概览   —— 全网 PPS/BPS 实时汇总、速率趋势曲线、EWMA 多窗口速率、TOP 来源 IP（含协议拆分）
//   热力图 —— 24 小时攻击热力网格（封禁 / 失败尝试 / DDoS 事件三种口径可切换）
//   协议   —— 协议占比雷达图 + UDP 端口分布 + ICMP 类型分布
//   流量特征 —— 包大小分布、TTL 分布、IP 分片占比
//   扫描探测 —— 端口扫描者、服务探测者（均为内核侧阈值判定结果）
// 影响什么：本页全部为只读展示，不触发任何写操作，不改变内核或守护进程状态。
//
// 数据来源（真实端点，无占位假数据）：
//   - 实时速率：优先全局 SSE 的 rates 事件（useSse().rates / rateHistory），未就绪时回退
//     GET /api/v1/rates/current 与 GET /api/v1/rates/history；
//   - 其余分区均为 REST 端点（/api/v1/rates/windows、/api/v1/stats/*），只在对应分区激活时请求，
//     避免一次性打出一堆慢查询。

import { useMemo, useState } from 'react'
import { Button, Card, List, NoticeBar, Selector, Skeleton, Tag } from 'antd-mobile'
import type { SelectorOption } from 'antd-mobile'
import { LoopOutline } from 'antd-mobile-icons'
import type {
  HourlyHeatmap,
  IcmpTypeDistributionResponse,
  IpFragmentStatsResponse,
  PacketSizeDistributionResponse,
  PortScanResponse,
  RateHistoryResponse,
  RateResponse,
  RateWindowSnapshot,
  ServiceProbeResponse,
  TtlDistributionResponse,
  UdpPortDistributionResponse,
} from '../api/types'
import { getJson } from '../api/client'
import { useAsync } from '../hooks/useAsync'
import { useSse } from '../hooks/useSse'
import { useToast } from '../hooks/useToast'
import { PageHeader } from '../components/PageHeader'
import { EmptyState } from '../components/EmptyState'
import { StatCard } from '../components/StatCard'
import { LineChart } from '../charts/LineChart'
import { RadarChart } from '../charts/RadarChart'
import { HeatmapChart } from '../charts/HeatmapChart'
import { PieChart } from '../charts/PieChart'
import { formatDatetime, formatDuration, formatNumber, formatRate } from '../lib/format'

/** 端点常量：与 handler.rs 的 build_router() 路由一一对应 */
const RATES_CURRENT_URL = '/api/v1/rates/current'
const RATES_HISTORY_URL = '/api/v1/rates/history'
const RATES_WINDOWS_URL = '/api/v1/rates/windows'
const HEATMAP_URL = '/api/v1/stats/heatmap'
const UDP_PORTS_URL = '/api/v1/stats/udp-ports'
const ICMP_TYPES_URL = '/api/v1/stats/icmp-types'
const PACKET_SIZES_URL = '/api/v1/stats/packet-sizes'
const TTL_DISTRIBUTION_URL = '/api/v1/stats/ttl-distribution'
const IP_FRAGMENTS_URL = '/api/v1/stats/ip-fragments'
const PORT_SCANNERS_URL = '/api/v1/stats/port-scanners'
const SERVICE_PROBES_URL = '/api/v1/stats/service-probes'

/** 分区开关：值即 tab key，直接做 Selector 的取值 */
type SectionKey = 'overview' | 'heatmap' | 'protocol' | 'traffic' | 'scan'

/** 顶部分区选择器（移动端用一排可横滑的按钮代替 Tab 组件，触摸目标由 Selector 保证） */
const SECTIONS: SelectorOption<SectionKey>[] = [
  { label: '概览', value: 'overview' },
  { label: '热力图', value: 'heatmap' },
  { label: '协议', value: 'protocol' },
  { label: '流量特征', value: 'traffic' },
  { label: '扫描探测', value: 'scan' },
]

/** 热力图口径：直接对应后端 HourlyBucket 的三个数值字段 */
type HeatMetric = 'bans' | 'failed_attempts' | 'ddos_events'

const HEAT_METRICS: SelectorOption<HeatMetric>[] = [
  { label: '封禁数', value: 'bans' },
  { label: '失败尝试', value: 'failed_attempts' },
  { label: 'DDoS 事件', value: 'ddos_events' },
]

/** 热力图口径 → 图例单位文案 */
const HEAT_LABEL: Record<HeatMetric, string> = {
  bans: '封禁数',
  failed_attempts: '失败尝试',
  ddos_events: 'DDoS 事件',
}

/** 次要说明文字样式 */
const MUTED = { color: 'var(--adm-color-text-secondary)', fontSize: 12 } as const
/** 行内两端对齐：左标签 + 右数值 */
const ROW = { display: 'flex', justifyContent: 'space-between', gap: 7 } as const
/** 等宽字体：IP 用等宽便于逐字符核对 */
const MONO = { fontFamily: 'var(--fw-font-mono)', wordBreak: 'break-all' } as const

/** 协议速率汇总（跨所有被追踪 IP 求和），雷达图与概览共用 */
interface ProtocolTotals {
  syn: number
  udp: number
  icmp: number
  ack: number
  rst: number
  fin: number
  pps: number
  bps: number
}

/** 按协议维度汇总速率；空数组时全部为 0（合法状态：当前没有被追踪的 IP） */
function sumRates(rates: RateResponse[]): ProtocolTotals {
  const totals: ProtocolTotals = { syn: 0, udp: 0, icmp: 0, ack: 0, rst: 0, fin: 0, pps: 0, bps: 0 }
  for (const rate of rates) {
    totals.syn += rate.syn_packets_per_sec
    totals.udp += rate.udp_packets_per_sec
    totals.icmp += rate.icmp_packets_per_sec
    totals.ack += rate.ack_packets_per_sec
    totals.rst += rate.rst_packets_per_sec
    totals.fin += rate.fin_packets_per_sec
    totals.pps += rate.packets_per_sec
    totals.bps += rate.bytes_per_sec
  }
  return totals
}

/** 时间戳（Unix 秒）→ 趋势图 X 轴标签 HH:MM:SS；非法值回退为空串 */
function clockLabel(unixSeconds: number): string {
  const text = formatDatetime(unixSeconds)
  return text === 'N/A' ? '' : text.slice(11, 19)
}

/** 通用空态文案：区分「后端无数据」与「加载失败」，避免用空态掩盖错误 */
function LoadError({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <NoticeBar
      color="error"
      wrap
      content={message}
      extra={
        <a onClick={onRetry} style={{ color: 'inherit', textDecoration: 'underline' }}>
          重试
        </a>
      }
    />
  )
}

export default function Ddos() {
  const toast = useToast()
  const { rates: sseRates, rateHistory, status } = useSse()

  const [section, setSection] = useState<SectionKey>('overview')
  const [heatMetric, setHeatMetric] = useState<HeatMetric>('bans')
  /** 手动刷新标记：自增后所有分区依赖它的 useAsync 都会重新取数 */
  const [nonce, setNonce] = useState(0)

  // 速率数据：概览与协议分区都要用，其它分区不必请求
  const needsRates = section === 'overview' || section === 'protocol'
  const restRates = useAsync<RateResponse[] | null>(
    () => (needsRates ? getJson<RateResponse[]>(RATES_CURRENT_URL) : Promise.resolve(null)),
    [needsRates, nonce],
  )
  const rates = sseRates ?? restRates.data ?? []

  // 速率趋势：SSE 已累积到足够点数时直接用，否则回退 REST 历史（最近 1 小时、每 2 秒一条）
  const restHistory = useAsync<RateHistoryResponse[] | null>(
    () => (section === 'overview' ? getJson<RateHistoryResponse[]>(RATES_HISTORY_URL) : Promise.resolve(null)),
    [section, nonce],
  )

  const windows = useAsync<RateWindowSnapshot | null>(
    () => (section === 'overview' ? getJson<RateWindowSnapshot>(RATES_WINDOWS_URL) : Promise.resolve(null)),
    [section, nonce],
  )

  const heatmap = useAsync<HourlyHeatmap | null>(
    () => (section === 'heatmap' ? getJson<HourlyHeatmap>(HEATMAP_URL) : Promise.resolve(null)),
    [section, nonce],
  )

  const udpPorts = useAsync<UdpPortDistributionResponse | null>(
    () => (section === 'protocol' ? getJson<UdpPortDistributionResponse>(UDP_PORTS_URL) : Promise.resolve(null)),
    [section, nonce],
  )
  const icmpTypes = useAsync<IcmpTypeDistributionResponse | null>(
    () => (section === 'protocol' ? getJson<IcmpTypeDistributionResponse>(ICMP_TYPES_URL) : Promise.resolve(null)),
    [section, nonce],
  )

  const packetSizes = useAsync<PacketSizeDistributionResponse | null>(
    () => (section === 'traffic' ? getJson<PacketSizeDistributionResponse>(PACKET_SIZES_URL) : Promise.resolve(null)),
    [section, nonce],
  )
  const ttlDistribution = useAsync<TtlDistributionResponse | null>(
    () => (section === 'traffic' ? getJson<TtlDistributionResponse>(TTL_DISTRIBUTION_URL) : Promise.resolve(null)),
    [section, nonce],
  )
  const ipFragments = useAsync<IpFragmentStatsResponse | null>(
    () => (section === 'traffic' ? getJson<IpFragmentStatsResponse>(IP_FRAGMENTS_URL) : Promise.resolve(null)),
    [section, nonce],
  )

  const portScanners = useAsync<PortScanResponse | null>(
    () => (section === 'scan' ? getJson<PortScanResponse>(PORT_SCANNERS_URL) : Promise.resolve(null)),
    [section, nonce],
  )
  const serviceProbes = useAsync<ServiceProbeResponse | null>(
    () => (section === 'scan' ? getJson<ServiceProbeResponse>(SERVICE_PROBES_URL) : Promise.resolve(null)),
    [section, nonce],
  )

  const totals = useMemo(() => sumRates(rates), [rates])

  /** TOP 来源：按包速率降序，只渲染前 20 条，避免长列表拖慢移动端 */
  const topRates = useMemo(
    () => [...rates].sort((a, b) => b.packets_per_sec - a.packets_per_sec).slice(0, 20),
    [rates],
  )

  /** 趋势数据：SSE 环形缓冲（≥2 点）优先，否则用 REST 历史的返回值 */
  const trend = useMemo(() => {
    if (rateHistory.length >= 2) {
      return {
        source: 'SSE 实时累积' as const,
        labels: rateHistory.map((point) => point.label),
        pps: rateHistory.map((point) => point.pps),
        bps: rateHistory.map((point) => point.bps),
      }
    }
    const history = restHistory.data ?? []
    return {
      source: 'REST 历史采样' as const,
      labels: history.map((point) => clockLabel(point.timestamp)),
      pps: history.map((point) => point.total_pps),
      bps: history.map((point) => point.total_bps),
    }
  }, [rateHistory, restHistory.data])

  /** 手动刷新：重置分区依赖的 nonce，并提示用户已发起（数据到达由各卡片自行更新） */
  const refresh = () => {
    setNonce((n) => n + 1)
    toast.info('已请求刷新当前分区数据')
  }

  return (
    <>
      <PageHeader
        title="DDoS 监控"
        subtitle="实时速率来自 SSE 推送；流量特征与扫描探测为内核侧累计统计"
        extra={
          <Button size="small" fill="none" style={{ minHeight: 44 }} aria-label="刷新当前分区" onClick={refresh}>
            <LoopOutline fontSize={18} />
          </Button>
        }
      />

      <div style={{ paddingBottom: 7 }}>
        {status !== 'connected' && (
          <NoticeBar
            color="info"
            wrap
            content="实时通道未连接：速率数据回退为一次性 REST 拉取，恢复后会自动切回实时推送。"
          />
        )}

        <Selector options={SECTIONS} value={[section]} onChange={(v) => setSection(v[0] ?? 'overview')} />

        {/* ------------------------------- 概览 ------------------------------- */}
        {section === 'overview' && (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 5, marginTop: 7 }}>
              <StatCard
                label="全网包速率"
                value={formatRate(totals.pps, 'pps')}
                tone="primary"
                hint={`被追踪 IP ${formatNumber(rates.length, false)} 个`}
              />
              <StatCard
                label="全网流量"
                value={formatRate(totals.bps, 'bps')}
                tone="success"
                hint="所有被追踪 IP 的字节速率之和"
              />
            </div>

            <Card title="速率趋势" style={{ marginTop: 7 }}>
              <div style={{ ...MUTED, marginBottom: 2 }}>数据来源：{trend.source}</div>
              <LineChart
                labels={trend.labels}
                series={[{ name: '总包速率', values: trend.pps }]}
                height={180}
                area
                yUnit="pps"
                emptyHint="暂无速率趋势数据"
              />
              <LineChart
                labels={trend.labels}
                series={[{ name: '总字节速率', values: trend.bps }]}
                height={160}
                yUnit="B/s"
                emptyHint="暂无流量趋势数据"
              />
            </Card>

            <Card title="多窗口 EWMA 速率" style={{ marginTop: 7 }}>
              {windows.error !== null ? (
                <LoadError message={`多窗口速率加载失败：${windows.error}`} onRetry={windows.reload} />
              ) : windows.data === null ? (
                <Skeleton.Paragraph lineCount={3} animated />
              ) : (
                <List>
                  <List.Item extra={formatRate(windows.data.pps_short, 'pps')}>包速率（短期 ~5s）</List.Item>
                  <List.Item extra={formatRate(windows.data.pps_mid, 'pps')}>包速率（中期 ~60s）</List.Item>
                  <List.Item extra={formatRate(windows.data.pps_long, 'pps')}>包速率（长期 ~300s）</List.Item>
                  <List.Item extra={formatRate(windows.data.bps_short, 'bps')}>字节速率（短期）</List.Item>
                  <List.Item extra={formatRate(windows.data.bps_mid, 'bps')}>字节速率（中期）</List.Item>
                  <List.Item extra={formatRate(windows.data.bps_long, 'bps')}>字节速率（长期）</List.Item>
                </List>
              )}
            </Card>

            <Card title="协议速率汇总" style={{ marginTop: 7 }}>
              <List>
                <List.Item extra={formatRate(totals.syn, 'pps')}>SYN</List.Item>
                <List.Item extra={formatRate(totals.udp, 'pps')}>UDP</List.Item>
                <List.Item extra={formatRate(totals.icmp, 'pps')}>ICMP</List.Item>
                <List.Item extra={formatRate(totals.ack, 'pps')}>ACK</List.Item>
                <List.Item extra={formatRate(totals.rst, 'pps')}>RST</List.Item>
                <List.Item extra={formatRate(totals.fin, 'pps')}>FIN</List.Item>
              </List>
            </Card>

            <Card title="TOP 来源 IP" style={{ marginTop: 7 }}>
              {restRates.error !== null && sseRates === null ? (
                <LoadError message={`速率数据加载失败：${restRates.error}`} onRetry={restRates.reload} />
              ) : sseRates === null && restRates.loading ? (
                <Skeleton.Paragraph lineCount={5} animated />
              ) : topRates.length === 0 ? (
                <EmptyState
                  compact
                  title="当前没有被追踪的 IP"
                  description="速率表为空表示近期没有触发速率统计的流量；有异常流量时会立即出现在这里"
                />
              ) : (
                topRates.map((rate) => (
                  <div key={rate.ip} style={{ padding: '5px 0', borderBottom: '1px solid var(--fw-border)' }}>
                    <div style={ROW}>
                      <span style={{ ...MONO, fontSize: 13 }}>{rate.ip}</span>
                      <span>{formatRate(rate.packets_per_sec, 'pps')}</span>
                    </div>
                    <div style={{ ...MUTED, marginTop: 1 }}>
                      {formatRate(rate.bytes_per_sec, 'bps')} · SYN {formatNumber(Math.round(rate.syn_packets_per_sec), false)} ·
                      UDP {formatNumber(Math.round(rate.udp_packets_per_sec), false)} · ICMP{' '}
                      {formatNumber(Math.round(rate.icmp_packets_per_sec), false)}
                    </div>
                  </div>
                ))
              )}
            </Card>
          </>
        )}

        {/* ------------------------------ 热力图 ------------------------------ */}
        {section === 'heatmap' && (
          <Card title="24 小时攻击热力图" style={{ marginTop: 7 }}>
            <Selector
              options={HEAT_METRICS}
              value={[heatMetric]}
              onChange={(v) => setHeatMetric(v[0] ?? 'bans')}
            />
            <div style={{ marginTop: 5 }}>
              {heatmap.error !== null ? (
                <LoadError message={`热力图加载失败：${heatmap.error}`} onRetry={heatmap.reload} />
              ) : heatmap.data === null ? (
                <Skeleton.Paragraph lineCount={4} animated />
              ) : (
                <>
                  <HeatmapChart
                    cells={heatmap.data.hours.map((bucket) => ({
                      hour: bucket.hour,
                      value: bucket[heatMetric],
                    }))}
                    height={170}
                    valueLabel={HEAT_LABEL[heatMetric]}
                    emptyHint="暂无小时级统计数据"
                  />
                  <div style={{ ...MUTED, marginTop: 4 }}>
                    色阶按 √(值/峰值) 分档：攻击量长尾分布下，开平方能让低值时段更容易分辨。
                  </div>
                </>
              )}
            </div>
          </Card>
        )}

        {/* ------------------------------- 协议 ------------------------------- */}
        {section === 'protocol' && (
          <>
            <Card title="协议占比（跨所有被追踪 IP 求和）" style={{ marginTop: 7 }}>
              <RadarChart
                axes={['SYN', 'UDP', 'ICMP', 'ACK', 'RST', 'FIN']}
                series={[
                  {
                    name: '协议包速率',
                    values: [totals.syn, totals.udp, totals.icmp, totals.ack, totals.rst, totals.fin],
                  },
                ]}
                height={230}
                emptyHint="暂无协议速率数据"
              />
            </Card>

            <Card title="UDP 端口分布" style={{ marginTop: 7 }}>
              {udpPorts.error !== null ? (
                <LoadError message={`UDP 端口分布加载失败：${udpPorts.error}`} onRetry={udpPorts.reload} />
              ) : udpPorts.data === null ? (
                <Skeleton.Paragraph lineCount={4} animated />
              ) : udpPorts.data.ports.length === 0 ? (
                <EmptyState compact title="暂无 UDP 端口记录" description="内核侧尚未统计到 UDP 流量" />
              ) : (
                <>
                  <div style={{ ...MUTED, marginBottom: 4 }}>
                    共 {formatNumber(udpPorts.data.total_entries, false)} 个端口（上限{' '}
                    {formatNumber(udpPorts.data.max_entries, false)}），已按包数降序
                  </div>
                  <PieChart
                    slices={udpPorts.data.ports
                      .slice(0, 8)
                      .map((entry) => ({ name: `端口 ${entry.port}`, value: entry.packets }))}
                    height={180}
                    donut
                    emptyHint="暂无 UDP 端口数据"
                  />
                  <List header="明细（前 8 个）">
                    {udpPorts.data.ports.slice(0, 8).map((entry) => (
                      <List.Item
                        key={entry.port}
                        extra={`${formatNumber(entry.packets, true)} 包 / ${formatNumber(entry.bytes, true)} B`}
                        description={`最近出现 ${formatDuration(entry.last_seen_secs)} 前`}
                      >
                        端口 {entry.port}
                      </List.Item>
                    ))}
                  </List>
                </>
              )}
            </Card>

            <Card title="ICMP 类型分布" style={{ marginTop: 7 }}>
              {icmpTypes.error !== null ? (
                <LoadError message={`ICMP 类型分布加载失败：${icmpTypes.error}`} onRetry={icmpTypes.reload} />
              ) : icmpTypes.data === null ? (
                <Skeleton.Paragraph lineCount={4} animated />
              ) : icmpTypes.data.types.length === 0 ? (
                <EmptyState compact title="暂无 ICMP 记录" description="内核侧尚未统计到 ICMP 报文" />
              ) : (
                <List
                  header={`共 ${formatNumber(icmpTypes.data.total_entries, false)} 个类型/代码组合（上限 ${formatNumber(icmpTypes.data.max_entries, false)}）`}
                >
                  {icmpTypes.data.types.slice(0, 20).map((entry) => (
                    <List.Item
                      key={`${entry.type}-${entry.code}`}
                      extra={`${formatNumber(entry.packets, true)} 包 / ${formatNumber(entry.bytes, true)} B`}
                      description={`最近出现 ${formatDuration(entry.last_seen_secs)} 前`}
                    >
                      type {entry.type} / code {entry.code}
                    </List.Item>
                  ))}
                </List>
              )}
            </Card>
          </>
        )}

        {/* ----------------------------- 流量特征 ----------------------------- */}
        {section === 'traffic' && (
          <>
            <Card title="包大小分布" style={{ marginTop: 7 }}>
              {packetSizes.error !== null ? (
                <LoadError message={`包大小分布加载失败：${packetSizes.error}`} onRetry={packetSizes.reload} />
              ) : packetSizes.data === null ? (
                <Skeleton.Paragraph lineCount={4} animated />
              ) : packetSizes.data.total === 0 ? (
                <EmptyState compact title="暂无包大小统计" description="内核侧尚未累计到数据包" />
              ) : (
                <>
                  <PieChart
                    slices={packetSizes.data.labels.map((label, index) => ({
                      name: label,
                      value: packetSizes.data?.counts[index] ?? 0,
                    }))}
                    height={190}
                    donut
                    emptyHint="暂无包大小数据"
                  />
                  <List header={`总包数 ${formatNumber(packetSizes.data.total, true)}`}>
                    {packetSizes.data.labels.map((label, index) => (
                      <List.Item
                        key={label}
                        extra={`${formatNumber(packetSizes.data?.counts[index] ?? 0, true)} 包 · ${(packetSizes.data?.percentages[index] ?? 0).toFixed(1)}%`}
                      >
                        {label}
                      </List.Item>
                    ))}
                  </List>
                </>
              )}
            </Card>

            <Card title="TTL 分布" style={{ marginTop: 7 }}>
              {ttlDistribution.error !== null ? (
                <LoadError message={`TTL 分布加载失败：${ttlDistribution.error}`} onRetry={ttlDistribution.reload} />
              ) : ttlDistribution.data === null ? (
                <Skeleton.Paragraph lineCount={4} animated />
              ) : ttlDistribution.data.total === 0 ? (
                <EmptyState compact title="暂无 TTL 统计" description="内核侧尚未累计到数据包" />
              ) : (
                <>
                  <PieChart
                    slices={ttlDistribution.data.labels.map((label, index) => ({
                      name: label,
                      value: ttlDistribution.data?.counts[index] ?? 0,
                    }))}
                    height={190}
                    donut
                    emptyHint="暂无 TTL 数据"
                  />
                  <List header={`总包数 ${formatNumber(ttlDistribution.data.total, true)}`}>
                    {ttlDistribution.data.labels.map((label, index) => (
                      <List.Item
                        key={label}
                        extra={`${formatNumber(ttlDistribution.data?.counts[index] ?? 0, true)} 包 · ${(ttlDistribution.data?.percentages[index] ?? 0).toFixed(1)}%`}
                      >
                        TTL {label}
                      </List.Item>
                    ))}
                  </List>
                </>
              )}
            </Card>

            <Card title="IP 分片统计" style={{ marginTop: 7 }}>
              {ipFragments.error !== null ? (
                <LoadError message={`IP 分片统计加载失败：${ipFragments.error}`} onRetry={ipFragments.reload} />
              ) : ipFragments.data === null ? (
                <Skeleton.Paragraph lineCount={3} animated />
              ) : (
                <>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 5 }}>
                    <StatCard
                      label="分片包数"
                      value={formatNumber(ipFragments.data.fragment_packets, true)}
                      tone={ipFragments.data.fragment_ratio >= 5 ? 'danger' : 'default'}
                      hint={`占全部包的 ${ipFragments.data.fragment_ratio.toFixed(2)}%`}
                    />
                    <StatCard
                      label="总包数"
                      value={formatNumber(ipFragments.data.total_packets, true)}
                      tone="primary"
                    />
                  </div>
                  <div style={{ ...MUTED, marginTop: 5 }}>
                    大量分片常被用于规避检测：分片占比持续偏高时建议结合端口扫描结果一起排查。
                  </div>
                </>
              )}
            </Card>
          </>
        )}

        {/* ----------------------------- 扫描探测 ----------------------------- */}
        {section === 'scan' && (
          <>
            <Card title="端口扫描检测" style={{ marginTop: 7 }}>
              {portScanners.error !== null ? (
                <LoadError message={`端口扫描结果加载失败：${portScanners.error}`} onRetry={portScanners.reload} />
              ) : portScanners.data === null ? (
                <Skeleton.Paragraph lineCount={4} animated />
              ) : (
                <>
                  <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 5 }}>
                    <Tag color="primary" fill="outline">
                      判定阈值：不同端口数 ≥ {formatNumber(portScanners.data.threshold, false)}
                    </Tag>
                    <Tag color={portScanners.data.total_detected > 0 ? 'danger' : 'success'} fill="outline">
                      检出 {formatNumber(portScanners.data.total_detected, false)} 个
                    </Tag>
                  </div>
                  {portScanners.data.scanners.length === 0 ? (
                    <EmptyState compact title="未检出端口扫描" description="没有来源超过不同端口数阈值" />
                  ) : (
                    <List>
                      {portScanners.data.scanners.slice(0, 20).map((scanner) => (
                        <List.Item
                          key={scanner.ip}
                          extra={`${formatNumber(scanner.unique_ports, false)} 个端口 / ${formatNumber(scanner.packets, true)} 包`}
                        >
                          <span style={MONO}>{scanner.ip}</span>
                        </List.Item>
                      ))}
                    </List>
                  )}
                </>
              )}
            </Card>

            <Card title="服务探测检测" style={{ marginTop: 7 }}>
              {serviceProbes.error !== null ? (
                <LoadError message={`服务探测结果加载失败：${serviceProbes.error}`} onRetry={serviceProbes.reload} />
              ) : serviceProbes.data === null ? (
                <Skeleton.Paragraph lineCount={4} animated />
              ) : (
                <>
                  <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 5 }}>
                    <Tag color="primary" fill="outline">
                      判定阈值：协议数 ≥ {formatNumber(serviceProbes.data.threshold, false)}
                    </Tag>
                    {serviceProbes.data.probes.length === 0 && (
                      <Tag color="success" fill="outline">
                        未检出
                      </Tag>
                    )}
                  </div>
                  {serviceProbes.data.probes.length === 0 ? (
                    <EmptyState compact title="未检出服务探测" description="没有来源超过协议数阈值" />
                  ) : (
                    <List>
                      {serviceProbes.data.probes.slice(0, 20).map((probe) => (
                        <List.Item
                          key={probe.ip}
                          extra={`${formatNumber(probe.protocol_count, false)} 个协议 / ${formatNumber(probe.packets, true)} 包`}
                        >
                          <span style={MONO}>{probe.ip}</span>
                        </List.Item>
                      ))}
                    </List>
                  )}
                </>
              )}
            </Card>
          </>
        )}
      </div>
    </>
  )
}
