// DDoS 监控页（移动优先，控制台式高密度）
//
// 做什么：把守护进程暴露的实时速率与内核流量特征集中到一页，按 5 个分区懒加载：
//   概览     —— 态势判决（速率阈值口径）、全网速率瓦片、速率趋势、多窗口 EWMA、协议速率、TOP 来源 IP
//   热力图   —— 24 小时攻击热力网格（封禁 / 失败尝试 / DDoS 事件三种口径可切换）
//   协议     —— 协议速率占比（雷达 + 逐协议占比行）、UDP 端口分布、ICMP 类型分布
//   流量特征 —— 包大小分布、TTL 分布、IP 分片占比
//   扫描探测 —— 端口扫描者、服务探测者（均为内核侧阈值判定结果）
// 影响什么：本页全部为只读展示，不触发任何写操作，不改变内核或守护进程状态。
//
// 设计约定（styles/global.css 的 fw-* 令牌 + components/console.tsx 的原语）：
//   · 结构一律用 Panel 承载，不铺卡片流；数值走等宽 + tabular-nums，跳变时不左右抖动；
//   · 数据行按 26px 密度排，但所有可点元素（分区切换、展开、刷新、重试）保持
//     ≥44px（--fw-tap）触摸目标——密度与触摸互不妥协；
//   · 分区切换用自绘分段条而非 antd-mobile Selector：全局样式把 Selector 压到 ~24px 高，
//     低于触摸目标下限，见 SegTabs 的注释。
//
// 数据来源（真实端点，无占位假数据）：
//   - 实时速率：优先全局 SSE 的 rates 事件（useSse().rates / rateHistory），未就绪时回退
//     GET /api/v1/rates/current 与 GET /api/v1/rates/history；
//   - 其余分区均为 REST 端点（/api/v1/rates/windows、/api/v1/stats/*），只在对应分区激活时请求，
//     避免一次性打出一堆慢查询；
//   - 判决条用的速率阈值取自 GET /api/v1/config 的 rate_warning_pps / rate_critical_pps，
//     与守护进程计算威胁等级时用的是同一组配置（见 web_ui/stats.rs）。

import { useCallback, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { PullToRefresh } from 'antd-mobile'

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
  WebuiConfigResponse,
} from '../api/types'
import {
  getConfig,
  getHeatmap,
  getIcmpTypes,
  getIpFragments,
  getPacketSizes,
  getPortScanners,
  getRatesCurrent,
  getRatesHistory,
  getRatesWindows,
  getServiceProbes,
  getTtlDistribution,
  getUdpPorts,
} from '../api/endpoints'
import { useAsync } from '../hooks/useAsync'
import { pickLiveData } from '../hooks/useLiveData'
import { usePollInterval } from '../hooks/usePollInterval'
import { useSse } from '../hooks/useSse'
import { Badge, InlineError, Meter, Note, Panel, PanelLoading, Row, Rows, SegTabs, Tile, Tiles, Verdict, toneColor } from '../components/console'
import type { Tone } from '../components/console'
import { EmptyState } from '../components/EmptyState'
import { PageHeader } from '../components/PageHeader'
import { HeatmapChart } from '../charts/HeatmapChart'
import { LineChart } from '../charts/LineChart'
import { PieChart } from '../charts/PieChart'
import { RadarChart } from '../charts/RadarChart'
import { formatDatetime, formatDuration, formatNumber, formatRate } from '../lib/format'

/** 分区开关：值即 tab key，直接做 SegTabs 的取值 */
type SectionKey = 'overview' | 'heatmap' | 'protocol' | 'traffic' | 'scan'

const SECTIONS: ReadonlyArray<{ label: string; value: SectionKey }> = [
  { label: '概览', value: 'overview' },
  { label: '热力图', value: 'heatmap' },
  { label: '协议', value: 'protocol' },
  { label: '流量特征', value: 'traffic' },
  { label: '扫描探测', value: 'scan' },
]

/** 热力图口径：直接对应后端 HourlyBucket 的三个数值字段 */
type HeatMetric = 'bans' | 'failed_attempts' | 'ddos_events'

const HEAT_METRICS: ReadonlyArray<{ label: string; value: HeatMetric }> = [
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

/** 协议速率汇总的展示顺序（与雷达图轴顺序一致） */
const PROTOCOLS: ReadonlyArray<{
  key: 'syn' | 'udp' | 'icmp' | 'ack' | 'rst' | 'fin'
  label: string
}> = [
  { key: 'syn', label: 'SYN' },
  { key: 'udp', label: 'UDP' },
  { key: 'icmp', label: 'ICMP' },
  { key: 'ack', label: 'ACK' },
  { key: 'rst', label: 'RST' },
  { key: 'fin', label: 'FIN' },
]

/** 趋势图最多绘制的采样点数：SSE 环形缓冲有 300 点，全画会在窄屏上糊成一片 */
const TREND_POINTS = 120
/** TOP 来源默认渲染条数（其余靠「展开全部」按需渲染，避免长列表挤占一屏） */
const TOP_VISIBLE = 8
/** 端口/ICMP 明细默认渲染条数（与旧版一致，不缩水） */
const UDP_VISIBLE = 8
const ICMP_VISIBLE = 20
/** 扫描/探测明细渲染条数（与旧版一致） */
const SCAN_VISIBLE = 20

/** 未激活分区的取数哨兵：见 useAsync 的 skipWhen（不得用它覆盖已有数据） */
const IDLE = null

/** 无数据时的占位符（比空格更明确，避免误读为 0） */
const DASH = '—'

/**
 * 实体行（IP / 协议）：等宽标识 + 可选迷你条 + 右对齐数值 + 次要明细。
 *
 * 与 Row 的分工：Row 是「标签固定列宽」的键值行（多行数值列自动对齐）；
 * 本行是「标识长度可变」的实体行——IPv6 可到 39 字符，固定列宽会被截断，
 * 因此标识占满剩余宽度并允许折行，数值与迷你条始终右对齐。
 */
function MetricRow({
  primary,
  value,
  unit,
  ratio,
  tone = 'default',
  detail,
  last,
}: {
  /** 左侧标识（IP / 协议名），等宽显示 */
  primary: string
  /** 右侧数值（已格式化） */
  value: string
  unit?: string
  /** 迷你条占比（0~1）；不传则不画条 */
  ratio?: number
  tone?: Tone
  /** 次要明细（协议拆分 / 包数 / 数据量），一行 dim 小字 */
  detail?: ReactNode
  /** 是否为列表末行：末行不画分隔线，避免与面板边框叠成双线 */
  last?: boolean
}) {
  return (
    <div
      style={{
        padding: '3px 6px',
        borderBottom: last ? 0 : '1px solid var(--fw-border)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <span
          className="fw-mono"
          style={{ flex: 1, minWidth: 0, fontSize: 12, wordBreak: 'break-all' }}
        >
          {primary}
        </span>
        {ratio === undefined ? null : (
          <span style={{ width: 44, flexShrink: 0 }}>
            <Meter ratio={ratio} tone={tone} />
          </span>
        )}
        <span
          className="fw-mono fw-num"
          style={{ flexShrink: 0, fontSize: 12, color: toneColor(tone) }}
        >
          {value}
        </span>
        {unit ? <span className="fw-row-unit">{unit}</span> : null}
      </div>
      {detail ? (
        <div
          className="fw-mono fw-num"
          style={{ fontSize: 10, color: 'var(--fw-text-3)', marginTop: 1 }}
        >
          {detail}
        </div>
      ) : null}
    </div>
  )
}

/** 列表尾部「展开 / 收起」：默认只渲染前若干条，长列表不挤占一屏（44px 触摸目标） */
function MoreToggle({
  expanded,
  total,
  onToggle,
}: {
  expanded: boolean
  total: number
  onToggle: () => void
}) {
  return (
    <button
      type="button"
      className="fw-cmd"
      style={{ width: '100%', border: 0, borderRadius: 0 }}
      onClick={onToggle}
    >
      {expanded ? '收起' : `展开全部 ${formatNumber(total, false)} 条`}
    </button>
  )
}

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

/**
 * 单个 IP 的包速率 → 语义色调。
 *
 * 阈值取自 webui 配置（守护进程算威胁等级时用同一组值），因此颜色不是拍的：
 * 达到 rate_critical_pps 标红、达到 rate_warning_pps 标黄，其余保持正文色。
 */
function rateTone(pps: number, config: WebuiConfigResponse | null): Tone {
  if (!config) return 'default'
  if (config.rate_critical_pps > 0 && pps >= config.rate_critical_pps) return 'danger'
  if (config.rate_warning_pps > 0 && pps >= config.rate_warning_pps) return 'warning'
  return 'default'
}

export default function Ddos() {
  const { rates: sseRates, payloadSeq, rateHistory, status } = useSse()

  const [section, setSection] = useState<SectionKey>('overview')
  const [heatMetric, setHeatMetric] = useState<HeatMetric>('bans')
  /** TOP 列表是否展开到全部（默认只渲染前 TOP_VISIBLE 条） */
  const [showAllTop, setShowAllTop] = useState(false)

  // 自动刷新间隔与 SSE 推送间隔同源（见 usePollInterval）。只用于**内核侧累计统计**
  // 这类没有实时推送的分区；速率数据走 SSE，不轮询（否则 REST 快照会盖掉更新的推流）。
  const pollMs = usePollInterval()
  const pushSecs = Math.max(1, Math.round(pollMs / 1000))

  // 速率阈值配置（rate_warning_pps / rate_critical_pps）：只服务判决条与 TOP 列表配色。
  // 不设 pollMs——阈值改动只需下次进页面生效，没必要在监控页反复请求。
  const config = useAsync<WebuiConfigResponse>(() => getConfig(), [])

  // 速率数据：概览与协议分区都要用，其它分区不必请求
  const needsRates = section === 'overview' || section === 'protocol'
  const restRates = useAsync<RateResponse[] | null>(
    () => (needsRates ? getRatesCurrent() : Promise.resolve(IDLE)),
    [needsRates],
    { skipWhen: IDLE },
  )
  // 取较新的一份而非「SSE 优先」：页内刷新（reload 触发 REST 重取）必须真正生效
  const liveRates = pickLiveData(sseRates, payloadSeq.rates, restRates)
  const rates = liveRates ?? []

  // 速率趋势：SSE 已累积到足够点数时直接用，否则回退 REST 历史（最近 1 小时、每 2 秒一条）
  const restHistory = useAsync<RateHistoryResponse[] | null>(
    () => (section === 'overview' ? getRatesHistory() : Promise.resolve(IDLE)),
    [section],
    { skipWhen: IDLE },
  )

  const windows = useAsync<RateWindowSnapshot | null>(
    () => (section === 'overview' ? getRatesWindows() : Promise.resolve(IDLE)),
    [section],
    { skipWhen: IDLE, pollMs },
  )

  const heatmap = useAsync<HourlyHeatmap | null>(
    () => (section === 'heatmap' ? getHeatmap() : Promise.resolve(IDLE)),
    [section],
    { skipWhen: IDLE, pollMs },
  )

  const udpPorts = useAsync<UdpPortDistributionResponse | null>(
    () => (section === 'protocol' ? getUdpPorts() : Promise.resolve(IDLE)),
    [section],
    { skipWhen: IDLE, pollMs },
  )
  const icmpTypes = useAsync<IcmpTypeDistributionResponse | null>(
    () => (section === 'protocol' ? getIcmpTypes() : Promise.resolve(IDLE)),
    [section],
    { skipWhen: IDLE, pollMs },
  )

  const packetSizes = useAsync<PacketSizeDistributionResponse | null>(
    () => (section === 'traffic' ? getPacketSizes() : Promise.resolve(IDLE)),
    [section],
    { skipWhen: IDLE, pollMs },
  )
  const ttlDistribution = useAsync<TtlDistributionResponse | null>(
    () => (section === 'traffic' ? getTtlDistribution() : Promise.resolve(IDLE)),
    [section],
    { skipWhen: IDLE, pollMs },
  )
  const ipFragments = useAsync<IpFragmentStatsResponse | null>(
    () => (section === 'traffic' ? getIpFragments() : Promise.resolve(IDLE)),
    [section],
    { skipWhen: IDLE, pollMs },
  )

  const portScanners = useAsync<PortScanResponse | null>(
    () => (section === 'scan' ? getPortScanners() : Promise.resolve(IDLE)),
    [section],
    { skipWhen: IDLE, pollMs },
  )
  const serviceProbes = useAsync<ServiceProbeResponse | null>(
    () => (section === 'scan' ? getServiceProbes() : Promise.resolve(IDLE)),
    [section],
    { skipWhen: IDLE, pollMs },
  )

  const totals = useMemo(() => sumRates(rates), [rates])

  /**
   * TOP 来源：按包速率降序取前 20 条**有流量的** IP。
   *
   * 必须过滤零速率：速率表里的条目会保留到过期为止，安静下来后每条都是 `0 pps`；
   * 不过滤时这 20 个名额会被历史条目占满，真正有流量的 IP 反而被挤下去，
   * 用户要滑很久才看到「现在是谁在打」。全为零时才退回显示空列表（由空态说明）。
   */
  const topRates = useMemo(
    () =>
      rates
        .filter((r) => r.packets_per_sec > 0 || r.bytes_per_sec > 0)
        .sort((a, b) => b.packets_per_sec - a.packets_per_sec)
        .slice(0, 20),
    [rates],
  )

  /** 迷你条的基准：当前峰值（TOP 首条），保证第一行是满条 */
  const topPeak = topRates.length > 0 ? topRates[0].packets_per_sec : 0
  /** 实际渲染的 TOP 行：默认前 TOP_VISIBLE 条 */
  const hasTopOverflow = topRates.length > TOP_VISIBLE
  const visibleTop = showAllTop || !hasTopOverflow ? topRates : topRates.slice(0, TOP_VISIBLE)

  /** 趋势数据：SSE 环形缓冲（≥2 点）优先，否则用 REST 历史的返回值 */
  const trend = useMemo(() => {
    if (rateHistory.length >= 2) {
      const points = rateHistory.slice(-TREND_POINTS)
      return {
        source: 'SSE 实时累积' as const,
        labels: points.map((point) => point.label),
        pps: points.map((point) => point.pps),
        bps: points.map((point) => point.bps),
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

  /** 趋势窗口峰值：比瞬时值更能说明「这段时间最高打到多少」 */
  const trendPeak = useMemo(
    () => (trend.pps.length > 0 ? Math.max(...trend.pps) : 0),
    [trend.pps],
  )

  /**
   * 态势判决：把「现在有没有事」压成一行结论（整页只此一处放大字号）。
   *
   * 判级口径与守护进程一致：拿**合计**包速率与配置阈值比较
   * （web_ui/stats.rs 的威胁等级同用 rate_warning_pps / rate_critical_pps），
   * 不另立标准；配置未取到时退化为不判级，只说「在追踪」。
   */
  const verdict = useMemo((): { text: string; tone: Tone; sub: string; right: string } => {
    const totalPps = totals.pps
    const peak = topRates.length > 0 ? topRates[0] : null
    const warn = config.data?.rate_warning_pps ?? 0
    const critical = config.data?.rate_critical_pps ?? 0

    if (!peak) {
      return {
        text: 'IDLE',
        tone: 'success',
        sub: '当前没有被追踪的 IP：速率表为空表示近期没有触发速率统计的流量',
        right: DASH,
      }
    }
    if (critical > 0 && totalPps >= critical) {
      return {
        text: 'ALERT',
        tone: 'danger',
        sub: `合计包速率已达严重阈值 ${formatRate(critical, 'pps')}（配置 rate_critical_pps），峰值来源 ${peak.ip}`,
        right: formatRate(totalPps, 'pps'),
      }
    }
    if (warn > 0 && totalPps >= warn) {
      return {
        text: 'WARN',
        tone: 'warning',
        sub: `合计包速率已达告警阈值 ${formatRate(warn, 'pps')}（配置 rate_warning_pps）`,
        right: formatRate(totalPps, 'pps'),
      }
    }
    return {
      text: 'ACTIVE',
      tone: 'primary',
      sub: `${formatNumber(rates.length, false)} 个 IP 在被追踪；峰值 ${peak.ip} ${formatRate(peak.packets_per_sec, 'pps')}${
        config.data === null ? '（阈值配置未取到，暂不判级）' : ''
      }`,
      right: formatRate(totalPps, 'pps'),
    }
  }, [totals.pps, topRates, rates.length, config.data])

  /** 热力图汇总：与图表同口径（同一小时重复出现时后者覆盖前者） */
  const heatSummary = useMemo(() => {
    const values = new Array<number>(24).fill(0)
    for (const bucket of heatmap.data?.hours ?? []) {
      const hour = Math.trunc(bucket.hour)
      if (!Number.isFinite(hour) || hour < 0 || hour > 23) continue
      values[hour] = Math.max(0, bucket[heatMetric])
    }
    let peak = 0
    let peakHour = -1
    let total = 0
    values.forEach((value, hour) => {
      total += value
      if (value > peak) {
        peak = value
        peakHour = hour
      }
    })
    return { peak, peakHour, total }
  }, [heatmap.data, heatMetric])

  /** 协议速率中的最大值：协议行的迷你条以它为基准 */
  const maxProtoPps = useMemo(
    () => PROTOCOLS.reduce((max, item) => Math.max(max, totals[item.key]), 0),
    [totals],
  )

  /**
   * 刷新**当前分区**用到的取数。
   *
   * 只重取当前分区而不是全部：未激活分区的取数会返回哨兵、白跑一趟。各分区共享 `section`
   * 通过依赖变化触发的，让所有分区共享它就会把「切 tab 触发全部重取」的老问题带回来。
   * 因此这里逐个调用真正与当前分区相关的那几个 `reload()`——它们的 Promise 在取数
   * **落定**后 resolve（见 useAsync），所以下拉刷新的转圈会一直转到数据真的到齐。
   */
  const doRefresh = useCallback(async (): Promise<void> => {
    const jobs: Promise<void>[] = []
    if (section === 'overview') {
      jobs.push(restRates.reload(), restHistory.reload(), windows.reload(), config.reload())
    } else if (section === 'heatmap') {
      jobs.push(heatmap.reload())
    } else if (section === 'protocol') {
      jobs.push(restRates.reload(), udpPorts.reload(), icmpTypes.reload())
    } else if (section === 'traffic') {
      jobs.push(packetSizes.reload(), ttlDistribution.reload(), ipFragments.reload())
    } else if (section === 'scan') {
      jobs.push(portScanners.reload(), serviceProbes.reload())
    }
    await Promise.all(jobs)
  }, [
    section,
    restRates,
    restHistory,
    windows,
    config,
    heatmap,
    udpPorts,
    icmpTypes,
    packetSizes,
    ttlDistribution,
    ipFragments,
    portScanners,
    serviceProbes,
  ])

  const liveSource = status === 'connected'

  return (
    <>
      <PullToRefresh onRefresh={doRefresh}>
        <div className="fw-page">
          {/* 页内区块标题：标题与顶栏同名，故只保留语义（srOnly），避免屏幕上
              出现两行「DDoS 监控」；h2 仍在 DOM 里供读屏器与 e2e 定位 */}
          <PageHeader title="DDoS 监控" srOnly />
          {/* ------------------------------ 态势与分区 ------------------------------ */}
          <Panel
            title="实时态势"
            meta={
              config.data === null
                ? `${formatNumber(rates.length, false)} IP · 阈值配置读取中`
                : `${formatNumber(rates.length, false)} IP · 告警 ${formatRate(
                    config.data.rate_warning_pps,
                    'pps',
                  )} / 严重 ${formatRate(config.data.rate_critical_pps, 'pps')}`
            }
            padded={false}
          >
            <Verdict
              text={verdict.text}
              tone={verdict.tone}
              sub={
                <>
                  <Badge tone={liveSource ? 'success' : 'warning'}>
                    {liveSource ? 'SSE LIVE' : 'REST 回退'}
                  </Badge>{' '}
                  {verdict.sub}
                  {liveSource
                    ? ''
                    : `；实时通道未连接，速率回退一次性拉取（推送间隔 ${pushSecs}s）`}
                </>
              }
              right={
                // 只放数值：与仪表盘判决条同一形态。刷新走顶栏「刷新」或下拉手势，
                // 判决条里再塞一个刷新按钮会让同一页出现两套刷新入口
                <span className="fw-mono fw-num" style={{ fontSize: 15, fontWeight: 600 }}>
                  {verdict.right}
                </span>
              }
            />
          </Panel>

          <div style={{ marginBottom: 6 }}>
            <SegTabs label="DDoS 监控分区" items={SECTIONS} value={section} onChange={setSection} />
          </div>

          {/* ------------------------------- 概览 ------------------------------- */}
          {section === 'overview' && (
            <>
              <Panel title="全网速率" meta={`内核统计轮询 ${pushSecs}s`} padded={false}>
                <Tiles columns={2}>
                  <Tile
                    label="包速率"
                    value={formatNumber(totals.pps, true)}
                    unit="pps"
                    tone="primary"
                  />
                  <Tile
                    label="字节速率"
                    value={formatNumber(totals.bps, true)}
                    unit="B/s"
                    tone="success"
                  />
                  <Tile label="SYN 速率" value={formatNumber(totals.syn, true)} unit="pps" />
                  <Tile
                    label="趋势窗口峰值"
                    value={trend.pps.length > 0 ? formatNumber(trendPeak, true) : DASH}
                    unit={trend.pps.length > 0 ? 'pps' : undefined}
                  />
                </Tiles>
              </Panel>

              <Panel
                title="速率趋势"
                meta={`${trend.source} · ${formatNumber(trend.labels.length, false)} 点`}
              >
                <LineChart
                  labels={trend.labels}
                  series={[{ name: '总包速率', values: trend.pps }]}
                  height={150}
                  area
                  yUnit="pps"
                  emptyHint="暂无速率趋势数据"
                />
                <LineChart
                  labels={trend.labels}
                  series={[{ name: '总字节速率', values: trend.bps }]}
                  height={120}
                  yUnit="B/s"
                  emptyHint="暂无流量趋势数据"
                />
                <Note>
                  SSE 每 {pushSecs}s 一个采样点、最多保留 300 点（REST 回退为最近 1 小时、每 2
                  秒一条）；曲线只画最近 {TREND_POINTS} 点。
                </Note>
              </Panel>

              <Panel title="多窗口 EWMA 速率" meta="短期 ~5s / 中期 ~60s / 长期 ~300s" padded={false}>
                {windows.error !== null ? (
                  <InlineError
                    message={`多窗口速率加载失败：${windows.error}`}
                    onRetry={windows.reload}
                  />
                ) : windows.data === null ? (
                  <PanelLoading lines={4} />
                ) : (
                  <Rows>
                    <Row wide label="包速率 短期" value={formatRate(windows.data.pps_short, 'pps')} />
                    <Row wide label="包速率 中期" value={formatRate(windows.data.pps_mid, 'pps')} />
                    <Row wide label="包速率 长期" value={formatRate(windows.data.pps_long, 'pps')} />
                    <Row wide label="字节速率 短期" value={formatRate(windows.data.bps_short, 'bps')} />
                    <Row wide label="字节速率 中期" value={formatRate(windows.data.bps_mid, 'bps')} />
                    <Row wide label="字节速率 长期" value={formatRate(windows.data.bps_long, 'bps')} />
                  </Rows>
                )}
              </Panel>

              <Panel
                title="协议速率汇总"
                meta={`合计 ${formatRate(totals.pps, 'pps')}`}
                padded={false}
              >
                {PROTOCOLS.map((item, index) => (
                  <MetricRow
                    key={item.key}
                    primary={item.label}
                    value={formatRate(totals[item.key], 'pps')}
                    ratio={maxProtoPps > 0 ? totals[item.key] / maxProtoPps : 0}
                    last={index === PROTOCOLS.length - 1}
                  />
                ))}
              </Panel>

              <Panel
                title="TOP 来源 IP"
                meta={`显示 ${formatNumber(visibleTop.length, false)} / 有流量 ${formatNumber(
                  topRates.length,
                  false,
                )} / 被追踪 ${formatNumber(rates.length, false)}`}
                padded={false}
              >
                {restRates.error !== null && liveRates === null ? (
                  <InlineError
                    message={`速率数据加载失败：${restRates.error}`}
                    onRetry={restRates.reload}
                  />
                ) : liveRates === null && restRates.loading ? (
                  <PanelLoading lines={4} />
                ) : topRates.length === 0 ? (
                  <EmptyState
                    compact
                    title="当前没有被追踪的 IP"
                    description="速率表为空表示近期没有触发速率统计的流量；有异常流量时会立即出现在这里"
                  />
                ) : (
                  <>
                    {visibleTop.map((rate, index) => (
                      <MetricRow
                        key={rate.ip}
                        primary={rate.ip}
                        value={formatRate(rate.packets_per_sec, 'pps')}
                        ratio={topPeak > 0 ? rate.packets_per_sec / topPeak : 0}
                        tone={rateTone(rate.packets_per_sec, config.data)}
                        detail={`${formatRate(rate.bytes_per_sec, 'bps')} · SYN ${formatNumber(
                          Math.round(rate.syn_packets_per_sec),
                          false,
                        )} · UDP ${formatNumber(Math.round(rate.udp_packets_per_sec), false)} · ICMP ${formatNumber(
                          Math.round(rate.icmp_packets_per_sec),
                          false,
                        )} pps`}
                        last={!hasTopOverflow && index === visibleTop.length - 1}
                      />
                    ))}
                    {hasTopOverflow ? (
                      <MoreToggle
                        expanded={showAllTop}
                        total={topRates.length}
                        onToggle={() => setShowAllTop((value) => !value)}
                      />
                    ) : null}
                  </>
                )}
              </Panel>
            </>
          )}

          {/* ------------------------------ 热力图 ------------------------------ */}
          {section === 'heatmap' && (
            <Panel
              title="24 小时攻击热力图"
              meta={`口径：${HEAT_LABEL[heatMetric]}`}
              padded={false}
            >
              <div style={{ padding: '5px 6px' }}>
                <SegTabs
                  label="热力图口径"
                  items={HEAT_METRICS}
                  value={heatMetric}
                  onChange={setHeatMetric}
                />
              </div>
              {heatmap.error !== null ? (
                <InlineError message={`热力图加载失败：${heatmap.error}`} onRetry={heatmap.reload} />
              ) : heatmap.data === null ? (
                <PanelLoading lines={4} />
              ) : (
                <>
                  <Tiles columns={3}>
                    <Tile
                      label="峰值"
                      value={formatNumber(heatSummary.peak, false)}
                      unit="次"
                      tone={heatSummary.peak > 0 ? 'warning' : 'default'}
                    />
                    <Tile
                      label="峰值时段"
                      value={heatSummary.peakHour < 0 ? DASH : `${heatSummary.peakHour} 时`}
                    />
                    <Tile label="24h 合计" value={formatNumber(heatSummary.total, true)} unit="次" />
                  </Tiles>
                  <div style={{ padding: '5px 6px' }}>
                    <HeatmapChart
                      cells={heatmap.data.hours.map((bucket) => ({
                        hour: bucket.hour,
                        value: bucket[heatMetric],
                      }))}
                      height={160}
                      valueLabel={HEAT_LABEL[heatMetric]}
                      emptyHint="暂无小时级统计数据"
                    />
                    <Note>
                      色阶按 √(值/峰值) 分档：攻击量长尾分布下，开平方能让低值时段更容易分辨。
                    </Note>
                  </div>
                </>
              )}
            </Panel>
          )}

          {/* ------------------------------- 协议 ------------------------------- */}
          {section === 'protocol' && (
            <>
              <Panel
                title="协议速率占比"
                meta={`合计 ${formatRate(totals.pps, 'pps')}`}
                padded={false}
              >
                <div style={{ padding: '5px 6px 0' }}>
                  <RadarChart
                    axes={PROTOCOLS.map((item) => item.label)}
                    series={[
                      {
                        name: '协议包速率',
                        values: PROTOCOLS.map((item) => totals[item.key]),
                      },
                    ]}
                    height={210}
                    emptyHint="暂无协议速率数据"
                  />
                </div>
                {PROTOCOLS.map((item, index) => {
                  const pps = totals[item.key]
                  const share = totals.pps > 0 ? (pps / totals.pps) * 100 : 0
                  return (
                    <MetricRow
                      key={item.key}
                      primary={item.label}
                      value={`${share.toFixed(1)}%`}
                      ratio={totals.pps > 0 ? pps / totals.pps : 0}
                      detail={formatRate(pps, 'pps')}
                      last={index === PROTOCOLS.length - 1}
                    />
                  )
                })}
              </Panel>

              <Panel
                title="UDP 端口分布"
                meta={
                  udpPorts.data === null
                    ? '内核侧累计'
                    : `共 ${formatNumber(udpPorts.data.total_entries, false)} / 上限 ${formatNumber(
                        udpPorts.data.max_entries,
                        false,
                      )}`
                }
                padded={false}
              >
                {udpPorts.error !== null ? (
                  <InlineError
                    message={`UDP 端口分布加载失败：${udpPorts.error}`}
                    onRetry={udpPorts.reload}
                  />
                ) : udpPorts.data === null ? (
                  <PanelLoading lines={4} />
                ) : udpPorts.data.ports.length === 0 ? (
                  <EmptyState compact title="暂无 UDP 端口记录" description="内核侧尚未统计到 UDP 流量" />
                ) : (
                  <>
                    <div style={{ padding: '5px 6px 0' }}>
                      <PieChart
                        slices={udpPorts.data.ports
                          .slice(0, UDP_VISIBLE)
                          .map((entry) => ({ name: `端口 ${entry.port}`, value: entry.packets }))}
                        height={170}
                        donut
                        emptyHint="暂无 UDP 端口数据"
                      />
                    </div>
                    <Rows>
                      {udpPorts.data.ports.slice(0, UDP_VISIBLE).map((entry) => (
                        <Row
                          key={entry.port}
                          label={`端口 ${entry.port}`}
                          value={formatNumber(entry.packets, true)}
                          unit="包"
                          tail={
                            <span style={{ fontSize: 10, color: 'var(--fw-text-3)' }}>
                              {formatDuration(entry.last_seen_secs)} 前
                            </span>
                          }
                        />
                      ))}
                    </Rows>
                    {udpPorts.data.ports.length > UDP_VISIBLE ? (
                      <Note>
                        明细按包数降序，只列前 {UDP_VISIBLE} 个端口（共{' '}
                        {formatNumber(udpPorts.data.ports.length, false)} 个）
                      </Note>
                    ) : null}
                  </>
                )}
              </Panel>

              <Panel
                title="ICMP 类型分布"
                meta={
                  icmpTypes.data === null
                    ? '内核侧累计'
                    : `共 ${formatNumber(icmpTypes.data.total_entries, false)} / 上限 ${formatNumber(
                        icmpTypes.data.max_entries,
                        false,
                      )}`
                }
                padded={false}
              >
                {icmpTypes.error !== null ? (
                  <InlineError
                    message={`ICMP 类型分布加载失败：${icmpTypes.error}`}
                    onRetry={icmpTypes.reload}
                  />
                ) : icmpTypes.data === null ? (
                  <PanelLoading lines={4} />
                ) : icmpTypes.data.types.length === 0 ? (
                  <EmptyState compact title="暂无 ICMP 记录" description="内核侧尚未统计到 ICMP 报文" />
                ) : (
                  <>
                    <Rows>
                      {icmpTypes.data.types.slice(0, ICMP_VISIBLE).map((entry) => (
                        <Row
                          key={`${entry.type}-${entry.code}`}
                          label={`type ${entry.type} · code ${entry.code}`}
                          value={formatNumber(entry.packets, true)}
                          unit="包"
                          tail={
                            <span style={{ fontSize: 10, color: 'var(--fw-text-3)' }}>
                              {formatNumber(entry.bytes, true)} B ·{' '}
                              {formatDuration(entry.last_seen_secs)} 前
                            </span>
                          }
                        />
                      ))}
                    </Rows>
                    {icmpTypes.data.types.length > ICMP_VISIBLE ? (
                      <Note>
                        明细按包数降序，只列前 {ICMP_VISIBLE} 个类型/代码组合（共{' '}
                        {formatNumber(icmpTypes.data.types.length, false)} 个）
                      </Note>
                    ) : null}
                  </>
                )}
              </Panel>
            </>
          )}

          {/* ----------------------------- 流量特征 ----------------------------- */}
          {section === 'traffic' && (
            <>
              <Panel
                title="包大小分布"
                meta={
                  packetSizes.data === null
                    ? '内核侧累计'
                    : `总包数 ${formatNumber(packetSizes.data.total, true)}`
                }
                padded={false}
              >
                {packetSizes.error !== null ? (
                  <InlineError
                    message={`包大小分布加载失败：${packetSizes.error}`}
                    onRetry={packetSizes.reload}
                  />
                ) : packetSizes.data === null ? (
                  <PanelLoading lines={4} />
                ) : packetSizes.data.total === 0 ? (
                  <EmptyState compact title="暂无包大小统计" description="内核侧尚未累计到数据包" />
                ) : (
                  <>
                    <div style={{ padding: '5px 6px 0' }}>
                      <PieChart
                        slices={packetSizes.data.labels.map((label, index) => ({
                          name: label,
                          value: packetSizes.data?.counts[index] ?? 0,
                        }))}
                        height={180}
                        donut
                        emptyHint="暂无包大小数据"
                      />
                    </div>
                    <Rows>
                      {packetSizes.data.labels.map((label, index) => (
                        <Row
                          key={label}
                          label={label}
                          value={formatNumber(packetSizes.data?.counts[index] ?? 0, true)}
                          unit="包"
                          tail={
                            <span
                              className="fw-mono"
                              style={{ fontSize: 10, color: 'var(--fw-text-3)' }}
                            >
                              {(packetSizes.data?.percentages[index] ?? 0).toFixed(1)}%
                            </span>
                          }
                        />
                      ))}
                    </Rows>
                  </>
                )}
              </Panel>

              <Panel
                title="TTL 分布"
                meta={
                  ttlDistribution.data === null
                    ? '内核侧累计'
                    : `总包数 ${formatNumber(ttlDistribution.data.total, true)}`
                }
                padded={false}
              >
                {ttlDistribution.error !== null ? (
                  <InlineError
                    message={`TTL 分布加载失败：${ttlDistribution.error}`}
                    onRetry={ttlDistribution.reload}
                  />
                ) : ttlDistribution.data === null ? (
                  <PanelLoading lines={4} />
                ) : ttlDistribution.data.total === 0 ? (
                  <EmptyState compact title="暂无 TTL 统计" description="内核侧尚未累计到数据包" />
                ) : (
                  <>
                    <div style={{ padding: '5px 6px 0' }}>
                      <PieChart
                        slices={ttlDistribution.data.labels.map((label, index) => ({
                          name: `TTL ${label}`,
                          value: ttlDistribution.data?.counts[index] ?? 0,
                        }))}
                        height={180}
                        donut
                        emptyHint="暂无 TTL 数据"
                      />
                    </div>
                    <Rows>
                      {ttlDistribution.data.labels.map((label, index) => (
                        <Row
                          key={label}
                          label={`TTL ${label}`}
                          value={formatNumber(ttlDistribution.data?.counts[index] ?? 0, true)}
                          unit="包"
                          tail={
                            <span
                              className="fw-mono"
                              style={{ fontSize: 10, color: 'var(--fw-text-3)' }}
                            >
                              {(ttlDistribution.data?.percentages[index] ?? 0).toFixed(1)}%
                            </span>
                          }
                        />
                      ))}
                    </Rows>
                  </>
                )}
              </Panel>

              <Panel title="IP 分片统计" meta="占比阈值 5%" padded={false}>
                {ipFragments.error !== null ? (
                  <InlineError
                    message={`IP 分片统计加载失败：${ipFragments.error}`}
                    onRetry={ipFragments.reload}
                  />
                ) : ipFragments.data === null ? (
                  <PanelLoading lines={4} />
                ) : (
                  <>
                    <Tiles columns={3}>
                      <Tile
                        label="分片包数"
                        value={formatNumber(ipFragments.data.fragment_packets, true)}
                        unit="包"
                        tone={ipFragments.data.fragment_ratio >= 5 ? 'danger' : 'default'}
                      />
                      <Tile
                        label="总包数"
                        value={formatNumber(ipFragments.data.total_packets, true)}
                        unit="包"
                        tone="primary"
                      />
                      <Tile
                        label="分片占比"
                        value={`${ipFragments.data.fragment_ratio.toFixed(2)}%`}
                        tone={ipFragments.data.fragment_ratio >= 5 ? 'danger' : 'default'}
                      />
                    </Tiles>
                    <Note tone={ipFragments.data.fragment_ratio >= 5 ? 'danger' : 'default'}>
                      大量分片常被用于规避检测：分片占比持续偏高时建议结合端口扫描结果一起排查。
                    </Note>
                  </>
                )}
              </Panel>
            </>
          )}

          {/* ----------------------------- 扫描探测 ----------------------------- */}
          {section === 'scan' && (
            <>
              <Panel
                title="端口扫描检测"
                meta={
                  portScanners.data === null
                    ? '内核侧阈值判定'
                    : `阈值：不同端口数 ≥ ${formatNumber(portScanners.data.threshold, false)}`
                }
                padded={false}
              >
                {portScanners.error !== null ? (
                  <InlineError
                    message={`端口扫描结果加载失败：${portScanners.error}`}
                    onRetry={portScanners.reload}
                  />
                ) : portScanners.data === null ? (
                  <PanelLoading lines={4} />
                ) : (
                  <>
                    <Tiles columns={2}>
                      <Tile
                        label="判定阈值"
                        value={formatNumber(portScanners.data.threshold, false)}
                        unit="个端口"
                      />
                      <Tile
                        label="检出"
                        value={formatNumber(portScanners.data.total_detected, false)}
                        unit="个来源"
                        tone={portScanners.data.total_detected > 0 ? 'danger' : 'success'}
                      />
                    </Tiles>
                    {portScanners.data.scanners.length === 0 ? (
                      <EmptyState
                        compact
                        title="未检出端口扫描"
                        description="没有来源的不同端口数超过阈值"
                      />
                    ) : (
                      <>
                        {portScanners.data.scanners.slice(0, SCAN_VISIBLE).map((scanner, index) => (
                          <MetricRow
                            key={scanner.ip}
                            primary={scanner.ip}
                            value={formatNumber(scanner.unique_ports, false)}
                            unit="端口"
                            detail={`${formatNumber(scanner.packets, true)} 包`}
                            // 后面还有「只列前 N 个」说明时保留末行分隔线，否则去掉避免与面板边框叠双线
                            last={
                              portScanners.data!.scanners.length <= SCAN_VISIBLE &&
                              index === portScanners.data!.scanners.length - 1
                            }
                          />
                        ))}
                        {portScanners.data.scanners.length > SCAN_VISIBLE ? (
                          <Note>
                            明细按不同端口数降序，只列前 {SCAN_VISIBLE} 个来源（共{' '}
                            {formatNumber(portScanners.data.scanners.length, false)} 个）
                          </Note>
                        ) : null}
                      </>
                    )}
                  </>
                )}
              </Panel>

              <Panel
                title="服务探测检测"
                meta={
                  serviceProbes.data === null
                    ? '内核侧阈值判定'
                    : `阈值：协议数 ≥ ${formatNumber(serviceProbes.data.threshold, false)}`
                }
                padded={false}
              >
                {serviceProbes.error !== null ? (
                  <InlineError
                    message={`服务探测结果加载失败：${serviceProbes.error}`}
                    onRetry={serviceProbes.reload}
                  />
                ) : serviceProbes.data === null ? (
                  <PanelLoading lines={4} />
                ) : (
                  <>
                    <Tiles columns={2}>
                      <Tile
                        label="判定阈值"
                        value={formatNumber(serviceProbes.data.threshold, false)}
                        unit="个协议"
                      />
                      <Tile
                        label="检出"
                        value={formatNumber(serviceProbes.data.probes.length, false)}
                        unit="个来源"
                        tone={serviceProbes.data.probes.length > 0 ? 'danger' : 'success'}
                      />
                    </Tiles>
                    {serviceProbes.data.probes.length === 0 ? (
                      <EmptyState compact title="未检出服务探测" description="没有来源的协议数超过阈值" />
                    ) : (
                      <>
                        {serviceProbes.data.probes.slice(0, SCAN_VISIBLE).map((probe, index) => (
                          <MetricRow
                            key={probe.ip}
                            primary={probe.ip}
                            value={formatNumber(probe.protocol_count, false)}
                            unit="协议"
                            detail={`${formatNumber(probe.packets, true)} 包`}
                            last={
                              serviceProbes.data!.probes.length <= SCAN_VISIBLE &&
                              index === serviceProbes.data!.probes.length - 1
                            }
                          />
                        ))}
                        {serviceProbes.data.probes.length > SCAN_VISIBLE ? (
                          <Note>
                            明细按协议数降序，只列前 {SCAN_VISIBLE} 个来源（共{' '}
                            {formatNumber(serviceProbes.data.probes.length, false)} 个）
                          </Note>
                        ) : null}
                      </>
                    )}
                  </>
                )}
              </Panel>
            </>
          )}
        </div>
      </PullToRefresh>
    </>
  )
}
