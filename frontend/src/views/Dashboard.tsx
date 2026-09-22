// 总览仪表盘（控制台式首屏）
//
// 做什么：先给结论，再按面板堆叠证据——
//   1) 判决条：一眼回答「现在有没有被打」（正常 / 观察 / 交战中）
//   2) 关键指标瓦片：实时速率、被追踪 IP、今日封禁、失败尝试、DDoS 事件、运行时长
//   3) 实时速率（含走势）、封禁概览、最新封禁（只取前几条）、Jail 状态、
//      协议分布、失败原因 TOP、24 小时封禁趋势
// 影响什么：本页全部为只读展示，不触发任何写操作，不改变内核或守护进程状态。
//
// 数据来源（每个域都走「SSE 优先 + REST 回退」，由 pickLiveData 按新鲜度戳裁决谁更新）：
//   stats  ← SSE `stats` 事件   / GET /api/v1/stats
//   rates  ← SSE `rates` 事件   / GET /api/v1/rates/current
//   jails  ← SSE `jails` 事件   / GET /api/v1/jails
//   bans   ← SSE `bans` 事件    / GET /api/v1/bans（第 1 页，按封禁时间倒序）
//   走势   ← SSE rateHistory（客户端环形缓冲）/ GET /api/v1/rates/history（通道断开时才轮询）
// 已有推送的域一律不轮询 REST：那会让两份快照互相覆盖（见 hooks/useAsync.ts 的说明）。
//
// 密度取舍：长列表只展示前几条（最新封禁 5 条、Jail 4 个、失败原因 4 类），
// 完整清单在其对应的二级页。高密度不等于全铺开——首屏只放「能立刻做判断」的信息。

import { PullToRefresh, Skeleton } from 'antd-mobile'
import { useCallback, useMemo } from 'react'

import { getBans, getJails, getRatesCurrent, getRatesHistory, getStats } from '../api/endpoints'
import type { RateResponse } from '../api/types'
import { LineChart } from '../charts/LineChart'
import { Badge, Panel, Row, Rows, Spark, Tile, Tiles, Verdict } from '../components/console'
import type { Tone } from '../components/console'
import { EmptyState } from '../components/EmptyState'
import { PageHeader } from '../components/PageHeader'
import { RecidivismPanel } from '../components/RecidivismPanel'
import { useAsync } from '../hooks/useAsync'
import { pickLiveData } from '../hooks/useLiveData'
import { usePollInterval } from '../hooks/usePollInterval'
import { useSse } from '../hooks/useSse'
import type { ConnectionStatus } from '../hooks/useSse'
import { sortChartDesc } from '../lib/defaults'
import { formatDuration, formatNumber, formatRate, formatUptime } from '../lib/format'

// ---------------------------------------------------------------------------
// 判决与展示阈值（口径写在这里，便于与后端 threat_level 的策略对齐）
// ---------------------------------------------------------------------------

/** 速率占告警阈值的比例：过半提醒关注，达到 1.0 即已超阈值 */
const WATCH_PPS_RATIO = 0.5
const ALERT_PPS_RATIO = 1

/** 近 5 分钟封禁数：出现封禁即观察，达到该值视为交战中 */
const WATCH_RECENT_BANS = 1
const ALERT_RECENT_BANS = 10

/** 封禁表占用：过半提醒关注，逼近 8 成说明新增封禁可能开始挤占哈希桶 */
const USAGE_WARN = 0.5
const USAGE_ALERT = 0.8

/** 剩余封禁时长低于该值（秒）时用告警色：即将自动解封，可留意是否会被反复触发 */
const EXPIRING_SOON_SECONDS = 60

/** 迷你走势取最近多少个采样点（SSE 1 秒一点 → 约 1 分钟；REST 2 秒一点 → 约 2 分钟） */
const SPARK_POINTS = 60

/** 长列表只展示前几条 */
const BAN_LIST_LIMIT = 5
const JAIL_LIST_LIMIT = 4
const REASON_LIMIT = 4

/** 实时通道状态 → 判决条里的说明文案 */
const STATUS_TEXT: Record<ConnectionStatus, string> = {
  connected: '实时通道正常',
  connecting: '实时通道连接中',
  disconnected: '实时通道断开，数据可能滞后',
  connection_limit: '实时通道超限，已停止重连',
}

/** 协议分布的固定顺序：不按大小排序，保证刷新时每行位置稳定，眼睛不用重新找 */
const PROTOCOLS: ReadonlyArray<{ label: string; pick: (row: RateResponse) => number }> = [
  { label: 'SYN', pick: (row) => row.syn_packets_per_sec },
  { label: 'UDP', pick: (row) => row.udp_packets_per_sec },
  { label: 'ICMP', pick: (row) => row.icmp_packets_per_sec },
  { label: 'ACK', pick: (row) => row.ack_packets_per_sec },
  { label: 'RST', pick: (row) => row.rst_packets_per_sec },
  { label: 'FIN', pick: (row) => row.fin_packets_per_sec },
]

interface VerdictInfo {
  text: string
  tone: Tone
  sub: string
}

/**
 * 计算判决条内容。
 *
 * 依据三类信号：后端威胁等级（它已综合了基线/时段）、速率与告警阈值的比例、
 * 近 5 分钟封禁数；再加上实时通道状态——通道不可用时**不替用户保证「正常」**，
 * 结论降级为观察并在说明里点明数据可能滞后。
 */
function computeVerdict(args: {
  level: string
  ppsRatio: number
  currentPps: number
  recentBans: number
  status: ConnectionStatus
}): VerdictInfo {
  const { level, ppsRatio, currentPps, recentBans, status } = args
  const combat =
    level === 'high' || level === 'critical' || ppsRatio >= ALERT_PPS_RATIO || recentBans >= ALERT_RECENT_BANS
  const watch = level === 'medium' || ppsRatio >= WATCH_PPS_RATIO || recentBans >= WATCH_RECENT_BANS
  const stale = status === 'disconnected' || status === 'connection_limit'

  let text = '正常'
  let tone: Tone = 'success'
  if (combat) {
    text = '交战中'
    tone = 'danger'
  } else if (watch) {
    text = '观察'
    tone = 'warning'
  } else if (stale) {
    text = '观察'
    tone = 'warning'
  }

  const facts = [
    STATUS_TEXT[status],
    `短期速率 ${formatRate(currentPps, 'pps')}（阈值 ${formatRatio(ppsRatio)}）`,
    recentBans > 0 ? `近 5 分钟封禁 ${formatNumber(recentBans, false)} 次` : '近 5 分钟无封禁',
  ]
  return { text, tone, sub: facts.join(' · ') }
}

/** 比值（0~1，可能超过 1）→ 百分比文本；用于阈值占比与封禁表占用 */
function formatRatio(value: number): string {
  if (!Number.isFinite(value)) return '0.0%'
  return `${(value * 100).toFixed(1)}%`
}

/** Unix 秒 → 本地 HH:MM:SS（判决条右上角的样本时间）；非法值返回空串 */
function formatClock(unixSeconds: number): string {
  if (!Number.isFinite(unixSeconds) || unixSeconds <= 0) return ''
  const date = new Date(unixSeconds * 1000)
  const pad = (value: number): string => String(value).padStart(2, '0')
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

/** 按取值函数汇总一组速率的某个字段（非有限值按 0 计，不让脏数据打断整格统计） */
function sumRates(rows: readonly RateResponse[], pick: (row: RateResponse) => number): number {
  let total = 0
  for (const row of rows) {
    const value = pick(row)
    if (Number.isFinite(value)) total += value
  }
  return total
}

export default function Dashboard() {
  const {
    stats: sseStats,
    rates: sseRates,
    jails: sseJails,
    bans: sseBans,
    payloadSeq,
    status,
    rateHistory,
  } = useSse()
  const pollMs = usePollInterval()

  // REST 回退：已有推送的域一律不轮询（否则两份快照会互相覆盖）
  const restStats = useAsync(() => getStats(), [])
  const restRates = useAsync(() => getRatesCurrent(), [])
  const restJails = useAsync(() => getJails(), [])
  // 封禁列表统一按「封禁时间倒序」取首页：SSE 载荷不保证顺序，两边用同一口径
  const restBans = useAsync(
    () => getBans({ page: 1, page_size: 8, sort_by: 'banned_at_desc' }).then((page) => page.items),
    [],
  )

  // 速率历史没有等价的推送域（SSE 侧是客户端自聚合的环形缓冲）：
  // 只在通道断开或缓冲不足时轮询 REST，通道恢复后立即停轮询
  const useRestSpark = status !== 'connected' || rateHistory.length < 2
  const restHistory = useAsync(() => getRatesHistory(), [], {
    pollMs: useRestSpark ? pollMs : undefined,
  })

  // 各域取「较新的一份」：钉死成 `sse ?? rest` 会让 REST 刷新永远失效（见 useLiveData.ts）
  const stats = pickLiveData(sseStats, payloadSeq.stats, restStats)
  const rates = pickLiveData(sseRates, payloadSeq.rates, restRates)
  const jails = pickLiveData(sseJails, payloadSeq.jails, restJails)
  const bans = pickLiveData(sseBans, payloadSeq.bans, restBans)

  /** 下拉刷新 / 失败重试：把所有 REST 回退源拉一遍（SSE 侧无需干预，它自己在推） */
  const reloadAll = useCallback(async () => {
    await Promise.all([
      restStats.reload(),
      restRates.reload(),
      restJails.reload(),
      restBans.reload(),
      restHistory.reload(),
    ])
  }, [restStats.reload, restRates.reload, restJails.reload, restBans.reload, restHistory.reload])

  const sparkValues = useMemo(() => {
    if (!useRestSpark && rateHistory.length >= 2) {
      return rateHistory.slice(-SPARK_POINTS).map((point) => point.pps)
    }
    return (restHistory.data ?? []).slice(-SPARK_POINTS).map((point) => point.total_pps)
  }, [useRestSpark, rateHistory, restHistory.data])

  const banRows = useMemo(() => {
    // 不改动入参：SSE 载荷是共享状态，先复制再排序
    return [...(bans ?? [])]
      .sort((a, b) => b.banned_at - a.banned_at || a.ip.localeCompare(b.ip))
      .slice(0, BAN_LIST_LIMIT)
  }, [bans])

  const jailRows = useMemo(() => {
    return [...(jails ?? [])]
      .sort((a, b) => b.ban_count - a.ban_count || a.name.localeCompare(b.name))
      .slice(0, JAIL_LIST_LIMIT)
  }, [jails])

  const protocolItems = useMemo(() => {
    const rows = rates ?? []
    const items = PROTOCOLS.map((proto) => ({ label: proto.label, value: sumRates(rows, proto.pick) }))
    const total = items.reduce((sum, item) => sum + item.value, 0)
    return { items, total }
  }, [rates])

  const reasons = useMemo(
    () => sortChartDesc(stats?.failure_reasons ?? { labels: [], values: [] }),
    [stats],
  )

  // 首屏还没拿到任何统计来源时先占位：避免把「还没取到」误渲染成「一切正常」
  if (stats === null) {
    return (
      <>
        <PageHeader
          title="总览"
          srOnly
          subtitle={restStats.loading ? '正在加载统计数据…' : '统计数据不可用'}
        />
        <Panel title="总体态势" padded={false}>
          {restStats.loading ? (
            <div style={{ padding: 6 }}>
              <Skeleton.Title animated />
              <Skeleton.Paragraph lineCount={5} animated />
            </div>
          ) : (
            <EmptyState
              title="统计数据不可用"
              description={restStats.error ?? '实时通道与 REST 均未返回数据，结论无法给出。'}
              action={
                <button type="button" className="fw-cmd" onClick={() => void reloadAll()}>
                  重试
                </button>
              }
            />
          )}
        </Panel>
      </>
    )
  }

  const threat = stats.threat_level
  const hasRates = rates !== null
  const trackedIps = rates?.length ?? 0
  // rates 域未到达时用 stats 的短期窗口 PPS 兜底，避免瓦片显示一个假的 0
  const totalPps = hasRates ? sumRates(rates, (row) => row.packets_per_sec) : threat.current_pps
  const totalBps = hasRates ? sumRates(rates, (row) => row.bytes_per_sec) : 0

  const ppsTone: Tone =
    threat.pps_ratio >= ALERT_PPS_RATIO ? 'danger' : threat.pps_ratio >= WATCH_PPS_RATIO ? 'warning' : 'default'
  const usageTone: Tone =
    threat.ban_table_usage >= USAGE_ALERT ? 'danger' : threat.ban_table_usage >= USAGE_WARN ? 'warning' : 'default'

  const verdict = computeVerdict({
    level: threat.level,
    ppsRatio: threat.pps_ratio,
    currentPps: threat.current_pps,
    recentBans: threat.recent_bans,
    status,
  })

  // 面板头的样本时间：走 SSE 缓冲时用帧标签，回退 REST 时用最后一笔采样的时间戳
  const lastFrame = rateHistory.length > 0 ? rateHistory[rateHistory.length - 1].label : ''
  const lastSample =
    restHistory.data && restHistory.data.length > 0
      ? formatClock(restHistory.data[restHistory.data.length - 1].timestamp)
      : ''
  const frameLabel = useRestSpark
    ? lastSample
      ? `样本 ${lastSample}`
      : undefined
    : lastFrame
      ? `样本 ${lastFrame}`
      : undefined

  const reasonRows = reasons.labels.slice(0, REASON_LIMIT).map((label, index) => ({
    // 下标参与 key：后端理论上可能出现同名原因，重复 key 会触发 React 告警（e2e 有零告警门槛）
    key: `${index}:${label}`,
    label,
    count: reasons.values[index] ?? 0,
  }))

  return (
    <>
      <PageHeader
        title="总览"
        srOnly
        subtitle={`守护进程 ${stats.daemon_version} · 内核 ${stats.kernel_version}`}
      />

      <PullToRefresh onRefresh={reloadAll}>
        <div className="fw-page">
        {/* 1) 判决条 + 关键指标：首屏的「有没有事 + 几个关键数字」 */}
        <Panel title="总体态势" meta={frameLabel} padded={false}>
          <div style={{ borderBottom: '1px solid var(--fw-border)' }}>
            <Verdict
              text={verdict.text}
              tone={verdict.tone}
              sub={verdict.sub}
              right={
                <>
                  <span className="fw-mono" style={{ fontSize: 22, fontWeight: 700, lineHeight: 1.1 }}>
                    {formatNumber(stats.current_bans, false)}
                  </span>
                  <div style={{ fontSize: 10, color: 'var(--fw-text-3)' }}>封禁中</div>
                </>
              }
            />
          </div>
          <Tiles columns={3}>
            <Tile label="实时速率" value={formatRate(totalPps, 'pps')} tone={ppsTone} />
            <Tile label="追踪 IP" value={formatNumber(trackedIps, false)} />
            <Tile label="今日封禁" value={formatNumber(stats.today_bans, false)} />
            <Tile label="失败尝试" value={formatNumber(stats.failed_attempts, true)} />
            <Tile
              label="DDoS 事件"
              value={formatNumber(stats.ddos_events, false)}
              tone={stats.ddos_events > 0 ? 'danger' : 'default'}
            />
            <Tile label="运行时长" value={formatUptime(stats.uptime_seconds)} />
          </Tiles>
        </Panel>

        {/* 2) 实时速率：数值 + 走势（走势来自 SSE 环形缓冲，通道断开时轮询 REST 历史） */}
        <Panel
          title="实时速率"
          meta={hasRates ? `追踪 ${formatNumber(trackedIps, false)} 个 IP` : undefined}
        >
          {hasRates ? (
            <Rows>
              <Row
                label="合计速率"
                value={formatRate(totalPps, 'pps')}
                tone={ppsTone}
                tail={<Spark values={sparkValues} tone={ppsTone === 'default' ? 'primary' : ppsTone} />}
              />
              <Row label="合计带宽" value={formatRate(totalBps, 'bps')} />
              <Row label="告警阈值占比" value={formatRatio(threat.pps_ratio)} tone={ppsTone} />
            </Rows>
          ) : (
            <EmptyState
              compact
              title="暂无速率样本"
              description="被追踪 IP 的速率由内核上报，出现流量后这里会显示实时速率与走势。"
            />
          )}
        </Panel>

        {/* 3) 封禁概览：内核与守护进程的累计计数（今日封禁已在瓦片里，不重复） */}
        <Panel title="封禁概览" meta={`累计 ${formatNumber(stats.total_bans, true)} 次`}>
          <Rows>
            <Row
              label="近 5 分钟"
              value={formatNumber(threat.recent_bans, false)}
              unit="次封禁"
              tone={threat.recent_bans > 0 ? 'warning' : 'default'}
            />
            <Row label="累计解封" value={formatNumber(stats.total_unbans, true)} />
            <Row label="白名单条目" value={formatNumber(stats.whitelist_count, false)} />
            <Row label="丢弃数据包" value={formatNumber(stats.packets_dropped, true)} />
            <Row label="放行数据包" value={formatNumber(stats.packets_accepted, true)} />
            <Row label="封禁表占用" value={formatRatio(threat.ban_table_usage)} tone={usageTone} />
          </Rows>
        </Panel>

        {/* 4) 最新封禁：只取前 5 条（完整清单在「封禁」页） */}
        <Panel title="最新封禁" meta={`共 ${formatNumber(stats.current_bans, false)} 条`}>
          {banRows.length === 0 ? (
            <EmptyState
              compact
              title={stats.current_bans > 0 ? '封禁列表未就绪' : '当前没有活跃封禁'}
              description={
                stats.current_bans > 0
                  ? `内核报告有 ${formatNumber(stats.current_bans, false)} 条活跃封禁，列表数据尚未到达。`
                  : '没有检测到攻击，或封禁已全部到期。'
              }
            />
          ) : (
            <Rows>
              {banRows.map((ban) => (
                <Row
                  key={`${ban.ip}:${ban.banned_at}`}
                  wide
                  label={<span className="fw-mono">{ban.ip}</span>}
                  value={formatDuration(ban.remaining_seconds)}
                  tone={
                    ban.is_permanent
                      ? 'danger'
                      : ban.remaining_seconds <= EXPIRING_SOON_SECONDS
                        ? 'warning'
                        : 'default'
                  }
                  tail={<Badge dim>{ban.jail}</Badge>}
                />
              ))}
            </Rows>
          )}
        </Panel>

        {/* 5) Jail 状态：按封禁数取前 4 个（完整清单与阈值配置在「Jail 管理」页） */}
        <Panel title="Jail 状态" meta={jails === null ? undefined : `共 ${jails.length} 个`}>
          {jailRows.length === 0 ? (
            <EmptyState
              compact
              title={jails === null ? (restJails.loading ? '正在加载 Jail 列表…' : 'Jail 列表不可用') : '没有已配置的 Jail'}
              description="Jail 定义各服务的检测阈值与封禁时长，配置在服务端 YAML 中。"
            />
          ) : (
            <Rows>
              {jailRows.map((jail) => (
                <Row
                  key={jail.name}
                  label={<span className="fw-mono">{jail.name}</span>}
                  value={formatNumber(jail.ban_count, false)}
                  unit="封禁"
                  tail={
                    <span style={{ display: 'inline-flex', gap: 3 }}>
                      {jail.is_peak_hours ? (
                        <Badge dim tone="warning">
                          高峰
                        </Badge>
                      ) : null}
                      <Badge dim tone={jail.enabled ? 'success' : 'default'}>
                        {jail.enabled ? '启用' : '停用'}
                      </Badge>
                    </span>
                  }
                />
              ))}
            </Rows>
          )}
        </Panel>

        {/* 6) 协议分布：固定顺序展示六类报文的速率与占比 */}
        <Panel title="协议分布" meta={hasRates ? `合计 ${formatRate(totalPps, 'pps')}` : undefined}>
          {protocolItems.total === 0 ? (
            <EmptyState
              compact
              title="暂无协议样本"
              description="协议维度来自内核的每协议速率统计，出现流量后这里会逐项显示。"
            />
          ) : (
            <Rows>
              {protocolItems.items.map((item) => (
                <Row
                  key={item.label}
                  label={item.label}
                  value={formatRate(item.value, 'pps')}
                  tail={
                    <Badge dim>{`${((item.value / protocolItems.total) * 100).toFixed(0)}%`}</Badge>
                  }
                />
              ))}
            </Rows>
          )}
        </Panel>

        {/* 7) 失败原因 TOP：按活跃封禁记录聚合，只取前 4 类 */}
        <Panel title="失败原因 TOP" meta={`${reasons.labels.length} 类`}>
          {reasonRows.length === 0 ? (
            <EmptyState
              compact
              title="暂无失败记录"
              description="失败原因按活跃封禁记录聚合，没有活跃封禁时为空。"
            />
          ) : (
            <Rows>
              {reasonRows.map((reason) => (
                <Row key={reason.key} wide label={reason.label} value={formatNumber(reason.count, false)} />
              ))}
            </Rows>
          )}
        </Panel>

        {/* 8) 24 小时封禁趋势：一天的时间维度，回答「最近是不是一直有事」 */}
        <Panel title="封禁趋势" meta="近 24 小时">
          <LineChart
            labels={stats.ban_trend.labels}
            series={[{ name: '封禁次数', values: stats.ban_trend.values }]}
            height={120}
            area
            yUnit="次"
            emptyHint="暂无封禁趋势数据"
          />
        </Panel>

        {/* 9) 封禁效果：历史维度（复发率 + 复发 TOP），回答「这套封禁策略有没有效」。
            组件自带面板、判决条与取数（GET /api/v1/stats/recidivism，按 SSE 同源间隔自动刷新）；
            TOP 列表只取 5 条，与最新封禁 / Jail 状态保持同一档密度。 */}
        <RecidivismPanel limit={5} />
        </div>
      </PullToRefresh>
    </>
  )
}
