import { useId, useMemo } from 'react'
import ReactECharts from 'echarts-for-react'
import type { EChartsOption } from 'echarts-for-react'
import { EmptyState } from '../state/EmptyState.tsx'
import { useTheme } from '../../providers/ThemeProvider.tsx'
import { CHART_COLORS, chartBaseTheme } from '../../theme/tokens.ts'

/**
 * 图表基座 —— 全站 ECharts 的唯一渲染入口。
 *
 * 集中四件事，保证「所有图看起来是一套的」：
 *   1. 主题：调色板（CHART_COLORS）、文字色、透明背景随明暗主题切换，不散落到各图各配；
 *   2. 空态：无数据时渲染设计系统的 EmptyState 而不是画一张空坐标轴（空轴会误导成「值为 0」）；
 *   3. 加载/尺寸：统一的 loading 遮罩、autoResize、canvas 渲染器与默认高度；
 *   4. 文本替代：canvas 里的文字不在无障碍树里，基座按 option 生成可播报文本——容器 role="img"
 *      + aria-label（图表名 + 数据概览），并用 aria-describedby 关联一段 .fw-sr-only 摘要，
 *      逐条列出序列名与最新值；空态与加载中播报状态文本。
 *
 * option 由调用方用 `useChartBase()` 拿到的轴色/文字色自行拼装——基座只负责「主题外壳」，
 * 具体图形（line/bar/pie/radar/heatmap/gauge）的形状知识留在各页的 option 构造里。
 */

export interface ChartBase {
  textColor: string
  axisLineColor: string
  splitLineColor: string
  palette: readonly string[]
  isDark: boolean
}

/** 供各页构造 option 时取用的主题化基色（轴线/文字/调色板）。 */
export function useChartBase(): ChartBase {
  const { mode } = useTheme()
  return useMemo(() => {
    const base = chartBaseTheme(mode)
    return {
      textColor: base.textColor,
      axisLineColor: base.axisLineColor,
      splitLineColor: base.splitLineColor,
      palette: CHART_COLORS,
      isDark: mode === 'dark',
    }
  }, [mode])
}

export interface BaseChartProps {
  option: EChartsOption
  /** 图表标题，用作无障碍名称（如「封禁趋势」）。缺省时依次取 option.title、序列名、图形类型名。 */
  title?: string
  /** 图表高度（px 或 CSS 长度）。 */
  height?: number | string
  /** 无数据时展示空态而非空坐标轴。 */
  empty?: boolean
  emptyText?: string
  loading?: boolean
  /** ECharts 事件绑定（如点击柱子弹详情）。 */
  onEvents?: Record<string, (params: unknown) => void>
}

// ---------------------------------------------------------------------------
// 文本替代：从 option 里读出「图上有哪些序列、各有多少点、最新值是多少」
// ---------------------------------------------------------------------------

type Dict = Record<string, unknown>

/** ECharts option 的类型是 any：先收窄成 unknown 再按需取值，避免 any 扩散到组件逻辑。 */
function isDict(value: unknown): value is Dict {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function asList(value: unknown): unknown[] {
  if (value == null) return []
  return Array.isArray(value) ? value : [value]
}

/** 取数组里最后一个可解析为数字的值（兼容 {value} 包装与 [x, y] 元组）。 */
function lastNumber(value: unknown): number | undefined {
  if (typeof value === 'number') return Number.isFinite(value) ? value : undefined
  if (typeof value === 'string') {
    const n = Number(value)
    return value.trim() !== '' && Number.isFinite(n) ? n : undefined
  }
  if (Array.isArray(value)) {
    for (let i = value.length - 1; i >= 0; i -= 1) {
      const n = lastNumber(value[i])
      if (n !== undefined) return n
    }
    return undefined
  }
  if (isDict(value)) return lastNumber(value.value)
  return undefined
}

function asText(value: unknown): string | undefined {
  if (typeof value === 'string' && value.trim() !== '') return value.trim()
  if (isDict(value) && typeof value.text === 'string' && value.text.trim() !== '') {
    return value.text.trim()
  }
  return undefined
}

/** 播报用数字：整数加千分位，小数保留两位，避免 1234.5678 这类噪音。 */
function formatValue(value: number): string {
  return Number.isInteger(value) ? value.toLocaleString('zh-CN') : value.toFixed(2)
}

type SeriesKind = 'category' | 'pie' | 'gauge' | 'radar' | 'heatmap' | 'other'

const SERIES_KINDS: Record<string, SeriesKind> = {
  line: 'category',
  bar: 'category',
  scatter: 'category',
  effectScatter: 'category',
  pie: 'pie',
  gauge: 'gauge',
  radar: 'radar',
  heatmap: 'heatmap',
}

/** 没有标题也没有序列名时，用图形类型兜底命名。 */
const KIND_NAMES: Record<SeriesKind, string> = {
  category: '图表',
  pie: '占比图',
  gauge: '仪表盘',
  radar: '雷达图',
  heatmap: '热力图',
  other: '图表',
}

interface SeriesBrief {
  kind: SeriesKind
  name: string
  /** 数据点数（饼图为扇区数，雷达图为维度数，热力图为格子数）。 */
  points: number
  /** 最新值：折线/柱状取最后一个点，仪表盘取指针值；饼图/热力图无此语义。 */
  latest?: number
  /** 峰值：饼图最大扇区、热力图最高格子、仪表盘/雷达图的量程上限。 */
  peak?: number
  peakLabel?: string
}

function readSeries(series: Dict): SeriesBrief {
  const kind = SERIES_KINDS[String(series.type ?? '')] ?? 'other'
  const data = asList(series.data)
  const brief: SeriesBrief = { kind, name: asText(series.name) ?? '', points: data.length }

  if (kind === 'pie') {
    for (const item of data) {
      const value = lastNumber(item)
      if (value === undefined) continue
      if (brief.peak === undefined || value > brief.peak) {
        brief.peak = value
        brief.peakLabel = isDict(item) ? asText(item.name) : undefined
      }
    }
    return brief
  }

  if (kind === 'gauge') {
    brief.latest = lastNumber(data[0])
    brief.peak = lastNumber(series.max)
    brief.name = brief.name || (isDict(data[0]) ? (asText(data[0].name) ?? '') : '')
    return brief
  }

  if (kind === 'radar') {
    const first = data[0]
    const values = isDict(first) ? asList(first.value) : []
    brief.points = values.length
    for (const item of values) {
      const value = lastNumber(item)
      if (value === undefined) continue
      if (brief.peak === undefined || value > brief.peak) brief.peak = value
    }
    brief.name = brief.name || (isDict(first) ? (asText(first.name) ?? '') : '')
    return brief
  }

  if (kind === 'heatmap') {
    for (const point of data) {
      const value = lastNumber(point)
      if (value === undefined) continue
      if (brief.peak === undefined || value > brief.peak) brief.peak = value
    }
    return brief
  }

  brief.latest = lastNumber(data[data.length - 1])
  return brief
}

/** 取类目轴的刻度文案（横向柱状图的类目在 yAxis，两者都看）。 */
function readAxisLabels(option: Dict): string[] {
  for (const key of ['xAxis', 'yAxis']) {
    for (const axis of asList(option[key])) {
      if (!isDict(axis) || !Array.isArray(axis.data)) continue
      const labels = axis.data
        .map((item) => (typeof item === 'string' ? item : asText(item)))
        .filter((item): item is string => item !== undefined)
      if (labels.length > 0) return labels
    }
  }
  return []
}

function readTitle(option: Dict): string | undefined {
  for (const item of asList(option.title)) {
    const text = asText(item)
    if (text) return text
  }
  return undefined
}

interface ChartA11y {
  /** 图表名：title 属性、option.title、序列名或图形类型名。 */
  name: string
  /** role="img" 的 aria-label：图表名 + 一句概览。 */
  label: string
  /** aria-describedby 指向的 sr-only 摘要。 */
  detail: string
  /** option 里是否有可播报的数据。 */
  hasData: boolean
}

function describeChart(option: unknown, title: string | undefined): ChartA11y {
  const opts: Dict = isDict(option) ? option : {}
  const briefs = asList(opts.series).filter(isDict).map(readSeries)
  const axisLabels = readAxisLabels(opts)
  const name =
    title ??
    readTitle(opts) ??
    briefs.find((b) => b.name !== '')?.name ??
    KIND_NAMES[briefs[0]?.kind ?? 'other']
  const hasData = briefs.some((b) => b.points > 0 || b.latest !== undefined)

  const headline: string[] = []
  const details: string[] = []

  if (hasData) {
    const category = briefs.filter((b) => b.kind === 'category' && b.points > 0)
    if (category.length > 0) {
      const points = Math.max(...category.map((b) => b.points))
      const range =
        axisLabels.length > 1 ? `范围 ${axisLabels[0]}–${axisLabels[axisLabels.length - 1]}` : ''
      headline.push(`最近 ${points} 个点`)
      if (range) headline.push(range)
      const latest = category.filter((b) => b.latest !== undefined).slice(0, 3)
      if (latest.length > 0) {
        headline.push(
          `最新值 ${latest.map((b) => `${b.name ? `${b.name} ` : ''}${formatValue(b.latest!)}`).join('、')}`,
        )
      }
      details.push(`共 ${points} 个点${range ? `，${range}` : ''}`)
    }

    const pie = briefs.find((b) => b.kind === 'pie' && b.points > 0)
    if (pie) {
      headline.push(`共 ${pie.points} 项`)
      if (pie.peak !== undefined) {
        headline.push(
          `占比最高${pie.peakLabel ? `的「${pie.peakLabel}」` : '的一项'}为 ${formatValue(pie.peak)}`,
        )
        details.push(
          `各分项共 ${pie.points} 项，最大${pie.peakLabel ? `「${pie.peakLabel}」` : '项'} ${formatValue(pie.peak)}`,
        )
      } else {
        details.push(`各分项共 ${pie.points} 项`)
      }
    }

    const gauge = briefs.find((b) => b.kind === 'gauge' && b.latest !== undefined)
    if (gauge) {
      headline.push(
        `当前值 ${formatValue(gauge.latest!)}${gauge.peak !== undefined ? `（满分 ${formatValue(gauge.peak)}）` : ''}`,
      )
      details.push(
        `当前值 ${formatValue(gauge.latest!)}${gauge.peak !== undefined ? `，满分 ${formatValue(gauge.peak)}` : ''}`,
      )
    }

    const radar = briefs.find((b) => b.kind === 'radar' && b.points > 0)
    if (radar) {
      headline.push(`共 ${radar.points} 个维度`)
      details.push(
        `共 ${radar.points} 个维度${radar.peak !== undefined ? `，最高值 ${formatValue(radar.peak)}` : ''}`,
      )
    }

    const heatmap = briefs.find((b) => b.kind === 'heatmap' && b.points > 0)
    if (heatmap) {
      headline.push(`共 ${heatmap.points} 个格子`)
      details.push(
        `共 ${heatmap.points} 个格子${heatmap.peak !== undefined ? `，最高值 ${formatValue(heatmap.peak)}` : ''}`,
      )
    }

    const others = briefs.filter(
      (b) => b.kind === 'other' && (b.points > 0 || b.latest !== undefined),
    )
    if (others.length > 0) {
      const points = Math.max(...others.map((b) => b.points))
      headline.push(`共 ${points} 个数据点`)
      details.push(`共 ${points} 个数据点`)
    }

    // 关键序列名 + 最新值：读屏器用户据此判断「哪条线现在是多少」
    const seriesLines = briefs
      .filter((b) => b.kind === 'category' || b.kind === 'other')
      .slice(0, 4)
      .map((b) =>
        b.latest !== undefined
          ? `序列「${b.name || '未命名'}」共 ${b.points} 个点，最新值 ${formatValue(b.latest)}`
          : `序列「${b.name || '未命名'}」共 ${b.points} 个点`,
      )
    if (seriesLines.length > 0) details.push(seriesLines.join('；'))
    const hiddenSeries =
      briefs.filter((b) => b.kind === 'category' || b.kind === 'other').length - seriesLines.length
    if (hiddenSeries > 0) details.push(`另有 ${hiddenSeries} 个序列未逐条列出`)
  } else {
    headline.push('暂无数据')
    details.push('暂无数据')
  }

  return {
    name,
    label: headline.length > 0 ? `${name}：${headline.join('，')}` : name,
    detail: `${name}。${details.join('。')}。`,
    hasData,
  }
}

export function BaseChart({
  option,
  title,
  height = 260,
  empty = false,
  emptyText = '暂无图表数据',
  loading = false,
  onEvents,
}: BaseChartProps) {
  const { mode } = useTheme()
  const summaryId = useId()

  // 主题对象按 mode memo：identity 稳定，避免每次渲染都触发 ECharts 重新初始化
  const theme = useMemo(() => {
    const base = chartBaseTheme(mode)
    return {
      color: [...CHART_COLORS],
      backgroundColor: base.backgroundColor,
      textStyle: { color: base.textColor, fontFamily: 'var(--fw-font-sans)' },
    }
  }, [mode])

  // canvas 内容对读屏器不可见，这份文本是唯一的信息来源，随 option 变化重算
  const a11y = useMemo(() => describeChart(option, title), [option, title])

  if (empty && !loading) {
    return (
      <div
        role="img"
        aria-label={`${a11y.name}：${emptyText}`}
        style={{ height: typeof height === 'number' ? height : undefined, minHeight: 160 }}
      >
        <EmptyState scenario="no-data" title={emptyText} />
      </div>
    )
  }

  const isLoading = loading && !a11y.hasData
  const label = isLoading ? `${a11y.name}：加载中` : a11y.label
  const detail = isLoading
    ? `${a11y.name}正在加载，暂无数据可读。`
    : loading
      ? `${a11y.detail}图表正在刷新。`
      : a11y.detail

  return (
    <>
      <div role="img" aria-label={label} aria-describedby={summaryId} style={{ width: '100%' }}>
        <ReactECharts
          option={option}
          theme={theme}
          notMerge
          lazyUpdate
          showLoading={loading}
          autoResize
          opts={{ renderer: 'canvas' }}
          onEvents={onEvents}
          style={{ height: typeof height === 'number' ? `${height}px` : height, width: '100%' }}
        />
      </div>
      <span id={summaryId} className="fw-sr-only">
        {detail}
      </span>
    </>
  )
}
