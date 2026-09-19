/**
 * LineChart —— 手写 SVG 折线图 / 面积图（不依赖任何图表库）
 *
 * # props 契约（其他视图按此调用，签名已冻结，勿改）
 * ```ts
 * interface LineSeries { name: string; values: number[]; color?: string }
 * interface LineChartProps {
 *   labels: string[]      // x 轴标签，与各 series.values 等长
 *   series: LineSeries[]  // 1..n 条序列
 *   height?: number       // 视觉高度，默认 180
 *   area?: boolean        // 是否渐变面积填充，默认 false
 *   yUnit?: string        // y 轴刻度数值后缀，如 "pps"
 *   emptyHint?: string    // 空态文案，默认「暂无数据」
 * }
 * ```
 *
 * # 自适应（移动端优先）
 * viewBox 固定宽 360，外层用 `width:100%` + `aspectRatio` 撑高，不写死像素宽。
 * 375px 视口减去页面左右内边距后容器约 343px，缩放比 ≈0.95，故最小字号取 12
 * （渲染后 ≈11.4px），满足「≥11px」的可读性要求。
 *
 * # 主题适配
 * 所有文字与网格线用 `currentColor` + 透明度绘制，随父级深浅主题自动变色；
 * 序列颜色来自 `chartColor()`，是固定中间调，不随主题切换。
 *
 * # 行为约定
 * - 非有限值（NaN/Infinity）按 0 处理，不中断整条线。
 * - 数据点 ≤ 12 时才画节点圆点，避免密集序列糊成一团。
 * - `area` 为 true 时**每条序列**各配一份渐变填充（渐变 id 经 useChartId 保证唯一）。
 * - 全 0 是合法数据（不算空态）；labels 为空或全部数值非有限才渲染空态。
 *
 * # 影响
 * 纯展示组件：无副作用、不发请求、不读写全局状态。
 */
import { useMemo } from 'react'
// React 19 的类型里 JSX 命名空间挂在 React 命名空间下（不再是全局 JSX），须显式引入
import type { CSSProperties, JSX } from 'react'
import { chartColor, useChartId } from './chartId'

/** 折线序列：一条数据线的名称与数值 */
export interface LineSeries {
  /** 图例与无障碍标签用的序列名 */
  name: string
  /** 数值数组，长度应与 labels 一致；非有限值按 0 处理 */
  values: number[]
  /** 线条颜色；缺省时按序列下标取 chartColor() */
  color?: string
}

/** LineChart 对外 props */
export interface LineChartProps {
  /** x 轴标签，与各 series.values 等长 */
  labels: string[]
  /** 1..n 条序列 */
  series: LineSeries[]
  /** 视觉高度（viewBox 高度），默认 180 */
  height?: number
  /** 是否渐变面积填充，默认 false */
  area?: boolean
  /** y 轴刻度数值后缀，如 "pps" */
  yUnit?: string
  /** 空态文案，默认「暂无数据」 */
  emptyHint?: string
}

/** viewBox 设计宽度；配合 width:100% 实现自适应，不要改成固定像素 */
const VIEW_WIDTH = 360
/** 默认视觉高度 */
const DEFAULT_HEIGHT = 180
/** 最小可读字号（viewBox 单位），375px 视口下渲染 ≈11.4px */
const SMALL_FONT = 12
/** y 轴刻度分档数（不含 0 刻度） */
const Y_TICK_STEPS = 4
/** x 轴最多渲染的标签数，防止窄屏拥挤 */
const MAX_X_LABELS = 5

/** 图例容器：窄屏自动换行，字号用绝对 px（不随 viewBox 缩放） */
const LEGEND_STYLE: CSSProperties = {
  display: 'flex',
  flexWrap: 'wrap',
  alignItems: 'center',
  gap: '2px 7px', // 4px 12px → 2px 7px
  marginBottom: 2, // 4 → 2
  fontSize: 12, // 13 → 12
  lineHeight: 1.4,
  color: 'currentColor',
}

const LEGEND_ITEM_STYLE: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: 3, // 5 → 3
  maxWidth: '100%',
}

const LEGEND_SWATCH_STYLE: CSSProperties = {
  display: 'inline-block',
  width: 6, // 10 → 6
  height: 2, // 3 → 2
  borderRadius: 1, // 2 → 1
  flex: '0 0 auto',
}

const LEGEND_LABEL_STYLE: CSSProperties = {
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
  opacity: 0.85,
}

/** 坐标轴 / 网格 / 文字统一走 currentColor，以适配深浅主题 */
const TEXT_COLOR = 'currentColor'

/** 单个数据点坐标 */
interface Point {
  x: number
  y: number
}

/** 一条序列算好的绘制指令 */
interface LinePath {
  key: string
  name: string
  color: string
  /** 折线 path 的 d 属性 */
  path: string
  /** 面积填充 path 的 d 属性；area 关闭或点数不足时为 null */
  areaPath: string | null
  /** 节点坐标（点数 > 12 时为空数组，不画圆点） */
  points: Point[]
}

/** 折线图几何：坐标系与 path 在渲染前一次性算好 */
interface LineGeometry {
  plotLeft: number
  plotRight: number
  plotTop: number
  plotBottom: number
  yTicks: { value: number; text: string; y: number }[]
  xLabels: { key: string; text: string; x: number; anchor: 'start' | 'middle' | 'end' }[]
  lines: LinePath[]
  /** 数据点总数，用于无障碍描述 */
  pointCount: number
}

/** 把任意输入高度收敛到可用区间，避免调用方传 0 / NaN / 极大值导致图形塌陷 */
function sanitizeHeight(value: number | undefined): number {
  if (value === undefined || !Number.isFinite(value)) return DEFAULT_HEIGHT
  return Math.min(480, Math.max(80, Math.round(value)))
}

/** 数字缩写：把刻度压到 4 字符内，窄屏 y 轴才不会挤占绘图区 */
function formatCompact(value: number): string {
  const abs = Math.abs(value)
  if (abs >= 1e9) return `${trimTo1(value / 1e9)}G`
  if (abs >= 1e6) return `${trimTo1(value / 1e6)}M`
  if (abs >= 1e4) return `${trimTo1(value / 1e3)}k`
  if (abs >= 1000) return `${Math.round(value / 100) / 10}k`
  if (abs >= 10 || Number.isInteger(value)) return String(Math.round(value * 10) / 10)
  return trimTo1(value)
}

/** 保留 1 位小数，并去掉无意义的 ".0" */
function trimTo1(value: number): string {
  const rounded = Math.round(value * 10) / 10
  return Number.isInteger(rounded) ? String(rounded) : rounded.toFixed(1)
}

/** 坐标数值保留 2 位小数，缩短 path 字符串 */
function n(value: number): string {
  return (Math.round(value * 100) / 100).toString()
}

/** 单字符宽度估算：ASCII 约 0.58em，CJK / 全角约 1em */
function charWidth(char: string, fontSize: number): number {
  return /[\u2e80-\u9fff\u3000-\u303f\uf900-\ufaff\uff00-\uffef]/.test(char)
    ? fontSize
    : fontSize * 0.58
}

/** 估算整串文字的渲染宽度（与 fitText 用同一套字宽假设） */
function estimateWidth(text: string, fontSize: number): number {
  let width = 0
  for (const char of text) width += charWidth(char, fontSize)
  return width
}

/**
 * 按可用像素宽度截断文字，超出时补省略号
 *
 * 不能按「字符个数」截断：同样 6 个字符，"12:00" 只有约 42 单位，
 * 而中文 jail 名（如「ssh 暴力破解」）会到 76 单位，窄屏上会与相邻标签叠压。
 */
function fitText(text: string, fontSize: number, maxWidth: number): string {
  const ellipsisWidth = fontSize * 0.58
  let width = 0
  let output = ''
  for (const char of text) {
    const w = charWidth(char, fontSize)
    if (width + w > maxWidth) {
      // 回退到还能容纳省略号的长度
      while (output.length > 0 && width + ellipsisWidth > maxWidth) {
        const last = output[output.length - 1]
        output = output.slice(0, -1)
        width -= charWidth(last, fontSize)
      }
      return output.length === 0 ? '' : `${output}…`
    }
    output += char
    width += w
  }
  return output
}

/**
 * 选挑 x 轴要显示哪些标签
 *
 * 抽稀步长按「标签实际渲染宽度」反推，而不是写死条数：中文 jail 名约 76~90 单位宽，
 * 4 条标签在 310 单位宽的点阵里必然互相叠压；而 "23:00" 只有约 35 单位，5 条也放得下。
 * 末位标签优先保留（时间轴右端最需要），但与前一条过近时替换掉前一条而不是硬挤。
 */
function pickLabelIndices(labels: string[], plotWidth: number): number[] {
  const count = labels.length
  if (count <= 1) return [0]

  const widths = labels.map((label) => estimateWidth(label, SMALL_FONT))
  const spacingOf = (gap: number): number => (plotWidth * gap) / (count - 1)

  for (let step = 1; step <= count - 1; step += 1) {
    const indices: number[] = []
    for (let i = 0; i < count; i += step) indices.push(i)
    if (indices[indices.length - 1] !== count - 1) {
      if (indices.length > 1) indices.pop()
      indices.push(count - 1)
    }
    if (indices.length > MAX_X_LABELS) continue

    let fits = true
    for (let i = 1; i < indices.length && fits; i += 1) {
      const prev = indices[i - 1]
      const curr = indices[i]
      // 首位左对齐、末位右对齐，都会朝单侧多占空间
      const need =
        (prev === 0 ? widths[prev] : widths[prev] / 2) +
        (curr === count - 1 ? widths[curr] : widths[curr] / 2) +
        6
      if (spacingOf(curr - prev) < need) fits = false
    }
    if (fits) return indices
  }

  // 极端情况（标签极长）：只留首末两条，交给 fitText 截断
  return [0, count - 1]
}

/**
 * 把上界抬到「整齐」的刻度值（1/2/2.5/5/10 × 10^n）
 *
 * 不做这一步，最大值 9873 会让刻度变成 2468.25 这类难读数字。
 */
function niceScale(max: number, steps: number): { max: number; step: number } {
  if (!Number.isFinite(max) || max <= 0) return { max: 1, step: 1 / steps }
  const rawStep = max / steps
  const magnitude = Math.pow(10, Math.floor(Math.log10(rawStep)))
  const norm = rawStep / magnitude
  const niceNorm = norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10
  const step = niceNorm * magnitude
  // 减去极小量，规避 0.30000000000000004 这类浮点误差把刻度多算一档
  return { max: Math.ceil(max / step - 1e-9) * step, step }
}

/** 计算全部绘制几何；无有效数据时返回 null 以走空态分支 */
function buildGeometry(
  labels: string[],
  series: LineSeries[],
  height: number,
  yUnit: string,
): LineGeometry | null {
  const count = labels.length
  if (count === 0 || series.length === 0) return null

  // 只要存在有限数值就认为有数据：全 0 表示「这段时间没有封禁」，是合法状态而非空态
  const hasData = series.some((item) => item.values.some((v) => Number.isFinite(v)))
  if (!hasData) return null

  let dataMax = 0
  for (const item of series) {
    for (const v of item.values) {
      if (Number.isFinite(v) && v > dataMax) dataMax = v
    }
  }

  const scale = niceScale(dataMax, Y_TICK_STEPS)
  const tickCount = Math.max(1, Math.round(scale.max / scale.step))
  const tickValues = Array.from({ length: tickCount + 1 }, (_, i) => i * scale.step)
  const tickTexts = tickValues.map((v) => `${formatCompact(v)}${yUnit}`)

  // 左侧留白按最长刻度文本的**实际估算宽度**反推：
  // 只数字符个数会在中文 yUnit（如「次」）上低估宽度，把刻度标签挤出 viewBox
  const maxTickWidth = tickTexts.reduce(
    (widest, text) => Math.max(widest, estimateWidth(text, SMALL_FONT)),
    0,
  )
  const plotLeft = Math.max(28, 8 + maxTickWidth + 4)
  const plotRight = VIEW_WIDTH - 10
  const plotTop = 12
  const plotBottom = height - 24
  const plotWidth = Math.max(40, plotRight - plotLeft)
  const plotHeight = Math.max(20, plotBottom - plotTop)

  const yTicks = tickValues.map((value, index) => ({
    value,
    text: tickTexts[index],
    y: plotBottom - (value / scale.max) * plotHeight,
  }))

  const xFor = (index: number): number => {
    if (count === 1) return plotLeft + plotWidth / 2
    return plotLeft + (index / (count - 1)) * plotWidth
  }

  const yFor = (value: number): number => {
    const safe = Number.isFinite(value) ? Math.min(Math.max(value, 0), scale.max) : 0
    return plotBottom - (safe / scale.max) * plotHeight
  }

  // x 轴标签抽稀：按标签**实际渲染宽度**选点，而不是固定条数。
  // 中文 jail 名（约 76~90 单位）4 条就会叠压，"23:00"（约 35 单位）5 条也放得下，
  // 因此由 pickLabelIndices 在「宽度不叠压」与「不超过 MAX_X_LABELS」之间取最小可行步长。
  const labelIndices = pickLabelIndices(labels, plotWidth)
  // 每个标签可用的横向宽度：取相邻保留标签间距的 90%，两端各留一点余量
  const labelSpacing =
    labelIndices.length > 1 ? plotWidth / (labelIndices.length - 1) : plotWidth
  const maxLabelWidth = Math.max(24, labelSpacing - 8)
  const xLabels = labelIndices.map((index) => ({
    key: `${index}-${labels[index]}`,
    text: fitText(labels[index], SMALL_FONT, maxLabelWidth),
    x: xFor(index),
    // 单点数据只有一条标签且落在绘图区正中，必须居中，否则长标签从中心向右溢出 viewBox；
    // 其余情况首/末标签改用 start/end 对齐，防止超出 viewBox 被裁切
    anchor: (count === 1 ? 'middle' : index === 0 ? 'start' : index === count - 1 ? 'end' : 'middle') as
      | 'start'
      | 'middle'
      | 'end',
  }))

  const showPoints = count <= 12
  const lines: LinePath[] = series.map((item, seriesIndex) => {
    const color = item.color ?? chartColor(seriesIndex)
    const points: Point[] = []

    for (let i = 0; i < count; i += 1) {
      points.push({ x: xFor(i), y: yFor(item.values[i]) })
    }

    const path = points
      .map((point, index) => `${index === 0 ? 'M' : 'L'} ${n(point.x)} ${n(point.y)}`)
      .join(' ')

    // 面积：沿折线走一遍后落到基线下沿，再回到起点闭合
    const areaPath =
      points.length >= 2
        ? `${path} L ${n(points[points.length - 1].x)} ${n(plotBottom)} L ${n(points[0].x)} ${n(plotBottom)} Z`
        : null

    return {
      key: `${item.name}-${seriesIndex}`,
      name: item.name,
      color,
      path,
      areaPath,
      points: showPoints ? points : [],
    }
  })

  return {
    plotLeft,
    plotRight,
    plotTop,
    plotBottom,
    yTicks,
    xLabels,
    lines,
    pointCount: count,
  }
}

/** 空态：虚线框 + 居中提示，给出明确反馈而不是留一片空白 */
function EmptyChart({ height, hint }: { height: number; hint: string }): JSX.Element {
  return (
    <svg
      viewBox={`0 0 ${VIEW_WIDTH} ${height}`}
      style={svgStyle(height)}
      role="img"
      aria-label={hint}
      preserveAspectRatio="xMidYMid meet"
    >
      <rect
        x={1}
        y={1}
        width={VIEW_WIDTH - 2}
        height={height - 2}
        rx={6}
        fill="none"
        stroke={TEXT_COLOR}
        strokeOpacity={0.2}
        strokeDasharray="4 4"
      />
      <text
        x={VIEW_WIDTH / 2}
        y={height / 2}
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize={13}
        fill={TEXT_COLOR}
        fillOpacity={0.55}
      >
        {hint}
      </text>
    </svg>
  )
}

/** SVG 外观：宽度自适应、按 viewBox 比例撑高；maxWidth 防止桌面端被拉成巨幅 */
function svgStyle(height: number): CSSProperties {
  return {
    display: 'block',
    width: '100%',
    maxWidth: 640,
    height: 'auto',
    aspectRatio: `${VIEW_WIDTH} / ${height}`,
    margin: '0 auto',
  }
}

/** 折线 / 面积图 */
export function LineChart(props: LineChartProps): JSX.Element {
  const {
    labels,
    series,
    height = DEFAULT_HEIGHT,
    area = false,
    yUnit = '',
    emptyHint = '暂无数据',
  } = props

  const uid = useChartId('line')
  const chartHeight = sanitizeHeight(height)

  const geometry = useMemo(
    () => buildGeometry(labels, series, chartHeight, yUnit),
    [labels, series, chartHeight, yUnit],
  )

  // 多序列才需要图例；单序列用标题即可说明，避免占地方
  const legend =
    series.length > 1 ? (
      <div style={LEGEND_STYLE}>
        {series.map((item, index) => (
          <span key={`${item.name}-${index}`} style={LEGEND_ITEM_STYLE}>
            <span
              style={{
                ...LEGEND_SWATCH_STYLE,
                background: item.color ?? chartColor(index),
              }}
            />
            <span style={LEGEND_LABEL_STYLE}>{item.name}</span>
          </span>
        ))}
      </div>
    ) : null

  if (geometry === null) {
    return (
      <div style={{ width: '100%' }}>
        {legend}
        <EmptyChart height={chartHeight} hint={emptyHint} />
      </div>
    )
  }

  const ariaLabel = `${series.map((item) => item.name).join('、')} 折线图，共 ${geometry.pointCount} 个数据点`

  return (
    <div style={{ width: '100%' }}>
      {legend}
      <svg
        viewBox={`0 0 ${VIEW_WIDTH} ${chartHeight}`}
        style={svgStyle(chartHeight)}
        role="img"
        aria-label={ariaLabel}
        preserveAspectRatio="xMidYMid meet"
      >
        <defs>
          {area
            ? geometry.lines.map((line, index) => (
                // 面积渐变 id 带序号 + 实例前缀：同页多图、单图多序列都不会撞名
                <linearGradient
                  key={line.key}
                  id={`${uid}-area-${index}`}
                  gradientUnits="userSpaceOnUse"
                  x1={0}
                  y1={geometry.plotTop}
                  x2={0}
                  y2={geometry.plotBottom}
                >
                  <stop offset="0%" stopColor={line.color} stopOpacity={0.35} />
                  <stop offset="100%" stopColor={line.color} stopOpacity={0} />
                </linearGradient>
              ))
            : null}
        </defs>

        {/* 横向网格线；0 刻度单独加深，作为基线 */}
        {geometry.yTicks.map((tick) => (
          <line
            key={`grid-${tick.value}`}
            x1={geometry.plotLeft}
            y1={tick.y}
            x2={geometry.plotRight}
            y2={tick.y}
            stroke={TEXT_COLOR}
            strokeOpacity={tick.value === 0 ? 0.32 : 0.12}
            strokeWidth={1}
          />
        ))}

        {/* 左侧纵轴 */}
        <line
          x1={geometry.plotLeft}
          y1={geometry.plotTop}
          x2={geometry.plotLeft}
          y2={geometry.plotBottom}
          stroke={TEXT_COLOR}
          strokeOpacity={0.32}
          strokeWidth={1}
        />

        {/* y 轴刻度文本 */}
        {geometry.yTicks.map((tick) => (
          <text
            key={`tick-${tick.value}`}
            x={geometry.plotLeft - 6}
            y={tick.y}
            textAnchor="end"
            dominantBaseline="middle"
            fontSize={SMALL_FONT}
            fill={TEXT_COLOR}
            fillOpacity={0.65}
          >
            {tick.text}
          </text>
        ))}

        {/* x 轴刻度文本 */}
        {geometry.xLabels.map((label) => (
          <text
            key={`xlabel-${label.key}`}
            x={label.x}
            y={geometry.plotBottom + 15}
            textAnchor={label.anchor}
            fontSize={SMALL_FONT}
            fill={TEXT_COLOR}
            fillOpacity={0.65}
          >
            {label.text}
          </text>
        ))}

        {/* 面积填充先画，保证压在折线下方 */}
        {area
          ? geometry.lines.map((line, index) =>
              line.areaPath === null ? null : (
                <path
                  key={`area-${line.key}`}
                  d={line.areaPath}
                  fill={`url(#${uid}-area-${index})`}
                  stroke="none"
                />
              ),
            )
          : null}

        {/* 折线本体 */}
        {geometry.lines.map((line) => (
          <path
            key={`line-${line.key}`}
            d={line.path}
            fill="none"
            stroke={line.color}
            strokeWidth={2}
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        ))}

        {/* 稀疏数据补节点，便于读数 */}
        {geometry.lines.map((line) =>
          line.points.map((point, index) => (
            <circle
              key={`dot-${line.key}-${index}`}
              cx={point.x}
              cy={point.y}
              r={2.5}
              fill={line.color}
            />
          )),
        )}
      </svg>
    </div>
  )
}
