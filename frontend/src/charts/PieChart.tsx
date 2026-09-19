/**
 * PieChart —— 手写 SVG 环形图 / 饼图（不依赖任何图表库）
 *
 * # props 契约（其他视图按此调用，签名已冻结，勿改）
 * ```ts
 * interface PieSlice { name: string; value: number }
 * interface PieChartProps {
 *   slices: PieSlice[]
 *   height?: number    // 默认 180
 *   donut?: boolean    // 默认 true（环形）
 *   emptyHint?: string
 * }
 * ```
 *
 * # 布局（移动端优先）
 * 圆环在上、图例在下分两行占满窄屏：环体用 viewBox 固定宽 360 自适应缩放，
 * 图例用 HTML 行（字号 13px 绝对值，不随缩放变小），窄屏也不会被挤成一条缝。
 * 375px 视口下环内百分比文字渲染 ≈11.4px，满足「≥11px」。
 *
 * # 主题适配
 * 轴线/文字用 `currentColor` + 透明度，随深浅主题自动变色；
 * 扇区颜色来自 `chartColor()`，为固定中间调。
 *
 * # 行为约定
 * - **不重排顺序**：扇区顺序即调用方给的顺序，颜色按该顺序分配，保证同一份数据每次渲染配色一致。
 * - value ≤ 0 或非有限的扇区不画弧段（仍在图例中列出，显示 0 与 0.0%），也不计入百分比分母。
 * - 占比 ≥ 8% 的扇区才在弧上标百分比，避免小扇区文字互相叠压；完整占比一律在图例里给出。
 * - 单个扇区占满 100% 时会画成整环（SVG 中起终点重合的单段圆弧会被视为零长度而不渲染，故拆两段半圆）。
 *
 * # 影响
 * 纯展示组件：无副作用、不发请求、不读写全局状态。无 defs，也不需要实例 id。
 */
import { useMemo } from 'react'
// React 19 的类型里 JSX 命名空间挂在 React 命名空间下（不再是全局 JSX），须显式引入
import type { CSSProperties, JSX } from 'react'
import { chartColor } from './chartId'

/** 扇区：类目名与数值 */
export interface PieSlice {
  /** 图例中的类目名 */
  name: string
  /** 数值（任意量纲，内部按总和换算百分比）；非正值不参与绘制 */
  value: number
}

/** PieChart 对外 props */
export interface PieChartProps {
  /** 扇区列表，按调用方顺序绘制 */
  slices: PieSlice[]
  /** 圆环区域视觉高度（viewBox 高度），默认 180 */
  height?: number
  /** 是否环形（中空），默认 true */
  donut?: boolean
  /** 空态文案，默认「暂无数据」 */
  emptyHint?: string
}

/** viewBox 设计宽度；配合 width:100% 实现自适应，不要改成固定像素 */
const VIEW_WIDTH = 360
/** 默认视觉高度 */
const DEFAULT_HEIGHT = 180
/** 最小可读字号（viewBox 单位），375px 视口下渲染 ≈11.4px */
const SMALL_FONT = 12
/** 弧上百分比标签的最小扇区占比：更小的扇区放不下文字 */
const MIN_LABEL_FRACTION = 0.08
/** 扇区之间的角度间隙（弧度，约 1.1°），让相邻色块有分界 */
const SLICE_GAP = 0.02
/** 整圆判定阈值：占比达到该值即按整环处理 */
const FULL_CIRCLE_EPSILON = 1e-6
const TAU = Math.PI * 2

/** 图例容器：一行一个类目，右侧数值与占比右对齐 */
const LEGEND_STYLE: CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  gap: 2, // 4 → 2
  marginTop: 4, // 6 → 4
  fontSize: 12, // 13 → 12
  lineHeight: 1.4,
  color: 'currentColor',
}

const LEGEND_ROW_STYLE: CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: 5, // 8 → 5
}

const LEGEND_SWATCH_STYLE: CSSProperties = {
  display: 'inline-block',
  width: 6, // 10 → 6
  height: 6, // 10 → 6
  borderRadius: 1, // 2 → 1
  flex: '0 0 auto',
}

const LEGEND_NAME_STYLE: CSSProperties = {
  flex: '1 1 auto',
  minWidth: 0,
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
  opacity: 0.85,
}

const LEGEND_VALUE_STYLE: CSSProperties = {
  flex: '0 0 auto',
  fontVariantNumeric: 'tabular-nums',
  opacity: 0.95,
}

const LEGEND_PCT_STYLE: CSSProperties = {
  flex: '0 0 52px',
  textAlign: 'right',
  fontVariantNumeric: 'tabular-nums',
  opacity: 0.65,
}

/** 坐标轴与文字统一走 currentColor，以适配深浅主题 */
const TEXT_COLOR = 'currentColor'

/** 一个算好的扇区 */
interface PieArc {
  key: string
  name: string
  value: number
  color: string
  /** 扇形 / 环带的 path d 属性 */
  path: string
  /** 是否在弧上标百分比 */
  showLabel: boolean
  /** 弧上百分比文字的位置 */
  labelX: number
  labelY: number
  /** 百分比文字（含未四舍五入的原始占比，供图例复用） */
  fraction: number
}

/** 圆环图几何 */
interface PieGeometry {
  arcs: PieArc[]
  /** 正值数值总和，用于中心总计 */
  total: number
}

/** 把任意输入高度收敛到可用区间 */
function sanitizeHeight(value: number | undefined): number {
  if (value === undefined || !Number.isFinite(value)) return DEFAULT_HEIGHT
  return Math.min(480, Math.max(100, Math.round(value)))
}

/** 坐标数值保留 2 位小数 */
function n(value: number): string {
  return (Math.round(value * 100) / 100).toString()
}

/** 极坐标转直角坐标（SVG 的 y 轴向下，角度增大即为顺时针） */
function toPoint(cx: number, cy: number, radius: number, angle: number): [number, number] {
  return [cx + radius * Math.cos(angle), cy + radius * Math.sin(angle)]
}

/**
 * 环形 / 扇形路径
 *
 * outerR 为外半径，innerR 为内半径（0 表示实心饼图）。整环需要特殊处理：
 * 单段圆弧若起终点重合，SVG 规范视其为零长度而不渲染，故拆成两段半圆。
 */
function ringPath(
  cx: number,
  cy: number,
  outerR: number,
  innerR: number,
  startAngle: number,
  endAngle: number,
): string {
  const isFull = endAngle - startAngle >= TAU - FULL_CIRCLE_EPSILON
  const end = isFull ? startAngle + TAU : endAngle
  const largeArc = end - startAngle > Math.PI ? 1 : 0
  const commands: string[] = []

  const [ox0, oy0] = toPoint(cx, cy, outerR, startAngle)
  commands.push(`M ${n(ox0)} ${n(oy0)}`)

  if (isFull) {
    const [oxm, oym] = toPoint(cx, cy, outerR, startAngle + Math.PI)
    commands.push(`A ${n(outerR)} ${n(outerR)} 0 1 1 ${n(oxm)} ${n(oym)}`)
    commands.push(`A ${n(outerR)} ${n(outerR)} 0 1 1 ${n(ox0)} ${n(oy0)}`)
  } else {
    const [ox1, oy1] = toPoint(cx, cy, outerR, end)
    commands.push(`A ${n(outerR)} ${n(outerR)} 0 ${largeArc} 1 ${n(ox1)} ${n(oy1)}`)
  }

  if (innerR <= 0) {
    commands.push('Z')
    return commands.join(' ')
  }

  // 内圈逆时针绕回，形成环带
  const [ix1, iy1] = toPoint(cx, cy, innerR, end)
  commands.push(`L ${n(ix1)} ${n(iy1)}`)
  if (isFull) {
    const [ixm, iym] = toPoint(cx, cy, innerR, startAngle + Math.PI)
    commands.push(`A ${n(innerR)} ${n(innerR)} 0 1 0 ${n(ixm)} ${n(iym)}`)
    commands.push(`A ${n(innerR)} ${n(innerR)} 0 1 0 ${n(ix1)} ${n(iy1)}`)
  } else {
    const [ix0, iy0] = toPoint(cx, cy, innerR, startAngle)
    commands.push(`A ${n(innerR)} ${n(innerR)} 0 ${largeArc} 0 ${n(ix0)} ${n(iy0)}`)
  }
  commands.push('Z')
  return commands.join(' ')
}

/** 依据背景色亮度选择前景文字色，保证弧上百分比可读 */
function contrastText(color: string): string {
  const hex = color.replace('#', '')
  if (hex.length < 6) return '#ffffff'
  const r = parseInt(hex.slice(0, 2), 16)
  const g = parseInt(hex.slice(2, 4), 16)
  const b = parseInt(hex.slice(4, 6), 16)
  if (!Number.isFinite(r) || !Number.isFinite(g) || !Number.isFinite(b)) return '#ffffff'
  // ITU-R BT.601 近似亮度：亮底用深字，暗底用白字
  const luma = (0.299 * r + 0.587 * g + 0.114 * b) / 255
  return luma > 0.6 ? '#10161c' : '#ffffff'
}

/** 百分比文案：小占比保留 1 位小数，否则取整，避免出现 "0%" 丢掉信息 */
function formatPercent(fraction: number): string {
  const pct = fraction * 100
  if (pct > 0 && pct < 10) return `${(Math.round(pct * 10) / 10).toFixed(1)}%`
  return `${Math.round(pct)}%`
}

/** 计算全部绘制几何；无有效数据时返回 null 以走空态分支 */
function buildGeometry(slices: PieSlice[], height: number, donut: boolean): PieGeometry | null {
  if (slices.length === 0) return null

  const total = slices.reduce((sum, slice) => {
    const value = Number.isFinite(slice.value) ? slice.value : 0
    return value > 0 ? sum + value : sum
  }, 0)
  if (total <= 0) return null

  const cx = VIEW_WIDTH / 2
  const cy = height / 2
  const outerR = Math.max(24, Math.min(150, height / 2 - 8))
  const innerR = donut ? outerR * 0.6 : 0
  const midR = donut ? (outerR + innerR) / 2 : outerR * 0.62

  // 从 12 点方向开始顺时针铺开
  let cursor = -Math.PI / 2
  const positiveCount = slices.filter((slice) => Number.isFinite(slice.value) && slice.value > 0)
    .length
  const gap = positiveCount > 1 ? SLICE_GAP : 0

  const arcs: PieArc[] = []
  slices.forEach((slice, index) => {
    const value = Number.isFinite(slice.value) ? slice.value : 0
    const color = chartColor(index)

    // 非正值不画弧，但仍进图例，让「有这一类但为 0」这件事可见
    if (value <= 0) {
      arcs.push({
        key: `${slice.name}-${index}`,
        name: slice.name,
        value,
        color,
        path: '',
        showLabel: false,
        labelX: 0,
        labelY: 0,
        fraction: 0,
      })
      return
    }

    const fraction = value / total
    const sweep = fraction * TAU
    const start = cursor
    const end = cursor + sweep
    cursor = end

    // 相邻扇区各让出半个间隙；整环时不留间隙，否则会露出一道缺口
    const drawStart = sweep >= TAU - FULL_CIRCLE_EPSILON ? start : start + gap / 2
    const drawEnd = sweep >= TAU - FULL_CIRCLE_EPSILON ? end : Math.max(end - gap / 2, drawStart)
    const mid = (drawStart + drawEnd) / 2
    const [labelX, labelY] = toPoint(cx, cy, midR, mid)

    arcs.push({
      key: `${slice.name}-${index}`,
      name: slice.name,
      value,
      color,
      path: ringPath(cx, cy, outerR, innerR, drawStart, drawEnd),
      showLabel: fraction >= MIN_LABEL_FRACTION,
      labelX,
      labelY,
      fraction,
    })
  })

  return { arcs, total }
}

/** 空态：虚线圆 + 居中提示 */
function EmptyChart({ height, hint }: { height: number; hint: string }): JSX.Element {
  const cy = height / 2
  const radius = Math.max(24, Math.min(60, height / 2 - 12))
  return (
    <svg
      viewBox={`0 0 ${VIEW_WIDTH} ${height}`}
      style={svgStyle(height)}
      role="img"
      aria-label={hint}
      preserveAspectRatio="xMidYMid meet"
    >
      <circle
        cx={VIEW_WIDTH / 2}
        cy={cy}
        r={radius}
        fill="none"
        stroke={TEXT_COLOR}
        strokeOpacity={0.2}
        strokeDasharray="4 4"
      />
      <text
        x={VIEW_WIDTH / 2}
        y={cy}
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

/** 环形图 / 饼图 */
export function PieChart(props: PieChartProps): JSX.Element {
  const { slices, height = DEFAULT_HEIGHT, donut = true, emptyHint = '暂无数据' } = props

  const chartHeight = sanitizeHeight(height)
  const geometry = useMemo(
    () => buildGeometry(slices, chartHeight, donut),
    [slices, chartHeight, donut],
  )

  if (geometry === null) {
    return (
      <div style={{ width: '100%' }}>
        <EmptyChart height={chartHeight} hint={emptyHint} />
      </div>
    )
  }

  const positiveArcs = geometry.arcs.filter((arc) => arc.path !== '')

  return (
    <div style={{ width: '100%' }}>
      <svg
        viewBox={`0 0 ${VIEW_WIDTH} ${chartHeight}`}
        style={svgStyle(chartHeight)}
        role="img"
        aria-label={`占比图，共 ${positiveArcs.length} 个类目，总计 ${geometry.total}`}
        preserveAspectRatio="xMidYMid meet"
      >
        {positiveArcs.map((arc) => (
          <path
            key={`arc-${arc.key}`}
            d={arc.path}
            fill={arc.color}
            stroke="none"
            // 整环独占时无相邻扇区，加一点内描边让边界更利落
            strokeLinejoin="round"
          />
        ))}

        {/* 弧上百分比：仅大扇区标注，细碎类目交给图例，避免文字互相叠压 */}
        {positiveArcs.map((arc) =>
          arc.showLabel ? (
            <text
              key={`pct-${arc.key}`}
              x={arc.labelX}
              y={arc.labelY}
              textAnchor="middle"
              dominantBaseline="middle"
              fontSize={SMALL_FONT}
              fontWeight={600}
              fill={contrastText(arc.color)}
            >
              {formatPercent(arc.fraction)}
            </text>
          ) : null,
        )}

        {/* 环形中心显示总计，占据中空区域 */}
        {donut ? (
          <>
            <text
              x={VIEW_WIDTH / 2}
              y={chartHeight / 2 - 7}
              textAnchor="middle"
              dominantBaseline="middle"
              fontSize={20}
              fontWeight={600}
              fill={TEXT_COLOR}
            >
              {geometry.total >= 10000 ? `${Math.round(geometry.total / 1000)}k` : geometry.total}
            </text>
            <text
              x={VIEW_WIDTH / 2}
              y={chartHeight / 2 + 13}
              textAnchor="middle"
              dominantBaseline="middle"
              fontSize={SMALL_FONT}
              fill={TEXT_COLOR}
              fillOpacity={0.6}
            >
              总计
            </text>
          </>
        ) : null}
      </svg>

      {/* 图例：类目 + 数值 + 占比，一行一个，窄屏也不会被压扁 */}
      <div style={LEGEND_STYLE}>
        {geometry.arcs.map((arc) => (
          <div key={`legend-${arc.key}`} style={LEGEND_ROW_STYLE}>
            <span style={{ ...LEGEND_SWATCH_STYLE, background: arc.color }} />
            <span style={LEGEND_NAME_STYLE}>{arc.name}</span>
            <span style={LEGEND_VALUE_STYLE}>{arc.value}</span>
            <span style={LEGEND_PCT_STYLE}>{formatPercent(arc.fraction)}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
