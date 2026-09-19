/**
 * HeatmapChart —— 手写 SVG 24 小时热力网格（不依赖任何图表库）
 *
 * # props 契约（其他视图按此调用，签名已冻结，勿改）
 * ```ts
 * interface HeatmapCell { hour: number; value: number }   // hour: 0..23
 * interface HeatmapChartProps {
 *   cells: HeatmapCell[]   // 24 个单元
 *   height?: number        // 默认 160
 *   valueLabel?: string    // 图例单位文案
 *   emptyHint?: string
 * }
 * ```
 *
 * # 布局（移动端优先）
 * 排成 **2 行 × 12 列**（上排 00–11 时，下排 12–23 时）。之所以不排成单行 24 格：
 * viewBox 宽 360、左右各留 10 后每格只有约 13 单位，375px 视口下仅 ≈12px 宽，
 * 塞不进 ≥11px 的小时数字。排成 12 列后每格约 26 单位（≈25px），
 * 小时号（字号 12，渲染 ≈11.4px）与数值都能放下，触摸目标也更大。
 *
 * # 色阶
 * 5 档离散色阶，按 `sqrt(value / max)` 分档：
 * 攻击量通常长尾分布（一个高峰小时会把其余时段全压成最低档），开平方后
 * 低值段的分辨率明显提高，梯度更可读。0 值单独用 `currentColor` 极低透明度填充，
 * 以适配深浅主题而不是写死底色。
 *
 * # 行为约定
 * - `cells` 为空数组才渲染空态；24 格全 0 是合法状态（当天没有攻击），照常画表格。
 * - `hour` 越界或非有限值的单元直接丢弃；同一小时重复出现时**后出现的覆盖先出现的**。
 * - 负值按 0 处理。
 * - 单元内数值超过 4 个字符（如 "123.4k"）时不画数字，避免溢出到相邻单元格。
 * - 图例用 5 段色块拼成（与分档一一对应），因此不需要 defs、不需要实例 id。
 *
 * # 影响
 * 纯展示组件：无副作用、不发请求、不读写全局状态。
 */
import { useMemo } from 'react'
// React 19 的类型里 JSX 命名空间挂在 React 命名空间下（不再是全局 JSX），须显式引入
import type { CSSProperties, JSX } from 'react'

/** 单个时段单元 */
export interface HeatmapCell {
  /** 小时编号 0..23；越界值会被丢弃 */
  hour: number
  /** 该时段的数值（封禁数 / 失败尝试数等，量纲由调用方决定） */
  value: number
}

/** HeatmapChart 对外 props */
export interface HeatmapChartProps {
  /** 24 个单元（hour 0..23） */
  cells: HeatmapCell[]
  /** 视觉高度（viewBox 高度），默认 160 */
  height?: number
  /** 图例单位文案，如「封禁数」 */
  valueLabel?: string
  /** 空态文案，默认「暂无数据」 */
  emptyHint?: string
}

/** viewBox 设计宽度；配合 width:100% 实现自适应，不要改成固定像素 */
const VIEW_WIDTH = 360
/** 默认视觉高度 */
const DEFAULT_HEIGHT = 160
/** 左右内边距 */
const PAD_X = 10
/** 网格列数（小时 0-11 / 12-23 分两行） */
const COLS = 12
/** 网格行数 */
const ROWS = 2
/** 单元格之间的间隙 */
const CELL_GAP = 3
/** 色阶档数 */
const LEVELS = 5
/** 每格最多能放下的数值字符数，超出就不画数字 */
const MAX_VALUE_CHARS = 4
/** 小于该格高时不再画数值，避免与小时号叠在一起 */
const MIN_CELL_HEIGHT_FOR_VALUE = 30
/** 最小可读字号（viewBox 单位），375px 视口下渲染 ≈11.4px */
const SMALL_FONT = 12

/**
 * 5 档色阶：低（青）→ 高（红）
 *
 * 取中间明度，深色主题的深底与浅色主题的白底上都能分辨；
 * 末档用红以突出最高强度时段。
 */
const HEAT_RAMP: readonly string[] = [
  '#1f4e5f', // 档 1 低
  '#2d7d8c', // 档 2
  '#4fa3a8', // 档 3 中
  '#d0973f', // 档 4
  '#c2453a', // 档 5 高
]

/** 网格与文字统一走 currentColor，以适配深浅主题 */
const TEXT_COLOR = 'currentColor'

/** 算好位置的单元格 */
interface HeatCell {
  key: string
  hour: number
  value: number
  x: number
  y: number
  fill: string
  /** 填充是不透明色阶时，文字需要用对比色 */
  onRamp: boolean
  /** 单元内显示的数值文案；过长或格子太矮时为空串 */
  valueText: string
}

/** 热力图几何 */
interface HeatGeometry {
  cellWidth: number
  cellHeight: number
  cells: HeatCell[]
  max: number
  /** 图例色块的起始 x */
  legendX: number
  legendY: number
  legendCellWidth: number
  legendCellHeight: number
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

/** 数值缩写：把单元格里的数字压到 4 字符内 */
function formatCompact(value: number): string {
  const abs = Math.abs(value)
  if (abs >= 1e9) return `${Math.round(value / 1e8) / 10}G`
  if (abs >= 1e6) return `${Math.round(value / 1e5) / 10}M`
  if (abs >= 1000) return `${Math.round(value / 100) / 10}k`
  return String(Math.round(value))
}

/** 依据背景色亮度选择前景文字色，保证单元内数字可读 */
function contrastText(color: string): string {
  const hex = color.replace('#', '')
  if (hex.length < 6) return '#ffffff'
  const r = parseInt(hex.slice(0, 2), 16)
  const g = parseInt(hex.slice(2, 4), 16)
  const b = parseInt(hex.slice(4, 6), 16)
  if (!Number.isFinite(r) || !Number.isFinite(g) || !Number.isFinite(b)) return '#ffffff'
  // ITU-R BT.601 近似亮度
  const luma = (0.299 * r + 0.587 * g + 0.114 * b) / 255
  return luma > 0.6 ? '#10161c' : '#ffffff'
}

/**
 * 把 0..max 映射到色阶下标
 *
 * 用开平方而非线性：攻击量长尾，线性映射会把绝大多数时段压进最低档。
 */
function levelOf(value: number, max: number): number {
  if (!(value > 0) || !(max > 0)) return -1
  const ratio = Math.sqrt(Math.min(value / max, 1))
  return Math.min(LEVELS - 1, Math.floor(ratio * LEVELS))
}

/** 计算全部绘制几何；无输入单元时返回 null 以走空态分支 */
function buildGeometry(cells: HeatmapCell[], height: number): HeatGeometry | null {
  if (cells.length === 0) return null

  // 按小时落位；重复小时后者覆盖前者，越界小时丢弃
  const hourly = new Array<number>(24).fill(0)
  for (const cell of cells) {
    const hour = Math.trunc(cell.hour)
    if (!Number.isFinite(hour) || hour < 0 || hour > 23) continue
    hourly[hour] = Number.isFinite(cell.value) && cell.value > 0 ? cell.value : 0
  }

  const max = hourly.reduce((peak, value) => (value > peak ? value : peak), 0)

  const gridWidth = VIEW_WIDTH - PAD_X * 2
  const cellWidth = (gridWidth - CELL_GAP * (COLS - 1)) / COLS
  // 纵向预算：顶部留白 8 + 网格 + 图例（色块 + 两个刻度行）
  const cellHeight = Math.min(64, Math.max(20, Math.round((height - 78) / ROWS)))
  const gridTop = 8

  const heatCells: HeatCell[] = []
  for (let hour = 0; hour < 24; hour += 1) {
    const row = Math.floor(hour / COLS)
    const col = hour % COLS
    const value = hourly[hour]
    const level = levelOf(value, max)
    const text = value > 0 ? formatCompact(value) : '0'
    heatCells.push({
      key: `cell-${hour}`,
      hour,
      value,
      x: PAD_X + col * (cellWidth + CELL_GAP),
      y: gridTop + row * (cellHeight + CELL_GAP),
      fill: level < 0 ? TEXT_COLOR : HEAT_RAMP[level],
      onRamp: level >= 0,
      valueText: text.length > MAX_VALUE_CHARS || cellHeight < MIN_CELL_HEIGHT_FOR_VALUE ? '' : text,
    })
  }

  const gridBottom = gridTop + ROWS * cellHeight + (ROWS - 1) * CELL_GAP
  const legendCellWidth = 30
  const legendCellHeight = 10
  // 图例紧跟网格下方，但不越过底边
  const legendY = Math.min(height - legendCellHeight - 12, gridBottom + 26)

  return {
    cellWidth,
    cellHeight,
    cells: heatCells,
    max,
    legendX: (VIEW_WIDTH - legendCellWidth * LEVELS) / 2,
    legendY,
    legendCellWidth,
    legendCellHeight,
  }
}

/** 空态：虚线框 + 居中提示 */
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

/** 24 小时热力网格 */
export function HeatmapChart(props: HeatmapChartProps): JSX.Element {
  const { cells, height = DEFAULT_HEIGHT, valueLabel, emptyHint = '暂无数据' } = props

  const chartHeight = sanitizeHeight(height)
  const geometry = useMemo(() => buildGeometry(cells, chartHeight), [cells, chartHeight])

  if (geometry === null) {
    return (
      <div style={{ width: '100%' }}>
        <EmptyChart height={chartHeight} hint={emptyHint} />
      </div>
    )
  }

  const legendEnd = geometry.legendX + geometry.legendCellWidth * LEVELS
  const legendTextY = geometry.legendY + geometry.legendCellHeight / 2
  const ariaLabel = `24 小时热力网格，峰值 ${geometry.max}${valueLabel ? ` ${valueLabel}` : ''}`

  return (
    <div style={{ width: '100%' }}>
      <svg
        viewBox={`0 0 ${VIEW_WIDTH} ${chartHeight}`}
        style={svgStyle(chartHeight)}
        role="img"
        aria-label={ariaLabel}
        preserveAspectRatio="xMidYMid meet"
      >
        {/* 网格：每格同时承载色阶与小时号 */}
        {geometry.cells.map((cell) => {
          const textColor = cell.onRamp ? contrastText(cell.fill) : TEXT_COLOR
          const textOpacity = cell.onRamp ? 0.95 : 0.55
          return (
            <g key={cell.key}>
              <rect
                x={n(cell.x)}
                y={n(cell.y)}
                width={n(geometry.cellWidth)}
                height={geometry.cellHeight}
                rx={3}
                fill={cell.fill}
                fillOpacity={cell.onRamp ? 1 : 0.08}
              />
              {/* 数值居中偏上 */}
              {cell.valueText === '' ? null : (
                <text
                  x={n(cell.x + geometry.cellWidth / 2)}
                  y={n(cell.y + geometry.cellHeight * 0.42)}
                  textAnchor="middle"
                  dominantBaseline="middle"
                  fontSize={SMALL_FONT}
                  fontWeight={600}
                  fill={textColor}
                  fillOpacity={textOpacity}
                >
                  {cell.valueText}
                </text>
              )}
              {/* 小时号贴底，用于定位列 */}
              <text
                x={n(cell.x + geometry.cellWidth / 2)}
                y={n(cell.y + geometry.cellHeight * 0.79)}
                textAnchor="middle"
                dominantBaseline="middle"
                fontSize={SMALL_FONT}
                fill={textColor}
                fillOpacity={cell.onRamp ? 0.75 : 0.55}
              >
                {cell.hour}
              </text>
            </g>
          )
        })}

        {/* 图例：单位文案 + 5 段色块 + 两端刻度 */}
        {valueLabel ? (
          <text
            x={PAD_X}
            y={legendTextY}
            textAnchor="start"
            dominantBaseline="middle"
            fontSize={SMALL_FONT}
            fill={TEXT_COLOR}
            fillOpacity={0.6}
          >
            {valueLabel}
          </text>
        ) : null}

        {HEAT_RAMP.map((color, index) => (
          <rect
            key={`legend-${color}`}
            x={n(geometry.legendX + index * geometry.legendCellWidth)}
            y={geometry.legendY}
            width={geometry.legendCellWidth}
            height={geometry.legendCellHeight}
            // 首尾两段切圆角，拼起来是一条连续的色带
            rx={index === 0 || index === LEVELS - 1 ? 2 : 0}
            fill={color}
          />
        ))}

        <text
          x={n(geometry.legendX - 6)}
          y={legendTextY}
          textAnchor="end"
          dominantBaseline="middle"
          fontSize={SMALL_FONT}
          fill={TEXT_COLOR}
          fillOpacity={0.6}
        >
          0
        </text>
        <text
          x={n(legendEnd + 6)}
          y={legendTextY}
          textAnchor="start"
          dominantBaseline="middle"
          fontSize={SMALL_FONT}
          fill={TEXT_COLOR}
          fillOpacity={0.6}
        >
          {formatCompact(geometry.max)}
        </text>
      </svg>
    </div>
  )
}
