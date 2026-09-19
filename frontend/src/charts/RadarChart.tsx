/**
 * RadarChart —— 手写 SVG 雷达图（不依赖任何图表库）
 *
 * # props 契约（其他视图按此调用，签名已冻结，勿改）
 * ```ts
 * interface RadarSeries { name: string; values: number[]; color?: string }
 * interface RadarChartProps {
 *   axes: string[]        // 轴名，长度与各 series.values 一致
 *   series: RadarSeries[]
 *   height?: number       // 默认 220
 *   maxValue?: number     // 不传则按数据自动取上界
 *   emptyHint?: string
 * }
 * ```
 *
 * # 布局（移动端优先）
 * 雷达是近似正方形的图形，viewBox 取 300×height（比其他图表窄），这样在窄屏上
 * 图形本身能占满宽度而不是缩在中间一小块。375px 视口下缩放比 ≈1.14，
 * 轴标签字号 12 渲染后 ≈13.7px，满足「≥11px」。
 *
 * # 主题适配
 * 网格/轴线/文字用 `currentColor` + 透明度，随深浅主题自动变色；
 * 序列颜色来自 `chartColor()`，为固定中间调。
 *
 * # 行为约定
 * - 轴数 < 3 无法构成多边形，直接渲染空态并说明原因（退化输入不静默画错）。
 * - `values` 长度不足时缺位按 0 处理；超过 `maxValue` 的值按上界截断（不画到框外）。
 * - 全 0 是合法数据（不算空态）；无轴、无序列或全部数值非有限才渲染空态。
 * - 网格 4 档，档位数值沿正上方轴标注（最外档不标，避免与顶部轴名重叠）。
 *
 * # 影响
 * 纯展示组件：无副作用、不发请求、不读写全局状态。无 defs，也不需要实例 id。
 */
import { useMemo } from 'react'
// React 19 的类型里 JSX 命名空间挂在 React 命名空间下（不再是全局 JSX），须显式引入
import type { CSSProperties, JSX } from 'react'
import { chartColor } from './chartId'

/** 雷达序列：一层的名称与各轴数值 */
export interface RadarSeries {
  /** 图例与无障碍标签用的序列名 */
  name: string
  /** 各轴数值，长度应与 axes 一致；缺位按 0 处理 */
  values: number[]
  /** 描边与填充色；缺省时按序列下标取 chartColor() */
  color?: string
}

/** RadarChart 对外 props */
export interface RadarChartProps {
  /** 轴名，长度与各 series.values 一致 */
  axes: string[]
  /** 1..n 层数据 */
  series: RadarSeries[]
  /** 视觉高度（viewBox 高度），默认 220 */
  height?: number
  /** 数值上界；不传则按数据自动取整齐上界 */
  maxValue?: number
  /** 空态文案，默认「暂无数据」 */
  emptyHint?: string
}

/** viewBox 设计宽度：雷达近似正方形，取窄一些让图形在窄屏上更大 */
const VIEW_WIDTH = 300
/** 默认视觉高度 */
const DEFAULT_HEIGHT = 220
/** 最小可读字号（viewBox 单位），375px 视口下渲染 ≈13.7px */
const SMALL_FONT = 12
/** 网格档数（含最外圈） */
const LEVELS = 4
/** 轴名与顶点的间距 */
const LABEL_GAP = 16

/** 图例容器：窄屏自动换行 */
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
  height: 6, // 10 → 6
  borderRadius: 1, // 2 → 1
  flex: '0 0 auto',
}

const LEGEND_LABEL_STYLE: CSSProperties = {
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
  opacity: 0.85,
}

/** 网格/轴线/文字统一走 currentColor，以适配深浅主题 */
const TEXT_COLOR = 'currentColor'

/** 一层算好坐标的序列 */
interface RadarLayer {
  key: string
  name: string
  color: string
  /** polygon 的 points 属性 */
  points: string
  /** 各轴顶点坐标，用于画小圆点 */
  vertices: { x: number; y: number }[]
}

/** 雷达图几何 */
interface RadarGeometry {
  centerX: number
  centerY: number
  radius: number
  /** 轴端点（用于画蛛网辐条） */
  spokes: { x: number; y: number }[]
  /** 各档网格多边形的 points 属性，从内到外 */
  gridRings: { level: number; points: string; labelY: number; labelText: string }[]
  axisLabels: {
    key: string
    text: string
    x: number
    y: number
    anchor: 'start' | 'middle' | 'end'
    baseline: 'auto' | 'middle' | 'hanging'
  }[]
  layers: RadarLayer[]
  /** 实际生效的上界，用于无障碍描述 */
  max: number
}

/** 把任意输入高度收敛到可用区间 */
function sanitizeHeight(value: number | undefined): number {
  if (value === undefined || !Number.isFinite(value)) return DEFAULT_HEIGHT
  return Math.min(600, Math.max(140, Math.round(value)))
}

/** 坐标数值保留 2 位小数 */
function n(value: number): string {
  return (Math.round(value * 100) / 100).toString()
}

/** 刻度数字缩写，避免网格档位标签过长压住图形 */
function formatScale(value: number): string {
  const abs = Math.abs(value)
  if (abs >= 1e9) return `${Math.round(value / 1e8) / 10}G`
  if (abs >= 1e6) return `${Math.round(value / 1e5) / 10}M`
  if (abs >= 1000) return `${Math.round(value / 100) / 10}k`
  if (Number.isInteger(value)) return String(value)
  return String(Math.round(value * 100) / 100)
}

/** 单字符宽度估算：ASCII 约 0.58em，CJK / 全角约 1em */
function charWidth(char: string, fontSize: number): number {
  return /[\u2e80-\u9fff\u3000-\u303f\uf900-\ufaff\uff00-\uffef]/.test(char)
    ? fontSize
    : fontSize * 0.58
}

/**
 * 按可用像素宽度截断文字，超出时补省略号
 *
 * 按字符个数截断在 CJK 轴名上会失效：「四次+封禁」5 个字符宽约 55 单位，
 * 而 5 个 ASCII 字符只有约 35 单位，窄屏上中文轴名会顶出 viewBox。
 */
function fitText(text: string, fontSize: number, maxWidth: number): string {
  const ellipsisWidth = fontSize * 0.58
  let width = 0
  let output = ''
  for (const char of text) {
    const w = charWidth(char, fontSize)
    if (width + w > maxWidth) {
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

/** 把上界抬到整齐数值（1/2/2.5/5 × 10^n） */
function niceMax(max: number): number {
  if (!Number.isFinite(max) || max <= 0) return 1
  const magnitude = Math.pow(10, Math.floor(Math.log10(max)))
  const norm = max / magnitude
  const niceNorm = norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10
  return niceNorm * magnitude
}

/** 计算全部绘制几何；输入退化或无数值时返回 null 以走空态分支 */
function buildGeometry(
  axes: string[],
  series: RadarSeries[],
  height: number,
  maxValue: number | undefined,
): RadarGeometry | null {
  if (axes.length < 3 || series.length === 0) return null

  const hasData = series.some((item) => item.values.some((v) => Number.isFinite(v)))
  if (!hasData) return null

  const valuesMax = series.reduce((acc, item) => {
    return item.values.reduce((inner, v) => (Number.isFinite(v) && v > inner ? v : inner), acc)
  }, 0)

  const max =
    maxValue !== undefined && Number.isFinite(maxValue) && maxValue > 0
      ? maxValue
      : niceMax(valuesMax)

  const centerX = VIEW_WIDTH / 2
  const centerY = height / 2
  const radius = Math.max(40, Math.min(110, height / 2 - 28))

  /** 第 index 根轴的极角：从正上方开始顺时针均分 */
  const angleAt = (index: number): number => -Math.PI / 2 + (index / axes.length) * Math.PI * 2

  const spokes = axes.map((_, index) => {
    const angle = angleAt(index)
    return {
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
    }
  })

  const gridRings = Array.from({ length: LEVELS }, (_, i) => {
    const level = i + 1
    const ringRadius = (radius * level) / LEVELS
    const points = axes
      .map((_, index) => {
        const angle = angleAt(index)
        return `${n(centerX + ringRadius * Math.cos(angle))},${n(centerY + ringRadius * Math.sin(angle))}`
      })
      .join(' ')
    return {
      level,
      points,
      // 档位数值沿正上方轴排布；最外档与顶部轴名位置冲突，故不标注
      labelY: centerY - ringRadius,
      labelText: level === LEVELS ? '' : formatScale((max * level) / LEVELS),
    }
  })

  const axisLabels = axes.map((name, index) => {
    const angle = angleAt(index)
    const cos = Math.cos(angle)
    const sin = Math.sin(angle)
    const labelRadius = radius + LABEL_GAP
    const labelX = centerX + labelRadius * cos
    // 按该轴实际可用的横向空间截断轴名：
    // 偏右的轴被右边界限制，偏左的被左边界限制，接近竖直的轴只能占半宽
    const available =
      cos > 0.25
        ? VIEW_WIDTH - 2 - labelX
        : cos < -0.25
          ? labelX - 2
          : Math.min(labelX - 2, VIEW_WIDTH - 2 - labelX) * 2
    return {
      key: `${name}-${index}`,
      text: fitText(name, SMALL_FONT, Math.max(18, available)),
      x: labelX,
      y: centerY + labelRadius * sin,
      // 顶点在左右两侧时用 start/end 对齐，避免文字越过 viewBox 被裁切
      anchor: (Math.abs(cos) < 0.25 ? 'middle' : cos > 0 ? 'start' : 'end') as
        | 'start'
        | 'middle'
        | 'end',
      baseline: (Math.abs(sin) < 0.25 ? 'middle' : sin > 0 ? 'hanging' : 'auto') as
        | 'auto'
        | 'middle'
        | 'hanging',
    }
  })

  const layers: RadarLayer[] = series.map((item, seriesIndex) => {
    const color = item.color ?? chartColor(seriesIndex)
    const vertices = axes.map((_, index) => {
      const raw = item.values[index]
      const value = Number.isFinite(raw) ? raw : 0
      // 超过上界的值截断到边框，避免画到网格之外
      const ratio = Math.min(Math.max(value, 0), max) / max
      const angle = angleAt(index)
      return {
        x: centerX + radius * ratio * Math.cos(angle),
        y: centerY + radius * ratio * Math.sin(angle),
      }
    })
    return {
      key: `${item.name}-${seriesIndex}`,
      name: item.name,
      color,
      points: vertices.map((point) => `${n(point.x)},${n(point.y)}`).join(' '),
      vertices,
    }
  })

  return { centerX, centerY, radius, spokes, gridRings, axisLabels, layers, max }
}

/** 空态：虚线圆 + 居中提示 */
function EmptyChart({ height, hint }: { height: number; hint: string }): JSX.Element {
  const centerY = height / 2
  const radius = Math.max(28, Math.min(64, height / 2 - 16))
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
        cy={centerY}
        r={radius}
        fill="none"
        stroke={TEXT_COLOR}
        strokeOpacity={0.2}
        strokeDasharray="4 4"
      />
      <text
        x={VIEW_WIDTH / 2}
        y={centerY}
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

/** 雷达图 */
export function RadarChart(props: RadarChartProps): JSX.Element {
  const { axes, series, height = DEFAULT_HEIGHT, maxValue, emptyHint = '暂无数据' } = props

  const chartHeight = sanitizeHeight(height)
  const geometry = useMemo(
    () => buildGeometry(axes, series, chartHeight, maxValue),
    [axes, series, chartHeight, maxValue],
  )

  const legend =
    series.length > 1 ? (
      <div style={LEGEND_STYLE}>
        {series.map((item, index) => (
          <span key={`${item.name}-${index}`} style={LEGEND_ITEM_STYLE}>
            <span
              style={{ ...LEGEND_SWATCH_STYLE, background: item.color ?? chartColor(index) }}
            />
            <span style={LEGEND_LABEL_STYLE}>{item.name}</span>
          </span>
        ))}
      </div>
    ) : null

  if (geometry === null) {
    // 轴数不足属于调用方数据退化，单独给出原因，不要笼统说"暂无数据"
    const hint = axes.length > 0 && axes.length < 3 ? `雷达图至少需要 3 个轴（当前 ${axes.length} 个）` : emptyHint
    return (
      <div style={{ width: '100%' }}>
        {legend}
        <EmptyChart height={chartHeight} hint={hint} />
      </div>
    )
  }

  const ariaLabel = `${series.map((item) => item.name).join('、')} 雷达图，${axes.length} 个轴，上界 ${geometry.max}`

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
        {/* 蛛网网格：由内到外的等比分档多边形 */}
        {geometry.gridRings.map((ring) => (
          <polygon
            key={`ring-${ring.level}`}
            points={ring.points}
            fill="none"
            stroke={TEXT_COLOR}
            strokeOpacity={ring.level === LEVELS ? 0.28 : 0.14}
            strokeWidth={1}
          />
        ))}

        {/* 辐条：中心到每根轴的端点 */}
        {geometry.spokes.map((point, index) => (
          <line
            key={`spoke-${index}`}
            x1={geometry.centerX}
            y1={geometry.centerY}
            x2={point.x}
            y2={point.y}
            stroke={TEXT_COLOR}
            strokeOpacity={0.14}
            strokeWidth={1}
          />
        ))}

        {/* 档位数值：只在正上方轴内侧标注，档位过多会糊成一片 */}
        {geometry.gridRings.map((ring) =>
          ring.labelText === '' ? null : (
            <text
              key={`ring-label-${ring.level}`}
              x={geometry.centerX + 5}
              y={ring.labelY}
              textAnchor="start"
              dominantBaseline="middle"
              fontSize={SMALL_FONT}
              fill={TEXT_COLOR}
              fillOpacity={0.5}
            >
              {ring.labelText}
            </text>
          ),
        )}

        {/* 数据层：填充 + 描边 + 顶点圆点 */}
        {geometry.layers.map((layer) => (
          <polygon
            key={`layer-${layer.key}`}
            points={layer.points}
            fill={layer.color}
            fillOpacity={0.18}
            stroke={layer.color}
            strokeWidth={1.6}
            strokeLinejoin="round"
          />
        ))}
        {geometry.layers.map((layer) =>
          layer.vertices.map((point, index) => (
            <circle
              key={`vertex-${layer.key}-${index}`}
              cx={point.x}
              cy={point.y}
              r={2.5}
              fill={layer.color}
            />
          )),
        )}

        {/* 轴名最后画，保证压在所有图形之上 */}
        {geometry.axisLabels.map((label) => (
          <text
            key={`axis-${label.key}`}
            x={label.x}
            y={label.y}
            textAnchor={label.anchor}
            dominantBaseline={label.baseline}
            fontSize={SMALL_FONT}
            fill={TEXT_COLOR}
            fillOpacity={0.75}
          >
            {label.text}
          </text>
        ))}
      </svg>
    </div>
  )
}
