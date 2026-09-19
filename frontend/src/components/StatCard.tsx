// 统计卡片：大数值 + 标签 + 可选迷你趋势线（自绘 SVG）
//
// 设计取舍：不引入图表库（契约要求），趋势线用一段 100x28 的 viewBox 折线绘制，
// `preserveAspectRatio="none"` 让它拉伸铺满卡片宽度，`vectorEffect="non-scaling-stroke"`
// 保证拉伸后线宽仍是 1.5px 不虚胖。
//
// 触摸目标：整卡高度远超 44px；可点击时（传 onClick）补充 role/tabIndex 与键盘回车，
// 因为外层不是 <button>，无障碍需要手工补齐。
import type { CSSProperties, ReactNode } from 'react'

export type StatTone = 'default' | 'primary' | 'success' | 'warning' | 'danger'

export interface StatCardProps {
  /** 指标名称 */
  label: string
  /** 指标值（已格式化好的字符串或数字，例如 "1,234"） */
  value: ReactNode
  /** 单位（小字跟在数值后，例如 "pps"） */
  unit?: string
  /** 补充说明（口径、对比对象等） */
  hint?: ReactNode
  /** 语义色：用于区分正常/告警/危险等状态 */
  tone?: StatTone
  /** 迷你趋势数据（按时间正序）；少于 2 个有限值时自动不绘制 */
  trend?: readonly number[]
  /** 趋势线的时间范围说明（如「近 60 秒」），也会作为趋势线的可读文本 */
  trendLabel?: string
  /** 传入即视为可点击卡片 */
  onClick?: () => void
  style?: CSSProperties
}

/** 迷你趋势线的画布尺寸（逻辑坐标，渲染时按宽度拉伸） */
const SPARK_W = 100
const SPARK_H = 28

/** tone → 颜色令牌 */
const TONE_COLOR: Record<StatTone, string> = {
  default: 'var(--fw-text)',
  primary: 'var(--fw-primary-strong)',
  success: 'var(--fw-success)',
  warning: 'var(--fw-warning)',
  danger: 'var(--fw-danger)',
}

/**
 * 把数值序列换算成 SVG 折线坐标。
 * 返回 null 表示数据不足以画线（少于 2 个有限值），调用方据此跳过绘制。
 */
function buildSparkline(values: readonly number[]) {
  // 过滤 NaN / Infinity：脏数据会让整条线消失，这里只丢坏点
  const finite = values.filter((v) => Number.isFinite(v))
  if (finite.length < 2) return null

  const min = Math.min(...finite)
  const max = Math.max(...finite)
  const span = max - min
  const step = SPARK_W / (finite.length - 1)

  const coords = finite.map((v, index) => {
    const x = index * step
    // span === 0（数值恒定）时贴中线，避免除零得到 NaN
    const y = span === 0 ? SPARK_H / 2 : SPARK_H - ((v - min) / span) * SPARK_H
    return `${x.toFixed(2)},${y.toFixed(2)}`
  })

  return {
    line: coords.join(' '),
    area: `0,${SPARK_H} ${coords.join(' ')} ${SPARK_W},${SPARK_H}`,
    min,
    max,
  }
}

export function StatCard({
  label,
  value,
  unit,
  hint,
  tone = 'default',
  trend,
  trendLabel,
  onClick,
  style,
}: StatCardProps) {
  const color = TONE_COLOR[tone]
  const spark = trend && trend.length > 0 ? buildSparkline(trend) : null

  return (
    <div
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={
        onClick
          ? (event) => {
              // 键盘可达：Enter / 空格 等价于点击
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault()
                onClick()
              }
            }
          : undefined
      }
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 4,
        minHeight: 'var(--fw-tap)',
        padding: 7,
        border: '1px solid var(--fw-border)',
        borderRadius: 'var(--fw-radius)',
        background: 'var(--fw-surface)',
        boxShadow: 'var(--fw-shadow)',
        cursor: onClick ? 'pointer' : 'default',
        ...style,
      }}
    >
      <div style={{ fontSize: 12, color: 'var(--fw-text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {label}
      </div>

      <div style={{ display: 'flex', alignItems: 'baseline', gap: 2, minWidth: 0 }}>
        <span
          className="fw-num"
          style={{
            fontSize: 22,
            fontWeight: 600,
            lineHeight: 1.15,
            color,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          {value}
        </span>
        {unit ? (
          <span style={{ fontSize: 12, color: 'var(--fw-text-3)', flexShrink: 0 }}>{unit}</span>
        ) : null}
      </div>

      {spark ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          {trendLabel ? (
            <span style={{ fontSize: 11, color: 'var(--fw-text-3)' }}>{trendLabel}</span>
          ) : null}
          {/* aria-hidden：装饰性图形，语义由 trendLabel 文本 + 卡片标签表达 */}
          <svg
            viewBox={`0 0 ${SPARK_W} ${SPARK_H}`}
            preserveAspectRatio="none"
            width="100%"
            height={SPARK_H}
            aria-hidden="true"
            focusable="false"
            style={{ display: 'block' }}
          >
            <polygon points={spark.area} fill={color} opacity={0.14} />
            <polyline
              points={spark.line}
              fill="none"
              stroke={color}
              strokeWidth={1.5}
              strokeLinecap="round"
              strokeLinejoin="round"
              vectorEffect="non-scaling-stroke"
            />
          </svg>
        </div>
      ) : null}

      {hint ? (
        <div style={{ fontSize: 12, lineHeight: 1.4, color: 'var(--fw-text-3)' }}>{hint}</div>
      ) : null}
    </div>
  )
}

export default StatCard
