// 空状态占位：列表/图表无数据、查询无结果、加载失败（无数据可展示）时统一使用
//
// 为什么不用 antd-mobile 的 ErrorBlock：ErrorBlock 的 status 取值与文案是固定的
// 「组件库语气」，本项目需要按主题令牌统一配色并支持自定义操作按钮，故自绘。
// 组件本身不含任何业务判断，是否展示由调用方决定（禁止用它掩盖数据错误）。
import type { ReactNode } from 'react'

export interface EmptyStateProps {
  /** 主标题，默认「暂无数据」 */
  title?: string
  /** 补充说明：说清「为什么空」以及「能做什么」，避免只有一个空洞的图标 */
  description?: ReactNode
  /** 自定义图标；不传则用内置线条图 */
  icon?: ReactNode
  /** 主操作区（例如「重试」「添加白名单」按钮） */
  action?: ReactNode
  /** 紧凑模式：用于卡片内部（减小上下留白，不占满整屏） */
  compact?: boolean
}

/** 内置默认图标：手绘 SVG，颜色继承 currentColor 以自动跟随主题 */
function DefaultEmptyIcon() {
  return (
    <svg width="44" height="44" viewBox="0 0 56 56" fill="none" aria-hidden="true">
      <rect
        x="10"
        y="8"
        width="36"
        height="40"
        rx="6"
        stroke="currentColor"
        strokeWidth="2"
        strokeDasharray="5 4"
      />
      <path
        d="M18 22h20M18 30h20M18 38h12"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
      />
    </svg>
  )
}

export function EmptyState({
  title = '暂无数据',
  description,
  icon,
  action,
  compact = false,
}: EmptyStateProps) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        gap: 6,
        padding: compact ? '12px 7px' : '24px 12px',
        color: 'var(--fw-text-3)',
      }}
    >
      <div style={{ color: 'var(--fw-text-3)', opacity: 0.75, lineHeight: 0 }}>
        {icon ?? <DefaultEmptyIcon />}
      </div>
      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--fw-text-2)' }}>{title}</div>
      {description ? (
        <div style={{ fontSize: 12, lineHeight: 1.6, maxWidth: 320 }}>{description}</div>
      ) : null}
      {action ? <div style={{ marginTop: 2 }}>{action}</div> : null}
    </div>
  )
}

export default EmptyState
