import type { KeyboardEvent, ReactNode } from 'react'
import { Card, Flex, Skeleton, Typography } from 'antd'
import type { NavIcon } from '../app/nav.ts'

/**
 * 指标卡 —— 仪表盘/DDoS/分析页共用的 KPI 单元。
 *
 * 统一的读法：左上图标 + 标签，主数值用等宽（数字对齐、可扫读），底部一行放同比/说明。
 * `tone` 把数值染成语义色（success/warning/danger/info/brand），让「这个数是好消息还是坏消息」
 * 不必读文案就知道——安全控制台里颜色即语义。
 *
 * 视觉增强：
 * - 左侧 3px 色条标识语义（与 tone 同色）
 * - 图标置于浅色圆形背景，提升层次
 * - hover 时轻微上浮 + 阴影加深，暗示可交互
 */

export type StatTone = 'default' | 'brand' | 'success' | 'warning' | 'danger' | 'info'

const TONE_VAR: Record<StatTone, string> = {
  default: 'var(--fw-text-primary)',
  brand: 'var(--fw-brand)',
  success: 'var(--fw-success)',
  warning: 'var(--fw-warning)',
  danger: 'var(--fw-danger)',
  info: 'var(--fw-info)',
}

const TONE_BG: Record<StatTone, string> = {
  default: 'rgba(147,167,182,0.08)',
  brand: 'rgba(19,174,191,0.12)',
  success: 'rgba(47,191,113,0.12)',
  warning: 'rgba(245,165,36,0.12)',
  danger: 'rgba(255,85,97,0.12)',
  info: 'rgba(74,158,255,0.12)',
}

export interface StatCardProps {
  label: ReactNode
  value: ReactNode
  /** 单位（跟在数值右侧，小字）。 */
  unit?: ReactNode
  icon?: NavIcon
  tone?: StatTone
  /** 底部说明/同比行。 */
  footer?: ReactNode
  loading?: boolean
  onClick?: () => void
  /** 数值等宽显示（默认 true；纯文本值可关）。 */
  mono?: boolean
}

export function StatCard({
  label,
  value,
  unit,
  icon: Icon,
  tone = 'default',
  footer,
  loading = false,
  onClick,
  mono = true,
}: StatCardProps) {
  const color = TONE_VAR[tone]
  const iconBg = TONE_BG[tone]
  const interactiveProps = onClick
    ? {
        hoverable: true,
        onClick,
        role: 'button' as const,
        tabIndex: 0,
        onKeyDown: (e: KeyboardEvent) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            onClick()
          }
        },
      }
    : {}
  return (
    <Card
      size="small"
      {...interactiveProps}
      styles={{ body: { padding: '16px 16px 16px 19px' } }}
      style={{
        cursor: onClick ? 'pointer' : 'default',
        borderLeft: `3px solid ${color}`,
        transition: 'transform 0.2s var(--fw-ease), box-shadow 0.2s var(--fw-ease)',
      }}
      className="fw-stat-card"
    >
      {loading ? (
        <Skeleton active paragraph={{ rows: 1 }} title={{ width: '50%' }} />
      ) : (
        <Flex vertical gap={10}>
          <Flex align="center" gap={10}>
            {Icon && (
              <div
                style={{
                  width: 32,
                  height: 32,
                  borderRadius: 8,
                  background: iconBg,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                }}
              >
                <Icon style={{ fontSize: 16, color }} />
              </div>
            )}
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {label}
            </Typography.Text>
          </Flex>
          <Flex align="baseline" gap={4}>
            <span
              className={mono ? 'fw-mono' : undefined}
              style={{ fontSize: 28, fontWeight: 600, lineHeight: 1.1, color }}
            >
              {value}
            </span>
            {unit && (
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {unit}
              </Typography.Text>
            )}
          </Flex>
          {footer && (
            <Typography.Text type="secondary" style={{ fontSize: 12, lineHeight: 1.5 }}>
              {footer}
            </Typography.Text>
          )}
        </Flex>
      )}
    </Card>
  )
}
