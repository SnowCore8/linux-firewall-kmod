import type { ReactNode } from 'react'
import { Card, Flex, Skeleton, Typography } from 'antd'
import type { NavIcon } from '../app/nav.ts'

/**
 * 指标卡 —— 仪表盘/DDoS/分析页共用的 KPI 单元。
 *
 * 统一的读法：左上图标 + 标签，主数值用等宽（数字对齐、可扫读），底部一行放同比/说明。
 * `tone` 把数值染成语义色（success/warning/danger/info/brand），让「这个数是好消息还是坏消息」
 * 不必读文案就知道——安全控制台里颜色即语义。
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
  return (
    <Card
      size="small"
      hoverable={!!onClick}
      onClick={onClick}
      styles={{ body: { padding: 16 } }}
      style={{ cursor: onClick ? 'pointer' : 'default' }}
    >
      {loading ? (
        <Skeleton active paragraph={{ rows: 1 }} title={{ width: '50%' }} />
      ) : (
        <Flex vertical gap={10}>
          <Flex align="center" gap={8}>
            {Icon && <Icon style={{ fontSize: 15, color: 'var(--fw-text-secondary)' }} />}
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {label}
            </Typography.Text>
          </Flex>
          <Flex align="baseline" gap={4}>
            <span
              className={mono ? 'fw-mono' : undefined}
              style={{ fontSize: 26, fontWeight: 600, lineHeight: 1.1, color }}
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
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {footer}
            </Typography.Text>
          )}
        </Flex>
      )}
    </Card>
  )
}
