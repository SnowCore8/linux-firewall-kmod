import { Skeleton, Space, Card } from 'antd'
import type { ReactNode } from 'react'

/**
 * 加载态 —— 分场景骨架屏，替代「转圈 + 空白」。
 *
 * 为什么分场景：骨架要贴着最终布局，才不会在数据到达时发生布局跳动（表格塌成卡片、
 * 图表高度突变都很难看）。给四种形状：table（表格）/ cards（指标卡组）/ chart（图表）/
 * detail（详情抽屉）。默认 table。
 */

export type LoadingVariant = 'table' | 'cards' | 'chart' | 'detail'

export interface LoadingStateProps {
  variant?: LoadingVariant
  /** 表格行数 / 卡片个数。 */
  rows?: number
  /** 是否包在 Card 里（页面内联区块通常不包，独立卡片包）。 */
  bordered?: boolean
}

function TableSkeleton({ rows }: { rows: number }) {
  return (
    <div>
      <Skeleton.Input active block size="small" style={{ height: 32, marginBottom: 12 }} />
      <Space direction="vertical" size={8} style={{ width: '100%' }}>
        {Array.from({ length: rows }, (_, i) => (
          <Skeleton.Input key={i} active block size="small" style={{ height: 22 }} />
        ))}
      </Space>
    </div>
  )
}

function CardsSkeleton({ rows }: { rows: number }) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: `repeat(auto-fill, minmax(220px, 1fr))`,
        gap: 16,
      }}
    >
      {Array.from({ length: rows }, (_, i) => (
        <Card
          key={i}
          size="small"
          style={{
            borderRadius: 'var(--fw-radius, 6px)',
            borderLeft: '3px solid var(--fw-border)',
          }}
          styles={{ body: { padding: '16px 16px 16px 19px' } }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <div
              style={{
                width: 32,
                height: 32,
                borderRadius: 8,
                background: 'var(--fw-border)',
                opacity: 0.3,
              }}
            />
            <Skeleton.Input active size="small" style={{ width: 60, height: 14 }} />
          </div>
          <Skeleton.Input active size="large" style={{ width: 80, height: 28 }} />
          <div style={{ marginTop: 10 }}>
            <Skeleton.Input active size="small" style={{ width: 120, height: 12 }} />
          </div>
        </Card>
      ))}
    </div>
  )
}

function ChartSkeleton() {
  return (
    <div style={{ height: 260, display: 'flex', alignItems: 'flex-end', gap: 8, padding: '0 4px' }}>
      {[40, 70, 55, 90, 65, 80, 50, 95, 60, 75, 45, 85].map((h, i) => (
        <Skeleton.Button
          key={i}
          active
          style={{ height: `${h}%`, width: '100%', minWidth: 12, borderRadius: 4 }}
        />
      ))}
    </div>
  )
}

function DetailSkeleton() {
  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Skeleton avatar active paragraph={{ rows: 2 }} />
      <Skeleton active paragraph={{ rows: 4 }} title={false} />
    </Space>
  )
}

export function LoadingState({ variant = 'table', rows = 6, bordered = false }: LoadingStateProps) {
  let body: ReactNode
  switch (variant) {
    case 'cards':
      body = <CardsSkeleton rows={rows} />
      break
    case 'chart':
      body = <ChartSkeleton />
      break
    case 'detail':
      body = <DetailSkeleton />
      break
    default:
      body = <TableSkeleton rows={rows} />
  }
  return bordered ? (
    <Card size="small">
      {body}
    </Card>
  ) : (
    body
  )
}
