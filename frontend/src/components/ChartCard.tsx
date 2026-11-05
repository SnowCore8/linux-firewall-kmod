import type { ReactNode } from 'react'
import { Card } from 'antd'

/**
 * 图表卡 —— 给一张图配上统一的标题区（标题 + 右侧说明/操作）与内边距。
 *
 * 纯展示包装：图形本身由 children（通常是 BaseChart）负责，卡片只管「一块带标题的区域」
 * 长什么样，保证仪表盘上多图并排时标题层级、间距、圆角一致。
 *
 * 视觉增强：
 * - 顶部 2px 品牌色条，与 StatCard 的左侧色条呼应
 * - 标题区加粗 + 微妙分隔
 */

export interface ChartCardProps {
  title: ReactNode
  /** 右上角附加内容（图例说明、切换粒度的 Segmented、下载按钮等）。 */
  extra?: ReactNode
  children: ReactNode
  /** 卡片下方的一行说明文字。 */
  footnote?: ReactNode
  /** 占据网格的列宽（配合外层 grid 使用，1=最小单元）。 */
  span?: number
}

export function ChartCard({ title, extra, children, footnote, span = 1 }: ChartCardProps) {
  return (
    <Card
      size="small"
      title={
        <span style={{ fontWeight: 600, fontSize: 13, letterSpacing: '0.01em' }}>{title}</span>
      }
      extra={extra}
      style={{
        gridColumn: `span ${span}`,
        height: '100%',
        borderTop: '2px solid var(--fw-brand)',
      }}
      styles={{
        body: { padding: '12px 16px 16px' },
        header: { borderBottom: '1px solid var(--fw-border)', minHeight: 40 },
      }}
      className="fw-chart-card"
    >
      {children}
      {footnote && (
        <div style={{ marginTop: 8, fontSize: 12, color: 'var(--fw-text-secondary)' }}>{footnote}</div>
      )}
    </Card>
  )
}
